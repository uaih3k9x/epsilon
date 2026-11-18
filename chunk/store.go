package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store 是本地块缓存，布局 dir/<h[:2]>/<h>，和 Build 的 outDir 一样。并发安全。
type Store struct {
	dir   string
	quota int64 // 字节；<=0 不限

	mu    sync.Mutex
	items map[string]*item
	total int64
	clock int64 // 单调递增的"最近使用"时钟（纳秒），保证先后可比
}

type item struct {
	size int64
	used int64
}

// staleTmp: 临时文件放了这么久没动才算崩溃残留。同一块目录上可能同时开着别的 Store
// （探针和 epsilon-env、主控每个请求一个），不能把人家正在写的临时文件删掉。
const staleTmp = time.Hour

// emptyHash 是空内容的 sha256：只有它可以是 0 字节的块。
var emptyHash = func() string { h := sha256.Sum256(nil); return hex.EncodeToString(h[:]) }()

// NewStore 打开（必要时新建）块目录，扫描已有块；最近使用时间用文件修改时间初始化。
// 上次崩溃留下的临时文件（放了 staleTmp 以上的）顺手删掉；0 字节又不是空内容哈希的块
// （断电留下的典型样子）也删掉。别的大小不对、内容不对的块这里看不出来（不知道应有多大、
// 开机重算哈希太慢），拼装时发现再删（见 Assemble）。
func NewStore(dir string, quota int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, quota: quota, items: map[string]*item{}}
	subs, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, sub := range subs {
		if !sub.IsDir() || len(sub.Name()) != 2 {
			continue
		}
		ents, err := os.ReadDir(filepath.Join(dir, sub.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			name := e.Name()
			p := filepath.Join(dir, sub.Name(), name)
			if strings.HasPrefix(name, ".tmp-") {
				if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > staleTmp {
					os.Remove(p)
				}
				continue
			}
			if !ValidHash(name) || name[:2] != sub.Name() || !e.Type().IsRegular() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if fi.Size() == 0 && name != emptyHash {
				os.Remove(p)
				continue
			}
			s.items[name] = &item{size: fi.Size(), used: fi.ModTime().UnixNano()}
			s.total += fi.Size()
		}
	}
	return s, nil
}

// tick 返回严格递增的当前时间，调用方持锁。
func (s *Store) tick() int64 {
	now := time.Now().UnixNano()
	if now <= s.clock {
		now = s.clock + 1
	}
	s.clock = now
	return now
}

func (s *Store) Has(h string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.items[h] != nil
}

// Open 打开一个块读，返回大小；记一次最近使用。
func (s *Store) Open(h string) (io.ReadSeekCloser, int64, error) {
	if !ValidHash(h) {
		return nil, 0, fmt.Errorf("块哈希不合法: %q", h)
	}
	// 持锁打开：不然 Evict 删了、Put 又放回来之后，这里按"文件没了"去掉的会是新放进来的那块
	s.mu.Lock()
	it := s.items[h]
	if it == nil {
		s.mu.Unlock()
		return nil, 0, fmt.Errorf("没有块 %s: %w", h, os.ErrNotExist)
	}
	it.used = s.tick()
	f, err := os.Open(chunkPath(s.dir, h))
	if os.IsNotExist(err) { // 被外面删了
		s.forget(h, it)
	}
	s.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// forget 把块从表里去掉（只在表里还是 it 这一项时）。调用方持锁。
func (s *Store) forget(h string, it *item) {
	if s.items[h] == it {
		s.total -= it.size
		delete(s.items, h)
	}
}

// verify 重算一个块的 sha256；对不上就删掉文件、从表里去掉，返回 ErrHashMismatch。
// 拼装整文件哈希对不上时用来找出坏块（断电截断、磁盘坏），坏块删了下次就会重新取。
func (s *Store) verify(h string) error {
	s.mu.Lock()
	it := s.items[h]
	s.mu.Unlock()
	if it == nil {
		return fmt.Errorf("没有块 %s: %w", h, os.ErrNotExist)
	}
	p := chunkPath(s.dir, h)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	hs := sha256.New()
	_, err = io.Copy(hs, f)
	f.Close()
	if err != nil {
		return err
	}
	if hex.EncodeToString(hs.Sum(nil)) == h {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items[h] != it { // 算哈希期间被淘汰又重新放进来了：新的那块不归这次管
		return nil
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.forget(h, it)
	return fmt.Errorf("块 %s: %w", h, ErrHashMismatch)
}

// Put 存一个块：边写临时文件边算 sha256，对不上返回 ErrHashMismatch；对上了改名就位。
// 已有就读完丢弃返回 nil。
func (s *Store) Put(h string, r io.Reader) error {
	if !ValidHash(h) {
		return fmt.Errorf("块哈希不合法: %q", h)
	}
	s.mu.Lock()
	it := s.items[h]
	if it != nil {
		it.used = s.tick()
	}
	s.mu.Unlock()
	if it != nil {
		_, err := io.Copy(io.Discard, r)
		return err
	}
	_, _, err := s.ingest(r, h)
	return err
}

// ingest 把 r 写成一个块。want 非空时必须对上；为空时按算出来的哈希入库（Build 用）。
// 返回块哈希和字节数。同一块并发 ingest 时谁先改名算谁的，后来的删掉自己的临时文件。
func (s *Store) ingest(r io.Reader, want string) (string, int64, error) {
	tmpDir := s.dir
	if want != "" {
		tmpDir = filepath.Join(s.dir, want[:2])
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(tmpDir, ".tmp-*")
	if err != nil {
		return "", 0, err
	}
	tmp := f.Name()
	hs := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hs), r)
	if err == nil {
		err = f.Sync() // 先落盘再改名：不然断电后正式文件名下可能是半截或全零
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", n, err
	}
	h := hex.EncodeToString(hs.Sum(nil))
	if want != "" && h != want {
		os.Remove(tmp)
		return "", n, fmt.Errorf("块 %s: %w", want, ErrHashMismatch)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if it := s.items[h]; it != nil {
		os.Remove(tmp)
		it.used = s.tick()
		return h, n, nil
	}
	if err := os.MkdirAll(filepath.Join(s.dir, h[:2]), 0o755); err != nil {
		os.Remove(tmp)
		return "", n, err
	}
	if err := os.Rename(tmp, chunkPath(s.dir, h)); err != nil {
		os.Remove(tmp)
		return "", n, err
	}
	s.items[h] = &item{size: n, used: s.tick()}
	s.total += n
	return h, n, nil
}

// List 返回全部块，排好序。
func (s *Store) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.items))
	for h := range s.items {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Evict 超配额时按最近使用最久的先删（keep 里的不删），直到不超；返回删掉的（按删除顺序）。
// 删不掉的（比如 Windows 上正被读）跳过，下次再说。
func (s *Store) Evict(keep map[string]bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quota <= 0 || s.total <= s.quota {
		return nil
	}
	var cand []string
	for h := range s.items {
		if !keep[h] {
			cand = append(cand, h)
		}
	}
	sort.Slice(cand, func(i, j int) bool {
		a, b := s.items[cand[i]], s.items[cand[j]]
		if a.used != b.used {
			return a.used < b.used
		}
		return cand[i] < cand[j]
	})
	var gone []string
	for _, h := range cand {
		if s.total <= s.quota {
			break
		}
		if err := os.Remove(chunkPath(s.dir, h)); err != nil && !os.IsNotExist(err) {
			continue
		}
		s.total -= s.items[h].size
		delete(s.items, h)
		gone = append(gone, h)
	}
	return gone
}
