package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"epsilon/proto"
)

// StampSuffix 是拼好的文件旁边的校验记录后缀。
const StampSuffix = ".epsilon-ok"

// stamp 记录拼好时的整文件 sha256、大小、修改时间；开机核对大小和修改时间一致就不重算哈希。
type stamp struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime_ns"`
}

func checkFile(f proto.ManifestFile) error {
	if !SafePath(f.Path) {
		return fmt.Errorf("路径不合法: %q", f.Path)
	}
	if !ValidHash(f.SHA256) || f.Size < 0 {
		return fmt.Errorf("%s: 清单里的哈希或大小不合法", f.Path)
	}
	for _, h := range f.Chunks {
		if !ValidHash(h) {
			return fmt.Errorf("%s: 块哈希不合法: %q", f.Path, h)
		}
	}
	return nil
}

func dest(root string, f proto.ManifestFile) string {
	return filepath.Join(root, filepath.FromSlash(f.Path))
}

// stampOK 看 path 的 stamp 是否和文件现状、清单对得上。
func stampOK(path string, f proto.ManifestFile) bool {
	raw, err := os.ReadFile(path + StampSuffix)
	if err != nil {
		return false
	}
	var st stamp
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	return st.SHA256 == f.SHA256 && st.Size == f.Size &&
		fi.Size() == f.Size && fi.ModTime().UnixNano() == st.ModTime
}

// Ready 判断清单里所有文件都已拼好落在 root 下（只看 stamp，不重算哈希）。
func Ready(m proto.Manifest, root string) bool {
	for _, f := range m.Files {
		if checkFile(f) != nil || !stampOK(dest(root, f), f) {
			return false
		}
	}
	return true
}

// destLocks: 同一目标路径的拼装排队（按路径散列到固定的几把锁上）。不排队的话，
// 两个 goroutine 同时拼同一路径，最后留下的文件和 stamp 可能不是同一次拼的。只管本进程。
var destLocks [64]sync.Mutex

func lockDest(path string) *sync.Mutex {
	h := fnv.New32a()
	h.Write([]byte(destKey(path)))
	mu := &destLocks[h.Sum32()%uint32(len(destLocks))]
	mu.Lock()
	return mu
}

// destKey: 排队用的路径键。Windows（NTFS）和 macOS 默认文件系统不分大小写，Bin/x 和 bin/x 是同一个文件，
// 所以一律转小写；在分大小写的文件系统上只是多排一会儿队。
func destKey(path string) string { return strings.ToLower(filepath.Clean(path)) }

// errSize: 拼出来的大小和清单不符。
var errSize = errors.New("大小对不上")

// Assemble 把清单里每个文件从块拼到 root/<path>：写临时文件、校验整文件 sha256 和大小、改名，
// 再写 <文件>.epsilon-ok。stamp 对得上的文件跳过。动手前先查齐块，缺块直接报错、什么都不写。
// 整文件对不上时逐块重算，内容不对的块从 s 里删掉（错误里带块名、包着 ErrHashMismatch），
// 调用方看 s.Has 就知道该重新取哪些；不删的话本地坏块会让每次重试都同样失败。
// 某个文件发现坏块后接着拼剩下的文件，一次把所有文件的坏块都找出来（错误合在一起返回）。
func Assemble(m proto.Manifest, s *Store, root string) error {
	var todo []proto.ManifestFile
	for _, f := range m.Files {
		if err := checkFile(f); err != nil {
			return err
		}
		if stampOK(dest(root, f), f) {
			continue
		}
		for _, h := range f.Chunks {
			if !s.Has(h) {
				return fmt.Errorf("%s: 缺块 %s", f.Path, h)
			}
		}
		todo = append(todo, f)
	}
	var errs []error
	for _, f := range todo {
		err := assembleFile(f, s, dest(root, f))
		if err == nil {
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %w", f.Path, err))
		if !errors.Is(err, ErrHashMismatch) && !errors.Is(err, errSize) {
			break // 和块内容无关的错（磁盘满之类），后面的文件多半也一样
		}
	}
	return errors.Join(errs...)
}

func assembleFile(f proto.ManifestFile, s *Store, path string) error {
	defer lockDest(path).Unlock()
	if stampOK(path, f) { // 排队期间别人刚拼好
		return nil
	}
	err := writeFileFromChunks(f, s, path)
	if !errors.Is(err, ErrHashMismatch) && !errors.Is(err, errSize) {
		return err // 成功，或者和块内容无关的错（缺块、磁盘满）：不用逐块重算
	}
	var bad []string
	var verr error // 有块没核对成（读不了、删不掉）：不能断定是清单的错
	for _, h := range f.Chunks {
		switch e := s.verify(h); {
		case errors.Is(e, ErrHashMismatch):
			bad = append(bad, h)
		case e != nil && verr == nil:
			verr = e
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("坏块 %s 已从缓存删掉，要重新取: %w", strings.Join(bad, ", "), ErrHashMismatch)
	}
	if verr != nil {
		return fmt.Errorf("%w（逐块核对时: %v）", err, verr)
	}
	return fmt.Errorf("每块都对，清单里的整文件哈希或大小可能写错了: %w", err)
}

// writeFileFromChunks: 拼到临时文件、校验、改名、写 stamp。
func writeFileFromChunks(f proto.ManifestFile, s *Store, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	err = copyChunks(out, f.Chunks, s, f.Size, f.SHA256)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	// stamp 用改名前临时文件的 Stat：改名不改修改时间；改名后再按正式路径 Stat，读到的可能已经是
	// 别人（另一个进程）刚改名过来的文件。临时文件名只有本进程知道。要在关掉句柄之后读：
	// Windows 上写句柄全关之前修改时间不一定是最终的。
	var fi os.FileInfo
	if err == nil {
		fi, err = os.Stat(tmp)
	}
	if err == nil {
		os.Remove(path + StampSuffix) // 先删旧 stamp，免得改名后新文件配上旧记录
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	raw, _ := json.Marshal(stamp{SHA256: f.SHA256, Size: fi.Size(), ModTime: fi.ModTime().UnixNano()})
	return writeAtomic(path+StampSuffix, raw)
}

func copyChunks(w io.Writer, chunks []string, s *Store, size int64, sum string) error {
	hs := sha256.New()
	mw := io.MultiWriter(w, hs)
	var n int64
	for _, h := range chunks {
		rc, _, err := s.Open(h)
		if err != nil {
			return err
		}
		k, err := io.Copy(mw, rc)
		rc.Close()
		n += k
		if err != nil {
			return err
		}
	}
	if n != size {
		return fmt.Errorf("大小 %d，清单说 %d: %w", n, size, errSize)
	}
	if hex.EncodeToString(hs.Sum(nil)) != sum {
		return fmt.Errorf("整文件: %w", ErrHashMismatch)
	}
	return nil
}
