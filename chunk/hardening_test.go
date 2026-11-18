package chunk

// 加固测试：并发、断电留下的坏块、同一路径并发拼装。都要在 -race 下跑。

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/proto"
)

// diskChunks 返回磁盘上的块（名字 → 大小），不算临时文件。
func diskChunks(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	subs, _ := os.ReadDir(dir)
	for _, sub := range subs {
		if !sub.IsDir() {
			continue
		}
		ents, _ := os.ReadDir(filepath.Join(dir, sub.Name()))
		for _, e := range ents {
			if ValidHash(e.Name()) {
				fi, err := e.Info()
				if err == nil {
					out[e.Name()] = fi.Size()
				}
			}
		}
	}
	return out
}

func TestStoreConcurrentPutOpenEvictList(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir, 2000) // 能放下大约一半
	var blobs [][]byte
	for i := 0; i < 16; i++ {
		blobs = append(blobs, bytes.Repeat([]byte{byte('a' + i)}, 200+i))
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 300; i++ {
				b := blobs[r.Intn(len(blobs))]
				h := sum(b)
				switch r.Intn(4) {
				case 0:
					if err := s.Put(h, bytes.NewReader(b)); err != nil {
						t.Error(err)
					}
				case 1:
					if rc, _, err := s.Open(h); err == nil {
						got, _ := io.ReadAll(rc)
						rc.Close()
						if len(got) != 0 && !bytes.Equal(got, b) {
							t.Error("读到的内容不对")
						}
					}
				case 2:
					s.Evict(map[string]bool{sum(blobs[0]): true})
				case 3:
					s.List()
				}
			}
		}(g)
	}
	wg.Wait()

	disk := diskChunks(t, dir)
	var diskTotal int64
	var diskList []string
	for h, n := range disk {
		diskTotal += n
		diskList = append(diskList, h)
	}
	sort.Strings(diskList)
	s.mu.Lock()
	total := s.total
	s.mu.Unlock()
	if total != diskTotal {
		t.Fatalf("total=%d，磁盘上实际 %d", total, diskTotal)
	}
	if got := s.List(); !reflect.DeepEqual(got, diskList) && !(len(got) == 0 && len(diskList) == 0) {
		t.Fatalf("List 和磁盘不一致\nList %v\n磁盘 %v", got, diskList)
	}
}

func TestAssembleConcurrentSameManifest(t *testing.T) {
	m, s, files := buildFixture(t)
	root := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- Assemble(m, s, root) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !Ready(m, root) {
		t.Fatal("并发拼同一份清单，拼完却不 Ready")
	}
	for p, d := range files {
		got, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if !bytes.Equal(got, d) {
			t.Fatalf("%s 内容不对", p)
		}
	}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(fi.Name(), ".tmp-") {
			t.Errorf("残留临时文件 %s", p)
		}
		return nil
	})
}

// 疑点 4：两份清单同一路径、同样大小、内容不同，同时拼装。
// 不管谁赢，Ready(X) 为真时文件内容必须真是 X 的。
func TestAssembleSamePathDifferentManifests(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(src, "a", "w.bin"), bytes.Repeat([]byte("A"), 4096))
	writeFile(t, filepath.Join(src, "b", "w.bin"), bytes.Repeat([]byte("B"), 4096))
	ma, err := Build("ma", filepath.Join(src, "a"), []string{"w.bin"}, 1024, out)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := Build("mb", filepath.Join(src, "b"), []string{"w.bin"}, 1024, out)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := NewStore(out, 0)

	// 把"改名之后"这个窗口拉长，让另一边有机会插进来
	testHookRenamed = func(string) { time.Sleep(2 * time.Millisecond) }
	defer func() { testHookRenamed = nil }()

	for round := 0; round < 20; round++ {
		root := t.TempDir()
		var wg sync.WaitGroup
		for _, m := range []proto.Manifest{ma, mb} {
			wg.Add(1)
			go func(m proto.Manifest) { defer wg.Done(); Assemble(m, s, root) }(m)
		}
		wg.Wait()
		got, _ := os.ReadFile(filepath.Join(root, "w.bin"))
		for _, m := range []proto.Manifest{ma, mb} {
			if Ready(m, root) && sum(got) != m.Files[0].SHA256 {
				t.Fatalf("第 %d 轮：Ready(%s) 为真，文件却是另一份", round, m.ID)
			}
		}
	}
}

// 疑点 1：断电后块文件被截断（没刷盘就改了名）。
func TestNewStoreTruncatedChunk(t *testing.T) {
	m, s, files := buildFixture(t)
	a := m.Files[0].Chunks
	half, zero := a[0], a[1]
	truncate := func(h string, n int64) {
		if err := os.Truncate(chunkPath(s.dir, h), n); err != nil {
			t.Fatal(err)
		}
	}
	truncate(half, 3)
	truncate(zero, 0)

	s2, err := NewStore(s.dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Has(zero) {
		t.Fatal("0 字节的块（又不是空内容的哈希）开机就该丢掉")
	}
	if _, err := os.Stat(chunkPath(s.dir, zero)); !os.IsNotExist(err) {
		t.Fatal("0 字节的坏块文件该删掉")
	}
	root := t.TempDir()
	if err := Assemble(m, s2, root); err == nil || !strings.Contains(err.Error(), zero) {
		t.Fatalf("丢掉的 0 字节块应该按缺块报: %v", err)
	}
	// 缺的那块取回来了，剩下截了一半的那块：拼装时发现、删掉
	whole := files["models/a.gguf"]
	if err := s2.Put(zero, bytes.NewReader(whole[m.ChunkSize:2*m.ChunkSize])); err != nil {
		t.Fatal(err)
	}
	if err := Assemble(m, s2, root); !errors.Is(err, ErrHashMismatch) || !strings.Contains(err.Error(), half) {
		t.Fatalf("截断的块应该被认出来: %v", err)
	}
	healAndRetry(t, m, s2, root, files, half)
}

// 疑点 2：块内容坏了（大小不变），Assemble 要把它删掉，不能每次都同样失败。
func TestAssembleDropsCorruptChunk(t *testing.T) {
	m, s, files := buildFixture(t)
	bad := m.Files[0].Chunks[2]
	p := chunkPath(s.dir, bad)
	b, _ := os.ReadFile(p)
	b[0] ^= 0xff
	os.WriteFile(p, b, 0o644)

	root := t.TempDir()
	err := Assemble(m, s, root)
	if !errors.Is(err, ErrHashMismatch) || !strings.Contains(err.Error(), bad) {
		t.Fatalf("应报哈希不符并带出坏块名: %v", err)
	}
	healAndRetry(t, m, s, root, files, bad)
}

// healAndRetry: 坏块应该已经从缓存里删掉（Has 为假、文件没了），好块还在；
// 把坏块按原内容重新放进去，再拼就成。
func healAndRetry(t *testing.T, m proto.Manifest, s *Store, root string, files map[string][]byte, bad ...string) {
	t.Helper()
	isBad := map[string]bool{}
	for _, h := range bad {
		isBad[h] = true
		if s.Has(h) {
			t.Fatalf("坏块 %s 还在缓存里", h[:12])
		}
		if _, err := os.Stat(chunkPath(s.dir, h)); !os.IsNotExist(err) {
			t.Fatalf("坏块 %s 的文件还在", h[:12])
		}
	}
	for _, f := range m.Files {
		for _, h := range f.Chunks {
			if !isBad[h] && !s.Has(h) {
				t.Fatalf("好块 %s 被误删", h[:12])
			}
		}
	}
	// 按原文件内容重新切出坏块放回去
	whole := files["models/a.gguf"]
	for i, h := range m.Files[0].Chunks {
		if isBad[h] {
			lo, hi := int64(i)*m.ChunkSize, min(int64(i+1)*m.ChunkSize, int64(len(whole)))
			if err := s.Put(h, bytes.NewReader(whole[lo:hi])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := Assemble(m, s, root); err != nil {
		t.Fatalf("补齐坏块后还拼不成: %v", err)
	}
	if !Ready(m, root) {
		t.Fatal("补齐坏块后不 Ready")
	}
}

// NewStore 只清理放了很久的临时文件：同一目录上另开一个 Store（比如 epsilon-env 和探针共用块目录），
// 不能把别人正在写的临时文件删掉。
func TestNewStoreKeepsFreshTmp(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "ab")
	writeFile(t, filepath.Join(sub, ".tmp-fresh"), []byte("x"))
	writeFile(t, filepath.Join(sub, ".tmp-stale"), []byte("x"))
	old := time.Now().Add(-2 * staleTmp)
	os.Chtimes(filepath.Join(sub, ".tmp-stale"), old, old)
	if _, err := NewStore(dir, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sub, ".tmp-fresh")); err != nil {
		t.Fatal("刚写的临时文件被删了")
	}
	if _, err := os.Stat(filepath.Join(sub, ".tmp-stale")); !os.IsNotExist(err) {
		t.Fatal("放了很久的临时文件该删")
	}
}

// 0 字节的块只有在它就是空内容的哈希时才算好的。
func TestNewStoreKeepsEmptyChunk(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir, 0)
	h := sum(nil)
	if err := s.Put(h, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	s2, _ := NewStore(dir, 0)
	if !s2.Has(h) {
		t.Fatal("空内容的块被当成坏块丢了")
	}
}

func FuzzAssembleManifest(f *testing.F) {
	good := sum([]byte("hello"))
	seed := func(files ...proto.ManifestFile) {
		raw, _ := json.Marshal(proto.Manifest{ID: "fz", ChunkSize: 5, Files: files})
		f.Add(raw)
	}
	seed(proto.ManifestFile{Path: "a.bin", Size: 5, SHA256: good, Chunks: []string{good}})
	seed(proto.ManifestFile{Path: "d/a.bin", Size: 10, SHA256: sum([]byte("hellohello")), Chunks: []string{good, good}})
	seed(proto.ManifestFile{Path: "../escape", Size: 5, SHA256: good, Chunks: []string{good}})
	seed(proto.ManifestFile{Path: "/abs", Size: 5, SHA256: good, Chunks: []string{good}})
	seed(proto.ManifestFile{Path: "a/../../x", Size: 5, SHA256: good, Chunks: []string{good}})
	seed(proto.ManifestFile{Path: "C:/x", Size: 5, SHA256: good, Chunks: []string{good}})
	seed(proto.ManifestFile{Path: "a", Size: 5, SHA256: good, Chunks: []string{good}},
		proto.ManifestFile{Path: "a/b", Size: 5, SHA256: good, Chunks: []string{good}})
	seed(proto.ManifestFile{Path: "x", Size: -1, SHA256: "zz", Chunks: []string{"../../etc"}})
	f.Add([]byte(`{"id":"fz","files":[{"path":"x.epsilon-ok","size":5,"sha256":"` + good + `","chunks":["` + good + `"]}]}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var m proto.Manifest
		if json.Unmarshal(raw, &m) != nil {
			return
		}
		base := t.TempDir()
		root := filepath.Join(base, "root")
		s, err := NewStore(filepath.Join(base, "store"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(good, strings.NewReader("hello")); err != nil {
			t.Fatal(err)
		}
		Assemble(m, s, root)
		Ready(m, root)
		// root 外面只能有 store 和 root 本身；store 里只能有那一个块
		ents, _ := os.ReadDir(base)
		for _, e := range ents {
			if e.Name() != "root" && e.Name() != "store" {
				t.Fatalf("写到 root 外面去了: %s", e.Name())
			}
		}
		if got := diskChunks(t, filepath.Join(base, "store")); len(got) != 1 {
			t.Fatalf("块目录被改了: %v", got)
		}
		filepath.Walk(filepath.Join(base, "store"), func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() && filepath.Base(p) != good {
				t.Fatalf("块目录里多了 %s", p)
			}
			return nil
		})
	})
}
