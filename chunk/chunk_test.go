package chunk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/proto"
)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestValidHash(t *testing.T) {
	good := sum([]byte("x"))
	if !ValidHash(good) {
		t.Fatal("合法哈希被拒")
	}
	for _, h := range []string{"", good[:63], good + "0", strings.ToUpper(good), "../" + good[3:], strings.Repeat("g", 64)} {
		if ValidHash(h) {
			t.Errorf("%q 不该合法", h)
		}
	}
}

func TestSafePath(t *testing.T) {
	for _, p := range []string{"a", "a/b.gguf", "models/qwen/x.gguf", "a..b", "..a/b"} {
		if !SafePath(p) {
			t.Errorf("%q 应该合法", p)
		}
	}
	for _, p := range []string{"", "..", "../x", "a/../x", "a/..", "/x", "C:/x", "c:x", `a\b`, `..\x`, "a//b", "a/", "./a", "a/./b", "a\x00b"} {
		if SafePath(p) {
			t.Errorf("%q 不该合法", p)
		}
	}
}

// 切块边界：整除 / 不整除 / 0 字节 / 比块小。
func TestBuildBoundaries(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	files := map[string][]byte{
		"even.bin":      []byte("0123456789abcd"),  // 14 = 7*2
		"odd.bin":       []byte("0123456789abcde"), // 15 = 7*2+1
		"empty.bin":     {},
		"sub/small.bin": []byte("abc"),
	}
	for p, d := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(p)), d)
	}
	paths := []string{"even.bin", "odd.bin", "empty.bin", "sub/small.bin"}
	m, err := Build("m1", root, paths, 7, out)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "m1" || m.ChunkSize != 7 || len(m.Files) != 4 {
		t.Fatalf("清单不对: %+v", m)
	}
	want := map[string][]string{
		"even.bin":      {"0123456", "789abcd"},
		"odd.bin":       {"0123456", "789abcd", "e"},
		"empty.bin":     {},
		"sub/small.bin": {"abc"},
	}
	for i, f := range m.Files {
		if f.Path != paths[i] {
			t.Fatalf("顺序不对: %s", f.Path)
		}
		data := files[f.Path]
		if f.Size != int64(len(data)) || f.SHA256 != sum(data) {
			t.Errorf("%s 大小或哈希不对", f.Path)
		}
		if f.Chunks == nil {
			t.Errorf("%s chunks 不该是 nil（JSON 要是 []）", f.Path)
		}
		var hs []string
		for _, c := range want[f.Path] {
			hs = append(hs, sum([]byte(c)))
		}
		if len(hs) != len(f.Chunks) || (len(hs) > 0 && !reflect.DeepEqual(hs, f.Chunks)) {
			t.Errorf("%s 块不对: %v", f.Path, f.Chunks)
		}
		for i, h := range f.Chunks {
			got, err := os.ReadFile(filepath.Join(out, h[:2], h))
			if err != nil || string(got) != want[f.Path][i] {
				t.Errorf("块文件 %s 内容不对: %q %v", h, got, err)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(out, "m1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back proto.Manifest
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(back, m) {
		t.Fatalf("清单文件和返回值不一致: %v", err)
	}
	// 输出目录可以直接当块缓存用，没有残留临时文件
	s, err := NewStore(out, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 4 { // 0123456 去重，789abcd 去重，e，abc
		t.Fatalf("块数不对: %v", s.List())
	}
	// 再建一次：已有的块跳过，结果一样
	m2, err := Build("m1", root, paths, 7, out)
	if err != nil || !reflect.DeepEqual(m, m2) {
		t.Fatalf("重复 Build 结果不同: %v", err)
	}
}

func TestBuildDefaultsAndRejects(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(root, "a"), []byte("hello"))
	m, err := Build("m", root, []string{"a"}, 0, out)
	if err != nil || m.ChunkSize != DefaultChunkSize || len(m.Files[0].Chunks) != 1 {
		t.Fatalf("默认块大小不对: %+v %v", m, err)
	}
	for _, c := range []struct {
		id    string
		paths []string
	}{
		{"m", []string{"../a"}},
		{"m", []string{"missing"}},
		{"m", []string{"a", "a"}},
		{"m", nil},
		{"", []string{"a"}},
		{"../m", []string{"a"}},
		{"x/m", []string{"a"}},
	} {
		if _, err := Build(c.id, root, c.paths, 7, out); err == nil {
			t.Errorf("Build(%q, %v) 应该失败", c.id, c.paths)
		}
	}
}

func TestStorePutHasOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("chunk-data")
	h := sum(data)
	if s.Has(h) {
		t.Fatal("还没放就有了")
	}
	if err := s.Put(h, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(h) {
		t.Fatal("放了没有")
	}
	rc, n, err := s.Open(h)
	if err != nil || n != int64(len(data)) {
		t.Fatalf("Open: %d %v", n, err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("内容不对")
	}
	if _, err := os.Stat(filepath.Join(dir, h[:2], h)); err != nil {
		t.Fatal("布局不对", err)
	}
	// 已有：读完丢弃
	r := strings.NewReader("whatever")
	if err := s.Put(h, r); err != nil || r.Len() != 0 {
		t.Fatalf("已有块应读完丢弃并返回 nil: %v", err)
	}
	if _, _, err := s.Open(sum([]byte("nope"))); err == nil {
		t.Fatal("没有的块 Open 应该失败")
	}
	if err := s.Put("bad", bytes.NewReader(data)); err == nil {
		t.Fatal("非法哈希应该拒绝")
	}
	// 重启扫描
	s2, err := NewStore(dir, 0)
	if err != nil || !reflect.DeepEqual(s2.List(), []string{h}) {
		t.Fatalf("重启扫描不对: %v %v", s2.List(), err)
	}
}

func TestStorePutMismatch(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir, 0)
	h := sum([]byte("good"))
	err := s.Put(h, strings.NewReader("evil"))
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("要 ErrHashMismatch，得到 %v", err)
	}
	if s.Has(h) || len(s.List()) != 0 {
		t.Fatal("坏块不该进缓存")
	}
	// 不留临时文件
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			t.Errorf("残留文件 %s", p)
		}
		return nil
	})
}

func TestStorePutConcurrent(t *testing.T) {
	s, _ := NewStore(t.TempDir(), 0)
	var blobs [][]byte
	for i := 0; i < 8; i++ {
		blobs = append(blobs, bytes.Repeat([]byte{byte('a' + i)}, 1000+i))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for round := 0; round < 4; round++ { // 每块 4 个 goroutine 同时放
		for _, b := range blobs {
			wg.Add(1)
			go func(b []byte) {
				defer wg.Done()
				errs <- s.Put(sum(b), bytes.NewReader(b))
			}(b)
		}
	}
	// 夹几个坏的（声明的块永远不会有人放对）
	never := sum([]byte("never"))
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Put(never, strings.NewReader("bad")); !errors.Is(err, ErrHashMismatch) {
				errs <- errors.New("坏块没被拒")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.Has(never) || len(s.List()) != len(blobs) {
		t.Fatalf("块数不对: %d", len(s.List()))
	}
	for _, b := range blobs {
		rc, _, err := s.Open(sum(b))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, b) {
			t.Fatal("内容不对")
		}
	}
}

func TestStoreEvict(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir, 30) // 每块 10 字节，最多 3 块
	var hs []string
	for i := 0; i < 5; i++ {
		b := bytes.Repeat([]byte{byte('0' + i)}, 10)
		hs = append(hs, sum(b))
		if err := s.Put(hs[i], bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}
	// 使用顺序：0 1 2 3 4，然后再用一次 0 → 最久没用的是 1、2、3
	rc, _, _ := s.Open(hs[0])
	rc.Close()
	got := s.Evict(map[string]bool{hs[1]: true})
	want := []string{hs[2], hs[3]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("淘汰顺序不对\n得到 %v\n想要 %v", got, want)
	}
	for _, h := range want {
		if s.Has(h) {
			t.Errorf("%s 应该被删", h)
		}
		if _, err := os.Stat(filepath.Join(dir, h[:2], h)); !os.IsNotExist(err) {
			t.Errorf("%s 文件还在", h)
		}
	}
	if !s.Has(hs[1]) || !s.Has(hs[0]) || !s.Has(hs[4]) {
		t.Fatal("不该删的被删了")
	}
	if got := s.Evict(nil); len(got) != 0 {
		t.Fatalf("不超配额不该删: %v", got)
	}
	// keep 全保住，就算超配额也不删
	b := bytes.Repeat([]byte("z"), 10)
	s.Put(sum(b), bytes.NewReader(b))
	keep := map[string]bool{}
	for _, h := range s.List() {
		keep[h] = true
	}
	if got := s.Evict(keep); len(got) != 0 {
		t.Fatalf("keep 里的不该删: %v", got)
	}
	// 不限配额
	u, _ := NewStore(dir, 0)
	if got := u.Evict(nil); len(got) != 0 {
		t.Fatalf("不限配额不该删: %v", got)
	}
}

func TestStoreEvictStartupOrderByMtime(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir, 0)
	var hs []string
	for i := 0; i < 3; i++ {
		b := bytes.Repeat([]byte{byte('a' + i)}, 10)
		h := sum(b)
		hs = append(hs, h)
		s.Put(h, bytes.NewReader(b))
		mt := time.Now().Add(time.Duration(-10+i) * time.Hour) // 0 最旧
		if i == 1 {
			mt = time.Now().Add(-20 * time.Hour) // 1 比 0 还旧
		}
		os.Chtimes(filepath.Join(dir, h[:2], h), mt, mt)
	}
	s2, _ := NewStore(dir, 10)
	got := s2.Evict(nil)
	if !reflect.DeepEqual(got, []string{hs[1], hs[0]}) {
		t.Fatalf("启动后按修改时间淘汰不对: %v", got)
	}
}

func buildFixture(t *testing.T) (proto.Manifest, *Store, map[string][]byte) {
	t.Helper()
	src, out := t.TempDir(), t.TempDir()
	files := map[string][]byte{
		"models/a.gguf": []byte("the quick brown fox jumps over the lazy dog"),
		"b.txt":         []byte("1234567"),
		"empty":         {},
	}
	paths := []string{"models/a.gguf", "b.txt", "empty"} // 固定顺序
	for p, d := range files {
		writeFile(t, filepath.Join(src, filepath.FromSlash(p)), d)
	}
	m, err := Build("fx", src, paths, 7, out)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(out, 0)
	if err != nil {
		t.Fatal(err)
	}
	return m, s, files
}

func TestAssemble(t *testing.T) {
	m, s, files := buildFixture(t)
	root := t.TempDir()
	if Ready(m, root) {
		t.Fatal("还没拼就 Ready")
	}
	if err := Assemble(m, s, root); err != nil {
		t.Fatal(err)
	}
	for p, d := range files {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil || !bytes.Equal(got, d) {
			t.Errorf("%s 内容不对: %v", p, err)
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p)) + ".epsilon-ok"); err != nil {
			t.Errorf("%s 没有 stamp", p)
		}
	}
	if !Ready(m, root) {
		t.Fatal("拼好了却不 Ready")
	}
	// 目录里只有成品和 stamp，没有临时文件
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && strings.Contains(fi.Name(), "tmp") {
			t.Errorf("残留临时文件 %s", p)
		}
		return nil
	})
}

func TestAssembleMissingChunk(t *testing.T) {
	m, s, _ := buildFixture(t)
	a := m.Files[0].Chunks
	h := a[len(a)-1] // models/a.gguf 的最后一块
	os.Remove(filepath.Join(s.dir, h[:2], h))
	s2, _ := NewStore(s.dir, 0)
	root := t.TempDir()
	err := Assemble(m, s2, root)
	if err == nil || !strings.Contains(err.Error(), h) {
		t.Fatalf("缺块应报错并带块名: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "models", "a.gguf")); !os.IsNotExist(err) {
		t.Fatal("缺块时不该留下半截文件")
	}
	if Ready(m, root) {
		t.Fatal("缺块不该 Ready")
	}
}

func TestAssembleStampSkip(t *testing.T) {
	m, s, _ := buildFixture(t)
	root := t.TempDir()
	if err := Assemble(m, s, root); err != nil {
		t.Fatal(err)
	}
	// stamp 对得上就不再读块：把块全删了，再拼一次也应成功
	for _, h := range s.List() {
		os.Remove(filepath.Join(s.dir, h[:2], h))
	}
	empty, _ := NewStore(s.dir, 0)
	if err := Assemble(m, empty, root); err != nil {
		t.Fatalf("stamp 对得上应跳过: %v", err)
	}
}

func TestStampInvalidatedByChange(t *testing.T) {
	m, s, files := buildFixture(t)
	root := t.TempDir()
	if err := Assemble(m, s, root); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "models", "a.gguf")

	// 改内容（同样大小），修改时间变了 → stamp 失效
	fi, _ := os.Stat(p)
	bad := bytes.Repeat([]byte("x"), int(fi.Size()))
	os.WriteFile(p, bad, 0o644)
	later := fi.ModTime().Add(2 * time.Second)
	os.Chtimes(p, later, later)
	if Ready(m, root) {
		t.Fatal("文件被改了还 Ready")
	}
	if err := Assemble(m, s, root); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, files["models/a.gguf"]) || !Ready(m, root) {
		t.Fatal("stamp 失效后应重新拼")
	}

	// 改大小
	os.WriteFile(p, []byte("short"), 0o644)
	if Ready(m, root) {
		t.Fatal("大小变了还 Ready")
	}

	// 清单换了哈希（新版本制品）→ 旧 stamp 不算数
	if err := Assemble(m, s, root); err != nil {
		t.Fatal(err)
	}
	m2 := m
	m2.Files = append([]proto.ManifestFile(nil), m.Files...)
	for i := range m2.Files {
		if m2.Files[i].Path == "models/a.gguf" {
			m2.Files[i].SHA256 = sum([]byte("other"))
		}
	}
	if Ready(m2, root) {
		t.Fatal("清单哈希不同不该 Ready")
	}

	// stamp 被删
	os.Remove(p + ".epsilon-ok")
	if Ready(m, root) {
		t.Fatal("没有 stamp 不该 Ready")
	}
}

func TestAssembleRejectsBadManifest(t *testing.T) {
	m, s, _ := buildFixture(t)
	root := t.TempDir()
	bad := m
	bad.Files = []proto.ManifestFile{m.Files[0]}
	bad.Files[0].Path = "../escape"
	if err := Assemble(bad, s, root); err == nil {
		t.Fatal("坏路径应拒绝")
	}
	if Ready(bad, root) {
		t.Fatal("坏路径不该 Ready")
	}
	// 块齐但整文件哈希对不上（清单写错）
	bad.Files[0] = m.Files[0]
	bad.Files[0].SHA256 = sum([]byte("lie"))
	if err := Assemble(bad, s, root); err == nil {
		t.Fatal("整文件哈希不符应报错")
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(bad.Files[0].Path))); !os.IsNotExist(err) {
		t.Fatal("校验失败不该落地")
	}
}
