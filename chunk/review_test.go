package chunk

// 第二轮审查发现的问题的复现测试。

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"epsilon/proto"
)

func corrupt(t *testing.T, s *Store, h string) {
	t.Helper()
	p := chunkPath(s.dir, h)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// 多个文件共用一块（全零块）且它坏了：前面文件核对时把它删了，后面文件 Open 报"没有块"，
// 不能就此停下，后面文件（以及这个文件其它块）的坏块也要在同一次 Assemble 里找出来。
func TestAssembleSharedCorruptChunkFindsLaterBadChunks(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	files := map[string][]byte{
		"a": []byte("ZZZZxxxx"),
		"b": []byte("ZZZZwwww"),
		"c": []byte("yyyy"),
	}
	paths := []string{"a", "b", "c"}
	for p, d := range files {
		writeFile(t, filepath.Join(src, p), d)
	}
	m, err := Build("shared", src, paths, 4, out)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(out, 0)
	if err != nil {
		t.Fatal(err)
	}
	z, w, y := m.Files[0].Chunks[0], m.Files[1].Chunks[1], m.Files[2].Chunks[0]
	if m.Files[1].Chunks[0] != z {
		t.Fatal("夹具里 a、b 应共用第一块")
	}
	for _, h := range []string{z, w, y} {
		corrupt(t, s, h)
	}
	err = Assemble(m, s, t.TempDir())
	if err == nil {
		t.Fatal("有坏块却拼成了")
	}
	for name, h := range map[string]string{"z": z, "w": w, "y": y} {
		if s.Has(h) {
			t.Fatalf("坏块 %s 一次 Assemble 没找出来: %v", name, err)
		}
	}
	// 补回来之后一次就拼成
	for _, p := range paths {
		for i, h := range m.Files[indexOf(paths, p)].Chunks {
			d := files[p]
			if err := s.Put(h, bytes.NewReader(d[i*4:min((i+1)*4, len(d))])); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	if err := Assemble(m, s, root); err != nil || !Ready(m, root) {
		t.Fatalf("补齐后拼不成: %v", err)
	}
}

func indexOf(l []string, s string) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
}

// 清单里两个路径只差大小写（或者一个路径正好是另一个的 stamp 名），在 Windows/macOS 上落到同一个文件，
// 每次重试都会互相覆盖、Ready 永远为假。整份拒收，什么都不写。
func TestAssembleRejectsCollidingPaths(t *testing.T) {
	m, s, _ := buildFixture(t)
	cases := map[string]func(f proto.ManifestFile) proto.ManifestFile{
		"大小写":   func(f proto.ManifestFile) proto.ManifestFile { f.Path = strings.ToUpper(f.Path); return f },
		"stamp": func(f proto.ManifestFile) proto.ManifestFile { f.Path += StampSuffix; return f },
		"尾点":    func(f proto.ManifestFile) proto.ManifestFile { f.Path += ". "; return f },
		"stamp大小写": func(f proto.ManifestFile) proto.ManifestFile {
			f.Path += strings.ToUpper(StampSuffix)
			return f
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			mm := m
			mm.Files = append(append([]proto.ManifestFile(nil), m.Files...), mk(m.Files[1]))
			root := t.TempDir()
			if err := Assemble(mm, s, root); err == nil {
				t.Fatal("路径冲突的清单应该拒收")
			}
			if Ready(mm, root) {
				t.Fatal("路径冲突的清单不该 Ready")
			}
			if ents, _ := os.ReadDir(root); len(ents) != 0 {
				t.Fatalf("拒收前不该写任何东西: %v", ents)
			}
		})
	}
}

// Windows 上坏块正被读（P2P 服务发给邻居）时删不掉：也要从表里去掉（不再报给邻居、
// 让调用方去重取），并按坏块报出来。
func TestVerifyForgetsCorruptChunkEvenIfRemoveFails(t *testing.T) {
	m, s, _ := buildFixture(t)
	bad := m.Files[0].Chunks[2]
	corrupt(t, s, bad)
	tried := 0
	s.remove = func(string) error { tried++; return errors.New("sharing violation") }
	err := Assemble(m, s, t.TempDir())
	if tried == 0 {
		t.Fatal("删块没走 Store.remove")
	}
	if !errors.Is(err, ErrHashMismatch) || !strings.Contains(err.Error(), bad) {
		t.Fatalf("删不掉也应报坏块: %v", err)
	}
	if s.Has(bad) {
		t.Fatal("删不掉的坏块还在表里，会继续报给邻居")
	}
	if _, _, err := s.Open(bad); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("坏块还能被 Open（P2P 服务会把它发出去）: %v", err)
	}
}
