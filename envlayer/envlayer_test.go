package envlayer

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"epsilon/chunk"
	"epsilon/proto"
)

const layer = "py311-test@1"

var d1, d2 = strings.Repeat("a", 64), strings.Repeat("b", 64)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type entry struct {
	name string
	body string
	mode os.FileMode
}

func writeZip(t *testing.T, path string, entries []entry) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(e.body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func goodEntries() []entry {
	return []entry{
		{name: "python.exe", body: "MZ fake"},
		{name: "Lib/site-packages/"},
		{name: "Lib/site-packages/torch/__init__.py", body: "x = 1\n"},
	}
}

// 没有残留: 失败时目标目录和临时目录都不留
func assertClean(t *testing.T, parent string) {
	t.Helper()
	es, _ := os.ReadDir(parent)
	for _, e := range es {
		if e.IsDir() {
			t.Fatalf("失败后留下了目录 %s", e.Name())
		}
	}
}

// ------------------------------------------------------------------ Expand

func TestExpandAndReady(t *testing.T) {
	d := t.TempDir()
	z, dir := filepath.Join(d, "l.zip"), filepath.Join(d, layer)
	writeZip(t, z, goodEntries())
	if Ready(dir, d1) {
		t.Fatal("还没解压就 Ready 了")
	}
	n, err := Expand(z, dir, d1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("文件数 = %d, 要 2 (目录不算)", n)
	}
	got, err := os.ReadFile(filepath.Join(dir, "Lib", "site-packages", "torch", "__init__.py"))
	if err != nil || string(got) != "x = 1\n" {
		t.Fatalf("内容不对: %q %v", got, err)
	}
	if !Ready(dir, d1) {
		t.Fatal("解压完应该 Ready")
	}
	if Ready(dir, d2) {
		t.Fatal("摘要换了 (钥匙环发了新摘要) 不该 Ready")
	}
}

func TestExpandRejectsBadLayers(t *testing.T) {
	py := entry{name: "python.exe", body: "x"}
	cases := map[string][]entry{
		"路径穿越":    {py, {name: "../evil.dll", body: "x"}},
		"深层穿越":    {py, {name: "Lib/../../evil.dll", body: "x"}},
		"绝对路径":    {py, {name: "/evil.dll", body: "x"}},
		"反斜杠穿越":   {py, {name: "..\\evil.dll", body: "x"}},
		"盘符":      {py, {name: "C:/evil.dll", body: "x"}},
		"备用数据流":   {py, {name: "python.exe:evil", body: "x"}},
		"软链接":     {py, {name: "link", body: "/etc/passwd", mode: os.ModeSymlink | 0o777}},
		"大小写冲突":   {py, {name: "Lib/a.py", body: "1"}, {name: "lib/A.py", body: "2"}},
		"没有解释器":   {{name: "Lib/a.py", body: "x"}},
		"解释器不在根下": {{name: "bin/python.exe", body: "x"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			sub := filepath.Join(d, "envs")
			os.Mkdir(sub, 0o755)
			z := filepath.Join(d, "l.zip")
			writeZip(t, z, entries)
			if _, err := Expand(z, filepath.Join(sub, layer), d1); err == nil {
				t.Fatal("竟然解压了")
			}
			assertClean(t, sub)
			if _, err := os.Stat(filepath.Join(d, "evil.dll")); err == nil {
				t.Fatal("文件写到目录外面去了")
			}
		})
	}
}

func TestExpandCorruptZipLeavesNothing(t *testing.T) {
	d := t.TempDir()
	sub := filepath.Join(d, "envs")
	os.Mkdir(sub, 0o755)
	z := filepath.Join(d, "l.zip")
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range []entry{{name: "python.exe", body: "MZ"}, {name: "payload.bin", body: "AAAA-MARK-AAAA"}} {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		f, _ := w.CreateHeader(h)
		f.Write([]byte(e.body))
	}
	w.Close()
	raw := bytes.Replace(buf.Bytes(), []byte("AAAA-MARK-AAAA"), []byte("AAAA-EVIL-AAAA"), 1)
	os.WriteFile(z, raw, 0o644)
	if _, err := Expand(z, filepath.Join(sub, layer), d1); err == nil {
		t.Fatal("CRC 不对的 zip 竟然解压了")
	}
	assertClean(t, sub)
}

func TestExpandReplacesHalfDoneDir(t *testing.T) {
	// 上次没完成 (没有 stamp): 残留要清掉, 不能和新内容混在一起
	d := t.TempDir()
	z, dir := filepath.Join(d, "l.zip"), filepath.Join(d, layer)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "stale.dll"), []byte("old"), 0o644)
	os.MkdirAll(filepath.Join(d, layer+".tmp-123"), 0o755)
	writeZip(t, z, goodEntries())
	if _, err := Expand(z, dir, d1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "stale.dll")); err == nil {
		t.Fatal("旧文件没清掉")
	}
	if _, err := os.Stat(filepath.Join(d, layer+".tmp-123")); err == nil {
		t.Fatal("上次的临时目录没清掉")
	}
}

func TestReadyNeedsInterpreter(t *testing.T) {
	d := t.TempDir()
	z, dir := filepath.Join(d, "l.zip"), filepath.Join(d, layer)
	writeZip(t, z, goodEntries())
	if _, err := Expand(z, dir, d1); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "python.exe"))
	if Ready(dir, d1) {
		t.Fatal("解释器都没了还 Ready")
	}
}

// ------------------------------------------------------------------ Parse

func TestParseChecksDigestAndShape(t *testing.T) {
	h := strings.Repeat("c", 64)
	one := proto.ManifestFile{Path: "envs/" + layer + ".zip", Size: 1, SHA256: h, Chunks: []string{h}}
	good := proto.Manifest{ID: layer, ChunkSize: 64, Files: []proto.ManifestFile{one}}
	raw, _ := json.Marshal(good)
	if _, err := Parse(raw, layer, sum(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw, layer, d1); err == nil {
		t.Fatal("摘要对不上 (主控换了清单) 竟然过了")
	}
	if _, err := Parse(raw, "py311-other@1", sum(raw)); err == nil {
		t.Fatal("拿别的环境层的清单冒充竟然过了")
	}
	for name, mut := range map[string]func(*proto.Manifest){
		"两个文件": func(m *proto.Manifest) { m.Files = append(m.Files, one) },
		"没有文件": func(m *proto.Manifest) { m.Files = nil },
		"路径不对": func(m *proto.Manifest) {
			m.Files = []proto.ManifestFile{{Path: "../x.zip", Size: 1, SHA256: h, Chunks: []string{h}}}
		},
	} {
		m := good
		mut(&m)
		b, _ := json.Marshal(m)
		if _, err := Parse(b, layer, sum(b)); err == nil {
			t.Errorf("%s: 竟然过了", name)
		}
	}
}

// ------------------------------------------------------------------ Install

func buildLayer(t *testing.T) (raw []byte, s *chunk.Store, root string) {
	t.Helper()
	d := t.TempDir()
	src, chunks := filepath.Join(d, "src"), filepath.Join(d, "chunks")
	os.MkdirAll(filepath.Join(src, "envs"), 0o755)
	writeZip(t, filepath.Join(src, "envs", layer+".zip"), goodEntries())
	if _, err := chunk.Build(layer, src, []string{"envs/" + layer + ".zip"}, 1<<20, chunks); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(chunks, layer+".json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err = chunk.NewStore(chunks, 0)
	if err != nil {
		t.Fatal(err)
	}
	return raw, s, filepath.Join(d, "root")
}

func TestInstallEndToEnd(t *testing.T) {
	raw, s, root := buildLayer(t)
	res, err := Install(raw, layer, sum(raw), s, root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Dir != Dir(root, layer) || res.Files != 2 {
		t.Fatalf("结果不对: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "python.exe")); err != nil {
		t.Fatal(err)
	}
	// zip 解压完就删 (块缓存里还有), 省一份磁盘
	if _, err := os.Stat(filepath.Join(root, "envs", layer+".zip")); err == nil {
		t.Fatal("解压后 zip 没删")
	}
	res, err = Install(raw, layer, sum(raw), s, root)
	if err != nil || res.Files != 0 {
		t.Fatalf("已经装好的不该再装一遍: %+v %v", res, err)
	}
}

func TestInstallRefusesWrongDigestBeforeTouchingDisk(t *testing.T) {
	raw, s, root := buildLayer(t)
	if _, err := Install(raw, layer, d1, s, root); err == nil {
		t.Fatal("摘要不对竟然装了")
	}
	if _, err := os.Stat(root); err == nil {
		t.Fatal("摘要不对时不该写任何东西")
	}
}

func TestInstallMissingChunkFails(t *testing.T) {
	raw, _, root := buildLayer(t)
	empty, err := chunk.NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(raw, layer, sum(raw), empty, root); err == nil {
		t.Fatal("缺块竟然装了")
	}
}

func TestCommandAlwaysIsolates(t *testing.T) {
	// 层里没有 ._pth, 隔离全靠 -E; 不写字节码靠 -B。调用方不能漏掉。
	cmd := Command("/r/envs/x@1", "/j/code/train.py", "--a")
	want := []string{filepath.Join("/r/envs/x@1", Interpreter), "-E", "-B", "/j/code/train.py", "--a"}
	if strings.Join(cmd.Args, " ") != strings.Join(want, " ") || cmd.Path != want[0] {
		t.Fatalf("命令不对: %q %q", cmd.Path, cmd.Args)
	}
}
