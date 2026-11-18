package boot

// 模糊测试（设计书 11.12 "模糊测试"）：状态文件、staged.json、签名清单、事件文件被写坏、截断、塞垃圾，
// 不能崩，不能放行没验过签的东西。种子语料在 testdata/fuzz/<目标>/ 下。
// 长跑：go test ./boot -run '^$' -fuzz=FuzzReadState -fuzztime=5m

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// addSeed 加一条种子；设了 EPSILON_FUZZ_CORPUS=1 时顺便写进 testdata/fuzz/<目标>/（提交进仓库的种子语料就是这样生成的）。
func addSeed(f *testing.F, args ...any) {
	f.Add(args...)
	if os.Getenv("EPSILON_FUZZ_CORPUS") == "" {
		return
	}
	var buf strings.Builder
	buf.WriteString("go test fuzz v1\n")
	for _, a := range args {
		switch v := a.(type) {
		case []byte:
			fmt.Fprintf(&buf, "[]byte(%q)\n", v)
		case string:
			fmt.Fprintf(&buf, "string(%q)\n", v)
		}
	}
	sum := sha256.Sum256([]byte(buf.String()))
	dir := filepath.Join("testdata", "fuzz", f.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "seed-"+hex.EncodeToString(sum[:8])), []byte(buf.String()), 0o644); err != nil {
		f.Fatal(err)
	}
}

// fuzzPriv 是固定的测试私钥：种子语料里的签名要跨进程、跨次运行都有效。
var fuzzPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func fuzzKeys() []ed25519.PublicKey {
	return []ed25519.PublicKey{fuzzPriv.Public().(ed25519.PublicKey)}
}

// fuzzRoot 建一个根目录：日志静音，刷盘跳过（只为快），A 是好槽 1.A，B 被篡改。
func fuzzRoot(f *testing.F) *Boot {
	f.Helper()
	old := log.Writer()
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(old) })
	root := f.TempDir()
	onFault(f, root, func(op, path string) error {
		if op == "sync" {
			return errSkip
		}
		return nil
	})
	if err := makeSlot(filepath.Join(root, "A"), fuzzPriv, "1.A", 1); err != nil {
		f.Fatal(err)
	}
	if err := makeSlot(filepath.Join(root, "B"), fuzzPriv, "1.B", 1); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "B", "epsilon-probe.exe"), []byte("evil"), 0o644); err != nil {
		f.Fatal(err)
	}
	return &Boot{Root: root, Keys: fuzzKeys()}
}

// 任意 boot-state.json 之后跑 Pick：不 panic，不启动验不过（或非试启动时版本对不上）的槽。
func FuzzReadState(f *testing.F) {
	for _, s := range []string{
		``, `{`, `null`, `[]`, `{}`,
		`{"current":"A","pending":"","tries":0,"good":"","bad":"","versions":{"A":"1.A"}}`,
		`{"current":"A","pending":"B","tries":1,"good":"","bad":"","versions":{"A":"1.A","B":"1.B"}}`,
		`{"current":"B","good":"A","versions":{"A":"1.A","B":"1.B"}}`,
		`{"current":"","pending":"A","tries":3,"versions":{"A":"1.A"}}`,
		`{"pending":"A","tries":-5,"versions":{"A":"1.A"}}`,
		`{"current":"A","pending":"A","good":"A","versions":{"A":"1.A"}}`,
		`{"current":"../A","versions":{"../A":"1.A"}}`,
		`{"pending":"R","versions":{"R":"1.R"}}`,
		`{"current":"A","versions":null}`,
		`{"current":"A","tries":1e99}`,
		`{"current":"A","versions":{"A":"1.A"}}` + "\x00\x00",
	} {
		addSeed(f, []byte(s))
	}
	b := fuzzRoot(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(filepath.Join(b.Root, StateFile), data, 0o644); err != nil {
			t.Fatal(err)
		}
		ReadState(b.Root)
		b.rescueWhy()
		slot, trial := b.Pick()
		if slot == "" {
			return
		}
		m, err := VerifySlot(filepath.Join(b.Root, slot), b.Keys)
		if err != nil {
			t.Fatalf("启动了验不过的槽 %q: %v", slot, err)
		}
		st, err := ReadState(b.Root)
		if err != nil {
			t.Fatalf("Pick 选了槽却留下读不出的 state: %v", err)
		}
		if !trial && m.Version != st.Versions[slot] {
			t.Fatalf("非试启动的槽 %q 版本 %s，记的 %q", slot, m.Version, st.Versions[slot])
		}
	})
}

// 任意 staged.json 之后跑 consumeStaged：被接受的话，槽必须是 A 或 B、验签通过、版本取自清单。
func FuzzStaged(f *testing.F) {
	for _, s := range []string{
		``, `{`, `null`, `{}`,
		`{"slot":"A","version":"1.A"}`,
		`{"slot":"A","version":"9.9.9"}`,
		`{"slot":"B","version":"1.B"}`,
		`{"slot":"R","version":"1.R"}`,
		`{"slot":"..\\A","version":"1.A"}`,
		`{"slot":"a","version":"1.A"}`,
		`{"slot":"A ","version":"1.A"}`,
		`{"slot":"A","slot":"C"}`,
		`{"slot":"A"}garbage`,
	} {
		addSeed(f, []byte(s))
	}
	b := fuzzRoot(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		// 首次安装的现场：没有 current，A、B 都可以被交接
		if err := writeState(b.Root, State{Bad: "2.A", Versions: map[string]string{}}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(b.Root, StagedFile), data, 0o644); err != nil {
			t.Fatal(err)
		}
		accepted := b.consumeStaged()
		if _, err := os.Stat(filepath.Join(b.Root, StagedFile)); err == nil {
			t.Fatal("staged.json 没被消费")
		}
		st, err := ReadState(b.Root)
		if err != nil {
			t.Fatal(err)
		}
		if !accepted {
			if st.Pending != "" {
				t.Fatalf("没接受却改了 pending: %+v", st)
			}
			return
		}
		if st.Pending != "A" && st.Pending != "B" {
			t.Fatalf("接受的槽 %q 不是 A/B", st.Pending)
		}
		m, err := VerifySlot(filepath.Join(b.Root, st.Pending), b.Keys)
		if err != nil {
			t.Fatalf("接受了验不过的槽 %s: %v", st.Pending, err)
		}
		if st.Versions[st.Pending] != m.Version {
			t.Fatalf("版本不是取自清单: 记 %q，清单 %q", st.Versions[st.Pending], m.Version)
		}
	})
}

// fuzzSigned 是用测试私钥签过的清单原文；VerifySlot 放行的只能是这些。
var fuzzSigned = map[string]bool{}

func fuzzRelease(m Manifest) []byte {
	s, err := Sign(m, fuzzPriv)
	if err != nil {
		panic(err)
	}
	fuzzSigned[s.Manifest] = true
	raw, _ := json.Marshal(s)
	return raw
}

func fileEntry(name, body string) File {
	sum := sha256.Sum256([]byte(body))
	return File{Path: name, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
}

// 任意 release.json 和本体文件：只要清单原文不是测试私钥签的，就绝不返回 nil；
// 返回 nil 时 Files 的路径都合 safeName，本体文件和清单对得上。
func FuzzVerifySlot(f *testing.F) {
	exe := "probe 1.0"
	seeds := []Manifest{
		{Version: "1.0", MinBoot: 1, Files: []File{fileEntry("epsilon-probe.exe", exe)}},
		{Version: "1.0", MinBoot: Version + 1, Files: []File{fileEntry("epsilon-probe.exe", exe)}},
		{Version: "1.0", MinBoot: 1},
		{Version: "", MinBoot: 1},
		{Version: "1.0", Files: []File{fileEntry(`..\epsilon-probe.exe`, exe)}},
		{Version: "1.0", Files: []File{fileEntry("sub/epsilon-probe.exe", exe)}},
		{Version: "1.0", Files: []File{fileEntry("epsilon-probe.exe", exe), fileEntry("workloads.json", "{}")}},
	}
	for _, m := range seeds {
		addSeed(f, fuzzRelease(m), []byte(exe))
	}
	good := fuzzRelease(seeds[0])
	var s Signed
	json.Unmarshal(good, &s)
	reformatted := s
	reformatted.Manifest = strings.ReplaceAll(s.Manifest, "\n  ", "\n ")
	raw, _ := json.Marshal(reformatted)
	addSeed(f, raw, []byte(exe))
	addSeed(f, good, []byte("probe 1.1"))
	addSeed(f, []byte(`{"manifest":"{\"version\":\"1\"}","sig":"`+base64.StdEncoding.EncodeToString(make([]byte, 64))+`"}`), []byte(exe))
	addSeed(f, []byte(`{"manifest":"x","sig":"!!"}`), []byte(exe))
	addSeed(f, []byte(`{}`), []byte(nil))

	old := log.Writer()
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(old) })
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, release, body []byte) {
		os.WriteFile(filepath.Join(dir, ReleaseFile), release, 0o644)
		os.WriteFile(filepath.Join(dir, "epsilon-probe.exe"), body, 0o644)
		m, err := VerifySlot(dir, fuzzKeys())
		if err != nil {
			return
		}
		var s Signed
		if json.Unmarshal(release, &s) != nil || !fuzzSigned[s.Manifest] {
			t.Fatalf("放行了不是测试私钥签的清单: %q", release)
		}
		for _, fl := range m.Files {
			if !safeName.MatchString(fl.Path) {
				t.Fatalf("放行了非法文件名 %q", fl.Path)
			}
			if fl.Path == "epsilon-probe.exe" {
				sum := sha256.Sum256(body)
				if int64(len(body)) != fl.Size || hex.EncodeToString(sum[:]) != fl.SHA256 {
					t.Fatal("本体文件和清单对不上也放行了")
				}
			}
		}
	})
}

// events 文件已有任意内容，追加以后新的那一行一定完整可解析。
func FuzzAppendLine(f *testing.F) {
	for _, s := range []string{
		"", "\n", "x", `{"time":"2026`, `{"time":"","kind":"a","detail":""}` + "\n",
		"a\r", "\x00\x00\x00", "a\n\n", "\xff\xfe",
	} {
		addSeed(f, []byte(s), "槽 A 第 1 次")
	}
	addSeed(f, []byte("x"), "\n换行\"引号\\")
	addSeed(f, []byte("x"), "\xff坏的 UTF-8")
	b := fuzzRoot(f)
	path := filepath.Join(b.Root, EventsFile)
	f.Fuzz(func(t *testing.T, existing []byte, detail string) {
		if err := os.WriteFile(path, existing, 0o644); err != nil {
			t.Fatal(err)
		}
		b.event("boot_fuzz", "%s", detail)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(raw, existing) {
			t.Fatal("原有内容被改了")
		}
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			t.Fatalf("新行没有以换行结尾: %q", raw)
		}
		lines := bytes.Split(raw[:len(raw)-1], []byte("\n"))
		var e Event
		if err := json.Unmarshal(lines[len(lines)-1], &e); err != nil || e.Kind != "boot_fuzz" {
			t.Fatalf("新行不完整: %q: %v", lines[len(lines)-1], err)
		}
	})
}
