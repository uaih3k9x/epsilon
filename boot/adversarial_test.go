package boot

// 对抗用例（设计书 11.12）：签名攻击、版本回滚、槽文件不完整。
// 以 "TestKnownIssue" 开头的用例记录的是现状而不是期望（docs/boot.md "冻结前暴露的问题"），
// 定下怎么改之后把断言反过来。

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// putRelease 往槽里放任意 release.json 原文和文件。
func putRelease(t *testing.T, b *Boot, slot string, release []byte, files map[string]string) {
	t.Helper()
	dir := filepath.Join(b.Root, slot)
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		write(t, filepath.Join(dir, name), body)
	}
	if release != nil {
		write(t, filepath.Join(dir, ReleaseFile), string(release))
	}
}

func probeManifest(version string) (Manifest, map[string]string) {
	body := "probe " + version
	return Manifest{Version: version, MinBoot: 1, Files: []File{fileEntry(ProbeExe, body)}},
		map[string]string{ProbeExe: body}
}

func signedRaw(t *testing.T, m Manifest, priv ed25519.PrivateKey) (Signed, []byte) {
	t.Helper()
	s, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	return s, raw
}

// assertRejected：VerifySlot 不放行，staged 交接也被拒、state 不变。
func assertRejected(t *testing.T, b *Boot, slot string) {
	t.Helper()
	if _, err := VerifySlot(filepath.Join(b.Root, slot), b.Keys); err == nil {
		t.Fatal("VerifySlot 放行了")
	}
	stage(t, b, slot, "9.9.9")
	before := readFile(t, filepath.Join(b.Root, StateFile))
	if b.consumeStaged() {
		t.Fatal("staged 交接被接受了")
	}
	if readFile(t, filepath.Join(b.Root, StateFile)) != before {
		t.Fatal("拒绝时改了 state")
	}
	if s, _ := b.Pick(); s == slot {
		t.Fatalf("Pick 选了槽 %s", slot)
	}
}

func TestAdversarialSignature(t *testing.T) {
	_, other := keys(t)
	cases := map[string]func(t *testing.T, priv ed25519.PrivateKey) []byte{
		"换了钥匙": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			_, raw := signedRaw(t, m, other)
			return raw
		},
		"签名对着另一份字节": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			s, _ := signedRaw(t, m, priv)
			o, _ := signedRaw(t, Manifest{Version: "0.0.1"}, priv)
			s.Sig = o.Sig
			raw, _ := json.Marshal(s)
			return raw
		},
		"清单重新序列化只改了空白": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			s, _ := signedRaw(t, m, priv)
			var compact bytes.Buffer
			if err := json.Compact(&compact, []byte(s.Manifest)); err != nil {
				t.Fatal(err)
			}
			if compact.String() == s.Manifest {
				t.Fatal("没改出空白差异")
			}
			s.Manifest = compact.String() // 语义完全一样，字节不一样
			raw, _ := json.Marshal(s)
			return raw
		},
		"签名为空": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			s, _ := signedRaw(t, m, priv)
			s.Sig = ""
			raw, _ := json.Marshal(s)
			return raw
		},
		"签名不是合法 base64": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			s, _ := signedRaw(t, m, priv)
			s.Sig = "!!!" + s.Sig[3:]
			raw, _ := json.Marshal(s)
			return raw
		},
		"签名截短": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			s, _ := signedRaw(t, m, priv)
			sig, _ := base64.StdEncoding.DecodeString(s.Sig)
			s.Sig = base64.StdEncoding.EncodeToString(sig[:ed25519.SignatureSize-1])
			raw, _ := json.Marshal(s)
			return raw
		},
		"全零签名": func(t *testing.T, priv ed25519.PrivateKey) []byte {
			m, _ := probeManifest("0.2.0")
			s, _ := signedRaw(t, m, priv)
			s.Sig = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			raw, _ := json.Marshal(s)
			return raw
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			b, priv, _ := newBoot(t)
			putSlot(t, b, priv, "A", "0.1.0")
			setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
			_, files := probeManifest("0.2.0")
			putRelease(t, b, "B", mk(t, priv), files)
			assertRejected(t, b, "B")
		})
	}
}

// current 槽里被塞进一份更旧、但签名合法的 release：check 因为版本对不上拒绝，不当已确认的版本跑。
func TestAdversarialRollbackInCurrent(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0") // 旧的，签名合法
	putSlot(t, b, priv, "B", "0.1.5")
	setState(t, b, State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.2.0", "B": "0.1.5"}})
	if err := b.check(getState(t, b), "A"); err == nil {
		t.Fatal("check 放行了版本对不上的 current")
	}
	if slot, trial := b.Pick(); slot != "B" || trial {
		t.Fatalf("Pick=%q,%v，应回到 good B", slot, trial)
	}
	// 连 good 也没有时：什么都不跑（交给救援），也不跑旧版本
	b2, priv2, _ := newBoot(t)
	putSlot(t, b2, priv2, "A", "0.1.0")
	setState(t, b2, State{Current: "A", Versions: map[string]string{"A": "0.2.0"}})
	if slot, _ := b2.Pick(); slot != "" {
		t.Fatalf("跑了被换成旧版本的 current: %q", slot)
	}
}

// 通过 staged 下发更旧的版本：这是主控合法的回滚（管理员把目标版本调回去），boot 要接受。
// boot 不比版本新旧，只认签名和 bad；防回滚靠的是签名钥匙只在主控手里。
func TestAdversarialStagedOlderVersionAccepted(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "A", "0.2.0")
	putSlot(t, b, priv, "B", "0.1.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.2.0"}})
	stage(t, b, "B", "0.1.0")
	if !b.consumeStaged() {
		t.Fatal("合法回滚被拒")
	}
	if st := getState(t, b); st.Pending != "B" || st.Versions["B"] != "0.1.0" {
		t.Fatalf("state %+v", st)
	}
}

func TestAdversarialStagedBadVersion(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "A", "0.2.0")
	putSlot(t, b, priv, "B", "0.3.0")
	setState(t, b, State{Current: "A", Bad: "0.3.0", Versions: map[string]string{"A": "0.2.0"}})
	stage(t, b, "B", "0.3.1") // staged 里写的版本不作数，槽里是 bad 那个
	if b.consumeStaged() {
		t.Fatal("接受了 bad 版本")
	}
}

func TestAdversarialSlotFiles(t *testing.T) {
	cases := map[string]func(t *testing.T, b *Boot, priv ed25519.PrivateKey){
		"本体文件被截断": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			p := filepath.Join(b.Root, "B", ProbeExe)
			body := readFile(t, p)
			write(t, p, body[:len(body)-1])
		},
		"本体文件多了一个字节": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			p := filepath.Join(b.Root, "B", ProbeExe)
			write(t, p, readFile(t, p)+"x")
		},
		"本体文件缺失": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			os.Remove(filepath.Join(b.Root, "B", ProbeExe))
		},
		"release.json 缺失": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			os.Remove(filepath.Join(b.Root, "B", ReleaseFile))
		},
		"release.json 截断": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			p := filepath.Join(b.Root, "B", ReleaseFile)
			body := readFile(t, p)
			write(t, p, body[:len(body)/2])
		},
		"min_boot 大于本引导器": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlotMin(t, b, priv, "B", "0.2.0", Version+1)
		},
		"文件名带目录": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			for _, name := range []string{"sub/epsilon-probe.exe", `sub\epsilon-probe.exe`, "../epsilon-probe.exe", `C:\x.exe`, ".hidden"} {
				m := Manifest{Version: "0.2.0", Files: []File{fileEntry(name, "x")}}
				_, raw := signedRaw(t, m, priv)
				putRelease(t, b, "B", raw, nil)
				if _, err := VerifySlot(filepath.Join(b.Root, "B"), b.Keys); err == nil {
					t.Fatalf("放行了文件名 %q", name)
				}
			}
		},
		"本体是指向别处的符号链接且内容不对": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			outside := filepath.Join(t.TempDir(), "evil.exe")
			write(t, outside, "evil")
			p := filepath.Join(b.Root, "B", ProbeExe)
			os.Remove(p)
			if err := os.Symlink(outside, p); err != nil {
				t.Skipf("建不了符号链接: %v", err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			b, priv, _ := newBoot(t)
			putSlot(t, b, priv, "A", "0.1.0")
			setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
			setup(t, b, priv)
			assertRejected(t, b, "B")
		})
	}
}

// 记录现状：符号链接会被跟随，只要目标内容和清单一致就放行。哈希仍然把关，所以跑的字节是签过的；
// 风险和普通文件一样是"验完之后被换掉"（TOCTOU），能写槽目录的人本来就能做到。不算问题，只记下来。
func TestAdversarialSymlinkFollowed(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "B", "0.2.0")
	p := filepath.Join(b.Root, "B", ProbeExe)
	outside := filepath.Join(t.TempDir(), "same.exe")
	write(t, outside, readFile(t, p))
	os.Remove(p)
	if err := os.Symlink(outside, p); err != nil {
		t.Skipf("建不了符号链接: %v", err)
	}
	if _, err := VerifySlot(filepath.Join(b.Root, "B"), b.Keys); err != nil {
		t.Fatalf("现状变了（符号链接不再放行）: %v；更新 docs/boot.md 和这条用例", err)
	}
}

// 记录现状（F3）：槽里多出清单以外的文件不拦。只有清单里的文件受保护；
// 本体或它拉起的程序按名字加载同目录的 DLL 时，多出来的文件就是没验过签的代码。
func TestKnownIssueF3ExtraFilesIgnored(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "B", "0.2.0")
	write(t, filepath.Join(b.Root, "B", "version.dll"), "unsigned")
	if _, err := VerifySlot(filepath.Join(b.Root, "B"), b.Keys); err != nil {
		t.Fatalf("现状变了: %v；更新 docs/boot.md 和这条用例", err)
	}
}

// F1（已决定）：清单里必须有 ProbeExe。缺了就是坏槽：校验失败、交接被拒、回退到上一个好槽。
// 名字和 safeName 一样按字节比较，不折叠大小写（boot 启动的就是这个名字，Linux 上大小写不同是另一个文件）；
// 带目录的写法 Verify 已经拒掉了。
func TestF1ManifestMustListProbe(t *testing.T) {
	const fake = "任意未签名的程序"
	cases := map[string][]File{
		"只有 workloads.json": {fileEntry("workloads.json", "{}")},
		"空清单":               nil,
		"大写":                {fileEntry("EPSILON-PROBE.EXE", fake)},
		"首字母大写":             {fileEntry("Epsilon-Probe.exe", fake)},
		"多了后缀":              {fileEntry(ProbeExe+".bak", fake)},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			b, priv, _ := newBoot(t)
			putSlot(t, b, priv, "A", "0.1.0")
			setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
			_, raw := signedRaw(t, Manifest{Version: "0.2.0", MinBoot: 1, Files: files}, priv)
			bodies := map[string]string{"workloads.json": "{}", ProbeExe: fake}
			for _, f := range files {
				bodies[f.Path] = fake
				if f.Path == "workloads.json" {
					bodies[f.Path] = "{}"
				}
			}
			putRelease(t, b, "B", raw, bodies)
			assertRejected(t, b, "B")
		})
	}
}

func TestF1ManifestWithProbePasses(t *testing.T) {
	b, priv, _ := newBoot(t)
	files := map[string]string{ProbeExe: "probe", "workloads.json": "{}"}
	m := Manifest{Version: "0.2.0", MinBoot: 1, Files: []File{fileEntry(ProbeExe, "probe"), fileEntry("workloads.json", "{}")}}
	_, raw := signedRaw(t, m, priv)
	putRelease(t, b, "B", raw, files)
	if _, err := VerifySlot(filepath.Join(b.Root, "B"), b.Keys); err != nil {
		t.Fatal(err)
	}
}

// F1：已转正的槽如果清单缺本体（比如旧 boot 时代收下的），按现有逻辑回退到 good。
func TestF1CurrentWithoutProbeFallsBackToGood(t *testing.T) {
	b, priv, r := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	_, raw := signedRaw(t, Manifest{Version: "0.2.0", MinBoot: 1, Files: []File{fileEntry("workloads.json", "{}")}}, priv)
	putRelease(t, b, "B", raw, map[string]string{"workloads.json": "{}", ProbeExe: "任意未签名的程序"})
	setState(t, b, State{Current: "B", Good: "A", Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}})
	if slot, trial := b.Pick(); slot != "A" || trial {
		t.Fatalf("Pick=%q,%v", slot, trial)
	}
	// 真跑一遍 Run：启动的是 A，缺本体的 B 一次都没启动
	stop := run(t, b)
	waitFor(t, "A 启动", func() bool { return r.count("A") > 0 })
	stop()
	if r.count("B") != 0 {
		t.Fatalf("跑了缺本体的槽: %v", r.list())
	}
}

// F1（救援槽 R）：R 走同一个 VerifySlot，R 的清单缺本体时不运行 R，只记 boot_rescue_bad。
func TestF1RescueSlotMustListProbe(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) { p.Kill() }
	m := Manifest{Version: "0.0.1", MinBoot: 1, Files: []File{fileEntry("workloads.json", "{}")}}
	_, raw := signedRaw(t, m, priv)
	putRelease(t, b, RescueSlot, raw, map[string]string{"workloads.json": "{}", ProbeExe: "任意未签名的程序"})
	setState(t, b, State{})
	why := b.rescueWhy()
	if why == "" {
		t.Fatal("没东西可跑却不救援")
	}
	b.rescue(nil, why)
	if r.count(RescueSlot) != 0 || !hasEvent(t, b, "boot_rescue_bad") {
		t.Fatalf("R 的清单缺本体却运行了。事件 %+v", events(t, b))
	}
}

// 记录现状（F2）：bad 只记一个版本。两个坏版本交替下发时，每次都重新试满 MaxTries 次，来回空转。
func TestKnownIssueF2BadRemembersOneVersion(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	trials := 0
	for _, v := range []string{"0.2.0", "0.3.0", "0.2.0", "0.3.0"} {
		putSlot(t, b, priv, "B", v)
		stage(t, b, "B", v)
		if !b.consumeStaged() {
			t.Fatalf("现状变了：%s 第二次下发被拒；更新 docs/boot.md 和这条用例", v)
		}
		for {
			slot, trial := b.Pick() // 每次试启动都起不来（崩溃）
			if !trial {
				if slot != "A" {
					t.Fatalf("回退后跑 %q", slot)
				}
				break
			}
			trials++
		}
		if st := getState(t, b); st.Bad != v {
			t.Fatalf("state %+v", st)
		}
	}
	if trials != 4*MaxTries {
		t.Fatalf("试启动 %d 次", trials)
	}
}
