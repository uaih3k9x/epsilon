package boot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProc struct {
	exited chan struct{}
	once   sync.Once
}

func (p *fakeProc) Exited() <-chan struct{} { return p.exited }
func (p *fakeProc) Kill()                   { p.once.Do(func() { close(p.exited) }) }

func (p *fakeProc) dead() bool {
	select {
	case <-p.exited:
		return true
	default:
		return false
	}
}

// fakeRunner 记录启动了哪个槽、启动那一刻 state 里的 tries；behave 决定本体起来后干什么。
type fakeRunner struct {
	mu     sync.Mutex
	starts []string
	tries  []int
	procs  []*fakeProc
	behave func(slot, confirm string, p *fakeProc)
}

func (r *fakeRunner) start(slotDir, confirm string) (Proc, error) {
	slot := filepath.Base(slotDir)
	st, _ := ReadState(filepath.Dir(slotDir))
	p := &fakeProc{exited: make(chan struct{})}
	r.mu.Lock()
	r.starts = append(r.starts, slot)
	r.tries = append(r.tries, st.Tries)
	r.procs = append(r.procs, p)
	behave := r.behave
	r.mu.Unlock()
	if behave != nil {
		go behave(slot, confirm, p)
	}
	return p, nil
}

func (r *fakeRunner) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.starts...)
}

func (r *fakeRunner) count(slot string) int {
	n := 0
	for _, s := range r.list() {
		if s == slot {
			n++
		}
	}
	return n
}

func (r *fakeRunner) proc(i int) *fakeProc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[i]
}

func newBoot(t *testing.T) (*Boot, ed25519.PrivateKey, *fakeRunner) {
	t.Helper()
	pub, priv := keys(t)
	r := &fakeRunner{}
	b := &Boot{Root: t.TempDir(), Keys: []ed25519.PublicKey{pub}, Start: r.start,
		ConfirmWithin: 300 * time.Millisecond, Backoff: 20 * time.Millisecond, Poll: 5 * time.Millisecond}
	return b, priv, r
}

// putSlot 模拟 loader 写好一个槽：本体文件 + 签名的 release.json。
func putSlot(t *testing.T, b *Boot, priv ed25519.PrivateKey, slot, version string) {
	putSlotMin(t, b, priv, slot, version, 1)
}

func putSlotMin(t *testing.T, b *Boot, priv ed25519.PrivateKey, slot, version string, minBoot int) {
	t.Helper()
	dir := filepath.Join(b.Root, slot)
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "probe " + version
	sum := sha256.Sum256([]byte(body))
	m := Manifest{Version: version, MinBoot: minBoot,
		Files: []File{{Path: "epsilon-probe.exe", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}}}
	s, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	write(t, filepath.Join(dir, "epsilon-probe.exe"), body)
	write(t, filepath.Join(dir, ReleaseFile), string(raw))
}

func tamper(t *testing.T, b *Boot, slot string) {
	write(t, filepath.Join(b.Root, slot, "epsilon-probe.exe"), "evil")
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stage(t *testing.T, b *Boot, slot, version string) {
	t.Helper()
	raw, _ := json.Marshal(Staged{Slot: slot, Version: version})
	write(t, filepath.Join(b.Root, StagedFile), string(raw))
}

func stagedExists(b *Boot) bool {
	_, err := os.Stat(filepath.Join(b.Root, StagedFile))
	return err == nil
}

func setState(t *testing.T, b *Boot, st State) {
	t.Helper()
	if err := b.save(st); err != nil {
		t.Fatal(err)
	}
}

func getState(t *testing.T, b *Boot) State {
	t.Helper()
	st, err := ReadState(b.Root)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func events(t *testing.T, b *Boot) []Event {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(b.Root, EventsFile))
	var out []Event
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("事件行不是 JSON: %q", line)
		}
		out = append(out, e)
	}
	return out
}

func hasEvent(t *testing.T, b *Boot, kind string) bool {
	t.Helper()
	for _, e := range events(t, b) {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// run 在后台跑 Run；返回的 stop 可以多次调用，测试结束时自动调用。
func run(t *testing.T, b *Boot) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { b.Run(stop); close(done) }()
	var once sync.Once
	f := func() { once.Do(func() { close(stop); <-done }) }
	t.Cleanup(f)
	return f
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等不到: %s", what)
}

func confirmAfterStart(slot, confirm string, p *fakeProc) {
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(confirm, nil, 0o644)
}

func crash(slot, confirm string, p *fakeProc) { p.Kill() }

// ---- staged.json 的消费 ----

func TestStagedSwitch(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	setState(t, b, State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.1.0", "B": "0.0.9"}})
	stage(t, b, "B", "9.9.9") // staged.json 里写的版本不作数，以槽里验过的为准

	if !b.consumeStaged() {
		t.Fatal("没接受")
	}
	st := getState(t, b)
	if st.Pending != "B" || st.Tries != 0 || st.Versions["B"] != "0.2.0" || st.Current != "A" {
		t.Fatalf("state %+v", st)
	}
	if st.Good != "" {
		t.Fatalf("B 被覆盖了还留作退路: %+v", st)
	}
	if stagedExists(b) || !hasEvent(t, b, "boot_staged") {
		t.Fatal("staged.json 没删或没事件")
	}
}

func TestStagedRejected(t *testing.T) {
	cases := map[string]func(t *testing.T, b *Boot, priv ed25519.PrivateKey){
		"等于 current": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.2.0")
			stage(t, b, "A", "0.2.0")
		},
		"不是 A/B": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) { stage(t, b, `..\C`, "0.2.0") },
		"验签不过": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.2.0")
			tamper(t, b, "B")
			stage(t, b, "B", "0.2.0")
		},
		"没有清单": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) { stage(t, b, "B", "0.2.0") },
		"版本等于 bad": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "B", "0.0.5")
			stage(t, b, "B", "0.0.5")
		},
		"min_boot 太大": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlotMin(t, b, priv, "B", "0.2.0", Version+1)
			stage(t, b, "B", "0.2.0")
		},
		"不是 JSON": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			write(t, filepath.Join(b.Root, StagedFile), "{")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			b, priv, _ := newBoot(t)
			putSlot(t, b, priv, "A", "0.1.0")
			before := State{Current: "A", Bad: "0.0.5", Versions: map[string]string{"A": "0.1.0"}}
			setState(t, b, before)
			setup(t, b, priv)
			if b.consumeStaged() {
				t.Fatal("接受了")
			}
			st := getState(t, b)
			if st.Pending != "" || st.Current != "A" || st.Bad != "0.0.5" || len(st.Versions) != 1 {
				t.Fatalf("state 被改了: %+v", st)
			}
			if stagedExists(b) {
				t.Fatal("staged.json 没删")
			}
			if !hasEvent(t, b, "boot_staged_rejected") {
				t.Fatal("没有事件")
			}
		})
	}
}

func TestNoStagedNoop(t *testing.T) {
	b, _, _ := newBoot(t)
	if b.consumeStaged() {
		t.Fatal("没有 staged.json 也返回 true")
	}
	if _, err := os.Stat(filepath.Join(b.Root, StateFile)); err == nil {
		t.Fatal("没事也写了 state")
	}
}

// 写完 state、删 staged.json 之前断电：手工摆出这个磁盘状态。
func TestStagedPowerLossAfterStateWrite(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = confirmAfterStart
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	disk := State{Current: "A", Pending: "B", Tries: 2, Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}}
	setState(t, b, disk)
	stage(t, b, "B", "0.2.0")

	if !b.consumeStaged() {
		t.Fatal("应当指向待试槽")
	}
	if stagedExists(b) {
		t.Fatal("staged.json 没删")
	}
	if st := getState(t, b); st.Pending != "B" || st.Tries != 2 || st.Current != "A" {
		t.Fatalf("重来不幂等（tries 被清零会让反复断电无限试）: %+v", st)
	}
	if b.consumeStaged() {
		t.Fatal("第二次不该再有动作")
	}

	// 完整重启一遍：从这个状态起，B 试启动并转正
	stage(t, b, "B", "0.2.0")
	stop := run(t, b)
	waitFor(t, "B 转正", func() bool { st := getState(t, b); return st.Current == "B" && st.Pending == "" })
	stop()
	if st := getState(t, b); st.Good != "A" || r.list()[0] != "B" {
		t.Fatalf("state %+v starts %v", st, r.list())
	}
}

// ---- 选槽：核对版本 ----

func TestPickChecksVersion(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, b *Boot, priv ed25519.PrivateKey)
		want     string
		wantCur  string
		wantGood string
	}{
		{"current 正常", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.2.0")
		}, "A", "A", "B"},
		{"current 被覆盖成新版本，good 正常", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.3.0")
			putSlot(t, b, priv, "B", "0.1.0")
		}, "B", "B", ""},
		{"current 坏，good 被 loader 覆盖", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.2.0")
			tamper(t, b, "A")
			putSlot(t, b, priv, "B", "0.3.0") // 签名、哈希都对，但不是 versions[B]
		}, "", "A", "B"},
		{"current 坏，good 正在被下载", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			halfDownloaded(t, b, priv)
		}, "", "A", "B"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, priv, _ := newBoot(t)
			setState(t, b, State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.2.0", "B": "0.1.0"}})
			c.setup(t, b, priv)
			slot, trial := b.Pick()
			st := getState(t, b)
			if slot != c.want || trial || st.Current != c.wantCur || st.Good != c.wantGood {
				t.Fatalf("Pick=%q,%v state %+v", slot, trial, st)
			}
		})
	}
}

// halfDownloaded: A 坏；B 只有文件没有 release.json（loader 下到一半）。
func halfDownloaded(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
	putSlot(t, b, priv, "A", "0.2.0")
	tamper(t, b, "A")
	putSlot(t, b, priv, "B", "0.1.0")
	os.Remove(filepath.Join(b.Root, "B", ReleaseFile))
}

func TestPickDropsBrokenPending(t *testing.T) {
	b, priv, _ := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	tamper(t, b, "B")
	setState(t, b, State{Current: "A", Pending: "B", Tries: 1, Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}})
	slot, trial := b.Pick()
	if slot != "A" || trial {
		t.Fatalf("Pick=%q,%v", slot, trial)
	}
	if st := getState(t, b); st.Pending != "" || st.Bad != "" {
		t.Fatalf("文件坏不算版本坏: %+v", st)
	}
	if !hasEvent(t, b, "boot_slot_bad") {
		t.Fatal("没有事件")
	}
}

func TestPickNothing(t *testing.T) {
	b, _, _ := newBoot(t)
	if slot, _ := b.Pick(); slot != "" {
		t.Fatalf("空目录选了 %q", slot)
	}
}

// ---- 试启动 ----

func TestTrialPromote(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = confirmAfterStart
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	stage(t, b, "B", "0.2.0")
	stop := run(t, b)
	waitFor(t, "B 转正", func() bool { return getState(t, b).Current == "B" })
	stop()
	st := getState(t, b)
	if st.Good != "A" || st.Pending != "" || st.Tries != 0 || st.Bad != "" {
		t.Fatalf("state %+v", st)
	}
	if got := r.list(); got[0] != "B" {
		t.Fatalf("starts %v", got)
	}
	if !hasEvent(t, b, "boot_promoted") {
		t.Fatal("没有事件")
	}
}

func TestTrialRollback(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {
		if slot == "B" {
			p.Kill() // B 一起来就崩
		}
	}
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	stage(t, b, "B", "0.2.0")
	stop := run(t, b)
	waitFor(t, "回退后跑 A", func() bool { l := r.list(); return len(l) > 0 && l[len(l)-1] == "A" })
	time.Sleep(50 * time.Millisecond) // 坏版本不再试
	stop()

	st := getState(t, b)
	if st.Current != "A" || st.Pending != "" || st.Bad != "0.2.0" {
		t.Fatalf("state %+v", st)
	}
	if n := r.count("B"); n != MaxTries {
		t.Fatalf("B 试了 %d 次，应为 %d: %v", n, MaxTries, r.list())
	}
	r.mu.Lock()
	tries := append([]int(nil), r.tries[:MaxTries]...)
	r.mu.Unlock()
	for i, n := range tries {
		if n != i+1 {
			t.Fatalf("启动前没先记次数: %v", tries)
		}
	}
	if !hasEvent(t, b, "boot_rollback") {
		t.Fatal("没有事件")
	}
}

func TestTrialUnconfirmedIsKilled(t *testing.T) {
	b, priv, r := newBoot(t)
	b.ConfirmWithin = 30 * time.Millisecond
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}}) // 都不崩也不确认：卡住
	stage(t, b, "B", "0.2.0")
	stop := run(t, b)
	waitFor(t, "回退", func() bool { return getState(t, b).Bad == "0.2.0" })
	stop()
	for i := 0; i < MaxTries; i++ {
		if !r.proc(i).dead() {
			t.Fatalf("第 %d 次试启动没被杀", i+1)
		}
	}
}

// 首次安装：没有退路，起不来也一直试，不判 bad。
func TestFirstInstallRetriesForever(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = crash
	putSlot(t, b, priv, "A", "0.1.0")
	stage(t, b, "A", "0.1.0")
	stop := run(t, b)
	waitFor(t, "一直重试", func() bool { return r.count("A") > 2*MaxTries })
	stop()
	if st := getState(t, b); st.Bad != "" || st.Pending != "A" || st.Current != "" {
		t.Fatalf("唯一的版本不能判 bad: %+v", st)
	}
}

// current 也坏了（比如被杀毒软件删了文件）：同样没有退路。
func TestNoFallbackWhenCurrentBroken(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = crash
	putSlot(t, b, priv, "A", "0.1.0")
	tamper(t, b, "A")
	putSlot(t, b, priv, "B", "0.2.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	stage(t, b, "B", "0.2.0")
	stop := run(t, b)
	waitFor(t, "一直重试", func() bool { return r.count("B") > 2*MaxTries })
	stop()
	if st := getState(t, b); st.Bad != "" || st.Pending != "B" {
		t.Fatalf("没有退路时不能判 bad: %+v", st)
	}
	if r.count("A") != 0 {
		t.Fatalf("跑了坏的 A: %v", r.list())
	}
}

func TestStaleConfirmIgnored(t *testing.T) {
	b, priv, r := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, "B", "0.2.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	write(t, filepath.Join(b.Root, "confirm-B"), "") // 上一次留下的
	stage(t, b, "B", "0.2.0")
	stop := run(t, b)
	waitFor(t, "B 启动", func() bool { return r.count("B") > 0 })
	time.Sleep(50 * time.Millisecond)
	stop()
	if st := getState(t, b); st.Current != "A" || st.Pending != "B" {
		t.Fatalf("旧确认文件让 B 转正了: %+v", st)
	}
}

// ---- 看护 ----

func TestStagedWhileRunningSwitches(t *testing.T) {
	b, priv, r := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	stop := run(t, b)
	waitFor(t, "A 在跑", func() bool { return r.count("A") == 1 })

	putSlot(t, b, priv, "B", "0.2.0")
	stage(t, b, "B", "0.2.0")
	waitFor(t, "切到 B", func() bool { return r.count("B") == 1 })
	stop()
	if !r.proc(0).dead() {
		t.Fatal("A 没停")
	}
	if got := r.list(); len(got) != 2 {
		t.Fatalf("starts %v", got)
	}
	if st := getState(t, b); st.Pending != "B" {
		t.Fatalf("state %+v", st)
	}
}

func TestStagedDuringTrialIgnored(t *testing.T) {
	b, priv, r := newBoot(t)
	b.ConfirmWithin = 500 * time.Millisecond
	putSlot(t, b, priv, "A", "0.1.0")
	stage(t, b, "A", "0.1.0") // 首次安装，A 卡住不确认
	stop := run(t, b)
	waitFor(t, "A 试启动", func() bool { return r.count("A") == 1 })

	putSlot(t, b, priv, "B", "0.2.0")
	stage(t, b, "B", "0.2.0")
	time.Sleep(100 * time.Millisecond)
	if !stagedExists(b) || len(r.list()) != 1 || r.proc(0).dead() {
		t.Fatalf("试启动期间动了 staged.json 或本体: %v", r.list())
	}
	// 试启动超时后才处理
	waitFor(t, "超时后切到 B", func() bool { return r.count("B") == 1 })
	stop()
	if st := getState(t, b); st.Pending != "B" || stagedExists(b) {
		t.Fatalf("state %+v", st)
	}
}

func TestCrashOfGoodVersionRestarts(t *testing.T) {
	b, priv, r := newBoot(t)
	var mu sync.Mutex
	n := 0
	r.behave = func(slot, confirm string, p *fakeProc) {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			p.Kill()
		}
	}
	putSlot(t, b, priv, "A", "0.1.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	stop := run(t, b)
	waitFor(t, "崩了重启", func() bool { return r.count("A") >= 2 })
	stop()
	if st := getState(t, b); st.Current != "A" || st.Bad != "" {
		t.Fatalf("好版本崩一次不能判 bad: %+v", st)
	}
}

func TestStopKillsProbe(t *testing.T) {
	b, priv, r := newBoot(t)
	putSlot(t, b, priv, "A", "0.1.0")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
	stop := run(t, b)
	waitFor(t, "在跑", func() bool { return len(r.list()) == 1 })
	stop()
	if !r.proc(0).dead() {
		t.Fatal("stop 之后本体还在跑")
	}
}

// ---- 事件文件 ----

func TestEventFormat(t *testing.T) {
	b, _, _ := newBoot(t)
	b.event("boot_test", "槽 %s 第 %d 次", "A", 1)
	b.event("boot_test2", "x")
	evs := events(t, b)
	if len(evs) != 2 || evs[0].Kind != "boot_test" || evs[0].Detail != "槽 A 第 1 次" {
		t.Fatalf("%+v", evs)
	}
	ts, err := time.Parse(time.RFC3339, evs[0].Time)
	if err != nil || !strings.HasSuffix(evs[0].Time, "Z") || time.Since(ts) > time.Minute {
		t.Fatalf("时间 %q: %v", evs[0].Time, err)
	}
}

func TestEventRotate(t *testing.T) {
	b, _, _ := newBoot(t)
	path := filepath.Join(b.Root, EventsFile)
	write(t, path+".1", "旧的\n")
	line := `{"time":"","kind":"x","detail":""}` + "\n"
	big := strings.Repeat(line, eventsMax/len(line)+1)
	write(t, path, big)
	b.event("boot_test", "轮转后")
	if old, _ := os.ReadFile(path + ".1"); string(old) != big {
		t.Fatalf(".1 不是轮转前的文件（%d 字节）", len(old))
	}
	if evs := events(t, b); len(evs) != 1 || evs[0].Detail != "轮转后" {
		t.Fatalf("%+v", evs)
	}
	b.event("boot_test", "没到 1 MB 不轮转")
	if evs := events(t, b); len(evs) != 2 {
		t.Fatalf("%+v", evs)
	}
}

// 断电留下半行：下一条事件另起一行，不被拖累。
func TestEventAfterTornLine(t *testing.T) {
	b, _, _ := newBoot(t)
	path := filepath.Join(b.Root, EventsFile)
	write(t, path, `{"time":"2026-10-30T08:00:00Z","kind":"a","detail":"ok"}`+"\n"+`{"time":"2026`)
	b.event("boot_test", "断电后")
	lines := strings.Split(strings.TrimSuffix(readFile(t, path), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("%q", lines)
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[2]), &e); err != nil || e.Detail != "断电后" {
		t.Fatalf("%q: %v", lines[2], err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
