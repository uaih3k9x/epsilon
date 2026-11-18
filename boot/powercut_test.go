package boot

// 断电注入（设计书 11.12 "断电模拟"）：每个场景先无故障跑一遍，数出一共 N 个写盘点；
// 再对 k = 0..N-1 每个点都试一次（不抽样），每次从同一个初始现场出发：
//   - 第 k 个写盘点失败（若是 write，先写进一半：撕裂写）；之后 Run 再走到写盘点就直接结束
//     （runtime.Goexit，像真断电一样后面的代码不再跑），fake Start / Rescue 也失败，然后停掉这个 Boot；
//   - 在同一个目录上新建一个 Boot（hook 只计数、不再注入），跑到稳定，检查不变量 I1–I7。
//
// 模型的前提：改名、删除一旦返回成功就算落盘；刷盘前断电丢的只有临时文件。
// "改名还没落盘就断电"这种更弱的模型这里不模拟（见 docs/boot.md "冻结前暴露的问题"）。

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeSlot 在 dir 写一个签好名的槽（本体文件 + release.json）。不用 t：救援 fake 在 Run 的 goroutine 里调它。
func makeSlot(dir string, priv ed25519.PrivateKey, version string, minBoot int) error {
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body := "probe " + version
	sum := sha256.Sum256([]byte(body))
	s, err := Sign(Manifest{Version: version, MinBoot: minBoot,
		Files: []File{{Path: "epsilon-probe.exe", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}}}, priv)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(dir, "epsilon-probe.exe"), []byte(body), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ReleaseFile), raw, 0o644)
}

// writeStaged 像 loader 那样原子写 staged.json，但不走 boot 的写盘点（loader 不归 hook 管）。
func writeStaged(root, slot, version string) error {
	raw, _ := json.Marshal(Staged{Slot: slot, Version: version})
	tmp := filepath.Join(root, StagedFile+".loader")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(root, StagedFile))
}

func writeState(root string, st State) error {
	raw, _ := json.Marshal(st)
	return os.WriteFile(filepath.Join(root, StateFile), raw, 0o644)
}

type pcScenario struct {
	name     string
	fallback bool                 // 开始时有退路：I3 适用
	final    []string             // 稳定后允许在跑的"槽:版本"（I4：新版本，或者回到旧的好版本）
	crash    map[string]bool      // 这些版本一起来就崩，其余版本启动即确认
	setup    func(e *pcEnv) error // 布置初始现场
	rescue   func(e *pcEnv) error // 救援槽跑一次做什么（模拟 loader -seed）；nil 表示什么也不写
}

type pcStart struct {
	slot, version string
	trial         bool
}

type pcEnv struct {
	sc   *pcScenario
	root string
	priv ed25519.PrivateKey
	keys []ed25519.PublicKey

	mu     sync.Mutex
	cutAt  int // 第几个写盘点断电；-1 不断
	cut    bool
	cutCh  chan struct{}
	after  int      // 断电之后还被调到的写盘点次数（真断电后不会再有代码跑）
	ops    []string // 这一阶段断电前走过的写盘点
	lastOp time.Time
	starts []pcStart // 两个阶段累计
	procs  []*fakeProc
	bad    []string // 启动那一刻发现的违规（I2）
}

func newPCEnv(t *testing.T, sc *pcScenario, priv ed25519.PrivateKey, cutAt int) *pcEnv {
	t.Helper()
	e := &pcEnv{sc: sc, root: t.TempDir(), priv: priv, keys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)},
		cutAt: cutAt, cutCh: make(chan struct{}), lastOp: time.Now()}
	if err := sc.setup(e); err != nil {
		t.Fatal(err)
	}
	onFault(t, e.root, e.hook)
	return e
}

func (e *pcEnv) hook(op, path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cut {
		// 断电之后又走到写盘点：直接结束这个 goroutine（Run 的），和真断电一样后面的代码不再跑。
		// 断电那一下本身仍返回错误，撕裂写才能写进一半。
		e.after++
		runtime.Goexit()
	}
	if len(e.ops) == e.cutAt {
		e.cut = true
		close(e.cutCh)
		if op == "write" {
			return errors.Join(errPowerCut, errTorn)
		}
		return errPowerCut
	}
	rel, _ := filepath.Rel(e.root, path)
	e.ops = append(e.ops, op+" "+filepath.ToSlash(rel))
	e.lastOp = time.Now()
	if op == "sync" {
		return errSkip
	}
	return nil
}

func (e *pcEnv) isCut() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cut
}

// powerOn 是重新上电：之后的写盘点只计数、不注入。
func (e *pcEnv) powerOn() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cutAt, e.cut, e.ops, e.lastOp = -1, false, nil, time.Now()
}

func (e *pcEnv) boot() *Boot {
	return &Boot{Root: e.root, Keys: e.keys, Start: e.start, Rescue: e.startRescue,
		ConfirmWithin: time.Minute, Backoff: 10 * time.Millisecond, Poll: 5 * time.Millisecond,
		RescueWithin: time.Second, RescueGap: time.Hour}
}

func (e *pcEnv) start(slotDir, confirm string) (Proc, error) {
	if e.isCut() {
		return nil, errPowerCut
	}
	slot := filepath.Base(slotDir)
	st, serr := ReadState(e.root)
	m, verr := VerifySlot(slotDir, e.keys)
	trial := st.Pending == slot
	var bad string
	switch {
	case serr != nil:
		bad = fmt.Sprintf("启动槽 %s 时 state 读不出: %v", slot, serr)
	case verr != nil:
		bad = fmt.Sprintf("I2: 启动了验不过的槽 %s: %v", slot, verr)
	case !trial && (st.Current != slot || m.Version != st.Versions[slot]):
		bad = fmt.Sprintf("I2: 非试启动的槽 %s 版本 %s，state %+v", slot, m.Version, st)
	}
	p := &fakeProc{exited: make(chan struct{})}
	if e.sc.crash[m.Version] {
		p.Kill()
	} else if err := os.WriteFile(confirm, nil, 0o644); err != nil {
		bad = "写确认文件: " + err.Error()
	}
	e.mu.Lock()
	e.starts = append(e.starts, pcStart{slot, m.Version, trial})
	e.procs = append(e.procs, p)
	if bad != "" {
		e.bad = append(e.bad, bad)
	}
	e.mu.Unlock()
	return p, nil
}

func (e *pcEnv) startRescue(dir string) (Proc, error) {
	if e.isCut() {
		return nil, errPowerCut
	}
	if e.sc.rescue != nil {
		if err := e.sc.rescue(e); err != nil {
			e.mu.Lock()
			e.bad = append(e.bad, "救援 fake: "+err.Error())
			e.mu.Unlock()
		}
	}
	p := &fakeProc{exited: make(chan struct{})}
	p.Kill()
	return p, nil
}

// stable：最后启动的本体还活着，没有待试槽，staged.json 已消费，而且 50ms 没有新的写盘点。
func (e *pcEnv) stable() bool {
	e.mu.Lock()
	quiet := time.Since(e.lastOp) > 50*time.Millisecond
	alive := len(e.procs) > 0 && !e.procs[len(e.procs)-1].dead()
	e.mu.Unlock()
	if !quiet || !alive {
		return false
	}
	if _, err := os.Stat(filepath.Join(e.root, StagedFile)); err == nil {
		return false
	}
	st, err := ReadState(e.root)
	return err == nil && st.Pending == ""
}

func runBoot(b *Boot) (stop func()) {
	stopCh, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done) // 断电时 hook 用 Goexit 结束这个 goroutine，defer 照样跑
		b.Run(stopCh)
	}()
	return func() { close(stopCh); <-done }
}

// runToStable 跑一个 Boot 到稳定；返回稳定时在跑的"槽:版本"，到时没稳定返回空。
func (e *pcEnv) runToStable() string {
	stop := runBoot(e.boot())
	defer stop()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if e.stable() {
			e.mu.Lock()
			defer e.mu.Unlock()
			last := e.starts[len(e.starts)-1]
			return last.slot + ":" + last.version
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ""
}

func (e *pcEnv) diag() string {
	st, err := ReadState(e.root)
	ev, _ := os.ReadFile(filepath.Join(e.root, EventsFile))
	e.mu.Lock()
	defer e.mu.Unlock()
	return fmt.Sprintf("state %+v (%v)\nstarts %+v\nevents:\n%s", st, err, e.starts, ev)
}

// check 检查稳定后的不变量；running 是稳定时在跑的"槽:版本"，cuts 是断过几次电。
func (e *pcEnv) check(running string, cuts int) []string {
	var out []string
	st, err := ReadState(e.root)
	if err != nil {
		out = append(out, fmt.Sprintf("I1: boot-state.json 读不出: %v", err))
	}
	e.mu.Lock()
	out = append(out, e.bad...)
	tries := map[string]int{}
	for _, s := range e.starts {
		if s.trial {
			tries[s.slot+":"+s.version]++
		}
	}
	e.mu.Unlock()
	if e.sc.fallback {
		for k, n := range tries {
			if n > MaxTries {
				out = append(out, fmt.Sprintf("I3: 有退路时 %s 试启动了 %d 次（上限 %d）", k, n, MaxTries))
			}
		}
	}
	if !slices.Contains(e.sc.final, running) {
		out = append(out, fmt.Sprintf("I4: 最后在跑 %s，应为 %v 之一", running, e.sc.final))
	} else if _, err := VerifySlot(filepath.Join(e.root, strings.SplitN(running, ":", 2)[0]), e.keys); err != nil {
		out = append(out, fmt.Sprintf("I4: 最后在跑的 %s 验不过: %v", running, err))
	}
	if _, err := os.Stat(filepath.Join(e.root, StagedFile)); err == nil {
		out = append(out, "I5: staged.json 没被消费")
	}
	if n, err := tornEventLines(e.root); err != nil || n > cuts {
		out = append(out, fmt.Sprintf("I6: 事件文件有 %d 行解析不了（断电 %d 次）: %v", n, cuts, err))
	}
	if !distinctSlots(st) {
		out = append(out, fmt.Sprintf("I7: current/pending/good 有重复: %+v", st))
	}
	return out
}

// tornEventLines 数事件文件（含轮转出去的 .1）里坏掉的行：解析不了的整行，加上末尾没有换行的半行
// （断电后没有再记事件时，半行就留在末尾；下一条事件会先补换行，见 appendLine）。
func tornEventLines(root string) (int, error) {
	n := 0
	for _, name := range []string{EventsFile + ".1", EventsFile} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return n, err
		}
		lines := strings.Split(string(raw), "\n")
		if tail := lines[len(lines)-1]; tail != "" {
			n++ // 末尾半行
		}
		for _, line := range lines[:len(lines)-1] {
			var ev Event
			if json.Unmarshal([]byte(line), &ev) != nil {
				n++
			}
		}
	}
	return n, nil
}

func distinctSlots(st State) bool {
	return (st.Current == "" || (st.Current != st.Pending && st.Current != st.Good)) &&
		(st.Pending == "" || st.Pending != st.Good)
}

func pcScenarios() []*pcScenario {
	ab := func(e *pcEnv, a, b string) error {
		if err := makeSlot(filepath.Join(e.root, "A"), e.priv, a, 1); err != nil {
			return err
		}
		return makeSlot(filepath.Join(e.root, "B"), e.priv, b, 1)
	}
	tamperA := func(e *pcEnv) error {
		return os.WriteFile(filepath.Join(e.root, "A", "epsilon-probe.exe"), []byte("evil"), 0o644)
	}
	stagedAccept := func(e *pcEnv) error {
		if err := ab(e, "0.1.0", "0.2.0"); err != nil {
			return err
		}
		if err := writeState(e.root, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}}); err != nil {
			return err
		}
		return writeStaged(e.root, "B", "0.2.0")
	}
	return []*pcScenario{
		{name: "消费staged-接受", fallback: true, final: []string{"B:0.2.0"}, setup: stagedAccept},
		{name: "消费staged-拒绝", fallback: true, final: []string{"A:0.1.0"}, setup: func(e *pcEnv) error {
			if err := ab(e, "0.1.0", "0.0.5"); err != nil {
				return err
			}
			if err := writeState(e.root, State{Current: "A", Bad: "0.0.5", Versions: map[string]string{"A": "0.1.0"}}); err != nil {
				return err
			}
			return writeStaged(e.root, "B", "0.0.5")
		}},
		{name: "试启动确认转正", fallback: true, final: []string{"B:0.2.0"}, setup: func(e *pcEnv) error {
			if err := ab(e, "0.1.0", "0.2.0"); err != nil {
				return err
			}
			return writeState(e.root, State{Current: "A", Pending: "B", Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}})
		}},
		{name: "试满回退", fallback: true, final: []string{"A:0.1.0"}, crash: map[string]bool{"0.2.0": true}, setup: stagedAccept},
		{name: "current坏改跑good", fallback: true, final: []string{"B:0.1.0"}, setup: func(e *pcEnv) error {
			if err := ab(e, "0.2.0", "0.1.0"); err != nil {
				return err
			}
			if err := tamperA(e); err != nil {
				return err
			}
			return writeState(e.root, State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.2.0", "B": "0.1.0"}})
		}},
		{name: "首次安装", final: []string{"A:0.1.0"}, setup: func(e *pcEnv) error {
			if err := makeSlot(filepath.Join(e.root, "A"), e.priv, "0.1.0", 1); err != nil {
				return err
			}
			return writeStaged(e.root, "A", "0.1.0")
		}},
		{name: "救援后消费staged", final: []string{"B:0.3.0"}, setup: func(e *pcEnv) error {
			if err := makeSlot(filepath.Join(e.root, "A"), e.priv, "0.2.0", 1); err != nil {
				return err
			}
			if err := tamperA(e); err != nil {
				return err
			}
			if err := makeSlot(filepath.Join(e.root, RescueSlot), e.priv, "0.0.1", 1); err != nil {
				return err
			}
			return writeState(e.root, State{Current: "A", Versions: map[string]string{"A": "0.2.0"}})
		}, rescue: func(e *pcEnv) error {
			if err := makeSlot(filepath.Join(e.root, "B"), e.priv, "0.3.0", 1); err != nil {
				return err
			}
			return writeStaged(e.root, "B", "0.3.0")
		}},
		{name: "事件文件轮转", fallback: true, final: []string{"B:0.2.0"}, setup: func(e *pcEnv) error {
			line := `{"time":"","kind":"x","detail":""}` + "\n"
			big := strings.Repeat(line, eventsMax/len(line)+1)
			if err := os.WriteFile(filepath.Join(e.root, EventsFile), []byte(big), 0o644); err != nil {
				return err
			}
			return stagedAccept(e)
		}},
	}
}

func TestPowerCut(t *testing.T) {
	_, priv := keys(t)
	for _, sc := range pcScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			// 无故障跑一遍：数写盘点，顺便确认场景本身成立
			dry := newPCEnv(t, sc, priv, -1)
			running := dry.runToStable()
			if running == "" {
				t.Fatalf("无故障也跑不到稳定\n%s", dry.diag())
			}
			for _, v := range dry.check(running, 0) {
				t.Errorf("无故障: %s", v)
			}
			dry.mu.Lock()
			ops := append([]string(nil), dry.ops...)
			dry.mu.Unlock()
			if len(ops) == 0 {
				t.Fatal("一个写盘点都没有")
			}
			t.Run("每个写盘点", func(t *testing.T) {
				for k := range ops {
					if testing.Short() && k%5 != 0 && k != len(ops)-1 {
						continue // -short 只断每第 5 个和最后一个，开发时快速回归用；冻结、合并前跑全量
					}
					t.Run(fmt.Sprintf("%02d-%s", k, strings.ReplaceAll(ops[k], " ", "_")), func(t *testing.T) {
						t.Parallel()
						powerCutAt(t, sc, priv, ops, k)
					})
				}
			})
			if !t.Failed() && !testing.Short() {
				t.Logf("%s：%d 个写盘点全试过\n  %s", sc.name, len(ops), strings.Join(ops, "\n  "))
			}
		})
	}
}

// 断电那一下之后，Run 不能再走到下一个写盘点：真断电后没有代码在跑。
// 否则断在改名上时 writeAtomic 还要重试 10 次（约 0.9 秒）才回到 Run 看 stop。
func TestPowerCutNoCodeAfterCut(t *testing.T) {
	_, priv := keys(t)
	sc := pcScenarios()[0] // 消费staged-接受：第一个写盘点之后就是写 state 的改名
	dry := newPCEnv(t, sc, priv, -1)
	if dry.runToStable() == "" {
		t.Fatal(dry.diag())
	}
	k := slices.Index(dry.ops, "rename "+StateFile+".tmp")
	if k < 0 {
		t.Fatalf("没有改名写盘点: %v", dry.ops)
	}
	e := newPCEnv(t, sc, priv, k)
	stop := runBoot(e.boot())
	<-e.cutCh
	time.Sleep(300 * time.Millisecond)
	stop()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.after > 1 {
		t.Fatalf("断电后又走了 %d 个写盘点", e.after)
	}
}

func powerCutAt(t *testing.T, sc *pcScenario, priv ed25519.PrivateKey, dry []string, k int) {
	e := newPCEnv(t, sc, priv, k)
	stop := runBoot(e.boot())
	select {
	case <-e.cutCh:
	case <-time.After(20 * time.Second):
	}
	stop()
	e.mu.Lock()
	before, cut := append([]string(nil), e.ops...), e.cut
	e.mu.Unlock()
	if !cut || !slices.Equal(before, dry[:k]) {
		// 写盘点的顺序和无故障那遍不一样，"每个点都试过"就不成立了
		t.Fatalf("第 %d 个点没按无故障那遍的顺序走到：\n got %v\nwant %v", k, before, dry[:k])
	}
	if _, err := ReadState(e.root); err != nil {
		t.Errorf("I1: 断电后 boot-state.json 读不出: %v", err)
	}

	e.powerOn()
	running := e.runToStable()
	if running == "" {
		t.Fatalf("断在第 %d 个点（%s）后重启，跑不到稳定\n%s", k, dry[k], e.diag())
	}
	for _, v := range e.check(running, 1) {
		t.Errorf("断在第 %d 个点（%s）后: %s", k, dry[k], v)
	}
	if t.Failed() {
		t.Log(e.diag())
	}
}
