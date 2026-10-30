package boot

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- 救援槽 R（docs/boot.md "救援槽 R"）----

func countEvents(t *testing.T, b *Boot, kind string) int {
	t.Helper()
	n := 0
	for _, e := range events(t, b) {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func eventDetail(t *testing.T, b *Boot, kind string) string {
	t.Helper()
	for _, e := range events(t, b) {
		if e.Kind == kind {
			return e.Detail
		}
	}
	return ""
}

// 情况 1：current、good 都跑不了，没有 pending → 救援。救援不写 state、不写确认文件、不碰 R。
func TestRescueWhenNothingRuns(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {
		if slot == RescueSlot {
			p.code = 7
			p.Kill()
		}
	}
	putSlot(t, b, priv, "A", "0.2.0")
	tamper(t, b, "A")
	putSlot(t, b, priv, "B", "0.3.0") // good 被 loader 覆盖成了别的版本
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	setState(t, b, State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.2.0", "B": "0.1.0"}})
	stateBefore := readFile(t, filepath.Join(b.Root, StateFile))
	rBefore := readFile(t, filepath.Join(b.Root, RescueSlot, ReleaseFile))

	stop := run(t, b)
	waitFor(t, "救援跑完", func() bool { return hasEvent(t, b, "boot_rescue_done") })
	time.Sleep(50 * time.Millisecond)
	stop()

	if got := r.list(); len(got) != 1 || got[0] != RescueSlot {
		t.Fatalf("starts %v", got)
	}
	if !hasEvent(t, b, "boot_rescue") || !strings.Contains(eventDetail(t, b, "boot_rescue_done"), "7") {
		t.Fatalf("事件 %+v", events(t, b))
	}
	if readFile(t, filepath.Join(b.Root, StateFile)) != stateBefore {
		t.Fatal("救援写了 state")
	}
	if readFile(t, filepath.Join(b.Root, RescueSlot, ReleaseFile)) != rBefore {
		t.Fatal("救援动了 R")
	}
	if _, err := VerifySlot(filepath.Join(b.Root, RescueSlot), b.Keys); err != nil {
		t.Fatalf("R 被改坏: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.Root, "confirm-"+RescueSlot)); err == nil {
		t.Fatal("救援写了确认文件")
	}
}

// 情况 1 的后续：救援写好槽 B 和 staged.json → 照常消费、试启动、转正。
func TestRescueThenStagedTrial(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {
		switch slot {
		case RescueSlot:
			putSlot(t, b, priv, "B", "0.3.0")
			stage(t, b, "B", "0.3.0")
			p.Kill()
		case "B":
			confirmAfterStart(slot, confirm, p)
		}
	}
	putSlot(t, b, priv, "A", "0.2.0")
	tamper(t, b, "A")
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.2.0"}})
	stop := run(t, b)
	waitFor(t, "B 转正", func() bool { return getState(t, b).Current == "B" })
	stop()
	if got := r.list(); len(got) != 2 || got[0] != RescueSlot || got[1] != "B" {
		t.Fatalf("starts %v", got)
	}
	if stagedExists(b) {
		t.Fatal("staged.json 没消费")
	}
}

// 情况 2：current 为空，pending 已经试满次数没确认 → 先救援；救不好就照旧接着试。
func TestRescueFirstInstallUnconfirmed(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = crash
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	setState(t, b, State{Pending: "A", Tries: MaxTries, Versions: map[string]string{"A": "0.1.0"}})
	stop := run(t, b)
	waitFor(t, "救援后接着试 A", func() bool { return r.count("A") > MaxTries })
	stop()
	if got := r.list(); got[0] != RescueSlot || r.count(RescueSlot) != 1 {
		t.Fatalf("starts %v", got)
	}
	if st := getState(t, b); st.Pending != "A" || st.Bad != "" {
		t.Fatalf("state %+v", st)
	}
	if !strings.Contains(eventDetail(t, b, "boot_rescue"), "0.1.0") {
		t.Fatalf("原因没写版本: %+v", events(t, b))
	}
}

// 首次装的版本是坏的：A 试满 → 救援写好 B 和 staged.json → 改试 B（tries 从 0 算）→ 转正。
func TestRescueReplacesBadFirstInstall(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {
		switch slot {
		case "A":
			p.Kill()
		case RescueSlot:
			putSlot(t, b, priv, "B", "0.1.1")
			stage(t, b, "B", "0.1.1")
			p.Kill()
		case "B":
			confirmAfterStart(slot, confirm, p)
		}
	}
	putSlot(t, b, priv, "A", "0.1.0")
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	stage(t, b, "A", "0.1.0") // 安装脚本 -seed 的结果
	stop := run(t, b)
	waitFor(t, "B 转正", func() bool { return getState(t, b).Current == "B" })
	stop()

	want := []string{"A", "A", "A", RescueSlot, "B"}
	if got := r.list(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("starts %v，应为 %v", got, want)
	}
	r.mu.Lock()
	bTries := r.tries[4]
	r.mu.Unlock()
	if bTries != 1 {
		t.Fatalf("B 启动时 tries=%d，应从 0 算起（这次是第 1 次）", bTries)
	}
	if st := getState(t, b); st.Pending != "" || st.Bad != "" || st.Versions["B"] != "0.1.1" {
		t.Fatalf("state %+v", st)
	}
}

func TestRescueBadR(t *testing.T) {
	cases := map[string]func(t *testing.T, b *Boot, priv ed25519.PrivateKey){
		"没有 R": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {},
		"R 被改过": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, RescueSlot, "0.0.1")
			tamper(t, b, RescueSlot)
		},
		"R 要更新的引导器": func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlotMin(t, b, priv, RescueSlot, "0.0.1", Version+1)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			b, priv, r := newBoot(t)
			setup(t, b, priv) // 空目录：没有能跑的槽
			stop := run(t, b)
			waitFor(t, "boot_rescue_bad", func() bool { return hasEvent(t, b, "boot_rescue_bad") })
			time.Sleep(50 * time.Millisecond)
			stop()
			if r.count(RescueSlot) != 0 || hasEvent(t, b, "boot_rescue") {
				t.Fatalf("跑了验不过的 R: %v", r.list())
			}
			if n := countEvents(t, b, "boot_rescue_bad"); n != 1 {
				t.Fatalf("验不过也要限频，记了 %d 次", n)
			}
		})
	}
}

func TestRescueRateLimit(t *testing.T) {
	t.Run("间隔内不再救", func(t *testing.T) {
		b, priv, r := newBoot(t) // RescueGap 1 小时
		r.behave = crash
		putSlot(t, b, priv, RescueSlot, "0.0.1")
		stop := run(t, b)
		waitFor(t, "救援", func() bool { return hasEvent(t, b, "boot_rescue_done") })
		time.Sleep(100 * time.Millisecond) // 期间 Backoff 是 20ms，选槽转了好几轮
		stop()
		if n := r.count(RescueSlot); n != 1 {
			t.Fatalf("救了 %d 次", n)
		}
	})
	t.Run("过了间隔再救", func(t *testing.T) {
		b, priv, r := newBoot(t)
		b.RescueGap = 30 * time.Millisecond
		r.behave = crash
		putSlot(t, b, priv, RescueSlot, "0.0.1")
		stop := run(t, b)
		waitFor(t, "再救一次", func() bool { return r.count(RescueSlot) >= 2 })
		stop()
	})
}

func TestRescueTimeoutKilled(t *testing.T) {
	b, priv, r := newBoot(t)
	b.RescueWithin = 30 * time.Millisecond // R 卡住不退出
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	stop := run(t, b)
	waitFor(t, "超时", func() bool { return hasEvent(t, b, "boot_rescue_done") })
	stop()
	if !r.proc(0).dead() {
		t.Fatal("超时的救援进程没被杀")
	}
	if d := eventDetail(t, b, "boot_rescue_done"); !strings.Contains(d, "超时") {
		t.Fatalf("detail %q", d)
	}
}

func TestStopDuringRescue(t *testing.T) {
	b, priv, r := newBoot(t)
	b.RescueWithin = 3 * time.Second // R 卡住；stop 不管用的话要等它超时
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	stop := run(t, b)
	waitFor(t, "救援在跑", func() bool { return r.count(RescueSlot) == 1 })
	t0 := time.Now()
	stop()
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("stop 等了 %s", d)
	}
	if !r.proc(0).dead() {
		t.Fatal("stop 之后救援进程还在跑")
	}
}

// 有能跑的槽时绝不救援。
func TestNoRescueWhenRunnable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, b *Boot, priv ed25519.PrivateKey)
		runs  string
	}{
		{"current 正常", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.1.0")
			setState(t, b, State{Current: "A", Versions: map[string]string{"A": "0.1.0"}})
		}, "A"},
		{"current 坏、good 正常", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.2.0")
			tamper(t, b, "A")
			putSlot(t, b, priv, "B", "0.1.0")
			setState(t, b, State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.2.0", "B": "0.1.0"}})
		}, "B"},
		{"首次安装还没试满", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.1.0")
			setState(t, b, State{Pending: "A", Tries: MaxTries - 1, Versions: map[string]string{"A": "0.1.0"}})
		}, "A"},
		{"试满了但有退路", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.1.0")
			putSlot(t, b, priv, "B", "0.2.0")
			setState(t, b, State{Current: "A", Pending: "B", Tries: MaxTries, Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}})
		}, "A"},
		{"staged.json 待消费", func(t *testing.T, b *Boot, priv ed25519.PrivateKey) {
			putSlot(t, b, priv, "A", "0.1.0")
			stage(t, b, "A", "0.1.0")
		}, "A"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, priv, r := newBoot(t)
			putSlot(t, b, priv, RescueSlot, "0.0.1")
			c.setup(t, b, priv)
			stop := run(t, b)
			waitFor(t, "跑 "+c.runs, func() bool { return r.count(c.runs) > 0 })
			stop()
			if r.count(RescueSlot) != 0 || hasEvent(t, b, "boot_rescue") || hasEvent(t, b, "boot_rescue_bad") {
				t.Fatalf("有能跑的槽还救援: %v", r.list())
			}
		})
	}
}

// state 读不出来：拿不准就不动，不救援。
func TestNoRescueWhenStateUnreadable(t *testing.T) {
	b, priv, r := newBoot(t)
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	write(t, filepath.Join(b.Root, StateFile), "{")
	stop := run(t, b)
	time.Sleep(100 * time.Millisecond)
	stop()
	if len(r.list()) != 0 || hasEvent(t, b, "boot_rescue") || hasEvent(t, b, "boot_rescue_bad") {
		t.Fatalf("starts %v 事件 %+v", r.list(), events(t, b))
	}
}

// current 坏了（比如被杀毒软件隔离）、pending 又是坏版本试满了：没有退路，要救援，不能一直试坏版本。
func TestRescueWhenCurrentBrokenAndPendingExhausted(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = crash
	putSlot(t, b, priv, "A", "0.1.0")
	tamper(t, b, "A")
	putSlot(t, b, priv, "B", "0.2.0")
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	setState(t, b, State{Current: "A", Pending: "B", Tries: MaxTries, Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}})
	stop := run(t, b)
	waitFor(t, "救援", func() bool { return r.count(RescueSlot) > 0 })
	stop()
	if got := r.list(); got[0] != RescueSlot {
		t.Fatalf("没有退路时应先救援: %v", got)
	}
}

// 接上一个场景：救援把修复版覆盖写进试满的槽 B（loader -seed 规则），boot 按新版本从 0 次重试并转正。
func TestRescueOverwritesExhaustedPending(t *testing.T) {
	b, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {
		switch slot {
		case RescueSlot:
			putSlot(t, b, priv, "B", "0.2.1")
			stage(t, b, "B", "0.2.1")
			p.Kill()
		case "B":
			if getState(t, b).Versions["B"] == "0.2.1" {
				confirmAfterStart(slot, confirm, p)
			} else {
				p.Kill()
			}
		default:
			p.Kill()
		}
	}
	putSlot(t, b, priv, "A", "0.1.0")
	tamper(t, b, "A")
	putSlot(t, b, priv, "B", "0.2.0")
	putSlot(t, b, priv, RescueSlot, "0.0.1")
	setState(t, b, State{Current: "A", Pending: "B", Tries: MaxTries, Versions: map[string]string{"A": "0.1.0", "B": "0.2.0"}})
	stop := run(t, b)
	waitFor(t, "B(0.2.1) 转正", func() bool { st := getState(t, b); return st.Current == "B" && st.Versions["B"] == "0.2.1" })
	stop()
	if got := r.list(); strings.Join(got, ",") != "R,B" {
		t.Fatalf("starts %v，应为 R,B", got)
	}
}
