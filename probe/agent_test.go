package probe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"epsilon/proto"
)

type fakeSys struct {
	mu   sync.Mutex
	idle int
	apps string
	vram int // 已用显存 MB；0 = 用默认 300
	// model 不为空时，模型在跑就在 vram 上再加 3500（模拟模型占显存）
	model func() bool
}

func (f *fakeSys) IdleSeconds() int { f.mu.Lock(); defer f.mu.Unlock(); return f.idle }
func (f *fakeSys) GPUs() []proto.GPU {
	f.mu.Lock()
	defer f.mu.Unlock()
	used := f.vram
	if used == 0 {
		used = 300
	}
	if f.model != nil && f.model() {
		used += 3500
	}
	return []proto.GPU{{Name: "RTX 4060", MemUsed: used, MemTotal: 8188}}
}

func (f *fakeSys) set(idle, vram int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idle, f.vram = idle, vram
}
func (f *fakeSys) ComputeApps() string { f.mu.Lock(); defer f.mu.Unlock(); return f.apps }
func (f *fakeSys) MemFreeMB() int      { return 20000 }

type fakeController struct {
	mu       sync.Mutex
	desired  proto.DesiredState
	register int
	beats    []proto.Heartbeat
	events   []proto.Event
	auth     string
}

func (c *fakeController) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.register++
		c.auth = r.Header.Get("Authorization")
		c.mu.Unlock()
		w.Write([]byte("{}"))
	})
	mux.HandleFunc("POST /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var hb proto.Heartbeat
		json.NewDecoder(r.Body).Decode(&hb)
		c.mu.Lock()
		c.beats = append(c.beats, hb)
		d := c.desired
		c.mu.Unlock()
		json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		var ev proto.Event
		json.NewDecoder(r.Body).Decode(&ev)
		c.mu.Lock()
		c.events = append(c.events, ev)
		c.mu.Unlock()
	})
	return mux
}

func (c *fakeController) last() proto.Heartbeat {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.beats) == 0 {
		return proto.Heartbeat{}
	}
	return c.beats[len(c.beats)-1]
}

func TestAgentFollowsDesiredStateAndYields(t *testing.T) {
	fc := &fakeController{desired: proto.DesiredState{Workload: "fake", YieldOnInput: true,
		InputIdleSeconds: 60, HeartbeatSeconds: 1}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()

	w := fakeWorkload(t, false)
	sys := &fakeSys{idle: 9999}
	a := NewAgent(Config{Node: "pc-01", Controller: srv.URL, Token: "tok",
		Workloads: map[string]Workload{"fake": w}}, sys, "test")
	a.beatEvery = 200 * time.Millisecond
	stop := make(chan struct{})
	go a.Run(stop, 50*time.Millisecond)
	defer func() { close(stop); a.sup.Stop() }()

	waitFor(t, "serving reported", func() bool { s := fc.last().Serving; return s != nil && s.Model == "fake" })
	fc.mu.Lock()
	if fc.register != 1 || fc.auth != "Bearer tok" {
		t.Fatalf("register=%d auth=%q", fc.register, fc.auth)
	}
	fc.mu.Unlock()

	sys.mu.Lock()
	sys.idle = 5 // 有人坐下来了
	sys.mu.Unlock()
	waitFor(t, "yield", func() bool { h := fc.last(); return h.Running == "" && h.Reason == "user_active" })
	waitFor(t, "yield event", func() bool {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		for _, e := range fc.events {
			if e.Kind == "yield" && e.Node == "pc-01" {
				return true
			}
		}
		return false
	})
}

func TestAgentIgnoresWorkloadNotInLocalConfig(t *testing.T) {
	fc := &fakeController{desired: proto.DesiredState{Workload: "rm-rf", HeartbeatSeconds: 1}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	a := NewAgent(Config{Node: "n", Controller: srv.URL, Workloads: map[string]Workload{}}, &fakeSys{idle: 9999}, "test")
	a.beatEvery = 100 * time.Millisecond
	stop := make(chan struct{})
	go a.Run(stop, 50*time.Millisecond)
	defer close(stop)
	waitFor(t, "unknown workload reported", func() bool { return fc.last().Reason == "unknown_workload" })
	if a.sup.Status().Name != "" {
		t.Fatal("must not run anything")
	}
}

func TestAgentStopsWhenControllerLost(t *testing.T) {
	fc := &fakeController{desired: proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1, MaxOfflineMins: 1}}
	srv := httptest.NewServer(fc.handler())
	w := fakeWorkload(t, false)
	a := NewAgent(Config{Node: "n", Controller: srv.URL, Workloads: map[string]Workload{"fake": w}}, &fakeSys{idle: 9999}, "test")
	a.beatEvery = 100 * time.Millisecond
	a.maxOfflineUnit = 500 * time.Millisecond // 测试里 1 "分钟" = 0.5 秒，要比心跳间隔长
	stop := make(chan struct{})
	go a.Run(stop, 20*time.Millisecond)
	defer func() { close(stop); a.sup.Stop() }()
	waitFor(t, "running", func() bool { return a.sup.Status().Healthy })
	srv.Close()
	waitFor(t, "stopped after controller lost", func() bool { return a.sup.Status().Name == "" })
}

func startAgent(t *testing.T, d proto.DesiredState, sys *fakeSys) (*fakeController, *Agent) {
	fc := &fakeController{desired: d}
	srv := httptest.NewServer(fc.handler())
	a := NewAgent(Config{Node: "n", Controller: srv.URL, Workloads: map[string]Workload{"fake": fakeWorkload(t, false)}}, sys, "test")
	a.beatEvery, a.gpuEvery = 100*time.Millisecond, 20*time.Millisecond
	a.vram.grace = 500 * time.Millisecond
	stop := make(chan struct{})
	go a.Run(stop, 20*time.Millisecond)
	t.Cleanup(func() { close(stop); a.sup.Stop(); srv.Close() })
	return fc, a
}

func TestAgentKeepWarmKeepsModelLoaded(t *testing.T) {
	sys := &fakeSys{idle: 9999}
	fc, a := startAgent(t, proto.DesiredState{Workload: "fake", YieldOnInput: true, InputIdleSeconds: 60,
		KeepWarm: true, HeartbeatSeconds: 1}, sys)
	waitFor(t, "serving", func() bool { return fc.last().Serving != nil })
	pid := a.sup.Status().PID

	sys.set(5, 0) // 有人坐下看网页
	waitFor(t, "warm", func() bool { h := fc.last(); return h.Serving == nil && h.Reason == "user_active" })
	if st := a.sup.Status(); st.PID != pid || st.Name != "fake" {
		t.Fatalf("model should stay loaded: %+v (pid was %d)", st, pid)
	}
	sys.set(9999, 0) // 人走了：立刻恢复接活，不用重新加载
	waitFor(t, "serving again", func() bool { return fc.last().Serving != nil })
	if a.sup.Status().PID != pid {
		t.Fatal("process was restarted")
	}
}

func TestAgentUnloadsWhenSomeoneNeedsVRAM(t *testing.T) {
	sys := &fakeSys{idle: 9999, vram: 300}
	fc, a := startAgent(t, proto.DesiredState{Workload: "fake", ForeignVRAMMB: 1500, HeartbeatSeconds: 1}, sys)
	sys.mu.Lock()
	sys.model = func() bool { return a.sup.Status().Healthy }
	sys.mu.Unlock()
	waitFor(t, "serving", func() bool { return fc.last().Serving != nil })
	time.Sleep(700 * time.Millisecond) // 等过稳定期，探针记下"模型加载后 3800"

	sys.set(9999, 3000) // 有人开游戏：桌面 300 -> 3000，多占 2700（游戏+模型其实装得下，也要让）
	waitFor(t, "unloaded and waiting", func() bool { return fc.last().Reason == "vram_short" })
	time.Sleep(300 * time.Millisecond)
	if a.sup.Status().Name != "" || fc.last().Reason != "vram_short" {
		t.Fatal("must not reload while the game still holds VRAM")
	}
	sys.set(9999, 300) // 游戏关了
	waitFor(t, "reloaded", func() bool { return fc.last().Serving != nil })
}

// 真机上显存是在模型加载过程中慢慢涨上去的，健康检查通过时显卡读数可能还是旧的；
// 2026-10-24 pc-05 因此把自己的模型当成"别人占的显存"，每 11 秒卸载重装一次。
func TestAgentDoesNotMistakeItsOwnModelForForeignVRAM(t *testing.T) {
	sys := &fakeSys{idle: 9999, vram: 300}
	fc, a := startAgent(t, proto.DesiredState{Workload: "fake", ForeignVRAMMB: 1500, HeartbeatSeconds: 1}, sys)
	a.gpuEvery = 400 * time.Millisecond // 显卡查得慢，健康时手里是旧读数
	var healthyAt time.Time
	sys.mu.Lock()
	sys.model = func() bool { // 健康 300ms 后显存才涨满
		if !a.sup.Status().Healthy {
			healthyAt = time.Time{}
			return false
		}
		if healthyAt.IsZero() {
			healthyAt = time.Now()
		}
		return time.Since(healthyAt) > 300*time.Millisecond
	}
	sys.mu.Unlock()
	waitFor(t, "serving", func() bool { return fc.last().Serving != nil })
	pid := a.sup.Status().PID
	time.Sleep(2 * time.Second)
	if a.sup.Status().PID != pid || fc.last().Reason != "" {
		t.Fatalf("model was unloaded by mistake: reason=%q", fc.last().Reason)
	}
}

func TestAgentConfirmsBootOnceOnline(t *testing.T) {
	fc := &fakeController{desired: proto.DesiredState{HeartbeatSeconds: 1}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	a := NewAgent(Config{Node: "pc-01", Controller: srv.URL}, &fakeSys{idle: 9999}, "test")
	a.Boot = "1/B"
	var mu sync.Mutex
	n := 0
	a.OnOnline = func() { mu.Lock(); n++; mu.Unlock() }
	a.beatEvery = 50 * time.Millisecond
	stop := make(chan struct{})
	go a.Run(stop, 10*time.Millisecond)
	defer close(stop)
	waitFor(t, "a few beats", func() bool { fc.mu.Lock(); defer fc.mu.Unlock(); return len(fc.beats) >= 3 })
	mu.Lock()
	defer mu.Unlock()
	if n != 1 || fc.last().Boot != "1/B" {
		t.Fatalf("OnOnline called %d times, boot %q", n, fc.last().Boot)
	}
}
