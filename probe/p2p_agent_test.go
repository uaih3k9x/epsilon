package probe

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"epsilon/proto"
)

// runFetchAgent 让 fetchEnv 里的 Agent 带上假工作负载真跑起来。
func runFetchAgent(t *testing.T, e *fetchEnv, d proto.DesiredState) {
	e.fc.mu.Lock()
	e.fc.desired = d
	e.fc.mu.Unlock()
	e.a.cfg.Workloads = map[string]Workload{"fake": fakeWorkload(t, false)}
	e.a.beatEvery = 100 * time.Millisecond
	stop := make(chan struct{})
	go e.a.Run(stop, 20*time.Millisecond)
	t.Cleanup(func() { close(stop); e.a.Shutdown() })
}

func (e *fetchEnv) eventKinds() (kinds []string) {
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	for _, x := range e.fc.events {
		kinds = append(kinds, x.Kind)
	}
	return kinds
}

func (e *fetchEnv) setDesired(d proto.DesiredState) {
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	e.fc.desired = d
}

func TestAgentFetchesArtifactsBeforeStarting(t *testing.T) {
	e := newFetchEnv(t, 3)
	old := []byte("早就有的块")
	e.store.Put(hashOf(old), strings.NewReader(string(old)))
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	e.fc.gate = gate
	var readyCalls atomic.Int32
	ready := e.a.Ready
	e.a.Ready = func(m proto.Manifest, root string) bool { readyCalls.Add(1); return ready(m, root) }

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.a.serveP2P(ln)
	runFetchAgent(t, e, proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1, Artifacts: []string{"m1"}, P2PUploadMbps: 5})

	waitFor(t, "fetching", func() bool { return e.fc.last().Reason == "fetching" })
	time.Sleep(200 * time.Millisecond)
	if e.a.sup.Status().Name != "" || e.fc.last().Reason != "fetching" {
		t.Fatal("制品没备齐不能起工作负载")
	}
	e.fc.mu.Lock()
	reg := e.fc.regs[0]
	e.fc.mu.Unlock()
	if reg.P2PPort != ln.Addr().(*net.TCPAddr).Port || len(reg.Chunks) != 1 || reg.Chunks[0] != hashOf(old) {
		t.Fatalf("登记要带分块服务端口和本地块: port=%d chunks=%v", reg.P2PPort, reg.Chunks)
	}
	e.a.upload.mu.Lock()
	bps := e.a.upload.bps
	e.a.upload.mu.Unlock()
	if bps != 5*1000000/8 {
		t.Fatalf("上传限速没跟期望状态: %d", bps)
	}

	release()
	waitFor(t, "serving", func() bool { return e.fc.last().Serving != nil })
	kinds := strings.Join(e.eventKinds(), ",")
	if strings.Contains(kinds, "yield") || strings.Count(kinds, "fetch") != 2 || !strings.Contains(kinds, "start") {
		t.Fatalf("fetching 不是让位；应有 fetch 开始/完成和 start: %s", kinds)
	}
	n := readyCalls.Load()
	time.Sleep(300 * time.Millisecond) // 十几个 Step
	if readyCalls.Load() != n {
		t.Fatal("备齐之后不该每个 Step 都去核对文件")
	}
}

func TestAgentRetriesFailedFetch(t *testing.T) {
	e := newFetchEnv(t, 2)
	e.a.fetchRetry = 200 * time.Millisecond
	m := e.fc.manifests["m1"]
	e.fc.manifests = map[string]proto.Manifest{} // 主控还没放清单
	runFetchAgent(t, e, proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1, Artifacts: []string{"m1"}})

	waitFor(t, "fetch failed", func() bool { return len(e.fetchEvents()) > 0 })
	waitFor(t, "fetching", func() bool { return e.fc.last().Reason == "fetching" })
	time.Sleep(500 * time.Millisecond) // 又重试了一两次
	if ev := e.fetchEvents(); len(ev) != 1 || !strings.Contains(ev[0], "失败") {
		t.Fatalf("同样的失败只报一次: %q", ev)
	}
	e.fc.mu.Lock()
	e.fc.manifests["m1"] = m
	e.fc.mu.Unlock()
	waitFor(t, "serving after retry", func() bool { return e.fc.last().Serving != nil })
}

func TestAgentDropsArtifactNoLongerWanted(t *testing.T) {
	e := newFetchEnv(t, 2)
	gate := make(chan struct{})
	e.fc.gate = gate
	defer close(gate)
	runFetchAgent(t, e, proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1, Artifacts: []string{"m1"}})
	waitFor(t, "fetching", func() bool { return e.fc.last().Reason == "fetching" })

	e.setDesired(proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1}) // 主控改主意了
	waitFor(t, "serving without artifacts", func() bool { return e.fc.last().Serving != nil })
	for _, ev := range e.fetchEvents() {
		if strings.Contains(ev, "失败") {
			t.Fatalf("取消的拉取不算失败: %q", ev)
		}
	}
}

// 预热：只把块拉进缓存，不拼文件，也不挡工作负载；以后改成 artifacts 时只差拼装。
func TestAgentPreloadsWithoutAssembling(t *testing.T) {
	e := newFetchEnv(t, 3)
	runFetchAgent(t, e, proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1, Preload: []string{"m1"}})
	waitFor(t, "serving while preloading", func() bool { return e.fc.last().Serving != nil })
	waitFor(t, "preloaded", func() bool {
		for _, h := range e.hashes() {
			if !e.store.Has(h) {
				return false
			}
		}
		return true
	})
	waitFor(t, "preload done event", func() bool {
		for _, ev := range e.fetchEvents() {
			if strings.Contains(ev, "预热完成") {
				return true
			}
		}
		return false
	})
	e.mu.Lock()
	n := e.assembled
	e.mu.Unlock()
	if n != 0 {
		t.Fatalf("预热不该拼文件，拼了 %d 次", n)
	}
	if got := e.store.Evict(map[string]bool{}); len(got) != 0 { // memStore 不限额：这里只验证没被探针自己淘汰掉
		t.Fatalf("不该有块被淘汰: %v", got)
	}

	e.setDesired(proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1, Artifacts: []string{"m1"}})
	waitFor(t, "assembled from cache", func() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.assembled == 1 })
	waitFor(t, "serving again", func() bool { return e.fc.last().Serving != nil })
}

func TestKeepIncludesPreload(t *testing.T) {
	e := newFetchEnv(t, 2)
	m2 := proto.Manifest{ID: "m2", Files: []proto.ManifestFile{{Path: "x", Chunks: []string{hashOf([]byte("m2"))}}}}
	e.a.fmu.Lock()
	e.a.manifests["m2"] = m2
	e.a.wanted = []string{"m2"} // 预热中的 m2
	e.a.fmu.Unlock()
	keep := e.a.keepFor(e.m)
	if !keep[m2.Files[0].Chunks[0]] || !keep[e.hashes()[0]] {
		t.Fatalf("淘汰要留下 artifacts 和预热的块: %v", keep)
	}
}
