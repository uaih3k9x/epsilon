package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"epsilon/proto"
)

// fetchEnv: 假主控 + 内存块缓存 + 假拼装，Agent 不跑 Run，直接调 fetch。
type fetchEnv struct {
	fc    *fakeController
	a     *Agent
	store *memStore
	m     proto.Manifest
	data  map[string][]byte

	mu        sync.Mutex
	ready     map[string]bool
	assembled int
	roots     []string
}

func newFetchEnv(t *testing.T, n int) *fetchEnv {
	e := &fetchEnv{store: newMemStore(), data: map[string][]byte{}, ready: map[string]bool{}}
	e.m = proto.Manifest{ID: "m1", ChunkSize: 1 << 20, Files: []proto.ManifestFile{{Path: "models/m1.gguf"}}}
	for i := 0; i < n; i++ {
		b := []byte(strings.Repeat(fmt.Sprintf("chunk-%d;", i), 1000))
		h := hashOf(b)
		e.data[h] = b
		e.m.Files[0].Chunks = append(e.m.Files[0].Chunks, h)
	}
	e.fc = &fakeController{manifests: map[string]proto.Manifest{"m1": e.m}, chunks: e.data}
	srv := httptest.NewServer(e.fc.handler())
	t.Cleanup(srv.Close)
	e.a = NewAgent(Config{Node: "pc-01", Controller: srv.URL, Token: "tok", ArtifactRoot: "/srv/epsilon"}, &fakeSys{idle: 9999}, "test")
	e.a.Chunks = e.store
	e.a.Ready = func(m proto.Manifest, root string) bool { e.mu.Lock(); defer e.mu.Unlock(); return e.ready[m.ID] }
	e.a.Assemble = func(m proto.Manifest, root string) error {
		for _, f := range m.Files {
			for _, h := range f.Chunks {
				if !e.store.Has(h) {
					return fmt.Errorf("拼装时缺块 %s", h)
				}
			}
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		e.assembled++
		e.roots = append(e.roots, root)
		e.ready[m.ID] = true
		return nil
	}
	e.a.retryUnit = 20 * time.Millisecond
	return e
}

func (e *fetchEnv) hashes() []string { return e.m.Files[0].Chunks }

// sources 给每块都排同样的来源。
func (e *fetchEnv) sources(src ...string) func(int) proto.Peers {
	return func(int) proto.Peers {
		p := proto.Peers{Sources: map[string][]string{}}
		for _, h := range e.hashes() {
			p.Sources[h] = src
		}
		return p
	}
}

func (e *fetchEnv) haveAdds() []string {
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	var add []string
	for _, h := range e.fc.haves {
		add = append(add, h.Add...)
	}
	sort.Strings(add)
	return add
}

func (e *fetchEnv) fetchEvents() []string {
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	var ev []string
	for _, x := range e.fc.events {
		if x.Kind == "fetch" {
			ev = append(ev, x.Detail)
		}
	}
	return ev
}

// neighbor 起一个假邻居：先验 token，再交给 serve。
func neighbor(t *testing.T, serve func(w http.ResponseWriter, h string)) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		h, ok := strings.CutPrefix(r.URL.Path, "/v1/chunks/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		serve(w, h)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func sorted(s []string) []string { s = append([]string(nil), s...); sort.Strings(s); return s }

func TestFetchPrefersNeighbors(t *testing.T) {
	e := newFetchEnv(t, 3)
	nb, hits := neighbor(t, func(w http.ResponseWriter, h string) { w.Write(e.data[h]) })
	e.fc.peers = e.sources(nb.URL, "")

	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 || e.fc.chunkHits != 0 {
		t.Fatalf("邻居 %d 次、主控 %d 次：邻居排在前面就该全从邻居拿", hits.Load(), e.fc.chunkHits)
	}
	if e.assembled != 1 || e.roots[0] != "/srv/epsilon" {
		t.Fatalf("拼装 %d 次 %v", e.assembled, e.roots)
	}
	if got, want := e.haveAdds(), sorted(e.hashes()); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("have 报的 %v，应该是 %v", got, want)
	}
	for _, h := range e.fc.haves {
		if h.Node != "pc-01" {
			t.Fatalf("have 没带节点名: %+v", h)
		}
	}
	if ev := e.fetchEvents(); len(ev) != 2 || !strings.Contains(ev[0], "m1: 缺 3/3 块") || !strings.Contains(ev[1], "m1") {
		t.Fatalf("应该有开始、完成两个 fetch 事件: %q", ev)
	}
}

func TestFetchBlacklistsNeighborWithBadData(t *testing.T) {
	e := newFetchEnv(t, 5)
	e.a.fetchParallel = 1 // 一块一块来，"连续 3 次"才好数
	nb, hits := neighbor(t, func(w http.ResponseWriter, h string) { w.Write([]byte("坏数据")) })
	e.fc.peers = e.sources(nb.URL, "")

	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 {
		t.Fatalf("坏邻居被要了 %d 次，连续 3 次校验失败后就该拉黑", hits.Load())
	}
	if e.fc.chunkHits != 5 || len(e.store.List()) != 5 || e.assembled != 1 {
		t.Fatalf("主控 %d 次、存了 %d 块、拼装 %d 次", e.fc.chunkHits, len(e.store.List()), e.assembled)
	}
}

func TestFetchMovesOnFromSlowSource(t *testing.T) {
	e := newFetchEnv(t, 2)
	e.a.sourceTimeout = 100 * time.Millisecond
	stuck := make(chan struct{})
	defer close(stuck)
	nb, hits := neighbor(t, func(w http.ResponseWriter, h string) {
		w.Header().Set("Content-Length", "100000")
		w.Write([]byte("半截"))
		w.(http.Flusher).Flush()
		<-stuck // 发了个头就不动了
	})
	e.fc.peers = e.sources(nb.URL, "")

	start := time.Now()
	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 || e.fc.chunkHits != 2 || e.assembled != 1 {
		t.Fatalf("邻居 %d 次、主控 %d 次、拼装 %d 次", hits.Load(), e.fc.chunkHits, e.assembled)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("卡住的来源应该 100ms 就放弃，用了 %v", d)
	}
}

func TestFetchWaitsRetryAfterWhenNoSource(t *testing.T) {
	e := newFetchEnv(t, 2)
	all := e.sources("")
	e.fc.peers = func(n int) proto.Peers {
		if n == 1 { // 种子还没拉到
			return proto.Peers{Sources: map[string][]string{}, RetryAfterSeconds: 3}
		}
		return all(n)
	}
	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	if len(e.fc.peerAt) != 2 {
		t.Fatalf("问了 %d 次 peers", len(e.fc.peerAt))
	}
	if gap := e.fc.peerAt[1].Sub(e.fc.peerAt[0]); gap < 3*e.a.retryUnit {
		t.Fatalf("没等 retry_after 就重问了: %v", gap)
	}
	if e.assembled != 1 {
		t.Fatal("没拼装")
	}
}

func TestFetchSkipsWhenAlreadyReady(t *testing.T) {
	e := newFetchEnv(t, 2)
	e.ready["m1"] = true // 开机：文件早就拼好了
	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if e.fc.chunkHits != 0 || len(e.fc.peerAt) != 0 || e.assembled != 0 || len(e.fetchEvents()) != 0 {
		t.Fatalf("已经备齐就不该拉、不该发事件: chunks=%d peers=%d events=%q", e.fc.chunkHits, len(e.fc.peerAt), e.fetchEvents())
	}
}

func TestFetchEvictsAndReportsDeleted(t *testing.T) {
	e := newFetchEnv(t, 2)
	old := []byte("上学期的模型")
	e.store.Put(hashOf(old), strings.NewReader(string(old)))
	e.store.evictFn = func(string) bool { return true } // 假装超配额：keep 以外的全删

	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if e.store.Has(hashOf(old)) || len(e.store.List()) != 2 {
		t.Fatalf("旧块没淘汰 / 新块被误删: %v", e.store.List())
	}
	if len(e.store.keeps) < 2 {
		t.Fatalf("拉之前、拉之后都该淘汰一次，调了 %d 次", len(e.store.keeps))
	}
	for _, keep := range e.store.keeps {
		for _, h := range e.hashes() {
			if !keep[h] {
				t.Fatal("keep 里缺当前制品的块")
			}
		}
	}
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	var del []string
	for _, h := range e.fc.haves {
		del = append(del, h.Del...)
	}
	if len(del) != 1 || del[0] != hashOf(old) {
		t.Fatalf("淘汰的块应该经 have.del 报: %v", del)
	}
}

func TestFetchGivesUpWhenEverySourceFails(t *testing.T) {
	e := newFetchEnv(t, 2)
	e.fc.chunks = map[string][]byte{} // 主控也给不出来
	err := e.a.fetch(context.Background(), "m1")
	if err == nil || e.assembled != 0 {
		t.Fatalf("所有来源都失败应该报错退出: %v", err)
	}
	if ev := e.fetchEvents(); len(ev) != 1 || !strings.HasPrefix(ev[0], "开始") {
		t.Fatalf("fetch 只发开始，失败由 Agent 发: %q", ev)
	}
}

func TestFetchStopsOnCancel(t *testing.T) {
	e := newFetchEnv(t, 2)
	e.fc.peers = func(int) proto.Peers { return proto.Peers{RetryAfterSeconds: 1000} } // 永远没来源
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- e.a.fetch(ctx, "m1") }()
	waitFor(t, "asked peers", func() bool { e.fc.mu.Lock(); defer e.fc.mu.Unlock(); return len(e.fc.peerAt) > 0 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消后没退出")
	}
}

func TestReportHave(t *testing.T) {
	e := newFetchEnv(t, 0)
	a := e.a
	a.registered.Store(true)

	e.fc.haveCode = http.StatusInternalServerError
	a.reportHave([]string{"aa"}, nil)
	e.fc.haveCode = 0
	a.reportHave([]string{"bb"}, []string{"aa"}) // 上次没报出去的要补上；先加后删的只报删
	e.fc.mu.Lock()
	if len(e.fc.haves) != 1 || fmt.Sprint(e.fc.haves[0].Add) != "[bb]" || fmt.Sprint(e.fc.haves[0].Del) != "[aa]" {
		t.Fatalf("haves: %+v", e.fc.haves)
	}
	e.fc.haveCode = http.StatusConflict // 主控重启过，不认识这台了
	e.fc.mu.Unlock()
	a.reportHave([]string{"cc"}, nil)
	if a.registered.Load() {
		t.Fatal("have 回 409 应该重新登记")
	}
	e.fc.mu.Lock()
	e.fc.haveCode = 0
	e.fc.mu.Unlock()
	a.reportHave([]string{"dd"}, nil) // 重新登记会带上全部块，409 时攒的就不用再报了
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	if last := e.fc.haves[len(e.fc.haves)-1]; fmt.Sprint(last.Add) != "[dd]" {
		t.Fatalf("last have: %+v", last)
	}
}
