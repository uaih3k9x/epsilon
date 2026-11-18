package probe

// 取块加固：邻居各种坏法、并发、取消、本地坏块自愈。都在 -race 下跑。

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/chunk"
	"epsilon/proto"
)

func (e *fetchEnv) haveDels() []string {
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	var del []string
	for _, h := range e.fc.haves {
		del = append(del, h.Del...)
	}
	return del
}

func (e *fetchEnv) masterHits() int {
	e.fc.mu.Lock()
	defer e.fc.mu.Unlock()
	return e.fc.chunkHits
}

// checkStore: 缓存里每块的内容都和块名对得上。
func (e *fetchEnv) checkStore(t *testing.T) {
	t.Helper()
	for _, h := range e.hashes() {
		if !e.store.Has(h) {
			t.Fatalf("缺块 %s", h[:12])
		}
		if !bytes.Equal(e.store.data[h], e.data[h]) {
			t.Fatalf("块 %s 内容不对", h[:12])
		}
	}
}

// 邻居给到一半就断：带 Content-Length 和 chunked 两种。半截不能入库，换主控取。
func TestFetchNeighborDiesMidway(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			e := newFetchEnv(t, 3)
			nb, hits := neighbor(t, func(w http.ResponseWriter, h string) {
				b := e.data[h]
				if !chunked {
					w.Header().Set("Content-Length", fmt.Sprint(len(b)))
				}
				w.Write(b[:len(b)/2])
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler) // 直接掐断连接
			})
			e.fc.peers = e.sources(nb.URL, "")
			if err := e.a.fetch(context.Background(), "m1"); err != nil {
				t.Fatal(err)
			}
			if hits.Load() == 0 || e.masterHits() != 3 || e.assembled != 1 {
				t.Fatalf("邻居 %d 次、主控 %d 次、拼装 %d 次", hits.Load(), e.masterHits(), e.assembled)
			}
			e.checkStore(t)
		})
	}
}

// 回 200，给的却是别的块：校验不过、拉黑，不会存到错的名字下。
func TestFetchNeighborSendsOtherChunk(t *testing.T) {
	e := newFetchEnv(t, 4)
	hs := e.hashes()
	nb, _ := neighbor(t, func(w http.ResponseWriter, h string) {
		i := slices.Index(hs, h)
		w.Write(e.data[hs[(i+1)%len(hs)]])
	})
	e.fc.peers = e.sources(nb.URL, "")
	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if e.masterHits() != 4 {
		t.Fatalf("主控 %d 次，应该全从主控补", e.masterHits())
	}
	e.checkStore(t)
}

// 疑点 3：邻居一直灌数据（或报一个超大的 Content-Length），不能等到 sourceTimeout，
// 也不能把临时文件写满磁盘：超过清单块大小就断。用真的 chunk.Store 看磁盘。
func TestFetchRejectsOversizedBody(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, stop <-chan struct{}){
		"无限长": func(w http.ResponseWriter, stop <-chan struct{}) {
			junk := bytes.Repeat([]byte("x"), 1<<20)
			for i := 0; i < 32; i++ { // 32 MiB 之后卡住（真坏邻居会一直灌，这里别把测试机写满）
				if _, err := w.Write(junk); err != nil {
					return
				}
			}
			<-stop
		},
		"Content-Length 超大": func(w http.ResponseWriter, stop <-chan struct{}) {
			w.Header().Set("Content-Length", fmt.Sprint(int64(1)<<40))
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			<-stop
		},
	}
	for name, serve := range cases {
		t.Run(name, func(t *testing.T) {
			e := newFetchEnv(t, 2)
			dir := t.TempDir()
			store, err := chunk.NewStore(dir, 0)
			if err != nil {
				t.Fatal(err)
			}
			e.a.Chunks = store
			e.a.Assemble = func(proto.Manifest, string) error { return nil }
			e.a.sourceTimeout = 3 * time.Second
			stop := make(chan struct{})
			nb, hits := neighbor(t, func(w http.ResponseWriter, h string) { serve(w, stop) })
			defer close(stop)
			e.fc.peers = e.sources(nb.URL, "")

			start := time.Now()
			if err := e.a.fetch(context.Background(), "m1"); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > 1500*time.Millisecond {
				t.Fatalf("超长回包应该超过块大小就断，用了 %v（sourceTimeout 3s）", d)
			}
			if hits.Load() == 0 || e.masterHits() != 2 {
				t.Fatalf("邻居 %d 次、主控 %d 次", hits.Load(), e.masterHits())
			}
			for _, h := range e.hashes() {
				if !store.Has(h) {
					t.Fatalf("缺块 %s", h[:12])
				}
			}
			filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
				if err == nil && strings.HasPrefix(fi.Name(), ".tmp-") {
					t.Errorf("残留临时文件 %s（%d 字节）", p, fi.Size())
				}
				return nil
			})
		})
	}
}

// 邻居在 peers 列表里，但已经下线（连接被拒）：很快换下一个来源。
func TestFetchNeighborOffline(t *testing.T) {
	e := newFetchEnv(t, 3)
	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close()
	e.fc.peers = e.sources(url, "")
	start := time.Now()
	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("连接被拒应该马上换来源，用了 %v", d)
	}
	if e.masterHits() != 3 || e.assembled != 1 {
		t.Fatalf("主控 %d 次、拼装 %d 次", e.masterHits(), e.assembled)
	}
}

// artifact 和预热共用一部分块，同时拉：都成功，块不重不漏。
func TestFetchArtifactAndPreloadShareChunks(t *testing.T) {
	e := newFetchEnv(t, 6)
	m2 := proto.Manifest{ID: "m2", ChunkSize: e.m.ChunkSize, Files: []proto.ManifestFile{{Path: "models/m2.gguf"}}}
	m2.Files[0].Chunks = append(m2.Files[0].Chunks, e.hashes()[3:]...)
	for i := 0; i < 3; i++ {
		b := []byte(strings.Repeat(fmt.Sprintf("m2-%d;", i), 1000))
		e.data[hashOf(b)] = b
		m2.Files[0].Chunks = append(m2.Files[0].Chunks, hashOf(b))
	}
	e.fc.mu.Lock()
	e.fc.manifests["m2"] = m2
	e.fc.mu.Unlock()
	nb, _ := neighbor(t, func(w http.ResponseWriter, h string) { w.Write(e.data[h]) })
	e.fc.peers = func(int) proto.Peers {
		p := proto.Peers{Sources: map[string][]string{}}
		for h := range e.data {
			p.Sources[h] = []string{nb.URL, ""}
		}
		return p
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, pre := range []bool{false, true} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = e.a.fetchAs(context.Background(), []string{"m1", "m2"}[i], pre)
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatal(errs)
	}
	if len(e.store.List()) != 9 || e.assembled != 1 {
		t.Fatalf("存了 %d 块（应 9）、拼装 %d 次（只拼 artifact）", len(e.store.List()), e.assembled)
	}
	adds := e.haveAdds()
	for h := range e.data {
		if !slices.Contains(adds, h) {
			t.Fatalf("块 %s 没报 have", h[:12])
		}
	}
}

// 拉取途中取消：fetch 马上退出，不留 goroutine。
func TestFetchCancelNoGoroutineLeak(t *testing.T) {
	e := newFetchEnv(t, 4)
	hit := make(chan struct{}, 16)
	nb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.Write([]byte("半截"))
		w.(http.Flusher).Flush()
		hit <- struct{}{}
		<-r.Context().Done() // 对方断了才走
	}))
	defer nb.Close()
	e.fc.peers = e.sources(nb.URL)
	base := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- e.a.fetch(ctx, "m1") }()
	<-hit
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消后没退出")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		e.a.p2pClient.CloseIdleConnections()
		e.a.client.CloseIdleConnections()
		n := runtime.NumGoroutine()
		if n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("取消后 goroutine %d 个，开始前 %d 个\n%s", n, base, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBlacklistConcurrent(t *testing.T) {
	b := &blacklist{fails: map[string]int{}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); b.record("a", fmt.Errorf("x")) }()
		go func() { defer wg.Done(); b.blocked("a"); b.record("b", fmt.Errorf("x")) }()
	}
	wg.Wait()
	if b.fails["a"] != 50 || b.fails["b"] != 50 || !b.blocked("a") {
		t.Fatalf("计数不对: %v", b.fails)
	}
	b.record("a", nil)
	if b.blocked("a") || b.fails["a"] != 0 {
		t.Fatal("成功一次应该清零")
	}
}

// 疑点 2：本地有一块坏了（大小不变，内容不对）。Has 说有，所以不会去取；
// 拼装发现整文件不对。要在这次拉取里把坏块删掉、经 have.del 报给主控、重新取、拼成。
func TestFetchHealsCorruptLocalChunk(t *testing.T) {
	src, master := t.TempDir(), t.TempDir()
	whole := bytes.Repeat([]byte("0123456789abcdef"), 256) // 4 KiB，切成 4 块
	os.MkdirAll(filepath.Join(src, "models"), 0o755)
	os.WriteFile(filepath.Join(src, "models", "m1.gguf"), whole, 0o644)
	m, err := chunk.Build("m1", src, []string{"models/m1.gguf"}, 1024, master)
	if err != nil {
		t.Fatal(err)
	}
	e := newFetchEnv(t, 0)
	e.m = m
	e.fc.manifests["m1"] = m
	for i, h := range m.Files[0].Chunks {
		e.fc.chunks[h] = whole[i*1024 : (i+1)*1024]
	}
	// 本地缓存：块都在，第 2 块坏了
	local := t.TempDir()
	bad := m.Files[0].Chunks[1]
	for i, h := range m.Files[0].Chunks {
		b := append([]byte(nil), whole[i*1024:(i+1)*1024]...)
		if h == bad {
			b[7] ^= 0x55
		}
		os.MkdirAll(filepath.Join(local, h[:2]), 0o755)
		os.WriteFile(filepath.Join(local, h[:2], h), b, 0o644)
	}
	store, err := chunk.NewStore(local, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	e.a.cfg.ArtifactRoot = root
	e.a.Chunks = store
	e.a.Ready = chunk.Ready
	e.a.Assemble = func(m proto.Manifest, root string) error { return chunk.Assemble(m, store, root) }

	if err := e.a.fetch(context.Background(), "m1"); err != nil {
		t.Fatalf("坏块应该在这次拉取里自愈: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "models", "m1.gguf")); !bytes.Equal(got, whole) || !chunk.Ready(m, root) {
		t.Fatal("没拼成")
	}
	if e.masterHits() != 1 {
		t.Fatalf("只该重取坏的那一块，取了 %d 次", e.masterHits())
	}
	if !slices.Contains(e.haveDels(), bad) {
		t.Fatalf("坏块要经 have.del 报给主控（别再把它排给邻居）: %v", e.haveDels())
	}
}

func TestCapReaderBoundary(t *testing.T) {
	body := strings.Repeat("x", 100)
	for _, c := range []struct {
		limit int64
		ok    bool
	}{{99, false}, {100, true}, {101, true}, {0, false}} {
		n, err := io.Copy(io.Discard, &capReader{r: strings.NewReader(body), left: c.limit})
		if (err == nil) != c.ok || (c.ok && n != 100) {
			t.Errorf("limit=%d: n=%d err=%v", c.limit, n, err)
		}
		if !c.ok && !errors.Is(err, errTooLong) {
			t.Errorf("limit=%d: 应报 errTooLong: %v", c.limit, err)
		}
	}
	if n, err := io.Copy(io.Discard, &capReader{r: strings.NewReader(""), left: 0}); n != 0 || err != nil {
		t.Errorf("空块 limit=0: n=%d err=%v", n, err)
	}
}
