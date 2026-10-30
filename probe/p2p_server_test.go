package probe

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock 让限速器"睡觉"只是把假时钟往前拨，并记下一共睡了多久。
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	slept time.Duration
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > 0 {
		c.t = c.t.Add(d)
		c.slept += d
	}
}
func (c *fakeClock) total() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.slept }

func testLimiter() (*limiter, *fakeClock) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	l := newLimiter()
	l.now, l.sleep = c.now, c.sleep
	return l, c
}

func TestLimiterPacesUploadAndFollowsRateChanges(t *testing.T) {
	l, c := testLimiter()
	w := &limitedWriter{w: io.Discard, l: l}

	if _, err := w.Write(make([]byte, 10<<20)); err != nil || c.total() != 0 {
		t.Fatalf("0 = 不限，不该睡: %v %v", err, c.total())
	}

	l.setMbps(1) // 125000 字节/秒
	w.Write(make([]byte, 250000))
	if got := c.total(); got < 1700*time.Millisecond || got > 2*time.Second {
		t.Fatalf("1 Mbps 发 250000 字节应约 2 秒，睡了 %v", got)
	}

	l.setMbps(8) // 运行中改限速：1 MB/s
	before := c.total()
	w.Write(make([]byte, 1000000))
	if got := c.total() - before; got < 800*time.Millisecond || got > 1100*time.Millisecond {
		t.Fatalf("8 Mbps 发 1 MB 应约 1 秒，睡了 %v", got)
	}

	l.setMbps(0)
	before = c.total()
	w.Write(make([]byte, 1<<20))
	if c.total() != before {
		t.Fatal("改回 0 之后不该再限")
	}
}

func TestChunkServer(t *testing.T) {
	data := bytes.Repeat([]byte("epsilon"), 40000) // 280000 字节
	h := hashOf(data)
	l, clk := testLimiter()
	srv := httptest.NewServer((&chunkServer{store: newMemStore(data), token: "tok", up: l}).handler())
	defer srv.Close()

	get := func(path, auth string) (int, []byte) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b
	}

	if code, _ := get("/v1/chunks/"+h, ""); code != http.StatusUnauthorized {
		t.Errorf("没带 token: %d", code)
	}
	if code, _ := get("/v1/chunks/"+h, "Bearer nope"); code != http.StatusUnauthorized {
		t.Errorf("token 不对: %d", code)
	}
	for _, bad := range []string{strings.ToUpper(h), h[:63], h + "0", "zz" + h[2:]} {
		if code, _ := get("/v1/chunks/"+bad, "Bearer tok"); code != http.StatusNotFound {
			t.Errorf("不合法的 hash %q: %d", bad, code)
		}
	}
	if code, _ := get("/v1/chunks/"+hashOf([]byte("没有的块")), "Bearer tok"); code != http.StatusNotFound {
		t.Errorf("没有的块: %d", code)
	}
	if code, _ := get("/v1/chunks/"+h, "Bearer tok"); code != http.StatusOK {
		t.Fatalf("有的块: %d", code)
	}
	if clk.total() != 0 {
		t.Fatal("没限速时不该睡")
	}

	l.setMbps(1)
	code, body := get("/v1/chunks/"+h, "Bearer tok")
	if code != http.StatusOK || !bytes.Equal(body, data) {
		t.Fatalf("内容不对: %d %d 字节", code, len(body))
	}
	if got := clk.total(); got < 2*time.Second || got > 2300*time.Millisecond {
		t.Fatalf("1 Mbps 发 280000 字节应约 2.2 秒，睡了 %v", got)
	}
}
