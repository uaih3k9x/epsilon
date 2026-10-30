package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"epsilon/proto"
)

// closedURL 是一个刚关掉的本机端口：连过去就是拒绝连接。
func closedURL(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := "http://" + ln.Addr().String()
	ln.Close()
	return u
}

func TestIsNetErr(t *testing.T) {
	refused := func() error {
		_, err := (&http.Client{Timeout: 2 * time.Second}).Get(closedURL(t))
		return err
	}()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	_, timeout := (&http.Client{Timeout: 50 * time.Millisecond}).Get(slow.URL)
	_, scheme := http.Get("nope://pc-01/")

	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"拒绝连接":     {refused, true},
		"超时":       {timeout, true},
		"DNS 失败":   {&url.Error{Op: "Post", URL: "http://pc-01.invalid", Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "pc-01.invalid", IsNotFound: true}}}, true},
		"DNS 裸错":   {&net.DNSError{Err: "no such host", Name: "pc-01.invalid"}, true},
		"上下文超时":    {&url.Error{Op: "Post", URL: "http://10.0.0.1", Err: context.DeadlineExceeded}, true},
		"连上就断":     {&url.Error{Op: "Post", URL: "http://10.0.0.1", Err: io.EOF}, true},
		"nil":      {nil, false},
		"HTTP 500": {fmt.Errorf("/v1/heartbeat: HTTP 500"), false},
		"409":      {errUnknownNode, false},
		"不支持的协议":   {scheme, false},
		"回包解析不了":   {fmt.Errorf("/v1/heartbeat: 回包解析: %v", io.EOF), false},
		"别的错":      {errors.New("x"), false},
	} {
		if c.err == nil && name != "nil" {
			t.Fatalf("%s: 没拿到错误", name)
		}
		if got := isNetErr(c.err); got != c.want {
			t.Errorf("%s: isNetErr(%v) = %v", name, c.err, got)
		}
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func refusedErr() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
}

func status(r *http.Request, code int) (*http.Response, error) {
	return &http.Response{StatusCode: code, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
}

// offlineAgent 起一个 Agent：主控地址 ctl，rt 不为 nil 时换掉传输层；返回 OnOnline 调用次数。
func offlineAgent(t *testing.T, ctl string, rt http.RoundTripper, after time.Duration) func() int {
	a := NewAgent(Config{Node: "pc-01", Controller: ctl}, &fakeSys{idle: 9999}, "test")
	if rt != nil {
		a.client = &http.Client{Transport: rt, Timeout: time.Second}
	}
	var n atomic.Int32
	a.OnOnline = func() { n.Add(1) }
	a.offlineAfter, a.beatEvery = after, 30*time.Millisecond
	stop := make(chan struct{})
	go a.Run(stop, 10*time.Millisecond)
	t.Cleanup(func() { close(stop); a.sup.Stop() })
	return func() int { return int(n.Load()) }
}

// 主控根本不存在：持续 offlineAfter 都是网络错误，按离线确认，只一次。
func TestOfflineConfirmWhenControllerUnreachable(t *testing.T) {
	calls := offlineAgent(t, closedURL(t), nil, 200*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	if calls() != 0 {
		t.Fatal("还没到时间就确认了")
	}
	waitFor(t, "离线确认", func() bool { return calls() == 1 })
	time.Sleep(200 * time.Millisecond)
	if calls() != 1 {
		t.Fatalf("OnOnline 调了 %d 次", calls())
	}
}

// 主控一直回 500：主控明确说不行，不确认。
func TestNoOfflineConfirmOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "坏了", http.StatusInternalServerError)
	}))
	defer srv.Close()
	calls := offlineAgent(t, srv.URL, nil, 100*time.Millisecond)
	time.Sleep(500 * time.Millisecond)
	if calls() != 0 {
		t.Fatalf("回 500 也确认了 %d 次", calls())
	}
}

// 先网络错误、后来主控回 401：这次启动不再走离线确认。
func TestNoOfflineConfirmAfterHTTPError(t *testing.T) {
	start := time.Now()
	calls := offlineAgent(t, "http://10.0.0.1:8090", rtFunc(func(r *http.Request) (*http.Response, error) {
		if time.Since(start) < 100*time.Millisecond {
			return nil, refusedErr()
		}
		return status(r, http.StatusUnauthorized)
	}), 300*time.Millisecond)
	time.Sleep(700 * time.Millisecond)
	if calls() != 0 {
		t.Fatalf("回过 401 还确认了 %d 次", calls())
	}
}

// 网络错误一阵后心跳成功：心跳成功时确认，只调一次（不管离线确认是否已经先到）。
func TestOfflineThenHeartbeatConfirmsOnce(t *testing.T) {
	for name, after := range map[string]time.Duration{"心跳先到": time.Hour, "离线先到": 100 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			fc := &fakeController{desired: proto.DesiredState{HeartbeatSeconds: 1}}
			srv := httptest.NewServer(fc.handler())
			defer srv.Close()
			start := time.Now()
			calls := offlineAgent(t, srv.URL, rtFunc(func(r *http.Request) (*http.Response, error) {
				if time.Since(start) < 300*time.Millisecond {
					return nil, refusedErr()
				}
				return http.DefaultTransport.RoundTrip(r)
			}), after)
			waitFor(t, "心跳成功", func() bool { fc.mu.Lock(); defer fc.mu.Unlock(); return len(fc.beats) >= 3 })
			if calls() != 1 {
				t.Fatalf("OnOnline 调了 %d 次", calls())
			}
		})
	}
}

// 409 照旧重新登记，既不算失败也不算网络错误：夹着 409 的网络故障照样离线确认。
func TestOfflineConfirmIgnores409(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	calls := offlineAgent(t, "http://10.0.0.1:8090", rtFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/v1/heartbeat" {
			return status(r, http.StatusConflict)
		}
		return nil, refusedErr()
	}), 200*time.Millisecond)
	waitFor(t, "离线确认", func() bool { return calls() == 1 })
	mu.Lock()
	defer mu.Unlock()
	if seen["/v1/heartbeat"] == 0 || seen["/v1/register"] < 2 {
		t.Fatalf("请求 %v", seen)
	}
}
