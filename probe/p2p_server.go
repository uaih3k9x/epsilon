package probe

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ChunkStore 是本地块缓存（chunk.Store 满足它）。块 ID = 内容的 sha256（小写十六进制）。
type ChunkStore interface {
	Has(h string) bool
	Open(h string) (io.ReadSeekCloser, int64, error)
	Put(h string, r io.Reader) error // 边收边算 sha256，不符就不存、返回错误
	List() []string
	Evict(keep map[string]bool) []string // 超配额按最近使用淘汰，不动 keep 里的；返回删掉的
}

// validHash: 64 位小写十六进制。块 ID 会拼进文件路径，别的一律不认。
func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// chunkServer 给邻居提供 GET /v1/chunks/{hash}。
type chunkServer struct {
	store ChunkStore
	token string
	up    *limiter
}

func (s *chunkServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/chunks/{hash}", s.serve)
	return mux
}

func (s *chunkServer) serve(w http.ResponseWriter, r *http.Request) {
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	h := r.PathValue("hash")
	if !validHash(h) || !s.store.Has(h) {
		http.NotFound(w, r)
		return
	}
	f, size, err := s.store.Open(h)
	if err != nil { // Has 之后刚被淘汰
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(size))
	io.Copy(&limitedWriter{w: w, l: s.up}, f) // 对方断了就算了，它会换来源
}

// serveP2P 在 ln 上开分块服务，登记时报这个端口。要在 Run 之前调。
func (a *Agent) serveP2P(ln net.Listener) {
	a.p2pSrv = &http.Server{Handler: (&chunkServer{store: a.Chunks, token: a.cfg.Token, up: a.upload}).handler(),
		ReadHeaderTimeout: 10 * time.Second}
	a.p2pPort = ln.Addr().(*net.TCPAddr).Port
	go a.p2pSrv.Serve(ln)
}

// ListenP2P 按 p2p_port 开分块服务；端口为 0 就不开。要先设好 Chunks，并在 Run 之前调。
func (a *Agent) ListenP2P() error {
	if a.cfg.P2PPort == 0 {
		return nil
	}
	if a.Chunks == nil {
		return fmt.Errorf("没有块缓存，不开分块服务")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", a.cfg.P2PPort))
	if err != nil {
		return err
	}
	a.serveP2P(ln)
	return nil
}

// limiter 是全机共享的上传限速（几个邻居同时来拿也一共只给这么多），速率可以随时改。
// 按"下一块最早什么时候能发"排队：每发 n 字节把这个时刻往后推 n/速率。
type limiter struct {
	mu    sync.Mutex
	bps   int64 // 字节/秒；0 = 不限
	next  time.Time
	now   func() time.Time
	sleep func(time.Duration)
}

func newLimiter() *limiter { return &limiter{now: time.Now, sleep: time.Sleep} }

func (l *limiter) setMbps(mbps int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if bps := int64(mbps) * 1000000 / 8; bps != l.bps {
		l.bps, l.next = bps, time.Time{} // 按旧速率排的队作废，免得调快了还要等
	}
}

func (l *limiter) wait(n int) {
	l.mu.Lock()
	if l.bps <= 0 {
		l.mu.Unlock()
		return
	}
	now := l.now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(time.Duration(int64(n) * int64(time.Second) / l.bps))
	l.mu.Unlock()
	l.sleep(at.Sub(now))
}

// limitedWriter 把大块写切成 32 KiB 一段再排队：改了限速很快生效，每次也不会睡太久。
type limitedWriter struct {
	w io.Writer
	l *limiter
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	done := 0
	for len(p) > 0 {
		n := min(len(p), 32<<10)
		lw.l.wait(n)
		m, err := lw.w.Write(p[:n])
		done += m
		if err != nil {
			return done, err
		}
		p = p[n:]
	}
	return done, nil
}
