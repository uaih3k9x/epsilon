package probe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestCheckHealth(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	port := func(addr string) int { _, p, _ := net.SplitHostPort(addr); n, _ := strconv.Atoi(p); return n }
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	tcpPort := port(ln.Addr().String())

	cases := []struct {
		w    Workload
		want bool
	}{
		{Workload{Port: port(srv.Listener.Addr().String()), Health: "/health"}, true},
		{Workload{Port: port(srv.Listener.Addr().String()), Health: "/nope"}, false},
		{Workload{Port: tcpPort, Health: "tcp"}, true},
		{Workload{Port: 1, Health: "none"}, true}, // 进程活着就算健康：不去碰只服务一个客户端的程序（rpc-server）
	}
	for _, c := range cases {
		if got := checkHealth(client, c.w); got != c.want {
			t.Errorf("%+v: %v", c.w, got)
		}
	}
	ln.Close()
	if checkHealth(client, Workload{Port: tcpPort, Health: "tcp"}) {
		t.Error("closed port reported healthy")
	}
}
