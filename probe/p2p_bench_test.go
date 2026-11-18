package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// BenchmarkPullRound: 一个快邻居给 32 块（每块 256 KiB），4 个并发 worker；/v1/have 人为放慢，
// 量"报 have 持锁做 HTTP"会不会把并发取块拖成串行（疑点 5）。
func BenchmarkPullRound(b *testing.B) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	data := map[string][]byte{}
	var miss []string
	for i := 0; i < 32; i++ {
		blk := bytes.Repeat([]byte(fmt.Sprintf("%04d", i)), 64<<10)
		h := hashOf(blk)
		data[h] = blk
		miss = append(miss, h)
	}
	nb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data[strings.TrimPrefix(r.URL.Path, "/v1/chunks/")])
	}))
	defer nb.Close()
	sources := map[string][]string{}
	for _, h := range miss {
		sources[h] = []string{nb.URL}
	}
	for _, delay := range []time.Duration{0, 2 * time.Millisecond, 20 * time.Millisecond} {
		b.Run(fmt.Sprintf("have=%v", delay), func(b *testing.B) {
			fc := &fakeController{}
			inner := fc.handler()
			ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/have" {
					time.Sleep(delay)
				}
				inner.ServeHTTP(w, r)
			}))
			defer ctl.Close()
			a := NewAgent(Config{Node: "pc-01", Controller: ctl.URL, Token: "tok"}, &fakeSys{idle: 9999}, "test")
			// 默认每个主机只留 2 条空闲连接，4 个 worker 的小块反复建连，跑 -count=10 会把本机临时端口用光；
			// 生产里块是 64 MiB，建连开销可以忽略，这里只为基准稳定
			a.p2pClient = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 8}}
			b.SetBytes(int64(len(miss) * (256 << 10)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.Chunks = newMemStore()
				got, _ := a.pullRound(context.Background(), miss, sources, &blacklist{fails: map[string]int{}}, 1<<20)
				if got != len(miss) {
					b.Fatalf("取到 %d 块", got)
				}
			}
			b.StopTimer()
			fc.mu.Lock()
			var n int
			for _, h := range fc.haves {
				n += len(h.Add)
			}
			posts := len(fc.haves)
			fc.mu.Unlock()
			if n < len(miss)*b.N {
				b.Fatalf("have 只报了 %d 块，应该 %d", n, len(miss)*b.N)
			}
			b.ReportMetric(float64(posts)/float64(b.N), "have-posts/op")
		})
	}
}
