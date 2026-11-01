package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"epsilon/proto"
)

var (
	h1 = strings.Repeat("a1", 32)
	h2 = strings.Repeat("b2", 32)
	h3 = strings.Repeat("c3", 32)
)

// p2pRig 直接调 Handler（不走网络），这样每个请求能指定来源 IP，时钟也能安全地拨。
type p2pRig struct {
	t   *testing.T
	c   *Controller
	h   http.Handler
	now time.Time
	dir string
}

func newP2PRig(t *testing.T, cfg Config) *p2pRig {
	dir := t.TempDir()
	m := proto.Manifest{ID: "m1", ChunkSize: 4, Files: []proto.ManifestFile{
		{Path: "a.gguf", Size: 8, Chunks: []string{h1, h2}},
		{Path: "b.gguf", Size: 4, Chunks: []string{h3}},
	}}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, "m1.json"), b, 0o644)
	os.MkdirAll(filepath.Join(dir, h1[:2]), 0o755)
	os.WriteFile(filepath.Join(dir, h1[:2], h1), []byte("blk1"), 0o644)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("secret"), 0o644)
	os.WriteFile(filepath.Join(dir, "py311-torch2.5-cu124@1.json"), []byte("layer"), 0o644)

	cfg.ProbeToken, cfg.ChunksDir, cfg.StaleSeconds = "tok", dir, 30
	if cfg.Default.Artifacts == nil {
		cfg.Default.Artifacts = []string{"m1"}
	}
	r := &p2pRig{t: t, c: New(cfg), now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), dir: dir}
	r.c.now = func() time.Time { return r.now }
	r.h = r.c.Handler()
	return r
}

func (r *p2pRig) do(method, path, ip, auth string, body any) *httptest.ResponseRecorder {
	r.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = ip + ":50000"
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

// join 登记一台节点；ip 用 10.0.0.x。
func (r *p2pRig) join(name, ip string, port int, chunks ...string) {
	r.t.Helper()
	if w := r.do("POST", "/v1/register", ip, "tok", proto.Register{Node: name, P2PPort: port, Chunks: chunks}); w.Code != 200 {
		r.t.Fatalf("register %s: %d", name, w.Code)
	}
}

func (r *p2pRig) peers(manifest, node string) (int, proto.Peers) {
	r.t.Helper()
	w := r.do("GET", "/v1/peers?manifest="+manifest+"&node="+node, "10.0.0.250", "tok", nil)
	var p proto.Peers
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			r.t.Fatalf("peers json: %v %s", err, w.Body)
		}
	}
	return w.Code, p
}

func TestManifestAndChunkPaths(t *testing.T) {
	r := newP2PRig(t, Config{})
	raw, _ := os.ReadFile(filepath.Join(r.dir, "m1.json"))
	cases := []struct {
		path, auth string
		code       int
		body       string
	}{
		{"/v1/manifests/m1", "tok", 200, string(raw)},
		{"/v1/manifests/m1", "wrong", 401, ""},
		{"/v1/manifests/nope", "tok", 404, ""},
		{"/v1/manifests/..%2fsecret.txt", "tok", 404, ""},
		{"/v1/manifests/.hidden", "tok", 404, ""},
		{"/v1/manifests/py311-torch2.5-cu124@1", "tok", 200, "layer"}, // 环境层: 名字@版本
		{"/v1/manifests/@1", "tok", 404, ""},
		{"/v1/manifests/..%2f@1", "tok", 404, ""},
		{"/v1/chunks/" + h1, "tok", 200, "blk1"},
		{"/v1/chunks/" + h1, "", 401, ""},
		{"/v1/chunks/" + strings.ToUpper(h1), "tok", 404, ""},
		{"/v1/chunks/" + h1[:63], "tok", 404, ""},
		{"/v1/chunks/" + h2, "tok", 404, ""}, // 合法但没有
		{"/v1/chunks/..%2fsecret.txt", "tok", 404, ""},
		{"/v1/chunks/" + h1[:62] + "%2f", "tok", 404, ""},
	}
	for _, tc := range cases {
		w := r.do("GET", tc.path, "10.0.0.1", tc.auth, nil)
		if w.Code != tc.code || tc.code == 200 && w.Body.String() != tc.body {
			t.Errorf("%s: %d %q", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestP2PDisabledWithoutChunksDir(t *testing.T) {
	c := New(Config{ProbeToken: "tok"})
	for _, p := range []string{"/v1/manifests/m1", "/v1/chunks/" + h1, "/v1/peers?manifest=m1&node=pc-01"} {
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, req)
		if w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}

func chunkCounts(t *testing.T, r *p2pRig) map[string]int {
	t.Helper()
	w := r.do("GET", "/v1/nodes", "10.0.0.250", "", nil)
	var rows []struct {
		Node   string `json:"node"`
		Chunks int    `json:"chunks"`
	}
	json.Unmarshal(w.Body.Bytes(), &rows)
	out := map[string]int{}
	for _, row := range rows {
		out[row.Node] = row.Chunks
	}
	return out
}

// neighbors 数来源里的邻居（不算主控 ""）。
func neighbors(srcs []string) int {
	k := 0
	for _, s := range srcs {
		if s != "" {
			k++
		}
	}
	return k
}

func TestHaveAndRegisterResetChunks(t *testing.T) {
	r := newP2PRig(t, Config{})
	if w := r.do("POST", "/v1/have", "10.0.0.1", "tok", proto.Have{Node: "pc-01", Add: []string{h1}}); w.Code != 409 {
		t.Fatalf("未登记应 409，得到 %d", w.Code)
	}
	if w := r.do("POST", "/v1/have", "10.0.0.1", "wrong", proto.Have{Node: "pc-01"}); w.Code != 401 {
		t.Fatalf("token: %d", w.Code)
	}
	r.join("pc-01", "10.0.0.1", 47100, h1)
	if w := r.do("POST", "/v1/have", "10.0.0.1", "tok", proto.Have{Node: "pc-01", Add: []string{h2, h3}, Del: []string{h1}}); w.Code != 200 {
		t.Fatalf("have: %d", w.Code)
	}
	if n := chunkCounts(t, r)["pc-01"]; n != 2 {
		t.Fatalf("have 后块数 %d", n)
	}
	r.join("pc-02", "10.0.0.2", 47100)
	if _, p := r.peers("m1", "pc-02"); neighbors(p.Sources[h1]) != 0 || neighbors(p.Sources[h2]) != 1 {
		t.Fatalf("del 没生效: %q", p.Sources)
	}
	r.join("pc-01", "10.0.0.1", 47100, h1) // 重新登记：块表以登记为准
	if n := chunkCounts(t, r)["pc-01"]; n != 1 {
		t.Fatalf("重新登记后块数 %d", n)
	}
	if _, p := r.peers("m1", "pc-02"); neighbors(p.Sources[h1]) != 1 || neighbors(p.Sources[h2]) != 0 {
		t.Fatalf("登记没重置块表: %q", p.Sources)
	}
}

func TestPeersTiersAndFilters(t *testing.T) {
	topo := map[string]Place{
		"pc-01": {Room: "R1", Switch: "R1U12"},
		"pc-02": {Room: "R1", Switch: "R1U12"},
		"pc-03": {Room: "R1", Switch: "R1U13"},
		"pc-04": {Room: "R2", Switch: "R2U01"},
		"pc-06": {Room: "R1", Switch: "R1U12"},
		"pc-07": {Room: "R1", Switch: "R1U12"},
	}
	// 只有 pc-01 要 m1：它是 R1 唯一的种子
	r := newP2PRig(t, Config{Topology: topo, Default: proto.DesiredState{Artifacts: []string{}},
		Nodes: map[string]proto.DesiredState{"pc-01": {Artifacts: []string{"m1"}}}})
	r.join("pc-06", "10.0.0.6", 47106, h1) // 稍后过期
	r.now = r.now.Add(25 * time.Second)
	r.join("pc-01", "10.0.0.1", 47101, h1) // 请求者自己有也不算
	r.join("pc-02", "10.0.0.2", 47102, h1)
	r.join("pc-03", "10.0.0.3", 47103, h1, h2)
	r.join("pc-04", "10.0.0.4", 47104, h1)
	r.join("pc-05", "10.0.0.5", 47105, h1) // 不在拓扑里
	r.join("pc-07", "10.0.0.7", 0, h1)     // 不开分块服务
	r.now = r.now.Add(10 * time.Second)

	want := []string{"http://10.0.0.2:47102", "http://10.0.0.3:47103"}
	other := map[string]bool{"http://10.0.0.4:47104": true, "http://10.0.0.5:47105": true}
	for i := 0; i < 20; i++ {
		code, p := r.peers("m1", "pc-01")
		if code != 200 {
			t.Fatalf("peers: %d", code)
		}
		got := p.Sources[h1]
		if len(got) != 5 || got[0] != want[0] || got[1] != want[1] || !other[got[2]] || !other[got[3]] || got[2] == got[3] || got[4] != "" {
			t.Fatalf("层次不对: %v", got)
		}
		if g := p.Sources[h2]; len(g) != 2 || g[0] != "http://10.0.0.3:47103" || g[1] != "" {
			t.Fatalf("h2: %v", g)
		}
		if g := p.Sources[h3]; len(g) != 1 || g[0] != "" {
			t.Fatalf("h3 只有主控: %v", g)
		}
		if p.RetryAfterSeconds != 0 {
			t.Fatalf("种子不该等: %d", p.RetryAfterSeconds)
		}
	}
	// 同交换机层内随机：pc-02 与 pc-06（重新心跳）轮流排第一
	r.join("pc-06", "10.0.0.6", 47106, h1)
	first := map[string]bool{}
	for i := 0; i < 50; i++ {
		_, p := r.peers("m1", "pc-01")
		first[p.Sources[h1][0]] = true
		if s := p.Sources[h1][2]; s != "http://10.0.0.3:47103" {
			t.Fatalf("第三个应是同教室: %v", p.Sources[h1])
		}
	}
	if len(first) != 2 {
		t.Fatalf("同层应随机: %v", first)
	}
}

func TestPeersSeeds(t *testing.T) {
	topo := map[string]Place{
		"pc-01": {Room: "R1", Switch: "R1U12"},
		"pc-02": {Room: "R1", Switch: "R1U12"},
		"pc-03": {Room: "R1", Switch: "R1U12"},
		"pc-04": {Room: "R1", Switch: "R1U12"},
		"pc-11": {Room: "R2", Switch: "R2U01"},
		"pc-12": {Room: "R2", Switch: "R2U01"},
	}
	// pc-03 不要 m1，不算种子；R1 种子 = pc-01、pc-02
	r := newP2PRig(t, Config{Topology: topo, Nodes: map[string]proto.DesiredState{"pc-03": {}}})
	r.join("pc-11", "10.0.0.11", 47100) // R2 的种子候选，稍后过期
	r.now = r.now.Add(25 * time.Second)
	for i, n := range []string{"pc-04", "pc-03", "pc-02", "pc-01"} {
		r.join(n, fmt.Sprintf("10.0.0.%d", i+1), 47100)
	}
	r.join("pc-09", "10.0.0.9", 47100) // 不在拓扑里
	r.now = r.now.Add(10 * time.Second)
	// R2 只剩 pc-12 不在线（没登记）、pc-11 过期 → 没有在线种子

	hasMaster := func(node string) bool {
		code, p := r.peers("m1", node)
		if code != 200 {
			t.Fatalf("%s: %d", node, code)
		}
		return len(p.Sources[h1]) == 1 && p.Sources[h1][0] == ""
	}
	for _, n := range []string{"pc-01", "pc-02"} {
		if !hasMaster(n) {
			t.Errorf("%s 是种子，应拿到主控", n)
		}
	}
	for _, n := range []string{"pc-03", "pc-04"} {
		if hasMaster(n) {
			t.Errorf("%s 不是种子，不该拿到主控", n)
		}
		if _, p := r.peers("m1", n); p.RetryAfterSeconds != 3 || p.Sources[h1] == nil || len(p.Sources[h1]) != 0 {
			t.Errorf("%s 没来源时应空列表+重试 3 秒: %+v", n, p)
		}
	}
	if !hasMaster("pc-09") {
		t.Error("不在拓扑里的节点应拿到主控")
	}
	r.join("pc-12", "10.0.0.12", 47100) // R2：pc-11 过期，pc-12 自己就是在线种子
	if !hasMaster("pc-12") {
		t.Error("pc-12 是 R2 唯一在线种子")
	}

	// 种子数可调
	r.c.cfg.SeedsPerRoom = 3
	if !hasMaster("pc-04") {
		t.Error("seeds_per_room=3 时 pc-04 是种子")
	}
}

func TestPeersRoomWithoutSeeds(t *testing.T) {
	topo := map[string]Place{"pc-01": {Room: "R1", Switch: "R1U12"}, "pc-02": {Room: "R1", Switch: "R1U12"}}
	// R1 没人要 m1（期望状态里没有）→ 没种子 → 谁来问都给主控
	r := newP2PRig(t, Config{Topology: topo, Default: proto.DesiredState{Artifacts: []string{}}})
	r.join("pc-01", "10.0.0.1", 47100)
	r.join("pc-02", "10.0.0.2", 47100, h1)
	_, p := r.peers("m1", "pc-01")
	if g := p.Sources[h1]; len(g) != 2 || g[0] != "http://10.0.0.2:47100" || g[1] != "" {
		t.Fatalf("h1: %v", g)
	}
	if p.RetryAfterSeconds != 0 {
		t.Fatalf("retry: %d", p.RetryAfterSeconds)
	}
}

func TestPeersErrors(t *testing.T) {
	r := newP2PRig(t, Config{})
	r.join("pc-01", "10.0.0.1", 47100)
	if code, _ := r.peers("nope", "pc-01"); code != 404 {
		t.Errorf("清单不存在: %d", code)
	}
	if code, _ := r.peers("..%2fsecret", "pc-01"); code != 404 {
		t.Errorf("坏 id: %d", code)
	}
	if code, _ := r.peers("m1", "pc-99"); code != 409 {
		t.Errorf("未登记: %d", code)
	}
	if w := r.do("GET", "/v1/peers?manifest=m1&node=pc-01", "10.0.0.1", "wrong", nil); w.Code != 401 {
		t.Errorf("token: %d", w.Code)
	}
}

// 老版本探针（没开分块服务）照样发心跳，但不会去拉块；选它当种子，整间教室就干等。
func TestSeedsSkipNodesWithoutP2P(t *testing.T) {
	topo := map[string]Place{"pc-01": {Room: "R1", Switch: "R1U12"}, "pc-02": {Room: "R1", Switch: "R1U12"}}
	r := newP2PRig(t, Config{Topology: topo, SeedsPerRoom: 1})
	r.join("pc-01", "10.0.0.1", 0)
	r.join("pc-02", "10.0.0.2", 47100)
	if _, p := r.peers("m1", "pc-02"); len(p.Sources[h1]) != 1 || p.Sources[h1][0] != "" {
		t.Fatalf("pc-01 没开分块服务，种子应是 pc-02: %v", p.Sources[h1])
	}
}

func TestHaveIgnoresBadHashes(t *testing.T) {
	r := newP2PRig(t, Config{})
	r.join("pc-01", "10.0.0.1", 47100)
	r.do("POST", "/v1/have", "10.0.0.1", "tok", proto.Have{Node: "pc-01", Add: []string{h1, "../x", strings.ToUpper(h2)}})
	if n := chunkCounts(t, r)["pc-01"]; n != 1 {
		t.Fatalf("只该记下合法块，得到 %d", n)
	}
}
