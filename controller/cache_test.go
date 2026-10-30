package controller

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/proto"
)

var (
	h4 = strings.Repeat("d4", 32)
	h9 = strings.Repeat("e9", 32) // 哪个清单里都没有
)

// writeM2 再放一个清单 m2：和 m1 共用 h1、h2，最后一块不满（10 字节 = 4+4+2）。
func writeM2(t *testing.T, dir string) {
	t.Helper()
	m := proto.Manifest{ID: "m2", ChunkSize: 4, Files: []proto.ManifestFile{
		{Path: "c.gguf", Size: 10, Chunks: []string{h1, h2, h4}},
	}}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "m2.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type cacheResp struct {
	Manifests []struct {
		ID       string `json:"id"`
		Chunks   int    `json:"chunks"`
		Bytes    int64  `json:"bytes"`
		Complete int    `json:"complete_nodes"`
		Partial  int    `json:"partial_nodes"`
		Rooms    []struct {
			Room     string `json:"room"`
			Complete int    `json:"complete_nodes"`
			Partial  int    `json:"partial_nodes"`
		} `json:"rooms"`
	} `json:"manifests"`
	Nodes []struct {
		Node      string `json:"node"`
		Room      string `json:"room"`
		Chunks    int    `json:"chunks"`
		Bytes     int64  `json:"bytes"`
		Manifests []struct {
			ID      string `json:"id"`
			Chunks  int    `json:"chunks"`
			Percent int    `json:"percent"`
		} `json:"manifests"`
	} `json:"nodes"`
	OfflineNodes int `json:"offline_nodes"`
	Preload      []struct {
		Manifest string   `json:"manifest"`
		Nodes    []string `json:"nodes"`
		Room     string   `json:"room"`
		All      bool     `json:"all"`
	} `json:"preload"`
}

func (r *p2pRig) cache() (cacheResp, string) {
	r.t.Helper()
	w := r.do("GET", "/v1/cache", "10.0.0.250", "sk-1", nil)
	if w.Code != 200 {
		r.t.Fatalf("cache: %d %s", w.Code, w.Body)
	}
	var out cacheResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		r.t.Fatalf("cache json: %v %s", err, w.Body)
	}
	return out, w.Body.String()
}

// desired 发一次心跳，拿回期望状态。
func (r *p2pRig) desired(name string) proto.DesiredState {
	r.t.Helper()
	w := r.do("POST", "/v1/heartbeat", "10.0.0.250", "tok", proto.Heartbeat{Node: name})
	if w.Code != 200 {
		r.t.Fatalf("heartbeat %s: %d", name, w.Code)
	}
	var d proto.DesiredState
	json.Unmarshal(w.Body.Bytes(), &d)
	return d
}

// doRaw 发原样的 body（测坏 JSON 用）。
func (r *p2pRig) doRaw(method, path, auth, body string) int {
	r.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "10.0.0.250:50000"
	req.Header.Set("Authorization", "Bearer "+auth)
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w.Code
}

func (r *p2pRig) preload(body any) int {
	r.t.Helper()
	return r.do("POST", "/v1/cache/preload", "10.0.0.250", "sk-1", body).Code
}

var cacheTopo = map[string]Place{
	"pc-01": {Room: "R1", Switch: "R1U12"},
	"pc-02": {Room: "R1", Switch: "R1U12"},
	"pc-03": {Room: "R2", Switch: "R2U01"},
	"pc-05": {Room: "R2", Switch: "R2U01"},
}

func TestCacheEmpty(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}})
	_, raw := r.cache()
	for _, s := range []string{`"nodes":[]`, `"preload":[]`, `"offline_nodes":0`} {
		if !strings.Contains(raw, s) {
			t.Errorf("缺 %s: %s", s, raw)
		}
	}
}

func TestCacheStats(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}, Topology: cacheTopo})
	writeM2(t, r.dir)
	os.WriteFile(filepath.Join(r.dir, "broken.json"), []byte("{坏"), 0o644)
	os.WriteFile(filepath.Join(r.dir, "a b.json"), []byte("{}"), 0o644) // 名字不合法

	r.join("pc-05", "10.0.0.5", 47100, h1, h2, h3) // 稍后过期，不算
	r.now = r.now.Add(35 * time.Second)
	r.join("pc-01", "10.0.0.1", 47100, h1, h2, h3)
	r.join("pc-02", "10.0.0.2", 47100, h1)
	r.join("pc-03", "10.0.0.3", 47100, h1, h2, h3, h4)
	r.join("pc-04", "10.0.0.4", 47100, h9) // 不在拓扑里；块查不到大小

	got, raw := r.cache()
	if len(got.Manifests) != 2 || got.Manifests[0].ID != "m1" || got.Manifests[1].ID != "m2" {
		t.Fatalf("清单: %+v", got.Manifests)
	}
	m1, m2 := got.Manifests[0], got.Manifests[1]
	if m1.Chunks != 3 || m1.Bytes != 12 || m1.Complete != 2 || m1.Partial != 1 {
		t.Errorf("m1: %+v", m1)
	}
	if len(m1.Rooms) != 2 || m1.Rooms[0].Room != "R1" || m1.Rooms[0].Complete != 1 || m1.Rooms[0].Partial != 1 ||
		m1.Rooms[1].Room != "R2" || m1.Rooms[1].Complete != 1 || m1.Rooms[1].Partial != 0 {
		t.Errorf("m1 教室: %+v", m1.Rooms)
	}
	if m2.Chunks != 3 || m2.Bytes != 10 || m2.Complete != 1 || m2.Partial != 2 {
		t.Errorf("m2（最后一块 2 字节）: %+v", m2)
	}
	if len(m2.Rooms) != 2 || m2.Rooms[0].Partial != 2 || m2.Rooms[0].Complete != 0 || m2.Rooms[1].Complete != 1 {
		t.Errorf("m2 教室: %+v", m2.Rooms)
	}

	if got.OfflineNodes != 1 || len(got.Nodes) != 4 {
		t.Fatalf("节点: offline=%d %+v", got.OfflineNodes, got.Nodes)
	}
	type pm struct {
		id  string
		pct int
	}
	want := []struct {
		node, room string
		chunks     int
		bytes      int64
		manifests  []pm
	}{
		{"pc-01", "R1", 3, 12, []pm{{"m1", 100}, {"m2", 66}}},
		{"pc-02", "R1", 1, 4, []pm{{"m1", 33}, {"m2", 33}}},
		{"pc-03", "R2", 4, 14, []pm{{"m1", 100}, {"m2", 100}}},
		{"pc-04", "", 1, 0, nil},
	}
	for i, w := range want {
		n := got.Nodes[i]
		if n.Node != w.node || n.Room != w.room || n.Chunks != w.chunks || n.Bytes != w.bytes || len(n.Manifests) != len(w.manifests) {
			t.Errorf("节点 %d: %+v", i, n)
			continue
		}
		for j, m := range w.manifests {
			if n.Manifests[j].ID != m.id || n.Manifests[j].Percent != m.pct {
				t.Errorf("%s 的 %s: %+v", w.node, m.id, n.Manifests[j])
			}
		}
	}
	if !strings.Contains(raw, `"manifests":[]`) {
		t.Errorf("pc-04 的 manifests 应是 []: %s", raw)
	}
}

func TestCacheAuth(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}})
	for _, tc := range []struct{ method, path, auth string }{
		{"GET", "/v1/cache", ""},
		{"GET", "/v1/cache", "tok"}, // probe token 不行
		{"POST", "/v1/cache/preload", "wrong"},
		{"DELETE", "/v1/cache/preload?manifest=m1", ""},
	} {
		if w := r.do(tc.method, tc.path, "10.0.0.1", tc.auth, map[string]any{"manifest": "m1", "all": true}); w.Code != 401 {
			t.Errorf("%s %s %q: %d", tc.method, tc.path, tc.auth, w.Code)
		}
	}
	if w := r.do("DELETE", "/v1/cache/preload?manifest=m1", "10.0.0.1", "sk-1", nil); w.Code != 404 {
		t.Errorf("没规则时删除应 404: %d", w.Code)
	}
}

func TestPreloadTargets(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}, Topology: cacheTopo,
		Nodes: map[string]proto.DesiredState{"pc-09": {Artifacts: []string{}, Preload: []string{"m2"}}}})
	writeM2(t, r.dir)
	for i, n := range []string{"pc-01", "pc-02", "pc-03", "pc-04", "pc-09"} {
		r.join(n, "10.0.0."+string(rune('1'+i)), 47100)
	}
	pre := func(n string) []string { return r.desired(n).Preload }

	if c := r.preload(map[string]any{"manifest": "m2", "nodes": []string{"pc-01"}}); c != 200 {
		t.Fatalf("preload nodes: %d", c)
	}
	if p := pre("pc-01"); !slices.Equal(p, []string{"m2"}) {
		t.Errorf("pc-01: %v", p)
	}
	if p := pre("pc-02"); p != nil {
		t.Errorf("pc-02 不该有: %v", p)
	}

	// 同一 manifest 再发一次就覆盖
	r.preload(map[string]any{"manifest": "m2", "room": "R1"})
	for n, want := range map[string]bool{"pc-01": true, "pc-02": true, "pc-03": false, "pc-04": false} {
		if has := slices.Contains(pre(n), "m2"); has != want {
			t.Errorf("room 规则 %s: %v", n, has)
		}
	}
	r.preload(map[string]any{"manifest": "m2", "all": true})
	for _, n := range []string{"pc-01", "pc-03", "pc-04"} { // pc-04 不在拓扑里也算
		if p := pre(n); !slices.Equal(p, []string{"m2"}) {
			t.Errorf("all 规则 %s: %v", n, p)
		}
	}

	// m1 已在默认 Artifacts 里就不重复放；pc-09 没 Artifacts → 合并、去重、排序
	r.preload(map[string]any{"manifest": "m1", "all": true})
	if p := pre("pc-01"); !slices.Equal(p, []string{"m2"}) {
		t.Errorf("已在 Artifacts 的不该进 Preload: %v", p)
	}
	if p := pre("pc-09"); !slices.Equal(p, []string{"m1", "m2"}) {
		t.Errorf("pc-09: %v", p)
	}
	if p := r.c.cfg.Nodes["pc-09"].Preload; !slices.Equal(p, []string{"m2"}) {
		t.Errorf("配置被改了: %v", p)
	}

	got, _ := r.cache()
	if len(got.Preload) != 2 || got.Preload[0].Manifest != "m1" || !got.Preload[0].All || got.Preload[1].Manifest != "m2" {
		t.Errorf("规则列表: %+v", got.Preload)
	}

	if w := r.do("DELETE", "/v1/cache/preload?manifest=m2", "10.0.0.250", "sk-1", nil); w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	if p := pre("pc-01"); p != nil {
		t.Errorf("删除后 pc-01: %v", p)
	}
	if p := pre("pc-09"); !slices.Equal(p, []string{"m1", "m2"}) { // 配置里的 m2 还在
		t.Errorf("删除后 pc-09: %v", p)
	}
}

func TestPreloadErrors(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}})
	cases := []struct {
		body any
		code int
	}{
		{"{坏", 400},
		{map[string]any{"manifest": "m1"}, 400},
		{map[string]any{"manifest": "m1", "nodes": []string{}}, 400},
		{map[string]any{"manifest": "m1", "nodes": []string{"pc-01"}, "all": true}, 400},
		{map[string]any{"manifest": "m1", "room": "R1", "all": true}, 400},
		{map[string]any{"manifest": "m1", "room": "R1", "nodes": []string{"pc-01"}}, 400},
		{map[string]any{"manifest": "m1", "nodes": []string{""}}, 400},
		{map[string]any{"all": true}, 400},
		{map[string]any{"manifest": "nope", "all": true}, 404},
		{map[string]any{"manifest": "..%2fsecret", "all": true}, 404},
		{map[string]any{"manifest": "preload", "all": true}, 404}, // preload.json 不是清单
		{map[string]any{"manifest": "m1", "all": true}, 200},
	}
	for _, tc := range cases {
		var w int
		if s, ok := tc.body.(string); ok {
			w = r.doRaw("POST", "/v1/cache/preload", "sk-1", s)
		} else {
			w = r.preload(tc.body)
		}
		if w != tc.code {
			t.Errorf("%v: %d，应 %d", tc.body, w, tc.code)
		}
	}
	if w := r.do("DELETE", "/v1/cache/preload", "10.0.0.250", "sk-1", nil); w.Code != 400 {
		t.Errorf("缺 manifest 参数: %d", w.Code)
	}
	if w := r.do("GET", "/v1/manifests/preload", "10.0.0.1", "tok", nil); w.Code != 404 {
		t.Errorf("preload.json 不该当清单发出去: %d", w.Code)
	}
}

func TestPreloadPersist(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}, Default: proto.DesiredState{Artifacts: []string{}}})
	writeM2(t, r.dir)
	r.preload(map[string]any{"manifest": "m1", "nodes": []string{"pc-02", "pc-01", "pc-01"}})
	r.preload(map[string]any{"manifest": "m2", "all": true})
	r.do("DELETE", "/v1/cache/preload?manifest=m2", "10.0.0.250", "sk-1", nil)

	c := New(r.c.cfg)
	if p := c.desiredFor("pc-01").Preload; !slices.Equal(p, []string{"m1"}) {
		t.Errorf("重启后 pc-01: %v", p)
	}
	if p := c.desiredFor("pc-03").Preload; p != nil {
		t.Errorf("重启后 pc-03: %v", p)
	}
	ents, _ := os.ReadDir(r.dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), "tmp") {
			t.Errorf("临时文件没清掉: %s", e.Name())
		}
	}

	os.WriteFile(filepath.Join(r.dir, "preload.json"), []byte("[坏"), 0o644)
	c = New(r.c.cfg) // 读坏了当空
	if p := c.desiredFor("pc-01").Preload; p != nil {
		t.Errorf("坏文件应当空: %v", p)
	}
}

// 预热的节点和要用的节点一样能当种子。
func TestPreloadNodesCanSeed(t *testing.T) {
	topo := map[string]Place{
		"pc-01": {Room: "R1", Switch: "R1U12"},
		"pc-02": {Room: "R1", Switch: "R1U12"},
	}
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}, Topology: topo, SeedsPerRoom: 1,
		Default: proto.DesiredState{Artifacts: []string{}}})
	r.join("pc-01", "10.0.0.1", 47100)
	r.join("pc-02", "10.0.0.2", 47100)
	master := func(n string) bool {
		_, p := r.peers("m1", n)
		return slices.Contains(p.Sources[h1], "")
	}
	if !master("pc-01") || !master("pc-02") {
		t.Fatal("没人要 m1 时没有种子，都给主控")
	}
	r.preload(map[string]any{"manifest": "m1", "nodes": []string{"pc-02"}})
	if !master("pc-02") || master("pc-01") {
		t.Errorf("pc-02 预热 m1，应是唯一种子")
	}
}

// 心跳、peers、改规则并发跑，-race 下不该报。
func TestPreloadConcurrent(t *testing.T) {
	topo := map[string]Place{"pc-01": {Room: "R1"}, "pc-02": {Room: "R1"}}
	r := newP2PRig(t, Config{APIKeys: []string{"sk-1"}, Topology: topo})
	r.join("pc-01", "10.0.0.1", 47100)
	r.join("pc-02", "10.0.0.2", 47100)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r.do("POST", "/v1/cache/preload", "10.0.0.250", "sk-1", map[string]any{"manifest": "m1", "room": "R1"})
				r.do("POST", "/v1/heartbeat", "10.0.0.1", "tok", proto.Heartbeat{Node: "pc-01"})
				r.do("GET", "/v1/peers?manifest=m1&node=pc-02", "10.0.0.2", "tok", nil)
				r.do("GET", "/v1/cache", "10.0.0.250", "sk-1", nil)
				r.do("DELETE", "/v1/cache/preload?manifest=m1", "10.0.0.250", "sk-1", nil)
			}
		}()
	}
	wg.Wait()
}
