package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"epsilon/proto"
)

// fakeLlama 冒充一台学生机上的 llama-server，回答里带上自己的名字。
func fakeLlama(t *testing.T, name string) (*httptest.Server, int) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"served_by":%q,"path":%q,"echo":%s}`, name, r.URL.Path, body)
	}))
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return srv, p
}

func newTestController(t *testing.T) (*Controller, *httptest.Server) {
	c := New(Config{ProbeToken: "tok", APIKeys: []string{"sk-1"}, StaleSeconds: 30,
		Default: proto.DesiredState{Workload: "qwen3.5-4b", YieldOnInput: true},
		Nodes:   map[string]proto.DesiredState{"pc-28": {}}})
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	return c, srv
}

func post(t *testing.T, url, auth string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func beat(t *testing.T, srv *httptest.Server, node string, port int) proto.DesiredState {
	t.Helper()
	post(t, srv.URL+"/v1/register", "tok", proto.Register{Node: node}).Body.Close()
	hb := proto.Heartbeat{Node: node}
	if port > 0 {
		hb.Running, hb.Serving = "qwen3.5-4b", &proto.Serving{Model: "qwen3.5-4b", Port: port}
	}
	r := post(t, srv.URL+"/v1/heartbeat", "tok", hb)
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("heartbeat %s: %d", node, r.StatusCode)
	}
	var d proto.DesiredState
	json.NewDecoder(r.Body).Decode(&d)
	return d
}

func TestProbeEndpointsNeedToken(t *testing.T) {
	_, srv := newTestController(t)
	if r := post(t, srv.URL+"/v1/register", "", proto.Register{Node: "x"}); r.StatusCode != 401 {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	if r := post(t, srv.URL+"/v1/heartbeat", "tok", proto.Heartbeat{Node: "never-registered"}); r.StatusCode != 409 {
		t.Fatalf("unknown node should get 409, got %d", r.StatusCode)
	}
}

func TestDesiredStatePerNode(t *testing.T) {
	_, srv := newTestController(t)
	if d := beat(t, srv, "pc-01", 0); d.Workload != "qwen3.5-4b" || !d.YieldOnInput || d.HeartbeatSeconds != 10 {
		t.Fatalf("default desired: %+v", d)
	}
	if d := beat(t, srv, "pc-28", 0); d.Workload != "" {
		t.Fatalf("override should disable: %+v", d)
	}
}

func chat(t *testing.T, srv *httptest.Server, key, model string) (int, map[string]any) {
	r := post(t, srv.URL+"/v1/chat/completions", key, map[string]any{"model": model, "messages": []any{}})
	defer r.Body.Close()
	var out map[string]any
	json.NewDecoder(r.Body).Decode(&out)
	return r.StatusCode, out
}

func TestRouterSpreadsAndSkipsDeadNodes(t *testing.T) {
	_, srv := newTestController(t)
	a, pa := fakeLlama(t, "A")
	defer a.Close()
	b, pb := fakeLlama(t, "B")
	beat(t, srv, "A", pa)
	beat(t, srv, "B", pb)

	if code, _ := chat(t, srv, "", "qwen3.5-4b"); code != 401 {
		t.Fatalf("api key required, got %d", code)
	}
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		code, out := chat(t, srv, "sk-1", "qwen3.5-4b")
		if code != 200 || out["path"] != "/v1/chat/completions" {
			t.Fatalf("code %d out %v", code, out)
		}
		seen[out["served_by"].(string)] = true
	}
	if !seen["A"] || !seen["B"] {
		t.Fatalf("both nodes should get traffic: %v", seen)
	}

	b.Close() // 关掉一台：请求自动转走
	for i := 0; i < 5; i++ {
		code, out := chat(t, srv, "sk-1", "qwen3.5-4b")
		if code != 200 || out["served_by"] != "A" {
			t.Fatalf("after B died: %d %v", code, out)
		}
	}
	if code, _ := chat(t, srv, "sk-1", "no-such-model"); code != 404 {
		t.Fatalf("unknown model: %d", code)
	}
}

func TestStaleNodesAreSkippedAndModelsListed(t *testing.T) {
	c, srv := newTestController(t)
	a, pa := fakeLlama(t, "A")
	defer a.Close()
	beat(t, srv, "A", pa)

	req, _ := http.NewRequest("GET", srv.URL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-1")
	r, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(body), `"qwen3.5-4b"`) {
		t.Fatalf("models: %s", body)
	}

	c.now = func() time.Time { return time.Now().Add(time.Minute) } // 一分钟没心跳
	if code, _ := chat(t, srv, "sk-1", "qwen3.5-4b"); code != 404 {
		t.Fatalf("stale node should not serve, got %d", code)
	}
}

func TestFileDownload(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/vc_redist.x64.exe", []byte("MZ-fake"), 0o644)
	c := New(Config{APIKeys: []string{"sk-1"}, FilesDir: dir})
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	get := func(key, path string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, body := get("sk-1", "/dl/vc_redist.x64.exe"); code != 200 || body != "MZ-fake" {
		t.Fatalf("download: %d %q", code, body)
	}
	if code, _ := get("", "/dl/vc_redist.x64.exe"); code != 401 {
		t.Fatalf("no key: %d", code)
	}
	if code, _ := get("sk-1", "/dl/../controller.go"); code == 200 {
		t.Fatal("path traversal")
	}
}

func TestBootRelease(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(dir+"/release", 0o755)
	os.MkdirAll(dir+"/release-canary", 0o755)
	os.WriteFile(dir+"/release/release.json", []byte(`{"manifest":"stable"}`), 0o644)
	os.WriteFile(dir+"/release/epsilon-probe.exe", []byte("v2"), 0o644)
	os.WriteFile(dir+"/release-canary/release.json", []byte(`{"manifest":"canary"}`), 0o644)
	os.WriteFile(dir+"/release-canary/epsilon-probe.exe", []byte("v3"), 0o644)
	c := New(Config{ProbeToken: "tok", FilesDir: dir, CanaryNodes: []string{"pc-01"}})
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	get := func(path, auth string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+auth)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	cases := []struct {
		path, auth, want string
		code             int
	}{
		{"/v1/boot/release?node=pc-02", "tok", `{"manifest":"stable"}`, 200},
		{"/v1/boot/release?node=pc-01", "tok", `{"manifest":"canary"}`, 200},
		{"/v1/boot/files/epsilon-probe.exe?node=pc-02", "tok", "v2", 200},
		{"/v1/boot/files/epsilon-probe.exe?node=pc-01", "tok", "v3", 200},
		{"/v1/boot/release?node=pc-02", "wrong", "", 401},
		{"/v1/boot/files/..%2fsecret?node=pc-02", "tok", "", 404},
	}
	for _, tc := range cases {
		code, body := get(tc.path, tc.auth)
		if code != tc.code || tc.code == 200 && body != tc.want {
			t.Errorf("%s: %d %q", tc.path, code, body)
		}
	}
}
