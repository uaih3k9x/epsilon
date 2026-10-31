package controller

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"epsilon/proto"
)

// 页面本身不带任何秘密，谁都能打开；数据接口照样要 key。
func TestUIPageIsPublicButDataNeedsKey(t *testing.T) {
	_, srv := newTestController(t)
	r, err := http.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("/ui/: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if r.Header.Get("Cache-Control") != "no-cache" { // 换了主控，浏览器不能还拿旧页面
		t.Fatalf("Cache-Control = %q", r.Header.Get("Cache-Control"))
	}
	if !strings.Contains(string(b), "<title>Epsilon") {
		t.Fatal("页面不对")
	}
	for _, ext := range []string{"https://", "http://"} { // 机房没外网，页面不能引外部资源
		if strings.Contains(string(b), "src=\""+ext) || strings.Contains(string(b), "href=\""+ext) {
			t.Fatalf("页面引了外部资源 %s", ext)
		}
	}
	r, _ = http.Get(srv.URL + "/v1/nodes")
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("/v1/nodes 没 key 应该 401，得到 %d", r.StatusCode)
	}
	// 根路径跳到页面，方便直接敲 IP:8090
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ = c.Get(srv.URL + "/")
	r.Body.Close()
	if r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/ui/" {
		t.Fatalf("/: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	r, _ = c.Get(srv.URL + "/nope")
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatalf("/nope 应该 404，得到 %d", r.StatusCode)
	}
}

// 页面按教室分组要用到位置。
func TestNodesListCarriesPlace(t *testing.T) {
	c, srv := newTestController(t)
	c.cfg.Topology = map[string]Place{"pc-01": {Room: "R1", Switch: "R1U12"}}
	beat(t, srv, "pc-01", 0)
	beat(t, srv, "pc-02", 0)
	req, _ := http.NewRequest("GET", srv.URL+"/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer sk-1")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	s := string(b)
	if !strings.Contains(s, `"node":"pc-01"`) || !strings.Contains(s, `"room":"R1","switch":"R1U12"`) {
		t.Fatalf("pc-01 没带位置: %s", s)
	}
	if strings.Count(s, `"room"`) != 1 {
		t.Fatalf("不在拓扑里的不该有 room: %s", s)
	}
}

// 页面按 Content-Type 决定要不要解析 JSON。
func TestRequestLogsAnswersJSON(t *testing.T) {
	_, srv := newTestController(t)
	beat(t, srv, "pc-01", 0)
	r := post(t, srv.URL+"/v1/nodes/pc-01/logs", "sk-1", nil)
	r.Body.Close()
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
}

// 心跳里的磁盘信息原样出现在节点列表里，网页靠它显示"D 盘剩余"。
func TestNodesListCarriesDisk(t *testing.T) {
	_, srv := newTestController(t)
	post(t, srv.URL+"/v1/register", "tok", proto.Register{Node: "pc-01"}).Body.Close()
	post(t, srv.URL+"/v1/heartbeat", "tok", proto.Heartbeat{Node: "pc-01",
		Disk: &proto.Disk{TotalMB: 476000, FreeMB: 12000, UsageMB: map[string]int64{"models": 2600}, Complete: true}}).Body.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer sk-1")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), `"disk":{"total_mb":476000,"free_mb":12000,"usage_mb":{"models":2600},"complete":true}`) {
		t.Fatalf("没带磁盘: %s", b)
	}
}
