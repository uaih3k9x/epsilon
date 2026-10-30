package controller

import (
	"encoding/json"
	"fmt"
	"testing"

	"epsilon/proto"
)

type evOut struct {
	Node, Kind, Detail string
}

func (r *p2pRig) events(query string) (int, []evOut) {
	r.t.Helper()
	w := r.do("GET", "/v1/events"+query, "10.0.0.250", "key", nil)
	var out []evOut
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			r.t.Fatalf("events json: %v %s", err, w.Body)
		}
	}
	return w.Code, out
}

func TestEventsKeptPerNodeNewestFirst(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"key"}})
	for i := 0; i < 60; i++ {
		r.do("POST", "/v1/events", "10.0.0.1", "tok", proto.Event{Node: "pc-01", Kind: "crash", Detail: fmt.Sprint(i)})
	}
	r.do("POST", "/v1/events", "10.0.0.2", "tok", proto.Event{Node: "pc-02", Kind: "yield", Detail: "user_active"})

	if code, _ := r.events("?node=pc-01"); code != 200 {
		t.Fatalf("events: %d", code)
	}
	_, evs := r.events("?node=pc-01")
	if len(evs) != 50 || evs[0].Detail != "59" || evs[49].Detail != "10" {
		t.Fatalf("每台留最近 50 条、新的在前: %d 条, 首 %+v", len(evs), evs[0])
	}
	if _, evs := r.events("?kind=yield"); len(evs) != 1 || evs[0].Node != "pc-02" {
		t.Fatalf("按类型过滤: %+v", evs)
	}
	if _, evs := r.events("?limit=3"); len(evs) != 3 {
		t.Fatalf("limit: %d", len(evs))
	}
	if w := r.do("GET", "/v1/events", "10.0.0.250", "tok", nil); w.Code != 401 {
		t.Fatalf("查事件要 api key，探针 token 不行: %d", w.Code)
	}
}

func TestLogRequestRoundTrip(t *testing.T) {
	r := newP2PRig(t, Config{APIKeys: []string{"key"}})
	if w := r.do("POST", "/v1/nodes/pc-01/logs", "10.0.0.250", "key", nil); w.Code != 404 {
		t.Fatalf("没登记的节点要日志应 404: %d", w.Code)
	}
	r.join("pc-01", "10.0.0.1", 47100)
	beat := func() proto.DesiredState {
		w := r.do("POST", "/v1/heartbeat", "10.0.0.1", "tok", proto.Heartbeat{Node: "pc-01"})
		var d proto.DesiredState
		json.Unmarshal(w.Body.Bytes(), &d)
		return d
	}
	if d := beat(); d.LogRequest != 0 {
		t.Fatalf("没人要日志时不该带 log_request: %d", d.LogRequest)
	}
	if w := r.do("GET", "/v1/nodes/pc-01/logs", "10.0.0.250", "key", nil); w.Code != 404 {
		t.Fatalf("还没传过日志应 404: %d", w.Code)
	}
	w := r.do("POST", "/v1/nodes/pc-01/logs", "10.0.0.250", "key", nil)
	var req struct{ Request int64 }
	json.Unmarshal(w.Body.Bytes(), &req)
	if w.Code != 200 || req.Request == 0 {
		t.Fatalf("要日志: %d %s", w.Code, w.Body)
	}
	if d := beat(); d.LogRequest != req.Request {
		t.Fatalf("心跳要带上 log_request=%d，得到 %d", req.Request, d.LogRequest)
	}
	up := proto.Logs{Node: "pc-01", Request: req.Request, Files: map[string]string{"probe.log": "hello", "q4b.log": "CUDA error"}}
	if w := r.do("POST", "/v1/logs", "10.0.0.1", "tok", up); w.Code != 200 {
		t.Fatalf("传日志: %d", w.Code)
	}
	if d := beat(); d.LogRequest != 0 {
		t.Fatalf("传上来以后不再要: %d", d.LogRequest)
	}
	w = r.do("GET", "/v1/nodes/pc-01/logs", "10.0.0.250", "key", nil)
	var got proto.Logs
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || got.Files["q4b.log"] != "CUDA error" || got.Request != req.Request {
		t.Fatalf("取日志: %d %+v", w.Code, got)
	}
	if w := r.do("POST", "/v1/logs", "10.0.0.9", "tok", proto.Logs{Node: "pc-09"}); w.Code != 409 {
		t.Fatalf("没登记的节点传日志应 409: %d", w.Code)
	}
	if w := r.do("GET", "/v1/nodes/pc-01/logs", "10.0.0.250", "tok", nil); w.Code != 401 {
		t.Fatalf("看日志要 api key: %d", w.Code)
	}
}
