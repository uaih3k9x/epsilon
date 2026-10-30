package controller

// 远程排障：最近事件、按需拉日志（设计书探针能力 16"日志回传"）。坏了不用跑到学生机跟前看。

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"epsilon/proto"
)

const keepEvents = 50 // 每台留最近多少条

type eventRec struct {
	seq    int64     // 到达顺序；同一时刻的事件也分得出先后
	Time   time.Time `json:"time"`
	Node   string    `json:"node"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

type logsRec struct {
	proto.Logs
	Time time.Time `json:"time"`
}

func (c *Controller) event(w http.ResponseWriter, r *http.Request) {
	var ev proto.Event
	json.NewDecoder(r.Body).Decode(&ev)
	log.Printf("事件 %s %s %s", ev.Node, ev.Kind, ev.Detail)
	c.mu.Lock()
	c.evSeq++
	evs := append(c.events[ev.Node], eventRec{c.evSeq, c.now(), ev.Node, ev.Kind, ev.Detail})
	if len(evs) > keepEvents {
		evs = evs[len(evs)-keepEvents:]
	}
	c.events[ev.Node] = evs
	c.mu.Unlock()
	w.Write([]byte("{}"))
}

// listEvents: GET /v1/events?node=&kind=&limit=（默认 100），新的在前。
func (c *Controller) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	node, kind := q.Get("node"), q.Get("kind")
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = 100
	}
	out := []eventRec{}
	c.mu.Lock()
	for name, evs := range c.events {
		if node != "" && name != node {
			continue
		}
		for _, e := range evs {
			if kind == "" || e.Kind == kind {
				out = append(out, e)
			}
		}
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].seq > out[j].seq })
	if len(out) > limit {
		out = out[:limit]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// requestLogs: POST /v1/nodes/{node}/logs，下次心跳让它把日志末尾传上来。
func (c *Controller) requestLogs(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	n, ok := c.nodes[r.PathValue("node")]
	var id int64
	if ok {
		id = c.now().UnixNano()
		n.logReq = id
	}
	c.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	json.NewEncoder(w).Encode(map[string]int64{"request": id})
}

// uploadLogs: POST /v1/logs，探针传上来的日志。
func (c *Controller) uploadLogs(w http.ResponseWriter, r *http.Request) {
	var l proto.Logs
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		http.Error(w, "bad logs", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	n, ok := c.nodes[l.Node]
	if ok {
		n.logs = &logsRec{Logs: l, Time: c.now()}
		if n.logReq == l.Request {
			n.logReq = 0
		}
	}
	c.mu.Unlock()
	if !ok {
		http.Error(w, "unknown node", http.StatusConflict)
		return
	}
	w.Write([]byte("{}"))
}

// nodeLogs: GET /v1/nodes/{node}/logs，最近一次传上来的。
func (c *Controller) nodeLogs(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	var l *logsRec
	if n, ok := c.nodes[r.PathValue("node")]; ok {
		l = n.logs
	}
	c.mu.Unlock()
	if l == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(l)
}
