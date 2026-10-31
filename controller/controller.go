// Package controller 是主控：管节点、下发期望状态、按模型把 OpenAI 请求路由到学生机。
package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"epsilon/proto"
)

type Config struct {
	Listen       string                        `json:"listen"`
	ProbeToken   string                        `json:"probe_token"`
	APIKeys      []string                      `json:"api_keys"`      // 空 = 路由不验 key
	StaleSeconds int                           `json:"stale_seconds"` // 多久没心跳算掉线
	Default      proto.DesiredState            `json:"default"`
	Nodes        map[string]proto.DesiredState `json:"nodes"`          // 按节点整个覆盖默认值
	FilesDir     string                        `json:"files_dir"`      // 给学生机下载的文件（运行库、新版探针）；空 = 不开
	CanaryNodes  []string                      `json:"canary_nodes"`   // 这些节点的引导器取 release-canary/ 里的本体，其余取 release/
	ChunksDir    string                        `json:"chunks_dir"`     // 制品清单和块（docs/p2p.md）；空 = 不开 P2P 接口
	Topology     map[string]Place              `json:"topology"`       // 节点在哪间教室、哪台交换机，peers 排序用
	SeedsPerRoom int                           `json:"seeds_per_room"` // 每间教室几台种子可以直接从主控拉块（默认 2）
}

// Place 是节点的物理位置；不在 Topology 里的节点两项都是空串。
type Place struct {
	Room   string `json:"room"`
	Switch string `json:"switch"`
}

type node struct {
	reg      proto.Register
	hb       proto.Heartbeat
	addr     string // 心跳来源 IP
	seen     time.Time
	inflight int
	downTill time.Time // 转发失败后暂停派活到这个时间
	chunks   map[string]bool
	logReq   int64    // 要它传日志（DesiredState.LogRequest）；0 = 不要
	logs     *logsRec // 最近一次传上来的日志
}

type Controller struct {
	cfg    Config
	mu     sync.Mutex
	nodes  map[string]*node
	events map[string][]eventRec // 每台最近的事件，新的在后
	evSeq  int64
	now    func() time.Time
	proxy  *http.Client

	// 预热规则单独一把锁：peers 持着 mu 时会经 desiredFor 读规则。加锁顺序只能 mu → pmu。
	pmu     sync.RWMutex
	preload map[string]preloadRule // manifest → 规则
}

func New(cfg Config) *Controller {
	if cfg.StaleSeconds <= 0 {
		cfg.StaleSeconds = 30
	}
	if cfg.SeedsPerRoom <= 0 {
		cfg.SeedsPerRoom = 2
	}
	c := &Controller{cfg: cfg, nodes: map[string]*node{}, events: map[string][]eventRec{}, now: time.Now, preload: map[string]preloadRule{},
		proxy: &http.Client{Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			ResponseHeaderTimeout: 10 * time.Minute, // 长回答首字也可能慢
		}}}
	if cfg.ChunksDir != "" {
		c.loadPreload()
	}
	return c
}

func (c *Controller) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", c.probeAuth(c.register))
	mux.HandleFunc("POST /v1/heartbeat", c.probeAuth(c.heartbeat))
	mux.HandleFunc("POST /v1/events", c.probeAuth(c.event))
	mux.HandleFunc("GET /v1/models", c.apiAuth(c.models))
	mux.HandleFunc("POST /v1/chat/completions", c.apiAuth(c.route))
	mux.HandleFunc("POST /v1/completions", c.apiAuth(c.route))
	mux.HandleFunc("POST /v1/embeddings", c.apiAuth(c.route))
	mux.HandleFunc("GET /v1/nodes", c.apiAuth(c.listNodes))
	mux.HandleFunc("GET /v1/events", c.apiAuth(c.listEvents))
	mux.HandleFunc("POST /v1/nodes/{node}/logs", c.apiAuth(c.requestLogs))
	mux.HandleFunc("GET /v1/nodes/{node}/logs", c.apiAuth(c.nodeLogs))
	mux.HandleFunc("POST /v1/logs", c.probeAuth(c.uploadLogs))
	mux.Handle("GET /ui/", uiHandler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/", http.StatusFound) })
	if c.cfg.FilesDir != "" { // 学生机上不了外网，要什么从主控拉
		mux.Handle("GET /dl/", c.apiAuth(http.StripPrefix("/dl/", http.FileServer(http.Dir(c.cfg.FilesDir))).ServeHTTP))
		mux.HandleFunc("GET /v1/boot/release", c.probeAuth(c.bootFile))
		mux.HandleFunc("GET /v1/boot/files/{name}", c.probeAuth(c.bootFile))
	}
	if c.cfg.ChunksDir != "" {
		mux.HandleFunc("GET /v1/manifests/{id}", c.probeAuth(c.manifest))
		mux.HandleFunc("GET /v1/chunks/{hash}", c.probeAuth(c.chunk))
		mux.HandleFunc("GET /v1/peers", c.probeAuth(c.peers))
		mux.HandleFunc("POST /v1/have", c.probeAuth(c.have))
		mux.HandleFunc("GET /v1/cache", c.apiAuth(c.cacheStats))
		mux.HandleFunc("POST /v1/cache/preload", c.apiAuth(c.setPreload))
		mux.HandleFunc("DELETE /v1/cache/preload", c.apiAuth(c.delPreload))
	}
	return mux
}

var bootName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// bootFile 给引导器发本体：签名清单 release.json 和清单里的文件。灰度节点取 release-canary/。
func (c *Controller) bootFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		name = "release.json"
	}
	if !bootName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	dir := "release"
	for _, n := range c.cfg.CanaryNodes {
		if n == r.URL.Query().Get("node") {
			dir = "release-canary"
		}
	}
	http.ServeFile(w, r, filepath.Join(c.cfg.FilesDir, dir, name))
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (c *Controller) probeAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.cfg.ProbeToken != "" && bearer(r) != c.cfg.ProbeToken {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (c *Controller) apiAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(c.cfg.APIKeys) > 0 {
			k, ok := bearer(r), false
			for _, want := range c.cfg.APIKeys {
				ok = ok || k == want
			}
			if !ok {
				writeErr(w, http.StatusUnauthorized, "invalid api key")
				return
			}
		}
		h(w, r)
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (c *Controller) register(w http.ResponseWriter, r *http.Request) {
	var reg proto.Register
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil || reg.Node == "" {
		http.Error(w, "bad register", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	chunks := make(map[string]bool, len(reg.Chunks))
	for _, h := range reg.Chunks {
		if chunkHash.MatchString(h) {
			chunks[h] = true
		}
	}
	c.nodes[reg.Node] = &node{reg: reg, addr: remoteIP(r), seen: c.now(), chunks: chunks}
	c.mu.Unlock()
	log.Printf("登记 %s (%s) 探针 %s 工作负载 %v", reg.Node, remoteIP(r), reg.Version, reg.Workload)
	w.Write([]byte("{}"))
}

func (c *Controller) heartbeat(w http.ResponseWriter, r *http.Request) {
	var hb proto.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "bad heartbeat", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	n, ok := c.nodes[hb.Node]
	var logReq int64
	if ok {
		n.hb, n.addr, n.seen = hb, remoteIP(r), c.now()
		logReq = n.logReq
	}
	c.mu.Unlock()
	if !ok { // 主控重启过：让探针重新登记
		http.Error(w, "unknown node", http.StatusConflict)
		return
	}
	d := c.desiredFor(hb.Node)
	d.LogRequest = logReq
	json.NewEncoder(w).Encode(d)
}

// desiredFor 是配置里的期望状态，再并上匹配本节点的预热规则。
func (c *Controller) desiredFor(name string) proto.DesiredState {
	d, ok := c.cfg.Nodes[name]
	if !ok {
		d = c.cfg.Default
	}
	d.Preload = mergePreload(d, c.preloadFor(name))
	return d.Defaults()
}

// alive: 心跳没过期、工作负载健康、最近没转发失败。调用方持锁。
func (c *Controller) alive(n *node, now time.Time) bool {
	return n.hb.Serving != nil && now.Sub(n.seen) < time.Duration(c.cfg.StaleSeconds)*time.Second &&
		now.After(n.downTill)
}

func (c *Controller) models(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	set := map[string]bool{}
	now := c.now()
	for _, n := range c.nodes {
		if c.alive(n, now) {
			set[n.hb.Serving.Model] = true
		}
	}
	c.mu.Unlock()
	type m struct {
		ID     string `json:"id"`
		Object string `json:"object"`
	}
	out := struct {
		Object string `json:"object"`
		Data   []m    `json:"data"`
	}{Object: "list", Data: []m{}}
	for id := range set {
		out.Data = append(out.Data, m{ID: id, Object: "model"})
	}
	sort.Slice(out.Data, func(i, j int) bool { return out.Data[i].ID < out.Data[j].ID })
	json.NewEncoder(w).Encode(out)
}

// pick 挑一个在跑这个模型、手上活最少的节点（并列随机），并把它的 inflight +1。
func (c *Controller) pick(model string, exclude map[string]bool) *node {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var best []*node
	for name, n := range c.nodes {
		if exclude[name] || !c.alive(n, now) || (model != "" && n.hb.Serving.Model != model) {
			continue
		}
		if len(best) == 0 || n.inflight < best[0].inflight {
			best = []*node{n}
		} else if n.inflight == best[0].inflight {
			best = append(best, n)
		}
	}
	if len(best) == 0 {
		return nil
	}
	n := best[rand.Intn(len(best))]
	n.inflight++
	return n
}

func (c *Controller) done(n *node, failed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n.inflight--
	if failed {
		n.downTill = c.now().Add(15 * time.Second) // 下一次心跳前先别派
	}
}

// route 把请求原样转给学生机；连不上就换一台再试（最多 3 台），已经开始回数据就不再换。
func (c *Controller) route(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	var head struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &head)

	tried := map[string]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		n := c.pick(head.Model, tried)
		if n == nil {
			break
		}
		tried[n.reg.Node] = true
		url := fmt.Sprintf("http://%s:%d%s", n.addr, n.hb.Serving.Port, r.URL.Path)
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.proxy.Do(req)
		if err != nil {
			if r.Context().Err() != nil { // 客户端自己断开了，不怪节点
				c.done(n, false)
				return
			}
			c.done(n, true)
			log.Printf("转发到 %s 失败: %v", n.reg.Node, err)
			continue
		}
		c.stream(w, resp, n.reg.Node)
		c.done(n, false)
		return
	}
	if len(tried) > 0 {
		writeErr(w, http.StatusBadGateway, "all nodes failed")
		return
	}
	writeErr(w, http.StatusNotFound, fmt.Sprintf("no node is serving model %q", head.Model))
}

func (c *Controller) stream(w http.ResponseWriter, resp *http.Response, node string) {
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Epsilon-Node", node)
	w.WriteHeader(resp.StatusCode)
	f, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		k, err := resp.Body.Read(buf)
		if k > 0 {
			w.Write(buf[:k])
			if f != nil {
				f.Flush() // 流式输出逐块推给客户端
			}
		}
		if err != nil {
			return
		}
	}
}

// listNodes 给人看的节点表。
func (c *Controller) listNodes(w http.ResponseWriter, _ *http.Request) {
	type row struct {
		Node     string      `json:"node"`
		Addr     string      `json:"addr"`
		Version  string      `json:"version"`
		Boot     string      `json:"boot,omitempty"`
		AgoSec   int         `json:"seconds_since_heartbeat"`
		Running  string      `json:"running"`
		Serving  bool        `json:"serving"`
		Reason   string      `json:"reason"`
		Idle     int         `json:"idle_seconds"`
		Foreign  []string    `json:"foreign_gpu"`
		Inflight int         `json:"inflight"`
		GPUs     []proto.GPU `json:"gpus"`
		Chunks   int         `json:"chunks"` // 持有的块数
		MemFree  int         `json:"mem_free_mb,omitempty"`
		Disk     *proto.Disk `json:"disk,omitempty"`
		Room     string      `json:"room,omitempty"`
		Switch   string      `json:"switch,omitempty"`
	}
	c.mu.Lock()
	now := c.now()
	rows := make([]row, 0, len(c.nodes))
	for name, n := range c.nodes {
		v := n.hb.Version
		if v == "" {
			v = n.reg.Version
		}
		rows = append(rows, row{Node: name, Addr: n.addr, Version: v, Boot: n.hb.Boot, AgoSec: int(now.Sub(n.seen).Seconds()),
			Running: n.hb.Running, Serving: c.alive(n, now), Reason: n.hb.Reason, Idle: n.hb.IdleSeconds, Foreign: n.hb.ForeignGPU,
			Inflight: n.inflight, GPUs: n.hb.GPUs, Chunks: len(n.chunks), MemFree: n.hb.MemFreeMB, Disk: n.hb.Disk,
			Room: c.cfg.Topology[name].Room, Switch: c.cfg.Topology[name].Switch})
	}
	c.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Node < rows[j].Node })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": msg}})
}
