package controller

// 缓存管理：看哪台缓存了什么、管预热规则。契约见 docs/p2p.md 最后一节。

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"epsilon/proto"
)

// preloadFile 存在 chunks_dir 里，和清单同目录；readManifest 不把它当清单。
const preloadFile = "preload.json"

// preloadRule 是一条预热规则：nodes / room / all 三选一。
type preloadRule struct {
	Manifest string   `json:"manifest"`
	Nodes    []string `json:"nodes,omitempty"`
	Room     string   `json:"room,omitempty"`
	All      bool     `json:"all,omitempty"`
}

// matches 判断规则是否覆盖这台节点。
func (p preloadRule) matches(name, room string) bool {
	return p.All || (p.Room != "" && p.Room == room) || slices.Contains(p.Nodes, name)
}

// loadPreload 读 preload.json；没有就空，读坏了打日志也当空。
func (c *Controller) loadPreload() {
	c.preload = map[string]preloadRule{}
	b, err := os.ReadFile(filepath.Join(c.cfg.ChunksDir, preloadFile))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var rules []preloadRule
	if err == nil {
		err = json.Unmarshal(b, &rules)
	}
	if err != nil {
		log.Printf("预热规则 %s 读不了，当空: %v", preloadFile, err)
		return
	}
	for _, p := range rules {
		c.preload[p.Manifest] = p
	}
}

// preloadRules 按 manifest 排序返回规则副本。调用方持 pmu。
func (c *Controller) preloadRules() []preloadRule {
	out := make([]preloadRule, 0, len(c.preload))
	for _, p := range c.preload {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest < out[j].Manifest })
	return out
}

// savePreload 原子写 preload.json：同目录临时文件再改名。调用方持 pmu。
func (c *Controller) savePreload() error {
	b, err := json.MarshalIndent(c.preloadRules(), "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.cfg.ChunksDir, ".preload-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // 改名成功后这里删不到东西
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(c.cfg.ChunksDir, preloadFile))
}

// preloadFor 返回匹配这台节点的预热 manifest。
func (c *Controller) preloadFor(name string) []string {
	room := c.cfg.Topology[name].Room
	c.pmu.RLock()
	defer c.pmu.RUnlock()
	var out []string
	for id, p := range c.preload {
		if p.matches(name, room) {
			out = append(out, id)
		}
	}
	return out
}

// mergePreload 把配置里的和规则给的合起来：去重、排序、去掉已在 Artifacts 里的。
func mergePreload(d proto.DesiredState, extra []string) []string {
	var out []string
	for _, id := range append(slices.Clone(d.Preload), extra...) {
		if !slices.Contains(d.Artifacts, id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (c *Controller) setPreload(w http.ResponseWriter, r *http.Request) {
	var p preloadRule
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	targets := 0
	for _, given := range []bool{len(p.Nodes) > 0, p.Room != "", p.All} {
		if given {
			targets++
		}
	}
	if p.Manifest == "" || targets != 1 || slices.Contains(p.Nodes, "") {
		writeErr(w, http.StatusBadRequest, "要给 manifest，nodes / room / all 三选一")
		return
	}
	if _, err := c.readManifest(p.Manifest); err != nil {
		writeErr(w, http.StatusNotFound, "没有这个 manifest: "+p.Manifest)
		return
	}
	if p.Nodes != nil {
		p.Nodes = slices.Compact(slices.Sorted(slices.Values(p.Nodes)))
	}
	c.pmu.Lock()
	old, had := c.preload[p.Manifest]
	c.preload[p.Manifest] = p
	err := c.savePreload()
	if err != nil { // 没存上就别生效，免得重启后规则凭空消失
		if had {
			c.preload[p.Manifest] = old
		} else {
			delete(c.preload, p.Manifest)
		}
	}
	c.pmu.Unlock()
	if err != nil {
		log.Printf("保存预热规则失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "保存预热规则失败")
		return
	}
	log.Printf("预热规则 %+v", p)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func (c *Controller) delPreload(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("manifest")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "要给 manifest 参数")
		return
	}
	c.pmu.Lock()
	old, had := c.preload[id]
	var err error
	if had {
		delete(c.preload, id)
		if err = c.savePreload(); err != nil {
			c.preload[id] = old
		}
	}
	c.pmu.Unlock()
	switch {
	case !had:
		writeErr(w, http.StatusNotFound, "没有这个 manifest 的预热规则: "+id)
	case err != nil:
		log.Printf("保存预热规则失败: %v", err)
		writeErr(w, http.StatusInternalServerError, "保存预热规则失败")
	default:
		log.Printf("撤掉预热规则 %s", id)
		w.Write([]byte("{}"))
	}
}

// ---- GET /v1/cache ----

type cacheView struct {
	Manifests    []manifestStat `json:"manifests"`
	Nodes        []nodeCache    `json:"nodes"`         // 只列在线节点
	OfflineNodes int            `json:"offline_nodes"` // 登记过但心跳过期的
	Preload      []preloadRule  `json:"preload"`
}

type manifestStat struct {
	ID       string     `json:"id"`
	Chunks   int        `json:"chunks"` // 不重复的块数
	Bytes    int64      `json:"bytes"`  // 这些块的总字节数
	Complete int        `json:"complete_nodes"`
	Partial  int        `json:"partial_nodes"`
	Rooms    []roomStat `json:"rooms"` // 只列有人持有的教室；不在拓扑里的节点归 ""
}

type roomStat struct {
	Room     string `json:"room"`
	Complete int    `json:"complete_nodes"`
	Partial  int    `json:"partial_nodes"`
}

type nodeCache struct {
	Node      string          `json:"node"`
	Room      string          `json:"room"`
	Chunks    int             `json:"chunks"` // 持有的全部块
	Bytes     int64           `json:"bytes"`  // 只算能在某个清单里查到大小的块
	Manifests []nodeManifests `json:"manifests"`
}

type nodeManifests struct {
	ID      string `json:"id"`
	Chunks  int    `json:"chunks"`  // 持有这个清单的块数
	Percent int    `json:"percent"` // 向下取整，100 = 齐了
}

// scanManifests 扫 <chunks_dir>/*.json；读不了或格式不对的跳过并打日志。
func (c *Controller) scanManifests() []proto.Manifest {
	paths, _ := filepath.Glob(filepath.Join(c.cfg.ChunksDir, "*.json"))
	var out []proto.Manifest
	for _, p := range paths {
		id := strings.TrimSuffix(filepath.Base(p), ".json")
		b, err := c.readManifest(id)
		if errors.Is(err, os.ErrNotExist) {
			continue // 名字不合法或 preload.json
		}
		var m proto.Manifest
		if err == nil {
			err = json.Unmarshal(b, &m)
		}
		if err != nil {
			log.Printf("清单 %s 读不了，跳过: %v", filepath.Base(p), err)
			continue
		}
		m.ID = id // 以文件名为准
		out = append(out, m)
	}
	return out // Glob 已按名字排好
}

// chunkSizes 算清单里每块的大小：第 i 块 = min(ChunkSize, 文件大小 − i×ChunkSize)。
func chunkSizes(m proto.Manifest) map[string]int64 {
	out := map[string]int64{}
	for _, f := range m.Files {
		for i, h := range f.Chunks {
			n := f.Size - int64(i)*m.ChunkSize
			if m.ChunkSize > 0 {
				n = min(n, m.ChunkSize)
			}
			out[h] = max(n, 0)
		}
	}
	return out
}

func (c *Controller) cacheStats(w http.ResponseWriter, _ *http.Request) {
	ms := c.scanManifests()
	// 块 → 大小、块 → 所在清单下标；按节点持有的块查表，代价 ≈ 全部节点的块数之和
	size := map[string]int64{}
	owners := map[string][]int{}
	view := cacheView{Manifests: make([]manifestStat, len(ms)), Nodes: []nodeCache{}}
	for i, m := range ms {
		sz := chunkSizes(m)
		view.Manifests[i] = manifestStat{ID: m.ID, Chunks: len(sz), Rooms: []roomStat{}}
		for h, n := range sz {
			size[h] = n
			owners[h] = append(owners[h], i)
			view.Manifests[i].Bytes += n
		}
	}
	c.pmu.RLock()
	view.Preload = c.preloadRules()
	c.pmu.RUnlock()

	rooms := make([]map[string]*roomStat, len(ms))
	for i := range rooms {
		rooms[i] = map[string]*roomStat{}
	}
	held := make([]int, len(ms))
	c.mu.Lock()
	now := c.now()
	for name, n := range c.nodes {
		if !c.online(n, now) {
			view.OfflineNodes++
			continue
		}
		room := c.cfg.Topology[name].Room
		nc := nodeCache{Node: name, Room: room, Chunks: len(n.chunks), Manifests: []nodeManifests{}}
		clear(held)
		for h := range n.chunks {
			nc.Bytes += size[h]
			for _, i := range owners[h] {
				held[i]++
			}
		}
		for i, k := range held {
			total := view.Manifests[i].Chunks
			if k == 0 || total == 0 {
				continue
			}
			nc.Manifests = append(nc.Manifests, nodeManifests{ID: ms[i].ID, Chunks: k, Percent: k * 100 / total})
			rs := rooms[i][room]
			if rs == nil {
				rs = &roomStat{Room: room}
				rooms[i][room] = rs
			}
			if k == total {
				view.Manifests[i].Complete++
				rs.Complete++
			} else {
				view.Manifests[i].Partial++
				rs.Partial++
			}
		}
		view.Nodes = append(view.Nodes, nc)
	}
	c.mu.Unlock()

	for i := range view.Manifests {
		for _, rs := range rooms[i] {
			view.Manifests[i].Rooms = append(view.Manifests[i].Rooms, *rs)
		}
		sort.Slice(view.Manifests[i].Rooms, func(a, b int) bool { return view.Manifests[i].Rooms[a].Room < view.Manifests[i].Rooms[b].Room })
	}
	sort.Slice(view.Nodes, func(i, j int) bool { return view.Nodes[i].Node < view.Nodes[j].Node })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}
