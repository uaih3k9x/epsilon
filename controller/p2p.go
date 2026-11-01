package controller

// 第 2 阶段：教室内 P2P 分块分发的主控一侧，契约见 docs/p2p.md。

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"

	"epsilon/proto"
)

var chunkHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// manifestName 比 bootName 多一个 @：环境层的清单 ID 是 名字@版本（docs/jobs.md）。
var manifestName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

// readManifest 读 <chunks_dir>/<id>.json；id 不合法或是预热规则文件当不存在。
func (c *Controller) readManifest(id string) ([]byte, error) {
	if !manifestName.MatchString(id) || id+".json" == preloadFile {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(c.cfg.ChunksDir, id+".json"))
}

func (c *Controller) manifest(w http.ResponseWriter, r *http.Request) {
	b, err := c.readManifest(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (c *Controller) chunk(w http.ResponseWriter, r *http.Request) {
	h := r.PathValue("hash")
	if !chunkHash.MatchString(h) {
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(c.cfg.ChunksDir, h[:2], h)
	if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, p)
}

func (c *Controller) have(w http.ResponseWriter, r *http.Request) {
	var hv proto.Have
	if err := json.NewDecoder(r.Body).Decode(&hv); err != nil {
		http.Error(w, "bad have", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	n, ok := c.nodes[hv.Node]
	if ok {
		for _, h := range hv.Add {
			if chunkHash.MatchString(h) {
				n.chunks[h] = true
			}
		}
		for _, h := range hv.Del {
			delete(n.chunks, h)
		}
	}
	c.mu.Unlock()
	if !ok {
		http.Error(w, "unknown node", http.StatusConflict)
		return
	}
	w.Write([]byte("{}"))
}

// online: 心跳没过期。调用方持锁。
func (c *Controller) online(n *node, now time.Time) bool {
	return now.Sub(n.seen) < time.Duration(c.cfg.StaleSeconds)*time.Second
}

// mayUseMaster: 请求者是本教室种子，或者本教室没有在线种子（不在拓扑里也算）。
// 候选 = 期望状态 Artifacts 或 Preload 含该 manifest 的节点。
// 种子只从开了分块服务的节点里选：老版本探针照发心跳但不拉块，选它当种子全教室就干等。调用方持锁。
func (c *Controller) mayUseMaster(manifest, req string, now time.Time) bool {
	room := c.cfg.Topology[req].Room
	if room == "" {
		return true
	}
	var cands []string
	for name, n := range c.nodes {
		if c.cfg.Topology[name].Room == room && n.reg.P2PPort > 0 && c.online(n, now) && wants(c.desiredFor(name), manifest) {
			cands = append(cands, name)
		}
	}
	sort.Strings(cands)
	if len(cands) > c.cfg.SeedsPerRoom {
		cands = cands[:c.cfg.SeedsPerRoom]
	}
	return len(cands) == 0 || slices.Contains(cands, req)
}

// peers 给每个块排来源：同交换机 > 同教室 > 其他（层内随机）> 主控（只给种子）。
func (c *Controller) peers(w http.ResponseWriter, r *http.Request) {
	id, req := r.URL.Query().Get("manifest"), r.URL.Query().Get("node")
	b, err := c.readManifest(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var m proto.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		http.Error(w, "清单格式不对", http.StatusInternalServerError)
		return
	}

	c.mu.Lock()
	if _, ok := c.nodes[req]; !ok {
		c.mu.Unlock()
		http.Error(w, "unknown node", http.StatusConflict)
		return
	}
	now := c.now()
	me := c.cfg.Topology[req]
	type src struct {
		addr   string
		tier   int
		chunks map[string]bool
	}
	var srcs []src
	for name, n := range c.nodes {
		if name == req || n.reg.P2PPort <= 0 || !c.online(n, now) {
			continue
		}
		p, tier := c.cfg.Topology[name], 2
		if me.Switch != "" && p.Switch == me.Switch {
			tier = 0
		} else if me.Room != "" && p.Room == me.Room {
			tier = 1
		}
		srcs = append(srcs, src{fmt.Sprintf("http://%s:%d", n.addr, n.reg.P2PPort), tier, n.chunks})
	}
	master := c.mayUseMaster(id, req, now)
	out := proto.Peers{Sources: map[string][]string{}}
	for _, f := range m.Files {
		for _, h := range f.Chunks {
			if _, done := out.Sources[h]; done {
				continue
			}
			var tiers [3][]string
			for _, s := range srcs {
				if s.chunks[h] {
					tiers[s.tier] = append(tiers[s.tier], s.addr)
				}
			}
			list := []string{}
			for _, t := range tiers {
				rand.Shuffle(len(t), func(i, j int) { t[i], t[j] = t[j], t[i] })
				list = append(list, t...)
			}
			if master {
				list = append(list, "")
			}
			if len(list) == 0 {
				out.RetryAfterSeconds = 3
			}
			out.Sources[h] = list
		}
	}
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// wants: 期望状态要用或要预热这个 manifest。
func wants(d proto.DesiredState, manifest string) bool {
	return slices.Contains(d.Artifacts, manifest) || slices.Contains(d.Preload, manifest)
}
