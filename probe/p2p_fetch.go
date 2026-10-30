package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"epsilon/proto"
)

// fetch 把一个制品备齐：取清单 → 已经拼好就返回 → 否则问 peers、取缺的块、拼装。
// 在后台 goroutine 里跑；开始、完成各发一个 fetch 事件（已经备齐的不发），失败的由 collectFetches 发。
func (a *Agent) fetch(ctx context.Context, id string) error { return a.fetchAs(ctx, id, false) }

// preloadKey 是预热任务在 jobs / ready 等表里的键，和同名制品的备齐任务分开记。
// manifest ID 里不会有 "/"（主控按 bootName 校验），不会撞。
const preloadKey = "preload/"

// fetchAs: preload 时只把块拉进缓存、不拼文件（预热，docs/p2p.md"缓存管理"）。
func (a *Agent) fetchAs(ctx context.Context, id string, preload bool) error {
	if a.Chunks == nil || a.Ready == nil || a.Assemble == nil {
		return fmt.Errorf("没有接块缓存，备不了 %s", id)
	}
	var m proto.Manifest
	if err := a.get(ctx, "/v1/manifests/"+url.PathEscape(id), &m); err != nil {
		return fmt.Errorf("取清单 %s: %w", id, err)
	}
	if err := checkManifest(m, id); err != nil {
		return err
	}
	keep := a.keepFor(m)
	if a.Ready(m, a.cfg.ArtifactRoot) {
		return nil
	}
	miss := len(a.missing(m))
	if preload && miss == 0 {
		return nil
	}
	what := "开始"
	if preload {
		what = "开始预热"
	}
	a.evict(keep) // 先腾地方
	a.sendEvent(proto.Event{Kind: "fetch", Detail: fmt.Sprintf("%s %s: 缺 %d/%d 块", what, id, miss, len(chunkSet(m)))})
	if err := a.pull(ctx, m); err != nil {
		return err
	}
	a.evict(a.keepFor(m))
	if preload {
		a.sendEvent(proto.Event{Kind: "fetch", Detail: "预热完成 " + id})
		return nil
	}
	if err := a.Assemble(m, a.cfg.ArtifactRoot); err != nil {
		return fmt.Errorf("拼装 %s: %w", id, err)
	}
	a.sendEvent(proto.Event{Kind: "fetch", Detail: "备齐 " + id})
	return nil
}

// checkManifest: 块 ID 会拼进 URL 和文件路径，不合法的整份不认。
func checkManifest(m proto.Manifest, id string) error {
	if m.ID != id {
		return fmt.Errorf("清单 %s 回来的是 %q", id, m.ID)
	}
	for _, f := range m.Files {
		for _, h := range f.Chunks {
			if !validHash(h) {
				return fmt.Errorf("清单 %s 里有不合法的块 %q", id, h)
			}
		}
	}
	return nil
}

// chunkSet: 清单用到的块（去重）。
func chunkSet(m proto.Manifest) map[string]bool {
	set := map[string]bool{}
	for _, f := range m.Files {
		for _, h := range f.Chunks {
			set[h] = true
		}
	}
	return set
}

func (a *Agent) missing(m proto.Manifest) []string {
	var miss []string
	for h := range chunkSet(m) {
		if !a.Chunks.Has(h) {
			miss = append(miss, h)
		}
	}
	return miss
}

// pull 一轮一轮地取缺的块，直到取齐。某块没来源就过 retry_after 再问；
// 连续 3 轮有来源却一块都没取到（来源全坏或全拉黑）就放弃，过一会儿整个重来。
func (a *Agent) pull(ctx context.Context, m proto.Manifest) error {
	bad := &blacklist{fails: map[string]int{}}
	stall := 0
	for {
		miss := a.missing(m)
		if len(miss) == 0 {
			return nil
		}
		var p proto.Peers
		q := url.Values{"manifest": {m.ID}, "node": {a.cfg.Node}}
		if err := a.get(ctx, "/v1/peers?"+q.Encode(), &p); err != nil {
			return fmt.Errorf("问 peers: %w", err)
		}
		got, offered := a.pullRound(ctx, miss, p.Sources, bad)
		if err := ctx.Err(); err != nil {
			return err
		}
		switch {
		case got > 0:
			stall = 0
		case offered:
			if stall++; stall >= 3 {
				return fmt.Errorf("还缺 %d 块，所有来源都取不到", len(miss))
			}
		}
		if got == len(miss) {
			continue
		}
		wait := p.RetryAfterSeconds
		if wait <= 0 {
			wait = 3
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(wait) * a.retryUnit):
		}
	}
}

// pullRound 并发取一轮；每块按来源顺序试，取到一块就报 have。返回取到几块、有没有块给了来源。
func (a *Agent) pullRound(ctx context.Context, miss []string, sources map[string][]string, bad *blacklist) (int, bool) {
	var got atomic.Int32
	var offered atomic.Bool
	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < a.fetchParallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range work {
				if len(sources[h]) > 0 {
					offered.Store(true)
				}
				for _, src := range sources[h] {
					if bad.blocked(src) || ctx.Err() != nil {
						continue
					}
					err := a.pullChunk(ctx, src, h)
					bad.record(src, err)
					if err == nil {
						got.Add(1)
						a.reportHave([]string{h}, nil)
						break
					}
					if ctx.Err() == nil {
						log.Printf("取块 %s 从 %q: %v", h[:12], src, err)
					}
				}
			}
		}()
	}
feed:
	for _, h := range miss {
		select {
		case work <- h:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	return int(got.Load()), offered.Load()
}

// pullChunk 从一个来源取一块存进缓存（Put 边收边校验）。"" 是主控。
func (a *Agent) pullChunk(ctx context.Context, src, h string) error {
	ctx, cancel := context.WithTimeout(ctx, a.sourceTimeout) // 卡住的邻居不能拖住这一块
	defer cancel()
	base := strings.TrimRight(src, "/")
	if src == "" {
		base = a.cfg.Controller
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/chunks/"+h, nil)
	if err != nil {
		return err
	}
	a.auth(req)
	r, err := a.p2pClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", r.StatusCode)
	}
	return a.Chunks.Put(h, r.Body)
}

// blacklist: 同一来源连续失败 3 次（校验不过、超时、连不上都算），本次拉取就不再找它。
type blacklist struct {
	mu    sync.Mutex
	fails map[string]int
}

func (b *blacklist) blocked(src string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fails[src] >= 3
}

func (b *blacklist) record(src string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.fails[src] = 0
	} else {
		b.fails[src]++
	}
}

// keepFor 记下这份清单，返回淘汰时要留的块：当前期望 artifacts 和预热用到的（加上这份自己的）。
func (a *Agent) keepFor(m proto.Manifest) map[string]bool {
	a.fmu.Lock()
	defer a.fmu.Unlock()
	a.manifests[m.ID] = m
	keep := chunkSet(m)
	for _, id := range a.wanted {
		maps.Copy(keep, chunkSet(a.manifests[id]))
	}
	return keep
}

func (a *Agent) evict(keep map[string]bool) {
	if del := a.Chunks.Evict(keep); len(del) > 0 {
		a.reportHave(nil, del)
	}
}

// reportHave 经 /v1/have 报块的增减。没报出去的留着下次一起报；
// 主控回 409（重启过、不认识这台）就重新登记，登记会带上全部块，攒的就不要了。
func (a *Agent) reportHave(add, del []string) {
	a.hmu.Lock()
	defer a.hmu.Unlock()
	// 同一块先加后删只报删、先删后加只报加：主控收到时不用管先后
	a.haveAdd = without(merge(a.haveAdd, add), del)
	a.haveDel = without(merge(a.haveDel, del), add)
	err := a.post("/v1/have", proto.Have{Node: a.cfg.Node, Add: a.haveAdd, Del: a.haveDel}, nil)
	switch {
	case err == errUnknownNode:
		a.registered.Store(false)
	case err != nil:
		log.Printf("have 没报出去（下次再报）: %v", err)
		return
	}
	a.haveAdd, a.haveDel = nil, nil
}

// merge 把 more 加进 list（去重）。
func merge(list, more []string) []string {
	for _, h := range more {
		if !slices.Contains(list, h) {
			list = append(list, h)
		}
	}
	return list
}

func without(list, drop []string) []string {
	out := list[:0]
	for _, h := range list {
		if !slices.Contains(drop, h) {
			out = append(out, h)
		}
	}
	return out
}

func (a *Agent) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Controller+path, nil)
	if err != nil {
		return err
	}
	a.auth(req)
	r, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, r.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(out)
}

func (a *Agent) auth(req *http.Request) {
	if a.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
}

type fetchJob struct{ cancel context.CancelFunc }

type fetchResult struct {
	id  string
	job *fetchJob
	err error
}

// artifactsReady: 期望的制品都备齐了没有；没齐又没在拉的，在后台开拉。每个 Step 都调，只查内存：
// 核对文件（取清单 + Ready）只在期望里新出现、或上次拉失败过了 fetchRetry 时做一次。
func (a *Agent) artifactsReady(now time.Time) bool {
	a.collectFetches(now)
	if !slices.Equal(a.wantArts, a.desired.Artifacts) {
		a.wantArts = slices.Clone(a.desired.Artifacts)
		a.dropUnwanted(a.wantArts, "")
		a.setWanted()
	}
	if !slices.Equal(a.wantPre, a.desired.Preload) {
		a.wantPre = slices.Clone(a.desired.Preload)
		a.dropUnwanted(a.wantPre, preloadKey)
		a.setWanted()
	}
	ok := true
	for _, id := range a.wantArts {
		if a.ready[id] {
			continue
		}
		ok = false
		if a.jobs[id] == nil && now.Sub(a.failedAt[id]) >= a.fetchRetry {
			a.startFetch(id)
		}
	}
	if ok { // 预热排在 artifacts 后面：别和马上要用的模型抢带宽
		for _, id := range a.wantPre {
			k := preloadKey + id
			if !a.ready[k] && a.jobs[k] == nil && now.Sub(a.failedAt[k]) >= a.fetchRetry {
				a.startFetch(k)
			}
		}
	}
	return ok
}

// dropUnwanted 取消、忘掉某一类（prefix 为 "" 是 artifacts，preloadKey 是预热）里期望已经不要的任务。
func (a *Agent) dropUnwanted(want []string, prefix string) {
	stale := func(k string) bool {
		if strings.HasPrefix(k, preloadKey) != (prefix == preloadKey) {
			return false // 另一类，不归这里管
		}
		return !slices.Contains(want, strings.TrimPrefix(k, prefix))
	}
	for k, j := range a.jobs {
		if stale(k) {
			j.cancel()
			delete(a.jobs, k)
		}
	}
	for k := range a.ready {
		if stale(k) {
			delete(a.ready, k)
		}
	}
}

// setWanted 更新淘汰时要留的制品：artifacts ∪ 预热。
func (a *Agent) setWanted() {
	a.fmu.Lock()
	a.wanted = merge(slices.Clone(a.wantArts), a.wantPre)
	a.fmu.Unlock()
}

// startFetch: key 是制品 ID，或 preloadKey+ID（预热）。
func (a *Agent) startFetch(key string) {
	ctx, cancel := context.WithCancel(a.fetchCtx)
	j := &fetchJob{cancel: cancel}
	a.jobs[key] = j
	id, preload := strings.CutPrefix(key, preloadKey)
	go func() {
		err := a.fetchAs(ctx, id, preload)
		a.fmu.Lock()
		a.results = append(a.results, fetchResult{id: key, job: j, err: err})
		a.fmu.Unlock()
	}()
}

// collectFetches 收后台拉取的结果；已经取消的旧任务不算（期望里去掉了，不是失败）。
// 失败发 fetch 事件，但和上次同样的错误不重复发：主控没放清单时每分钟一条没意义。
func (a *Agent) collectFetches(now time.Time) {
	a.fmu.Lock()
	rs := a.results
	a.results = nil
	a.fmu.Unlock()
	for _, r := range rs {
		r.job.cancel()
		if a.jobs[r.id] != r.job {
			continue
		}
		delete(a.jobs, r.id)
		if r.err != nil {
			log.Printf("制品 %s 没备齐: %v", r.id, r.err)
			if msg := r.err.Error(); msg != a.lastErr[r.id] {
				a.sendEvent(proto.Event{Kind: "fetch", Detail: fmt.Sprintf("失败 %s: %s", r.id, msg)})
				a.lastErr[r.id] = msg
			}
			a.failedAt[r.id] = now
			continue
		}
		a.ready[r.id] = true
		delete(a.failedAt, r.id)
		delete(a.lastErr, r.id)
	}
}
