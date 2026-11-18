package controller

// 批任务队列（docs/jobs.md，设计书 22.5）。主控只能挑签过名的任务包、填包内声明的参数、选机器：
// 任务包原文原样下发，探针自己拿钥匙环验签；主控这边也验一遍，只是为了早点拒、按钥匙的 max_nodes / rooms 派活。

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"

	"epsilon/jobsign"
	"epsilon/proto"
)

const (
	jobQueued    = "queued"
	jobAssigned  = "assigned" // 派了，探针还没报
	jobCancelled = "cancelled"
	queueFile    = "queue.json"
	maxJobCount  = 1000
)

var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]@[0-9]+\.[0-9]+\.[0-9]+$`)

// jobRec 是队列里的一份任务（一个单元）。存在 <jobs_dir>/queue.json。
type jobRec struct {
	ID         string                     `json:"id"`
	Package    string                     `json:"package"` // 名字@版本
	Signed     string                     `json:"signed"`  // 提交时的 job.signed.json 原文，原样下发
	Signer     string                     `json:"signer"`
	Digest     string                     `json:"digest"`
	Params     map[string]json.RawMessage `json:"params"`
	GPU        bool                       `json:"gpu"`
	GPUMemMB   int                        `json:"gpu_mem_mb"`
	Nodes      []string                   `json:"nodes,omitempty"` // 提交时的约束
	Rooms      []string                   `json:"rooms,omitempty"`
	MaxRetries int                        `json:"max_retries"`

	State     string    `json:"state"`
	Node      string    `json:"node,omitempty"`
	Attempt   int       `json:"attempt"`
	Delivered bool      `json:"delivered"`      // 当前这次已经随心跳回包发出去过
	Lost      []string  `json:"lost,omitempty"` // 在哪些节点上失联过
	Detail    string    `json:"detail,omitempty"`
	ExitCode  *int      `json:"exit_code,omitempty"`
	Seconds   float64   `json:"seconds,omitempty"`
	Submitted time.Time `json:"submitted"`
	Started   time.Time `json:"started,omitzero"`
	Finished  time.Time `json:"finished,omitzero"`
}

// active：派出去了、还没结束。
func (j *jobRec) active() bool {
	return j.State == jobAssigned || j.State == proto.JobFetching || j.State == proto.JobRunning || j.State == proto.JobUploading
}

func (j *jobRec) final() bool { return proto.JobFinal(j.State) || j.State == jobCancelled }

type queueState struct {
	Seq  int       `json:"seq"`
	Jobs []*jobRec `json:"jobs"`
}

func (c *Controller) jobsEnabled() bool { return c.cfg.JobsDir != "" && c.cfg.JobKeyring != "" }

func (c *Controller) maxRetries() int {
	if c.cfg.JobMaxRetries != nil && *c.cfg.JobMaxRetries >= 0 {
		return *c.cfg.JobMaxRetries
	}
	return 2
}

// loadQueue 在 New 里调；坏了就不开队列，免得把旧任务当没有、重复派活。
func (c *Controller) loadQueue() {
	c.jobs = map[string]*jobRec{}
	b, err := os.ReadFile(filepath.Join(c.cfg.JobsDir, queueFile))
	if os.IsNotExist(err) {
		return
	}
	var q queueState
	if err == nil {
		err = json.Unmarshal(b, &q)
	}
	if err != nil {
		log.Printf("任务队列读不了，批任务停用（修好或挪走 %s 再重启）: %v", queueFile, err)
		c.queueBroken = true
		return
	}
	c.jobSeq = q.Seq
	for _, j := range q.Jobs {
		c.jobs[j.ID] = j
	}
}

// saveQueue 原子写 queue.json。调用方持 c.mu。
func (c *Controller) saveQueue() {
	q := queueState{Seq: c.jobSeq, Jobs: c.sortedJobs()}
	b, _ := json.MarshalIndent(q, "", "  ")
	if err := os.MkdirAll(c.cfg.JobsDir, 0o755); err == nil {
		tmp := filepath.Join(c.cfg.JobsDir, queueFile+".tmp")
		if err = os.WriteFile(tmp, b, 0o644); err == nil {
			err = os.Rename(tmp, filepath.Join(c.cfg.JobsDir, queueFile))
		}
		if err != nil {
			log.Printf("任务队列没存上: %v", err)
		}
	}
}

func (c *Controller) sortedJobs() []*jobRec {
	out := make([]*jobRec, 0, len(c.jobs))
	for _, j := range c.jobs {
		out = append(out, j)
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].Submitted.Equal(out[b].Submitted) {
			return out[a].Submitted.Before(out[b].Submitted)
		}
		return out[a].ID < out[b].ID
	})
	return out
}

// keyring 读并验主控手上的钥匙环（每次现读：换钥匙环不用重启主控）。
func (c *Controller) keyring() (jobsign.Keyring, []byte, error) {
	raw, err := os.ReadFile(c.cfg.JobKeyring)
	if err != nil {
		return jobsign.Keyring{}, nil, err
	}
	var s jobsign.SignedKeyring
	if err := json.Unmarshal(raw, &s); err != nil {
		return jobsign.Keyring{}, nil, fmt.Errorf("钥匙环格式坏了: %v", err)
	}
	kr, err := jobsign.VerifyKeyring(s, c.JobRoots, 0, c.now())
	return kr, raw, err
}

func (c *Controller) serveKeyring(w http.ResponseWriter, r *http.Request) {
	_, raw, err := c.keyring()
	if err != nil {
		log.Printf("钥匙环发不出去: %v", err)
		http.Error(w, "钥匙环不可用", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func (c *Controller) loadPackage(name string) (jobsign.SignedJob, string, error) {
	var s jobsign.SignedJob
	raw, err := os.ReadFile(filepath.Join(c.cfg.JobPackagesDir, name+".json"))
	if err != nil {
		return s, "", err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, "", fmt.Errorf("任务包格式坏了: %v", err)
	}
	return s, string(raw), nil
}

type submitReq struct {
	Package string                     `json:"package"`
	Params  map[string]json.RawMessage `json:"params"`
	Count   *int                       `json:"count"` // 份数，没写 = 1
	Nodes   []string                   `json:"nodes"` // 只派给这些节点
	Rooms   []string                   `json:"rooms"` // 只派到这些教室（还要在钥匙的 rooms 里）
}

// CodeManifestID 是代码包在 chunks_dir 里的清单 ID：code-<code_sha256>，里面只有 jobcode/<code_sha256>.zip。
func CodeManifestID(sha string) string { return "code-" + sha }

func (c *Controller) submitJob(w http.ResponseWriter, r *http.Request) {
	var req submitReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields() // 不认识的字段直接拒（22.5）
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求看不懂: "+err.Error())
		return
	}
	count := 1
	if req.Count != nil {
		count = *req.Count
	}
	if count < 1 || count > maxJobCount {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("count 要在 1–%d", maxJobCount))
		return
	}
	if !packageName.MatchString(req.Package) {
		writeErr(w, http.StatusBadRequest, "package 要是 名字@x.y.z")
		return
	}
	signed, raw, err := c.loadPackage(req.Package)
	if errors.Is(err, os.ErrNotExist) {
		writeErr(w, http.StatusNotFound, "没有这个任务包: "+req.Package)
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	kr, _, err := c.keyring()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "钥匙环不可用: "+err.Error())
		return
	}
	job, key, err := jobsign.VerifyJob(signed, kr, c.now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if job.Name+"@"+job.Version != req.Package {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("任务包里写的是 %s@%s", job.Name, job.Version))
		return
	}
	if len(job.Data) > 0 { // 数据集清单还没被根钥匙钉住（手册 15.3 第 4 条），这一版不挂
		writeErr(w, http.StatusBadRequest, "数据集还没做：带 data 的任务包这一版不能跑")
		return
	}
	params, err := jobsign.FillParams(job.Params, req.Params)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(key.Limits.Rooms) > 0 {
		for _, room := range req.Rooms {
			if !slices.Contains(key.Limits.Rooms, room) {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("钥匙 %s 不许用教室 %s", key.Name, room))
				return
			}
		}
	}
	for _, id := range []string{CodeManifestID(job.CodeSHA256), job.Env} {
		if c.cfg.ChunksDir == "" {
			writeErr(w, http.StatusServiceUnavailable, "主控没配 chunks_dir，代码包和环境层发不出去")
			return
		}
		if _, err := c.readManifest(id); err != nil {
			writeErr(w, http.StatusBadRequest, "主控 chunks_dir 里没有清单 "+id)
			return
		}
	}
	c.mu.Lock()
	ids := make([]string, 0, count)
	now := c.now()
	for i := 0; i < count; i++ {
		var id string
		for {
			c.jobSeq++
			id = fmt.Sprintf("%s-%d", job.Name, c.jobSeq)
			if _, err := os.Stat(filepath.Join(c.cfg.JobsDir, id)); os.IsNotExist(err) && c.jobs[id] == nil {
				break // 不和手工回传过的任务目录撞
			}
		}
		c.jobs[id] = &jobRec{ID: id, Package: req.Package, Signed: raw, Signer: key.Name, Digest: jobsign.JobDigest(signed),
			Params: params, GPU: job.NeedsGPU(), GPUMemMB: job.GPUMemMB, Nodes: req.Nodes, Rooms: req.Rooms,
			MaxRetries: c.maxRetries(), State: jobQueued, Submitted: now}
		ids = append(ids, id)
	}
	c.scheduleLocked(now)
	c.saveQueue()
	c.mu.Unlock()
	log.Printf("提交任务 %s ×%d（签名 %s）: %v", req.Package, count, key.Name, ids)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jobs": ids})
}

// jobView 是给人看的任务记录。
type jobView struct {
	ID        string                     `json:"id"`
	Package   string                     `json:"package"`
	Signer    string                     `json:"signer"`
	Digest    string                     `json:"digest"`
	Params    map[string]json.RawMessage `json:"params"`
	Nodes     []string                   `json:"nodes,omitempty"`
	Rooms     []string                   `json:"rooms,omitempty"`
	GPUMemMB  int                        `json:"gpu_mem_mb"`
	State     string                     `json:"state"`
	Node      string                     `json:"node,omitempty"`
	Attempt   int                        `json:"attempt"`
	Lost      []string                   `json:"lost,omitempty"`
	Detail    string                     `json:"detail,omitempty"`
	ExitCode  *int                       `json:"exit_code,omitempty"`
	Seconds   float64                    `json:"seconds,omitempty"`
	Submitted string                     `json:"submitted"`
	Started   string                     `json:"started,omitempty"`
	Finished  string                     `json:"finished,omitempty"`
	Output    bool                       `json:"output"` // 输出已经传完（GET /v1/jobs/{id}/output）
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (c *Controller) view(j *jobRec) jobView {
	_, err := os.Stat(filepath.Join(c.cfg.JobsDir, j.ID, "manifest.json"))
	return jobView{ID: j.ID, Package: j.Package, Signer: j.Signer, Digest: j.Digest, Params: j.Params, Nodes: j.Nodes, Rooms: j.Rooms,
		GPUMemMB: j.GPUMemMB, State: j.State, Node: j.Node, Attempt: j.Attempt, Lost: j.Lost, Detail: j.Detail, ExitCode: j.ExitCode,
		Seconds: j.Seconds, Submitted: ts(j.Submitted), Started: ts(j.Started), Finished: ts(j.Finished), Output: err == nil}
}

func (c *Controller) listJobs(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	c.scheduleLocked(c.now())
	out := []jobView{}
	for _, j := range c.sortedJobs() {
		out = append(out, c.view(j))
	}
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (c *Controller) getJob(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	j := c.jobs[r.PathValue("id")]
	var v jobView
	if j != nil {
		v = c.view(j)
	}
	c.mu.Unlock()
	if j == nil {
		writeErr(w, http.StatusNotFound, "没有这个任务")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// cancelJob 撤销：排队的不再派；派出去的从期望状态里去掉，探针看不到了就整树杀掉。
func (c *Controller) cancelJob(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	j := c.jobs[r.PathValue("id")]
	switch {
	case j == nil:
		writeErr(w, http.StatusNotFound, "没有这个任务")
		return
	case j.final():
		writeErr(w, http.StatusConflict, "任务已经结束: "+j.State)
		return
	}
	j.State, j.Detail, j.Finished = jobCancelled, "撤销", c.now()
	c.saveQueue()
	log.Printf("撤销任务 %s（节点 %q）", j.ID, j.Node)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c.view(j))
}

// assignedTo 是当前派给 node、还没结束的任务。调用方持 c.mu。
func (c *Controller) assignedTo(node string) *jobRec {
	for _, j := range c.jobs {
		if j.Node == node && j.active() {
			return j
		}
	}
	return nil
}

// requeue：机器失联或重启，任务放回队列从头跑；重试用完就算失败。调用方持 c.mu。
func (c *Controller) requeue(j *jobRec, why string) {
	log.Printf("任务 %s 第 %d 次在 %s 上中断: %s", j.ID, j.Attempt, j.Node, why)
	j.Lost = append(j.Lost, j.Node)
	if j.Attempt > j.MaxRetries {
		j.State, j.Detail, j.Finished = proto.JobFailed, fmt.Sprintf("%s；重试 %d 次都没跑完", why, j.MaxRetries), c.now()
		return
	}
	j.State, j.Node, j.Delivered, j.Detail = jobQueued, "", false, why
	// 上一次没传完的块不要了，免得算进输出上限（传完的清单冻结，不会走到这里）
	dir := filepath.Join(c.cfg.JobsDir, j.ID)
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); os.IsNotExist(err) {
		os.RemoveAll(filepath.Join(dir, "chunks"))
	}
}

// reconcile 拿探针报的任务状态（登记或心跳）对账。调用方持 c.mu。
// 登记时 restarted = true：手上没有派给它的那次任务，说明探针重启过，任务已经跟着死了。
// 心跳时没报：多半是上次回包没收到，下次心跳再发一次，不算中断。
func (c *Controller) reconcile(node string, st *proto.JobStatus, restarted bool) bool {
	j := c.assignedTo(node)
	if j == nil {
		return false
	}
	if st == nil || st.ID != j.ID || st.Attempt != j.Attempt {
		if restarted && j.Delivered {
			c.requeue(j, "探针重启过，任务没了")
			return true
		}
		return false
	}
	changed := j.State != st.State || j.Detail != st.Detail
	switch {
	case proto.JobFinal(st.State):
		j.State, j.Detail, j.ExitCode, j.Seconds, j.Finished = st.State, st.Detail, st.ExitCode, st.Seconds, c.now()
		log.Printf("任务 %s 在 %s 上结束: %s %s", j.ID, node, st.State, st.Detail)
	case st.State == proto.JobFetching || st.State == proto.JobRunning || st.State == proto.JobUploading:
		if st.State == proto.JobRunning && j.Started.IsZero() {
			j.Started = c.now()
		}
		j.State, j.Detail, j.Seconds = st.State, st.Detail, st.Seconds
	}
	return changed
}

// nodeFree：开了能力 32、心跳没过期、手上没有没结束的任务（包括正在被杀的旧任务）。调用方持 c.mu。
func (c *Controller) nodeFree(name string, n *node, now time.Time) bool {
	if !n.hb.Jobs && !n.reg.Jobs || now.Sub(n.seen) >= time.Duration(c.cfg.StaleSeconds)*time.Second {
		return false
	}
	if n.hb.Job != nil && !proto.JobFinal(n.hb.Job.State) {
		return false
	}
	return c.assignedTo(name) == nil
}

func (c *Controller) fits(j *jobRec, key jobsign.Key, name string, n *node) bool {
	if len(j.Nodes) > 0 && !slices.Contains(j.Nodes, name) {
		return false
	}
	room := c.cfg.Topology[name].Room
	if len(j.Rooms) > 0 && !slices.Contains(j.Rooms, room) {
		return false
	}
	if len(key.Limits.Rooms) > 0 && !slices.Contains(key.Limits.Rooms, room) {
		return false // 不在拓扑里的节点不知道在哪间教室，钥匙限了教室就不派
	}
	if j.GPU {
		gpus := n.hb.GPUs
		if len(gpus) == 0 {
			gpus = n.reg.GPUs
		}
		if len(gpus) == 0 || gpus[0].MemTotal < j.GPUMemMB {
			return false
		}
	}
	return true
}

// scheduleLocked：先把失联节点上的任务放回队列，再给排队的任务挑节点。调用方持 c.mu。
func (c *Controller) scheduleLocked(now time.Time) bool {
	if !c.jobsEnabled() || c.queueBroken {
		return false
	}
	changed := false
	stale := time.Duration(c.cfg.StaleSeconds) * time.Second
	var queued []*jobRec
	for _, j := range c.sortedJobs() {
		if j.active() {
			if n := c.nodes[j.Node]; n == nil || now.Sub(n.seen) >= stale {
				c.requeue(j, fmt.Sprintf("节点 %s 失联", j.Node))
				changed = true
			}
		}
		if j.State == jobQueued {
			queued = append(queued, j)
		}
	}
	if len(queued) == 0 {
		return changed
	}
	kr, _, err := c.keyring()
	if err != nil {
		log.Printf("钥匙环不可用，先不派任务: %v", err)
		return changed
	}
	names := make([]string, 0, len(c.nodes))
	for name := range c.nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	busy := map[string]int{} // 每把钥匙现在占着几台
	for _, j := range c.jobs {
		if j.active() {
			busy[j.Signer]++
		}
	}
	for _, j := range queued {
		var signed jobsign.SignedJob
		json.Unmarshal([]byte(j.Signed), &signed)
		_, key, err := jobsign.VerifyJob(signed, kr, now) // 钥匙环可能换过：吊销、过期
		if err != nil {
			j.State, j.Detail, j.Finished = proto.JobRejected, "主控复核: "+err.Error(), now
			changed = true
			continue
		}
		if busy[key.Name] >= key.Limits.MaxNodes { // max_nodes 0 = 一台都不派
			continue
		}
		pick := ""
		for pass := 0; pass < 2 && pick == ""; pass++ { // 先避开失联过的节点，实在没有再用
			for _, name := range names {
				n := c.nodes[name]
				if (pass == 0) == slices.Contains(j.Lost, name) || !c.nodeFree(name, n, now) || !c.fits(j, key, name, n) {
					continue
				}
				pick = name
				break
			}
		}
		if pick == "" {
			continue
		}
		j.State, j.Node, j.Attempt, j.Delivered, j.Detail = jobAssigned, pick, j.Attempt+1, false, ""
		j.ExitCode, j.Started, j.Seconds = nil, time.Time{}, 0
		busy[key.Name]++
		changed = true
		log.Printf("任务 %s 第 %d 次派给 %s", j.ID, j.Attempt, pick)
	}
	return changed
}

// TickJobs 给主程序定时调：没有心跳进来时也要发现失联节点。
func (c *Controller) TickJobs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scheduleLocked(c.now()) {
		c.saveQueue()
	}
}

// jobFor 是这台节点心跳回包里要带的任务；带上就记"已发出"。调用方持 c.mu。
func (c *Controller) jobFor(node string) *proto.JobAssign {
	j := c.assignedTo(node)
	if j == nil {
		return nil
	}
	var signed jobsign.SignedJob
	json.Unmarshal([]byte(j.Signed), &signed)
	b, _ := json.Marshal(signed) // 只发 job / sig / key，warnings 之类不发
	j.Delivered = true
	return &proto.JobAssign{ID: j.ID, Attempt: j.Attempt, Signed: string(b), Params: j.Params}
}

// jobUploadAllowed：队列里的任务只认当前派到的节点和这一次（X-Epsilon-Node / X-Epsilon-Attempt）。
// 不在队列里的任务号（epsilon-env upload 手工传）照旧。探针共用一个 token，这只防错、不防冒充。
func (c *Controller) jobUploadAllowed(r *http.Request) bool {
	if !c.jobsEnabled() {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j := c.jobs[r.PathValue("id")]
	if j == nil {
		return true
	}
	attempt, _ := strconv.Atoi(r.Header.Get("X-Epsilon-Attempt"))
	return j.active() && j.Node == r.Header.Get("X-Epsilon-Node") && j.Attempt == attempt
}

func (c *Controller) bindJob(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.jobUploadAllowed(r) {
			http.Error(w, "这个任务现在不归这台机器传", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
