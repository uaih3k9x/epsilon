package controller

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/internal/jobtest"
	"epsilon/jobsign"
	"epsilon/proto"
)

type jobRig struct {
	t   *testing.T
	f   *jobtest.Fixture
	c   *Controller
	h   http.Handler
	cfg Config
	mu  sync.Mutex
	at  time.Time
}

func newJobRig(t *testing.T, mod func(*Config)) *jobRig {
	f := jobtest.New(t)
	cfg := Config{ProbeToken: "tok", APIKeys: []string{"sk-1"}, StaleSeconds: 30,
		Default:   proto.DesiredState{Workload: "qwen3.5-4b"},
		ChunksDir: f.ChunksDir, JobsDir: filepath.Join(f.Dir, "jobs"), JobKeyring: f.KeyringPath, JobPackagesDir: f.PackagesDir,
		Topology: map[string]Place{"pc-01": {Room: "R1"}, "pc-02": {Room: "R1"}, "pc-03": {Room: "R2"}}}
	if mod != nil {
		mod(&cfg)
	}
	r := &jobRig{t: t, f: f, cfg: cfg, at: time.Now()}
	r.restart()
	return r
}

// restart 用同一份配置新起一个主控（模拟主控重启）。
func (r *jobRig) restart() {
	r.c = New(r.cfg)
	r.c.JobRoots = []ed25519.PublicKey{r.f.RootPub}
	r.c.now = func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.at }
	r.h = r.c.Handler()
}

func (r *jobRig) advance(d time.Duration) { r.mu.Lock(); r.at = r.at.Add(d); r.mu.Unlock() }

func (r *jobRig) do(method, path, auth string, body any, hdr ...string) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func gpu(total int) []proto.GPU { return []proto.GPU{{Name: "RTX 4060", MemTotal: total}} }

func (r *jobRig) register(node string, jobs bool, st *proto.JobStatus) {
	r.t.Helper()
	if w := r.do("POST", "/v1/register", "tok", proto.Register{Node: node, Jobs: jobs, GPUs: gpu(8188), Job: st}); w.Code != 200 {
		r.t.Fatalf("register %s: %d", node, w.Code)
	}
}

func (r *jobRig) beat(node string, jobs bool, st *proto.JobStatus, gpus ...proto.GPU) proto.DesiredState {
	r.t.Helper()
	if gpus == nil {
		gpus = gpu(8188)
	}
	w := r.do("POST", "/v1/heartbeat", "tok", proto.Heartbeat{Node: node, Jobs: jobs, GPUs: gpus, Job: st})
	if w.Code != 200 {
		r.t.Fatalf("heartbeat %s: %d", node, w.Code)
	}
	var d proto.DesiredState
	json.Unmarshal(w.Body.Bytes(), &d)
	return d
}

func (r *jobRig) join(node string, jobs bool) proto.DesiredState {
	r.register(node, jobs, nil)
	return r.beat(node, jobs, nil)
}

type submitResp struct {
	Jobs []string `json:"jobs"`
}

func (r *jobRig) submit(body any) (int, submitResp, string) {
	w := r.do("POST", "/v1/jobs", "sk-1", body)
	var s submitResp
	json.Unmarshal(w.Body.Bytes(), &s)
	return w.Code, s, w.Body.String()
}

func (r *jobRig) mustSubmit(body any) []string {
	r.t.Helper()
	code, s, raw := r.submit(body)
	if code != 200 {
		r.t.Fatalf("提交失败 %d: %s", code, raw)
	}
	return s.Jobs
}

func (r *jobRig) job(id string) jobView {
	r.t.Helper()
	w := r.do("GET", "/v1/jobs/"+id, "sk-1", nil)
	if w.Code != 200 {
		r.t.Fatalf("GET job %s: %d", id, w.Code)
	}
	var v jobView
	json.Unmarshal(w.Body.Bytes(), &v)
	return v
}

func (r *jobRig) pkg(mod func(*jobsign.Job)) string {
	j := jobtest.Job("demo")
	if mod != nil {
		mod(&j)
	}
	return r.f.Package(r.t, j, map[string]string{"main.py": "ok"})
}

func st(id string, attempt int, state string) *proto.JobStatus {
	return &proto.JobStatus{ID: id, Attempt: attempt, State: state}
}

func TestJobKeyringServed(t *testing.T) {
	r := newJobRig(t, nil)
	if w := r.do("GET", "/v1/job-keyring", "", nil); w.Code != 401 {
		t.Fatalf("没 token 应该 401: %d", w.Code)
	}
	w := r.do("GET", "/v1/job-keyring", "tok", nil)
	want, _ := os.ReadFile(r.f.KeyringPath)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("钥匙环要原样发: %d", w.Code)
	}
}

func TestJobSubmitValidation(t *testing.T) {
	r := newJobRig(t, func(c *Config) {})
	ring := r.f.Ring
	ring.Keys[0].Limits.Rooms = []string{"R1"}
	r.f.WriteKeyring(t, ring)
	good := r.pkg(nil)
	withData := r.pkg(func(j *jobsign.Job) { j.Name = "with-data"; j.Data = []string{"cifar@1"} })
	noCode := r.pkg(func(j *jobsign.Job) { j.Name = "no-code"; j.CodeSHA256 = strings.Repeat("ab", 32) })
	j := jobtest.Job("forged")
	j.CodeSHA256 = r.f.Code(t, map[string]string{"main.py": "ok"})
	forged := r.f.Sign(t, j, jobtest.BadKey(t))
	if w := r.do("POST", "/v1/jobs", "", map[string]any{"package": good}); w.Code != 401 {
		t.Fatalf("没 key 应该 401: %d", w.Code)
	}
	cases := []struct {
		name string
		body map[string]any
		code int
	}{
		{"任务包不存在", map[string]any{"package": "nope@1.0.0"}, 404},
		{"包名不合法", map[string]any{"package": "../x"}, 400},
		{"不认识的参数", map[string]any{"package": good, "params": map[string]any{"cmd": "x"}}, 400},
		{"参数越界", map[string]any{"package": good, "params": map[string]any{"sleep_ms": -1}}, 400},
		{"签名不对", map[string]any{"package": forged}, 400},
		{"数据集还没做", map[string]any{"package": withData}, 400},
		{"代码包不在主控", map[string]any{"package": noCode}, 400},
		{"教室超出钥匙权限", map[string]any{"package": good, "rooms": []string{"R2"}}, 400},
		{"份数不对", map[string]any{"package": good, "count": 0}, 400},
		{"不认识的字段", map[string]any{"package": good, "command": "rm"}, 400},
	}
	for _, c := range cases {
		if code, _, raw := r.submit(c.body); code != c.code {
			t.Errorf("%s: 要 %d，是 %d %s", c.name, c.code, code, raw)
		}
	}
	ids := r.mustSubmit(map[string]any{"package": good, "params": map[string]any{"sleep_ms": 5}, "count": 3})
	if len(ids) != 3 {
		t.Fatalf("要 3 份: %v", ids)
	}
	v := r.job(ids[0])
	if v.State != "queued" || v.Signer != jobtest.Reviewer || v.Package != good || string(v.Params["sleep_ms"]) != "5" {
		t.Fatalf("记录不对: %+v", v)
	}
	w := r.do("GET", "/v1/jobs", "sk-1", nil)
	var list []jobView
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 3 || list[0].ID != ids[0] {
		t.Fatalf("列表不对: %s", w.Body)
	}
}

func TestJobAssignStopsInference(t *testing.T) {
	r := newJobRig(t, nil)
	if d := r.join("pc-01", true); d.Workload != "qwen3.5-4b" || d.Job != nil {
		t.Fatalf("没任务时照常推理: %+v", d)
	}
	r.join("pc-02", false) // 没开能力 32
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil)})[0]
	d := r.beat("pc-02", false, nil)
	if d.Job != nil || d.Workload != "qwen3.5-4b" {
		t.Fatalf("没开批任务的节点不能派: %+v", d)
	}
	d = r.beat("pc-01", true, nil)
	if d.Job == nil || d.Job.ID != id || d.Job.Attempt != 1 {
		t.Fatalf("应该派给 pc-01: %+v", d.Job)
	}
	if d.Workload != "" {
		t.Fatalf("派了任务要先停推理: %q", d.Workload)
	}
	var sj jobsign.SignedJob
	if err := json.Unmarshal([]byte(d.Job.Signed), &sj); err != nil || sj.Key != jobtest.Reviewer {
		t.Fatalf("要带签名原文: %v", err)
	}
	if string(d.Job.Params["sleep_ms"]) != "0" {
		t.Fatalf("default 要补上: %v", d.Job.Params)
	}
	if v := r.job(id); v.State != "assigned" || v.Node != "pc-01" {
		t.Fatalf("状态不对: %+v", v)
	}
}

func TestJobStatusFlow(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil)})[0]
	r.beat("pc-01", true, nil)
	r.beat("pc-01", true, st(id, 1, proto.JobRunning))
	if v := r.job(id); v.State != "running" {
		t.Fatalf("要 running: %+v", v)
	}
	done := st(id, 1, proto.JobSucceeded)
	zero := 0
	done.ExitCode, done.Seconds = &zero, 12
	d := r.beat("pc-01", true, done)
	if d.Job != nil || d.Workload != "qwen3.5-4b" {
		t.Fatalf("结束了就不再派、恢复推理: %+v", d)
	}
	v := r.job(id)
	if v.State != "succeeded" || v.ExitCode == nil || *v.ExitCode != 0 || v.Finished == "" {
		t.Fatalf("要 succeeded: %+v", v)
	}
	// 结束后探针还会报几次旧状态，不能把记录弄乱
	r.beat("pc-01", true, st(id, 1, proto.JobRunning))
	if v := r.job(id); v.State != "succeeded" {
		t.Fatalf("结束了不能再改: %+v", v)
	}
}

func TestJobFailedIsFinal(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	r.join("pc-02", true)
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil), "nodes": []string{"pc-01"}})[0]
	r.beat("pc-01", true, nil)
	r.beat("pc-01", true, &proto.JobStatus{ID: id, Attempt: 1, State: proto.JobFailed, Detail: "退出码 3"})
	if v := r.job(id); v.State != "failed" || v.Detail != "退出码 3" {
		t.Fatalf("失败不重试: %+v", v)
	}
	if d := r.beat("pc-02", true, nil); d.Job != nil {
		t.Fatal("失败的任务不能再派")
	}
}

func TestJobGPUMem(t *testing.T) {
	r := newJobRig(t, nil)
	r.do("POST", "/v1/register", "tok", proto.Register{Node: "pc-01", Jobs: true, GPUs: gpu(4096)})
	r.do("POST", "/v1/register", "tok", proto.Register{Node: "pc-02", Jobs: true})
	yes := true
	r.mustSubmit(map[string]any{"package": r.pkg(func(j *jobsign.Job) { j.GPU = &yes; j.GPUMemMB = 6000 })})
	if d := r.beat("pc-01", true, nil, gpu(4096)...); d.Job != nil {
		t.Fatal("4 GB 卡装不下 6000 MB")
	}
	if d := r.beat("pc-02", true, nil, gpu(8188)...); d.Job == nil {
		t.Fatal("8 GB 卡应该派")
	}
}

func TestJobRoomsAndNodes(t *testing.T) {
	r := newJobRig(t, nil)
	ring := r.f.Ring
	ring.Keys[0].Limits.Rooms = []string{"R2"}
	r.f.WriteKeyring(t, ring)
	r.join("pc-01", true) // R1
	r.join("pc-03", true) // R2
	r.join("pc-09", true) // 不在拓扑里
	r.mustSubmit(map[string]any{"package": r.pkg(nil)})
	if d := r.beat("pc-01", true, nil); d.Job != nil {
		t.Fatal("钥匙只许 R2")
	}
	if d := r.beat("pc-09", true, nil); d.Job != nil {
		t.Fatal("不知道在哪间教室的不能派")
	}
	if d := r.beat("pc-03", true, nil); d.Job == nil {
		t.Fatal("R2 应该派")
	}

	r2 := newJobRig(t, nil)
	r2.join("pc-01", true)
	r2.join("pc-02", true)
	r2.mustSubmit(map[string]any{"package": r2.pkg(nil), "nodes": []string{"pc-02"}})
	if d := r2.beat("pc-01", true, nil); d.Job != nil {
		t.Fatal("指定了 pc-02")
	}
	if d := r2.beat("pc-02", true, nil); d.Job == nil {
		t.Fatal("pc-02 应该派")
	}
}

func TestJobMaxNodes(t *testing.T) {
	r := newJobRig(t, nil)
	ring := r.f.Ring
	ring.Keys[0].Limits.MaxNodes = 1
	r.f.WriteKeyring(t, ring)
	r.join("pc-01", true)
	r.join("pc-02", true)
	ids := r.mustSubmit(map[string]any{"package": r.pkg(nil), "count": 2})
	d1 := r.beat("pc-01", true, nil)
	d2 := r.beat("pc-02", true, nil)
	if d1.Job == nil || d2.Job != nil {
		t.Fatalf("钥匙一次最多 1 台: %v %v", d1.Job, d2.Job)
	}
	if d := r.beat("pc-02", true, nil); d.Job != nil {
		t.Fatal("第一份还没完")
	}
	r.beat("pc-01", true, st(ids[0], 1, proto.JobSucceeded))
	if v := r.job(ids[1]); v.State != "assigned" {
		t.Fatalf("第一份完了第二份才派: %+v", v)
	}
}

func TestJobMaxNodesZeroMeansNone(t *testing.T) {
	r := newJobRig(t, nil)
	ring := r.f.Ring
	ring.Keys[0].Limits.MaxNodes = 0
	r.f.WriteKeyring(t, ring)
	r.join("pc-01", true)
	r.mustSubmit(map[string]any{"package": r.pkg(nil)})
	if d := r.beat("pc-01", true, nil); d.Job != nil {
		t.Fatal("max_nodes 0 = 一台都不派（宁可误拒）")
	}
}

func TestJobLostRequeue(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil)})[0]
	r.beat("pc-01", true, nil)
	r.beat("pc-01", true, st(id, 1, proto.JobRunning))
	r.advance(10 * time.Second)
	r.join("pc-02", true)
	r.advance(25 * time.Second) // pc-01 已经 35 秒没心跳
	d := r.beat("pc-02", true, nil)
	if d.Job == nil || d.Job.ID != id || d.Job.Attempt != 2 {
		t.Fatalf("失联要换一台从头跑: %+v", d.Job)
	}
	v := r.job(id)
	if v.Node != "pc-02" || v.Attempt != 2 || len(v.Lost) != 1 || v.Lost[0] != "pc-01" {
		t.Fatalf("记录不对: %+v", v)
	}
	// pc-01 回来报旧的那次，不认
	r.register("pc-01", true, st(id, 1, proto.JobRunning))
	r.beat("pc-01", true, st(id, 1, proto.JobSucceeded))
	if v := r.job(id); v.State != "assigned" || v.Node != "pc-02" {
		t.Fatalf("旧的一次不能改记录: %+v", v)
	}
	if d := r.beat("pc-01", true, st(id, 1, proto.JobSucceeded)); d.Job != nil {
		t.Fatal("pc-01 不该再拿到这个任务")
	}
}

func TestJobLostRetriesExhausted(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil)})[0]
	for attempt := 1; attempt <= 3; attempt++ {
		d := r.beat("pc-01", true, nil)
		if d.Job == nil || d.Job.Attempt != attempt {
			t.Fatalf("第 %d 次: %+v", attempt, d.Job)
		}
		r.beat("pc-01", true, st(id, attempt, proto.JobRunning))
		r.register("pc-01", true, nil) // 探针重启：手上没任务了
	}
	v := r.job(id)
	if v.State != "failed" || v.Attempt != 3 {
		t.Fatalf("默认最多重试 2 次: %+v", v)
	}
	if d := r.beat("pc-01", true, nil); d.Job != nil {
		t.Fatal("重试用完了不能再派")
	}
}

func TestJobUndeliveredIsResent(t *testing.T) {
	// 回包丢了：探针下一次心跳没报这个任务，不算失联，再发一次
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil)})[0]
	r.beat("pc-01", true, nil)
	d := r.beat("pc-01", true, nil)
	if d.Job == nil || d.Job.ID != id || d.Job.Attempt != 1 {
		t.Fatalf("要再发同一次: %+v", d.Job)
	}
}

func TestJobControllerRestart(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	ids := r.mustSubmit(map[string]any{"package": r.pkg(nil), "count": 2})
	r.beat("pc-01", true, nil)
	r.beat("pc-01", true, st(ids[0], 1, proto.JobRunning))
	r.restart()
	// 探针心跳 409 → 重新登记，带上手上的任务
	if w := r.do("POST", "/v1/heartbeat", "tok", proto.Heartbeat{Node: "pc-01"}); w.Code != 409 {
		t.Fatalf("主控重启后要 409: %d", w.Code)
	}
	r.register("pc-01", true, st(ids[0], 1, proto.JobRunning))
	d := r.beat("pc-01", true, st(ids[0], 1, proto.JobRunning))
	if d.Job == nil || d.Job.ID != ids[0] || d.Job.Attempt != 1 {
		t.Fatalf("重启后任务还在这台: %+v", d.Job)
	}
	if v := r.job(ids[1]); v.State != "queued" {
		t.Fatalf("排队的还在: %+v", v)
	}
	// 编号接着往下排，不和旧的撞
	more := r.mustSubmit(map[string]any{"package": r.pkg(nil)})
	if more[0] == ids[0] || more[0] == ids[1] {
		t.Fatalf("编号撞了: %v %v", more, ids)
	}
}

func TestJobCancel(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	ids := r.mustSubmit(map[string]any{"package": r.pkg(nil), "count": 2})
	r.beat("pc-01", true, nil)
	if w := r.do("DELETE", "/v1/jobs/"+ids[1], "sk-1", nil); w.Code != 200 {
		t.Fatalf("撤销排队的: %d", w.Code)
	}
	if w := r.do("DELETE", "/v1/jobs/"+ids[0], "sk-1", nil); w.Code != 200 {
		t.Fatalf("撤销在跑的: %d", w.Code)
	}
	d := r.beat("pc-01", true, st(ids[0], 1, proto.JobRunning))
	if d.Job != nil {
		t.Fatal("撤销了就不再发，探针看不到就杀")
	}
	if v := r.job(ids[0]); v.State != "cancelled" {
		t.Fatalf("要 cancelled: %+v", v)
	}
	if w := r.do("DELETE", "/v1/jobs/"+ids[0], "sk-1", nil); w.Code != 409 {
		t.Fatalf("已经结束的再撤销 409: %d", w.Code)
	}
	if w := r.do("DELETE", "/v1/jobs/nope", "sk-1", nil); w.Code != 404 {
		t.Fatalf("没有的 404: %d", w.Code)
	}
	// 节点在杀旧任务（还报着 running）时不派新的
	r.mustSubmit(map[string]any{"package": r.pkg(nil)})
	if d := r.beat("pc-01", true, st(ids[0], 1, proto.JobRunning)); d.Job != nil {
		t.Fatal("旧任务还没停下来，不能派新的")
	}
	if d := r.beat("pc-01", true, &proto.JobStatus{ID: ids[0], Attempt: 1, State: proto.JobKilled}); d.Job == nil {
		t.Fatal("旧任务停了就能派")
	}
}

func TestJobRevokedBeforeAssign(t *testing.T) {
	r := newJobRig(t, nil)
	pkg := r.pkg(nil)
	id := r.mustSubmit(map[string]any{"package": pkg})[0]
	raw, _ := os.ReadFile(filepath.Join(r.f.PackagesDir, pkg+".json"))
	var sj jobsign.SignedJob
	json.Unmarshal(raw, &sj)
	ring := r.f.Ring
	ring.Version = 2
	ring.RevokedJobs = []string{jobsign.JobDigest(sj)}
	r.f.WriteKeyring(t, ring)
	if d := r.join("pc-01", true); d.Job != nil {
		t.Fatal("吊销了不能派")
	}
	if v := r.job(id); v.State != "rejected" {
		t.Fatalf("要 rejected: %+v", v)
	}
}

func TestJobOutputBoundToNode(t *testing.T) {
	r := newJobRig(t, nil)
	r.join("pc-01", true)
	id := r.mustSubmit(map[string]any{"package": r.pkg(nil)})[0]
	r.beat("pc-01", true, nil)
	r.beat("pc-01", true, st(id, 1, proto.JobUploading))
	data := []byte("hello")
	h := jobtest.Sum(data)
	path := "/v1/jobs/" + id + "/chunks/" + h
	if w := r.do("PUT", path, "tok", data, "X-Epsilon-Node", "pc-02", "X-Epsilon-Attempt", "1"); w.Code != 403 {
		t.Fatalf("别的节点不能传: %d", w.Code)
	}
	if w := r.do("PUT", path, "tok", data, "X-Epsilon-Node", "pc-01", "X-Epsilon-Attempt", "2"); w.Code != 403 {
		t.Fatalf("不是这一次不能传: %d", w.Code)
	}
	if w := r.do("PUT", path, "tok", data, "X-Epsilon-Node", "pc-01", "X-Epsilon-Attempt", "1"); w.Code != 200 {
		t.Fatalf("派到的节点能传: %d %s", w.Code, w.Body)
	}
	// 不在队列里的任务号（epsilon-env upload 手工传）照旧
	if w := r.do("PUT", "/v1/jobs/manual-1/chunks/"+h, "tok", data); w.Code != 200 {
		t.Fatalf("手工任务照旧: %d", w.Code)
	}
	if v := r.job(id); v.Output {
		t.Fatal("还没传清单")
	}
}
