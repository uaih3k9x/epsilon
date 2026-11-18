package probe

// 端到端：本机 1 个真主控 + 2 个假探针（真 Agent，假 System），跑签名任务包并回传 output/。
// 解释器用测试二进制冒充（EPSILON_FAKE_PY），脚本内容就是要干什么，见 fakePython。

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/chunk"
	"epsilon/controller"
	"epsilon/internal/jobtest"
	"epsilon/jobsign"
	"epsilon/proto"
	"epsilon/winproc"
)

func fakePython(args []string) int {
	if len(args) < 3 || args[0] != "-E" || args[1] != "-B" {
		fmt.Fprintln(os.Stderr, "参数不对:", args)
		return 90
	}
	b, err := os.ReadFile(args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 91
	}
	f := strings.Fields(string(b))
	switch f[0] {
	case "ok":
		raw, _ := os.ReadFile("../params.json")
		var p struct {
			SleepMS int `json:"sleep_ms"`
		}
		json.Unmarshal(raw, &p)
		time.Sleep(time.Duration(p.SleepMS) * time.Millisecond)
		os.WriteFile("../output/RESULT.json", raw, 0o644)
		fmt.Println("job done")
		return 0
	case "exit":
		n, _ := strconv.Atoi(f[1])
		return n
	case "tree": // 起一个孙进程，写下 pid，都睡着
		os.WriteFile("sleep.py", []byte("sleep"), 0o644)
		c := exec.Command(os.Args[0], "-E", "-B", "sleep.py")
		c.Env = os.Environ()
		if err := c.Start(); err != nil {
			return 92
		}
		os.WriteFile("../output/child.pid", []byte(strconv.Itoa(c.Process.Pid)), 0o644)
		time.Sleep(time.Hour)
	case "sleep":
		time.Sleep(time.Hour)
	}
	return 0
}

// evil 包在真主控外面，冒充被拿下的主控：换钥匙环、换清单、改下发的任务。
type evil struct {
	h         http.Handler
	mu        sync.Mutex
	keyring   []byte
	manifests map[string][]byte
	mutate    func(*proto.JobAssign)
	noSource  bool // peers 一律说"现在没人能给"
}

func (e *evil) set(f func(e *evil)) { e.mu.Lock(); f(e); e.mu.Unlock() }

func (e *evil) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	kr, mutate := e.keyring, e.mutate
	m := e.manifests[strings.TrimPrefix(r.URL.Path, "/v1/manifests/")]
	e.mu.Unlock()
	if r.URL.Path == "/v1/peers" {
		e.mu.Lock()
		m = e.manifests[r.URL.Query().Get("manifest")]
		e.mu.Unlock()
		if m != nil && e.noSource {
			json.NewEncoder(w).Encode(proto.Peers{Sources: map[string][]string{}, RetryAfterSeconds: 1})
			return
		}
		if m != nil { // 换了清单就连 peers 一起编：每块都说找主控要
			var man proto.Manifest
			json.Unmarshal(m, &man)
			p := proto.Peers{Sources: map[string][]string{}}
			for _, f := range man.Files {
				for _, h := range f.Chunks {
					p.Sources[h] = []string{""}
				}
			}
			json.NewEncoder(w).Encode(p)
			return
		}
	}
	switch {
	case r.URL.Path == "/v1/job-keyring" && kr != nil:
		w.Write(kr)
	case strings.HasPrefix(r.URL.Path, "/v1/manifests/") && m != nil:
		w.Write(m)
	case r.URL.Path == "/v1/heartbeat" && mutate != nil:
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		var d proto.DesiredState
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &d) != nil {
			w.WriteHeader(rec.Code)
			w.Write(rec.Body.Bytes())
			return
		}
		if d.Job != nil {
			mutate(d.Job)
		}
		json.NewEncoder(w).Encode(d)
	default:
		e.h.ServeHTTP(w, r)
	}
}

type e2e struct {
	t    *testing.T
	f    *jobtest.Fixture
	c    *controller.Controller
	evil *evil
	srv  *httptest.Server
}

func newE2E(t *testing.T, stale int) *e2e {
	f := jobtest.New(t)
	c := controller.New(controller.Config{ProbeToken: "tok", APIKeys: []string{"sk"}, StaleSeconds: stale,
		ChunksDir: f.ChunksDir, JobsDir: filepath.Join(f.Dir, "jobs"), JobKeyring: f.KeyringPath, JobPackagesDir: f.PackagesDir})
	c.JobRoots = []ed25519.PublicKey{f.RootPub}
	ev := &evil{h: c.Handler(), manifests: map[string][]byte{}}
	srv := httptest.NewServer(ev)
	t.Cleanup(srv.Close)
	return &e2e{t: t, f: f, c: c, evil: ev, srv: srv}
}

type probeRig struct {
	a    *Agent
	root string
	stop chan struct{}
	once sync.Once
}

// freeze 停掉主循环（不再心跳），手上的任务还在后台跑：模拟断网。
func (p *probeRig) freeze() { p.once.Do(func() { close(p.stop) }) }

func (e *e2e) probe(name string, mod func(*Agent)) *probeRig {
	t := e.t
	root := t.TempDir()
	cfg := Config{Node: name, Controller: e.srv.URL, Token: "tok", Workloads: map[string]Workload{},
		ArtifactRoot: root, ChunkDir: filepath.Join(root, "chunks"), Jobs: true}
	a := NewAgent(cfg, &fakeSys{}, "test")
	store, err := chunk.NewStore(cfg.ChunkDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.Chunks, a.Ready = store, chunk.Ready
	a.Assemble = func(m proto.Manifest, root string) error { return chunk.Assemble(m, store, root) }
	a.JobRoots = []ed25519.PublicKey{e.f.RootPub}
	a.beatEvery, a.jobCheckEvery, a.jobUploadRetry = 100*time.Millisecond, 50*time.Millisecond, 100*time.Millisecond
	a.jobInterp = func(string) string { return os.Args[0] }
	a.jobEnv = []string{"EPSILON_FAKE_PY=1"}
	if mod != nil {
		mod(a)
	}
	p := &probeRig{a: a, root: root, stop: make(chan struct{})}
	go a.Run(p.stop, 20*time.Millisecond)
	t.Cleanup(func() { p.freeze(); a.Shutdown() })
	return p
}

func (e *e2e) api(method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer sk")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, b
}

func (e *e2e) submit(body map[string]any) []string {
	e.t.Helper()
	code, b := e.api("POST", "/v1/jobs", body)
	if code != 200 {
		e.t.Fatalf("提交 %d: %s", code, b)
	}
	var s struct{ Jobs []string }
	json.Unmarshal(b, &s)
	return s.Jobs
}

type jobRow struct {
	ID       string   `json:"id"`
	State    string   `json:"state"`
	Node     string   `json:"node"`
	Attempt  int      `json:"attempt"`
	Lost     []string `json:"lost"`
	Detail   string   `json:"detail"`
	ExitCode *int     `json:"exit_code"`
	Output   bool     `json:"output"`
}

func (e *e2e) job(id string) jobRow {
	code, b := e.api("GET", "/v1/jobs/"+id, nil)
	if code != 200 {
		e.t.Fatalf("GET %s: %d", id, code)
	}
	var v jobRow
	json.Unmarshal(b, &v)
	return v
}

// wait 等任务结束（任何终态），返回记录。
func (e *e2e) wait(id string) jobRow {
	e.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		v := e.job(id)
		if proto.JobFinal(v.State) || v.State == "cancelled" {
			return v
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("任务 %s 没结束: %+v", id, v)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *e2e) pkg(name string, script string, mod func(*jobsign.Job)) string {
	j := jobtest.Job(name)
	if mod != nil {
		mod(&j)
	}
	return e.f.Package(e.t, j, map[string]string{"main.py": script})
}

func (e *e2e) output(id string) (proto.Manifest, map[string][]byte) {
	e.t.Helper()
	code, b := e.api("GET", "/v1/jobs/"+id+"/output", nil)
	if code != 200 {
		e.t.Fatalf("取输出清单 %d", code)
	}
	var m proto.Manifest
	json.Unmarshal(b, &m)
	files := map[string][]byte{}
	for _, f := range m.Files {
		code, data := e.api("GET", "/v1/jobs/"+id+"/files/"+f.Path, nil)
		if code != 200 || jobtest.Sum(data) != f.SHA256 {
			e.t.Fatalf("下载 %s: %d，哈希和清单对不上", f.Path, code)
		}
		files[f.Path] = data
	}
	return m, files
}

func expectRejected(t *testing.T, v jobRow, want string) {
	t.Helper()
	if v.State != proto.JobRejected || !strings.Contains(v.Detail, want) {
		t.Fatalf("要被探针拒（%s），实际 %+v", want, v)
	}
	if v.Output {
		t.Fatal("拒了就不该有输出")
	}
}

func TestJobE2ETwoProbesRoundTrip(t *testing.T) {
	e := newE2E(t, 30)
	p1 := e.probe("pc-01", nil)
	p2 := e.probe("pc-02", nil)
	pkg := e.pkg("demo", "ok", nil)
	time.Sleep(300 * time.Millisecond) // 等两台都登记上
	ids := e.submit(map[string]any{"package": pkg, "params": map[string]any{"sleep_ms": 200}, "count": 2})
	nodes := map[string]bool{}
	for _, id := range ids {
		v := e.wait(id)
		if v.State != proto.JobSucceeded || v.ExitCode == nil || *v.ExitCode != 0 || !v.Output {
			t.Fatalf("%s 要成功并回传: %+v", id, v)
		}
		nodes[v.Node] = true
		_, files := e.output(id)
		if string(bytes.TrimSpace(files["RESULT.json"])) == "" || !strings.Contains(string(files["RESULT.json"]), `"sleep_ms": 200`) {
			t.Fatalf("RESULT.json 要是脚本读到的 params.json: %q", files["RESULT.json"])
		}
		var sum map[string]any
		json.Unmarshal(files["_runner/summary.json"], &sum)
		if sum["signer"] != jobtest.Reviewer || sum["node"] != v.Node || sum["package"] != pkg {
			t.Fatalf("运行摘要不对: %v", sum)
		}
		if !strings.Contains(string(files["_runner/job.log"]), "job done") {
			t.Fatalf("job.log 要随输出回传: %q", files["_runner/job.log"])
		}
	}
	if len(nodes) != 2 {
		t.Fatalf("两份应该分到两台: %v", nodes)
	}
	// 本机任务目录按约定展开
	for _, p := range []*probeRig{p1, p2} {
		dirs, _ := filepath.Glob(filepath.Join(p.root, "jobs", "*"))
		if len(dirs) != 1 {
			t.Fatalf("%s 的任务目录: %v", p.a.cfg.Node, dirs)
		}
		for _, x := range []string{"code/main.py", "params.json", "output", "tmp", "data", "job.log"} {
			if _, err := os.Stat(filepath.Join(dirs[0], x)); err != nil {
				t.Errorf("%s 缺 %s", dirs[0], x)
			}
		}
		if b, _ := os.ReadFile(filepath.Join(p.root, keyringVersionFile)); strings.TrimSpace(string(b)) != "1" {
			t.Errorf("钥匙环版本号要持久化: %q", b)
		}
	}
}

func TestJobE2EFailedExitCode(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", nil)
	id := e.submit(map[string]any{"package": e.pkg("boom", "exit 3", nil)})[0]
	v := e.wait(id)
	if v.State != proto.JobFailed || v.ExitCode == nil || *v.ExitCode != 3 || !v.Output {
		t.Fatalf("退出码 3 = 失败，日志照样回传: %+v", v)
	}
}

func TestJobE2EBadSignature(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", nil)
	// 被拿下的主控把下发的任务包改了一个字节（换脚本），签名留着
	e.evil.set(func(e *evil) {
		e.mutate = func(j *proto.JobAssign) {
			var s jobsign.SignedJob
			json.Unmarshal([]byte(j.Signed), &s)
			s.Job = strings.Replace(s.Job, `"max_hours": 1`, `"max_hours": 2`, 1)
			b, _ := json.Marshal(s)
			j.Signed = string(b)
		}
	})
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	expectRejected(t, e.wait(id), "验签失败")
}

func TestJobE2EUndeclaredParam(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", nil)
	e.evil.set(func(e *evil) {
		e.mutate = func(j *proto.JobAssign) { j.Params["cmd"] = json.RawMessage(`"calc.exe"`) }
	})
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	expectRejected(t, e.wait(id), "没有声明参数 cmd")
}

func TestJobE2EKeyringRollback(t *testing.T) {
	e := newE2E(t, 30)
	v1, _ := os.ReadFile(e.f.KeyringPath)
	ring := e.f.Ring
	ring.Version = 2
	e.f.WriteKeyring(t, ring)
	p := e.probe("pc-01", nil)
	pkg := e.pkg("demo", "ok", nil)
	if v := e.wait(e.submit(map[string]any{"package": pkg})[0]); v.State != proto.JobSucceeded {
		t.Fatalf("v2 下先跑通: %+v", v)
	}
	if b, _ := os.ReadFile(filepath.Join(p.root, keyringVersionFile)); strings.TrimSpace(string(b)) != "2" {
		t.Fatalf("要记住版本 2: %q", b)
	}
	// 主控换回 v1（同样是根钥匙签的，只是旧）
	e.evil.set(func(e *evil) { e.keyring = v1 })
	expectRejected(t, e.wait(e.submit(map[string]any{"package": pkg})[0]), "比见过的 2 旧")
}

func TestJobE2EKeyringVersionFileCorrupt(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", func(a *Agent) {
		os.WriteFile(filepath.Join(a.cfg.ArtifactRoot, keyringVersionFile), []byte("garbage"), 0o644)
	})
	expectRejected(t, e.wait(e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]), keyringVersionFile)
}

func TestJobE2EExpiredKey(t *testing.T) {
	// 主控那边钥匙还有效（能提交），但发给探针的是钥匙已过期的钥匙环（根钥匙签的真货）
	expired := func(e *e2e) {
		ring := e.f.Ring
		ring.Version = 2
		ring.Issued = time.Now().Add(-4 * time.Hour).UTC().Format(time.RFC3339)
		ring.Keys = append([]jobsign.Key(nil), ring.Keys...)
		ring.Keys[0].Expires = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		s, _ := jobsign.SignKeyring(ring, e.f.RootPriv)
		b, _ := json.Marshal(s)
		e.evil.set(func(ev *evil) { ev.keyring = b })
	}
	t.Run("本机时钟准", func(t *testing.T) {
		e := newE2E(t, 30)
		expired(e)
		e.probe("pc-01", nil)
		expectRejected(t, e.wait(e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]), "已过期")
	})
	t.Run("本机时钟慢了三小时", func(t *testing.T) {
		// 只看本机时间会放过；主控回包的 Date 更晚，按晚的算：宁可误拒不误放
		e := newE2E(t, 30)
		expired(e)
		e.probe("pc-01", func(a *Agent) { a.clock = func() time.Time { return time.Now().Add(-3 * time.Hour) } })
		expectRejected(t, e.wait(e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]), "已过期")
	})
}

func TestJobE2ECodeHashMismatch(t *testing.T) {
	t.Run("清单和 code_sha256 对不上", func(t *testing.T) {
		e := newE2E(t, 30)
		e.probe("pc-01", nil)
		pkg := e.pkg("demo", "ok", nil)
		other := e.f.Code(t, map[string]string{"main.py": "exit 0", "evil.py": "x"})
		raw, _ := os.ReadFile(filepath.Join(e.f.ChunksDir, "code-"+other+".json"))
		var m proto.Manifest
		json.Unmarshal(raw, &m)
		real := codeSHA(t, e, pkg)
		m.ID, m.Files[0].Path = "code-"+real, CodePath(real) // 冒名顶替，整文件哈希还是别的包的
		b, _ := json.Marshal(m)
		e.evil.set(func(ev *evil) { ev.manifests["code-"+real] = b })
		expectRejected(t, e.wait(e.submit(map[string]any{"package": pkg})[0]), "对不上")
	})
	t.Run("清单说的哈希对，块是别的包", func(t *testing.T) {
		e := newE2E(t, 30)
		e.probe("pc-01", nil)
		pkg := e.pkg("demo", "ok", nil)
		real := codeSHA(t, e, pkg)
		other := e.f.Code(t, map[string]string{"main.py": "exit 0", "evil.py": "x"})
		raw, _ := os.ReadFile(filepath.Join(e.f.ChunksDir, "code-"+other+".json"))
		var m proto.Manifest
		json.Unmarshal(raw, &m)
		m.ID, m.Files[0].Path, m.Files[0].SHA256 = "code-"+real, CodePath(real), real
		b, _ := json.Marshal(m)
		e.evil.set(func(ev *evil) { ev.manifests["code-"+real] = b })
		expectRejected(t, e.wait(e.submit(map[string]any{"package": pkg})[0]), "sha256")
	})
	t.Run("本地代码包被改过，校验戳还对得上", func(t *testing.T) {
		e := newE2E(t, 30)
		p := e.probe("pc-01", nil)
		pkg := e.pkg("demo", "ok", nil)
		if v := e.wait(e.submit(map[string]any{"package": pkg})[0]); v.State != proto.JobSucceeded {
			t.Fatalf("先跑通一次: %+v", v)
		}
		real := codeSHA(t, e, pkg)
		zp := filepath.Join(p.root, filepath.FromSlash(CodePath(real)))
		fi, err := os.Stat(zp)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(zp)
		b[len(b)/2] ^= 0xff // 同样大小
		os.WriteFile(zp, b, 0o644)
		os.Chtimes(zp, fi.ModTime(), fi.ModTime()) // 同样修改时间：chunk.Ready 只看 stamp 会当没变
		expectRejected(t, e.wait(e.submit(map[string]any{"package": pkg})[0]), "代码包哈希")
	})
}

func TestJobE2EFetchTimeout(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", func(a *Agent) { a.jobFetchTimeout = 500 * time.Millisecond })
	pkg := e.pkg("demo", "ok", nil)
	real := codeSHA(t, e, pkg)
	raw, _ := os.ReadFile(filepath.Join(e.f.ChunksDir, "code-"+real+".json"))
	e.evil.set(func(ev *evil) { ev.manifests["code-"+real] = raw; ev.noSource = true })
	v := e.wait(e.submit(map[string]any{"package": pkg})[0])
	if v.State != proto.JobFailed || !strings.Contains(v.Detail, "内没拉齐") {
		t.Fatalf("拉不下来要超时算失败、放出机器: %+v", v)
	}
}

func codeSHA(t *testing.T, e *e2e, pkg string) string {
	raw, err := os.ReadFile(filepath.Join(e.f.PackagesDir, pkg+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var s jobsign.SignedJob
	json.Unmarshal(raw, &s)
	var j jobsign.Job
	json.Unmarshal([]byte(s.Job), &j)
	return j.CodeSHA256
}

func TestJobE2ETimeoutKillsTree(t *testing.T) {
	e := newE2E(t, 30)
	p := e.probe("pc-01", nil)
	id := e.submit(map[string]any{"package": e.pkg("slow", "tree", func(j *jobsign.Job) { j.MaxHours = 0.0003 })})[0] // ≈1 秒
	v := e.wait(id)
	if v.State != proto.JobKilled || !strings.Contains(v.Detail, "超时") || !v.Output {
		t.Fatalf("要超时被杀、日志照样回传: %+v", v)
	}
	b, err := os.ReadFile(filepath.Join(p.root, "jobs", id, "output", "child.pid"))
	if err != nil {
		t.Fatal("孙进程没起来")
	}
	pid, _ := strconv.Atoi(string(b))
	deadline := time.Now().Add(5 * time.Second)
	for winproc.Alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("孙进程 %d 没被一起杀", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestJobE2ECancelKillsTree(t *testing.T) {
	e := newE2E(t, 30)
	p := e.probe("pc-01", nil)
	id := e.submit(map[string]any{"package": e.pkg("slow", "tree", nil)})[0]
	pidFile := filepath.Join(p.root, "jobs", id, "output", "child.pid")
	waitFor(t, "孙进程起来", func() bool { _, err := os.Stat(pidFile); return err == nil })
	if code, b := e.api("DELETE", "/v1/jobs/"+id, nil); code != 200 {
		t.Fatalf("撤销: %d %s", code, b)
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(string(b))
	waitFor(t, "撤销后整棵树被杀", func() bool { return !winproc.Alive(pid) })
	waitFor(t, "探针放下任务", func() bool { return p.a.jobStatus() == nil })
}

func TestJobE2ENodeLostReassigned(t *testing.T) {
	e := newE2E(t, 1)
	p1 := e.probe("pc-01", nil)
	time.Sleep(200 * time.Millisecond)
	pkg := e.pkg("demo", "ok", nil)
	id := e.submit(map[string]any{"package": pkg, "params": map[string]any{"sleep_ms": 1500}})[0]
	waitFor(t, "pc-01 开跑", func() bool { s := p1.a.jobStatus(); return s != nil && s.State == proto.JobRunning })
	e.probe("pc-02", nil)
	p1.freeze() // 断网：不再心跳，手上的任务还在跑
	v := e.wait(id)
	if v.State != proto.JobSucceeded || v.Node != "pc-02" || v.Attempt != 2 || len(v.Lost) != 1 || v.Lost[0] != "pc-01" {
		t.Fatalf("要在 pc-02 上第 2 次跑完: %+v", v)
	}
	_, files := e.output(id)
	var sum map[string]any
	json.Unmarshal(files["_runner/summary.json"], &sum)
	if sum["node"] != "pc-02" || sum["attempt"] != float64(2) {
		t.Fatalf("回传的要是 pc-02 那次: %v", sum)
	}
	// pc-01 那次跑完也传不上来（主控只认 pc-02 的第 2 次）
	waitFor(t, "pc-01 那次结束", func() bool { s := p1.a.jobStatus(); return s != nil && proto.JobFinal(s.State) })
	if s := p1.a.jobStatus(); s.State != proto.JobFailed || !strings.Contains(s.Detail, "403") {
		t.Fatalf("旧的一次回传应该被拒: %+v", s)
	}
}

func TestJobE2EJobsOffByDefault(t *testing.T) {
	e := newE2E(t, 30)
	p := e.probe("pc-01", func(a *Agent) { a.cfg.Jobs = false })
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	time.Sleep(500 * time.Millisecond)
	if v := e.job(id); v.State != "queued" {
		t.Fatalf("没开能力 32 的探针不该被派活: %+v", v)
	}
	if p.a.jobStatus() != nil {
		t.Fatal("探针不该接任务")
	}
}

func TestJobE2ERealPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("没有 python3")
	}
	e := newE2E(t, 30)
	e.probe("pc-01", func(a *Agent) { a.jobInterp = func(string) string { return py }; a.jobEnv = nil })
	script := `import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
P = json.loads((ROOT / "params.json").read_text(encoding="utf-8"))
(ROOT / "output" / "RESULT.json").write_text(json.dumps({"ok": True, "params": P, "argv": sys.argv[1:]}), encoding="utf-8")
print("EPSILON-PROGRESS 1.0 done", flush=True)
`
	id := e.submit(map[string]any{"package": e.pkg("pyjob", script, func(j *jobsign.Job) { j.Entry = []string{"python", "-u", "main.py", "--x"} }),
		"params": map[string]any{"sleep_ms": 1}})[0]
	v := e.wait(id)
	if v.State != proto.JobSucceeded {
		t.Fatalf("真 python 跑一遍: %+v", v)
	}
	_, files := e.output(id)
	if !strings.Contains(string(files["RESULT.json"]), `"sleep_ms": 1`) || !strings.Contains(string(files["RESULT.json"]), `"--x"`) {
		t.Fatalf("RESULT.json: %s", files["RESULT.json"])
	}
}
