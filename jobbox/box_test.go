package jobbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"epsilon/jobrun"
)

// ---- 假的系统一侧 ----

type fakeAudit struct {
	conns chan io.ReadCloser
	once  sync.Once
	done  chan struct{}
}

func newFakeAudit() *fakeAudit {
	return &fakeAudit{conns: make(chan io.ReadCloser, 16), done: make(chan struct{})}
}

func (a *fakeAudit) Accept() (io.ReadCloser, error) {
	select {
	case c := <-a.conns:
		return c, nil
	case <-a.done:
		return nil, errors.New("closed")
	}
}

func (a *fakeAudit) Close() error { a.once.Do(func() { close(a.done) }); return nil }

// dial 是任务进程里的 sitecustomize 连上管道。
func (a *fakeAudit) dial() *io.PipeWriter {
	r, w := io.Pipe()
	a.conns <- r
	return w
}

type fakeProc struct {
	pid  int
	code int
	done chan struct{}
	once sync.Once
	kill bool
}

func newProc(pid int) *fakeProc { return &fakeProc{pid: pid, done: make(chan struct{})} }

func (p *fakeProc) exit(code int) { p.once.Do(func() { p.code = code; close(p.done) }) }
func (p *fakeProc) Pid() int      { return p.pid }
func (p *fakeProc) Wait() (int, error) {
	<-p.done
	return p.code, nil
}
func (p *fakeProc) Kill()  { p.once.Do(func() { p.kill = true; p.code = -1; close(p.done) }) }
func (p *fakeProc) Close() { p.Kill() }

type plat struct {
	mu        sync.Mutex
	calls     []string
	healthErr error
	grantErr  error
	revokeErr error
	auditErr  error
	startErr  map[string]error // sys / hook / job
	sweepN    int
	sweepErr  error
	sysOut    string
	hookOut   string
	hookReady bool
	hookFile  string
	hookChild bool
	job       func(l jobrun.Launch, a *fakeAudit, p *fakeProc) // 任务进程干什么（goroutine 里跑）
	jobEnv    []string
	tmpAtJob  []string
	audit     *fakeAudit
	revoked   []string
	launches  []jobrun.Launch
}

func (f *plat) call(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *plat) Health() error          { f.call("health"); return f.healthErr }
func (f *plat) Grant(dir string) error { f.call("grant"); return f.grantErr }
func (f *plat) Revoke(dir string) error {
	f.call("revoke")
	f.mu.Lock()
	f.revoked = append(f.revoked, filepath.Base(dir))
	f.mu.Unlock()
	return f.revokeErr
}
func (f *plat) Sweep() (int, error) { f.call("sweep"); return f.sweepN, f.sweepErr }
func (f *plat) Audit() (AuditServer, error) {
	f.call("audit")
	if f.auditErr != nil {
		return nil, f.auditErr
	}
	f.audit = newFakeAudit()
	return f.audit, nil
}

// kind 按引导和源码文件认出两次金丝雀：-I -S -c 引导 canary\sys.txt；-E -s -B -c 引导 canary\hook.txt。
func kind(l jobrun.Launch) string {
	n := len(l.Args)
	if n < 4 || l.Args[n-4] != "-c" || l.Args[n-3] != canaryBoot {
		return "job"
	}
	switch {
	case l.Args[0] == "-I" && filepath.Base(l.Args[n-2]) == "sys.txt":
		return "sys"
	case l.Args[0] == "-E" && filepath.Base(l.Args[n-2]) == "hook.txt":
		return "hook"
	}
	return "job"
}

func (f *plat) Start(l jobrun.Launch) (jobrun.Proc, error) {
	k := kind(l)
	f.call("start-" + k)
	f.mu.Lock()
	f.launches = append(f.launches, l)
	f.mu.Unlock()
	if err := f.startErr[k]; err != nil {
		return nil, err
	}
	switch k {
	case "sys":
		p := newProc(100)
		io.WriteString(l.Log, f.sysOut)
		os.WriteFile(filepath.Join(filepath.Dir(l.Dir), "tmp", "canary.exe"), []byte("MZ"), 0o644) // 金丝雀留下的
		p.exit(0)
		return p, nil
	case "hook":
		p := newProc(110)
		io.WriteString(l.Log, f.hookOut)
		a := f.audit
		go func() {
			if f.hookReady {
				w := a.dial()
				fmt.Fprintf(w, `{"t":1,"ev":"ready","pid":110,"ppid":1,"il":"low","job_dir":%q,"file":%q,"layer":"x"}`+"\n", jobDirOf(l), f.hookFile)
				if f.hookChild {
					c := a.dial()
					fmt.Fprintf(c, `{"t":1,"ev":"ready","pid":111,"ppid":110,"il":"low","job_dir":%q,"file":"x","layer":"x"}`+"\n", jobDirOf(l))
					c.Close()
				}
				w.Close()
			}
			p.exit(0)
		}()
		return p, nil
	}
	f.mu.Lock()
	f.jobEnv = l.Env
	ents, _ := os.ReadDir(filepath.Join(filepath.Dir(l.Dir), "tmp"))
	for _, e := range ents {
		f.tmpAtJob = append(f.tmpAtJob, e.Name())
	}
	f.mu.Unlock()
	p := newProc(200)
	go f.job(l, f.audit, p)
	return p, nil
}

// jobDirOf 是 sitecustomize 会报的 job_dir（进程拿到的 EPSILON_JOB_DIR）。
func jobDirOf(l jobrun.Launch) string { return envMap(l.Env)["EPSILON_JOB_DIR"] }

func readyJob(code int) func(jobrun.Launch, *fakeAudit, *fakeProc) {
	return func(l jobrun.Launch, a *fakeAudit, p *fakeProc) {
		w := a.dial()
		fmt.Fprintf(w, `{"t":1,"ev":"ready","pid":200,"ppid":1,"il":"low","job_dir":%q,"file":"x","layer":"x"}`+"\n", jobDirOf(l))
		fmt.Fprintln(w, `{"t":2,"pid":200,"ev":"socket.connect","act":"block","args":"x"}`)
		time.Sleep(20 * time.Millisecond)
		w.Close()
		p.exit(code)
	}
}

func goodPlat(envDir string) *plat {
	return &plat{sysOut: okLines(SysChecks), hookOut: okLines(HookChecks), hookReady: true,
		hookFile: envDir + `\Lib\site-packages\sitecustomize.py`, hookChild: true, job: readyJob(0), startErr: map[string]error{}}
}

type rig struct {
	t   *testing.T
	b   *Box
	p   *plat
	job Job
}

func newRig(t *testing.T, mod func(*plat)) *rig {
	root := t.TempDir()
	dir := filepath.Join(root, "jobs", "demo-1")
	for _, d := range []string{"code", "data", "output", "tmp"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "params.json"), []byte("{}"), 0o644)
	env := `D:\epsilon\envs\py311@2`
	p := goodPlat(env)
	if mod != nil {
		mod(p)
	}
	b := NewBox(p, Config{Root: root, Controller: "ctl.example:8090", ReadyTimeout: 200 * time.Millisecond,
		Grace: 100 * time.Millisecond, CanaryTimeout: 2 * time.Second, SysEnv: []string{`SystemRoot=C:\Windows`, "EPS_KEY=sk-x"}})
	r := &rig{t: t, b: b, p: p, job: Job{Dir: dir, EnvDir: env, Interp: env + `\python.exe`, Entry: []string{"python", "main.py"},
		Timeout: time.Minute, CheckEvery: 20 * time.Millisecond}}
	if err := b.Check(); err != nil && p.healthErr == nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.calls = nil
	p.mu.Unlock()
	return r
}

func (r *rig) run() (Result, error) { return r.b.Run(context.Background(), r.job) }

func (r *rig) calls() string {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	return strings.Join(r.p.calls, " ")
}

func expectReject(t *testing.T, err error, want string) {
	t.Helper()
	var rj *RejectError
	if !errors.As(err, &rj) || !strings.Contains(rj.Msg, want) {
		t.Fatalf("要 rejected（%s），实际 %v", want, err)
	}
}

// ---- 测试 ----

func TestRunHappyPathOrder(t *testing.T) {
	r := newRig(t, nil)
	res, err := r.run()
	if err != nil || res.ExitCode != 0 || res.Killed != "" {
		t.Fatalf("%+v %v", res, err)
	}
	want := "grant start-sys audit start-hook audit start-job sweep revoke"
	if got := r.calls(); got != want {
		t.Fatalf("顺序:\n got %s\nwant %s", got, want)
	}
	if !res.Audit.Ready || res.Audit.Blocked != 1 || !strings.Contains(string(res.AuditLog), "socket.connect") {
		t.Fatalf("审计: %+v %s", res.Audit, res.AuditLog)
	}
	env := envMap(r.p.jobEnv)
	if env["EPSILON_JOB_DIR"] != r.job.Dir || env["EPS_KEY"] != "" {
		t.Fatalf("任务环境要从零拼: %v", r.p.jobEnv)
	}
	// 金丝雀在 tmp\ 留下的东西要在任务起来前清掉，home 和缓存目录要建好
	if strings.Join(r.p.tmpAtJob, ",") != "cache,home" {
		t.Fatalf("任务开始时 tmp 里: %v", r.p.tmpAtJob)
	}
	if r.b.Halted() != "" {
		t.Fatal(r.b.Halted())
	}
}

func TestNotHealthyUntilFirstCheck(t *testing.T) {
	b := NewBox(goodPlat("x"), Config{Root: t.TempDir(), Controller: "c:1"})
	if b.Halted() == "" {
		t.Fatal("还没做健康检查就不接任务")
	}
	_, err := b.Run(context.Background(), Job{Dir: t.TempDir()})
	expectReject(t, err, "健康检查")
}

func TestHealthFailureHaltsUntilNextPass(t *testing.T) {
	r := newRig(t, nil)
	r.p.healthErr = errors.New("密码文件解不开")
	if err := r.b.Check(); err == nil || !strings.Contains(r.b.Halted(), "install.ps1") {
		t.Fatalf("健康检查不过要停接任务并说重跑 install.ps1: %v %q", err, r.b.Halted())
	}
	_, err := r.run()
	expectReject(t, err, "密码文件解不开")
	if strings.Contains(r.calls(), "grant") {
		t.Fatal("停接任务时一步都不做")
	}
	r.p.healthErr = nil
	if err := r.b.Check(); err != nil || r.b.Halted() != "" {
		t.Fatalf("下一次检查通过就恢复: %v %q", err, r.b.Halted())
	}
}

func TestGrantFailureRejectsAndRemovesDir(t *testing.T) {
	r := newRig(t, func(p *plat) { p.grantErr = errors.New("拒绝访问") })
	_, err := r.run()
	expectReject(t, err, "权限")
	if _, serr := os.Stat(r.job.Dir); serr == nil {
		t.Fatal("设不上 ACL 要删掉任务目录")
	}
	if strings.Contains(r.calls(), "start") || r.b.Halted() != "" {
		t.Fatalf("不起进程、不停接任务: %s %q", r.calls(), r.b.Halted())
	}
}

func TestSysCanaryMismatchHalts(t *testing.T) {
	for i, name := range SysChecks {
		r := newRig(t, func(p *plat) {
			lines := strings.Split(okLines(SysChecks), "\n")
			lines[i] = "CANARY fail " + name + " 写进去了"
			p.sysOut = strings.Join(lines, "\n")
		})
		_, err := r.run()
		expectReject(t, err, name)
		if strings.Contains(r.calls(), "start-job") || strings.Contains(r.calls(), "start-hook") {
			t.Fatalf("%s 不符就不再往下: %s", name, r.calls())
		}
		if !strings.HasSuffix(r.calls(), "sweep revoke") {
			t.Fatalf("拒了也要清场、收回权限: %s", r.calls())
		}
		if !strings.Contains(r.b.Halted(), "配置漂移") {
			t.Fatalf("系统控制不符是本机的问题，要停接任务: %q", r.b.Halted())
		}
	}
}

func TestHookCanaryMismatchRejectsWithoutHalting(t *testing.T) {
	cases := map[string]func(*plat){
		"subprocess_blocked": func(p *plat) {
			p.hookOut = strings.Replace(p.hookOut, "ok subprocess_blocked", "fail subprocess_blocked 没拦", 1)
		},
		"就绪":             func(p *plat) { p.hookReady = false }, // @1 层没有钩子
		"ready_in_layer": func(p *plat) { p.hookFile = `D:\epsilon\jobs\demo-1\code\sitecustomize.py` },
		"子进程":            func(p *plat) { p.hookChild = false },
	}
	for want, mod := range cases {
		r := newRig(t, mod)
		_, err := r.run()
		expectReject(t, err, want)
		expectReject(t, err, "py311@2") // 写明是哪个环境层
		if strings.Contains(r.calls(), "start-job") {
			t.Fatalf("%s: 不起任务", want)
		}
		if r.b.Halted() != "" {
			t.Fatalf("%s: 钩子不对是层的问题，不停接任务: %q", want, r.b.Halted())
		}
	}
}

type logonErr struct{}

func (logonErr) Error() string { return "1326 用户名或密码不正确" }

func TestLogonErrorHaltsOtherStartErrorDoesNot(t *testing.T) {
	r := newRig(t, func(p *plat) { p.startErr["sys"] = &LogonError{Code: 1326, Msg: "用户名或密码不正确"} })
	_, err := r.run()
	expectReject(t, err, "1326")
	if !strings.Contains(r.b.Halted(), "登录") {
		t.Fatalf("登录失败是本机配置问题，要停接任务: %q", r.b.Halted())
	}
	if err := r.b.Check(); err != nil || r.b.Halted() != "" {
		t.Fatal("下一次健康检查通过就恢复")
	}

	r = newRig(t, func(p *plat) { p.startErr["job"] = fmt.Errorf("包了一层: %w", &LogonError{Code: 1385}) })
	_, err = r.run()
	expectReject(t, err, "1385")
	if r.b.Halted() == "" {
		t.Fatal("起任务时的登录错误也要停")
	}

	r = newRig(t, func(p *plat) { p.startErr["job"] = errors.New("AssignProcessToJobObject: 拒绝访问") })
	_, err = r.run()
	expectReject(t, err, "AssignProcessToJobObject")
	if r.b.Halted() != "" {
		t.Fatalf("别的启动错误只拒这一个: %q", r.b.Halted())
	}
}

func TestAuditPipeFailureRejects(t *testing.T) {
	r := newRig(t, func(p *plat) { p.auditErr = errors.New("管道已存在（被抢注）") })
	_, err := r.run()
	expectReject(t, err, "抢注")
}

func TestJobWithoutReadyIsRejected(t *testing.T) {
	// 30 秒内没收到主进程的就绪：整树杀，rejected
	r := newRig(t, func(p *plat) {
		p.job = func(l jobrun.Launch, a *fakeAudit, p *fakeProc) { <-p.done }
	})
	start := time.Now()
	_, err := r.run()
	expectReject(t, err, "就绪")
	if time.Since(start) > 3*time.Second {
		t.Fatal("要在就绪时限到了就杀")
	}
	// sitecustomize 出错 os._exit(97)：没发就绪就退出
	r = newRig(t, func(p *plat) {
		p.job = func(l jobrun.Launch, a *fakeAudit, p *fakeProc) { p.exit(97) }
	})
	_, err = r.run()
	expectReject(t, err, "97")
}

func TestJobAuditDisconnectIsFailedNotRejected(t *testing.T) {
	r := newRig(t, func(p *plat) {
		p.job = func(l jobrun.Launch, a *fakeAudit, p *fakeProc) {
			w := a.dial()
			fmt.Fprintf(w, `{"t":1,"ev":"ready","pid":200,"ppid":1,"il":"low","job_dir":%q,"file":"x","layer":"x"}`+"\n", jobDirOf(l))
			w.Close() // 任务把审计管道关了，自己接着跑
			<-p.done
		}
	})
	res, err := r.run()
	if err != nil || res.Killed != AbortAudit || !res.Audit.Ready {
		t.Fatalf("运行中管道断开：整树杀、记 failed、照常回传: %+v %v", res, err)
	}
}

func TestLeftoverProcessesHaltUntilRestart(t *testing.T) {
	r := newRig(t, nil)
	r.p.sweepN = 2
	res, err := r.run()
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(r.b.Halted(), "逃出") || len(res.Notes) == 0 {
		t.Fatalf("要停接任务并发事件: %q %v", r.b.Halted(), res.Notes)
	}
	r.p.sweepN = 0
	if r.b.Check(); r.b.Halted() == "" {
		t.Fatal("逃出作业的进程：重启前一直停")
	}
}

func TestRevokeFailureHalts(t *testing.T) {
	r := newRig(t, nil)
	r.p.revokeErr = errors.New("拒绝访问")
	res, err := r.run()
	if err != nil {
		t.Fatal(err) // 照常回传
	}
	if !strings.Contains(r.b.Halted(), "收回") || len(res.Notes) == 0 {
		t.Fatalf("收不回权限，下一个任务能读这一份输出：要停: %q", r.b.Halted())
	}
}

func TestFirstCheckRevokesLeftoverJobDirs(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"a-1", "b-2"} {
		os.MkdirAll(filepath.Join(root, "jobs", id), 0o755)
	}
	os.WriteFile(filepath.Join(root, "jobs", "stray.txt"), nil, 0o644)
	p := goodPlat("x")
	b := NewBox(p, Config{Root: root, Controller: "c:1"})
	if err := b.Check(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.revoked, ",") != "a-1,b-2" || !strings.Contains(strings.Join(p.calls, " "), "sweep") {
		t.Fatalf("探针启动时把 jobs\\* 收回一遍、清场: %v %v", p.revoked, p.calls)
	}
	b.Check()
	if len(p.revoked) != 2 {
		t.Fatal("只在第一次做")
	}

	p = goodPlat("x")
	p.revokeErr = errors.New("拒绝访问")
	b = NewBox(p, Config{Root: root, Controller: "c:1"})
	b.Check()
	if !strings.Contains(b.Halted(), "收回") {
		t.Fatalf("启动时收不回也要停: %q", b.Halted())
	}
}

func TestCancelDuringCanaryIsNotReject(t *testing.T) {
	r := newRig(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.b.Run(ctx, r.job)
	var rj *RejectError
	if err == nil || errors.As(err, &rj) {
		t.Fatalf("撤销不是 rejected: %v", err)
	}
}

func TestUnavailable(t *testing.T) {
	u := Unavailable{Reason: "这个系统上没有沙箱"}
	if u.Halted() == "" || u.Check() == nil {
		t.Fatal("没有沙箱就不接任务")
	}
	_, err := u.Run(context.Background(), Job{})
	expectReject(t, err, "没有沙箱")
}

func TestNewOffWindowsIsUnavailable(t *testing.T) {
	s := New(Config{Root: t.TempDir(), Controller: "c:1"})
	if _, ok := s.(Unavailable); !ok {
		t.Skip("这是 Windows")
	}
	if s.Halted() == "" {
		t.Fatal("非 Windows 构建没有真实现")
	}
}

func TestSelfTestPrintsTable(t *testing.T) {
	r := newRig(t, func(p *plat) {
		p.sysOut = strings.Replace(okLines(SysChecks), "ok exec_tmp", "fail exec_tmp tmp 里的 exe 跑起来了", 1)
	})
	var out strings.Builder
	err := r.b.SelfTest(context.Background(), r.job.EnvDir, &out)
	if err == nil {
		t.Fatal("有一项不过就返回错误")
	}
	s := out.String()
	for _, want := range []string{"exec_tmp", "FAIL", "tmp 里的 exe 跑起来了", "write_tmp", "mp_child", "ready_child", "OK"} {
		if !strings.Contains(s, want) {
			t.Fatalf("表里缺 %q:\n%s", want, s)
		}
	}
	if _, err := os.Stat(filepath.Join(r.b.Root, "jobs", "_selftest")); err == nil {
		t.Fatal("自检的目录要删掉")
	}
}
