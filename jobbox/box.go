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
	"time"

	"epsilon/envlayer"
	"epsilon/jobrun"
)

// Platform 是系统那一侧：Windows 实现在 platform_windows.go，测试里换假的。
type Platform interface {
	// Health 是健康检查：密码文件能解密、LookupAccountName 查到的 SID 和文件里的一致、不在管理员组、窗口站建好了。
	Health() error
	Grant(jobDir string) error  // 设 JobDirSDs
	Revoke(jobDir string) error // 设 RevokedSDs
	// Start 以任务账户、独立桌面起进程：挂起建 → 放进作业对象（winproc.SandboxLimits）→ 恢复。
	Start(l jobrun.Launch) (jobrun.Proc, error)
	Audit() (AuditServer, error) // 建审计管道（FIRST_PIPE_INSTANCE）
	Sweep() (int, error)         // 结束任务账户还活着的进程，返回找到几个
}

// AuditServer 是审计管道的服务端：每个连上来的进程一个连接。
type AuditServer interface {
	Accept() (io.ReadCloser, error) // Close 之后返回错误
	Close() error
}

// LogonError 是 CreateProcessWithLogonW 报的、说明本机配置坏了的错误：
// 1326 密码不对、1385 没有登录权限、1058 seclogon 被禁用。遇到就停接任务，直到下一次健康检查通过。
type LogonError struct {
	Code uint32
	Msg  string
}

func (e *LogonError) Error() string {
	return fmt.Sprintf("任务账户登录失败（%d）: %s", e.Code, e.Msg)
}

// RejectError 是"一行用户代码都没跑就拒了"，探针记 rejected。
type RejectError struct{ Msg string }

func (e *RejectError) Error() string { return e.Msg }

func rejectf(format string, args ...any) error { return &RejectError{fmt.Sprintf(format, args...)} }

// Job 是一次要在沙箱里跑的任务（目录已经由 jobrun.Prepare 展开）。
type Job struct {
	Dir, EnvDir, Interp string
	Entry               []string
	Timeout             time.Duration
	DiskMaxMB           int
	Env                 []string // 追加的环境变量（测试用）
	CheckEvery          time.Duration
}

// Result 是 jobrun.Result 加上审计（能力 35）。Notes 是要发事件的（逃出作业的进程、收不回权限）。
type Result struct {
	jobrun.Result
	Audit    Summary
	AuditLog []byte
	Notes    []string
}

// Sandbox 是探针看到的沙箱。
type Sandbox interface {
	Check() error   // 健康检查（探针启动时和每 10 分钟）
	Halted() string // 非空 = 本机停接任务，心跳报 jobs:false
	Run(ctx context.Context, j Job) (Result, error)
}

// Config 是沙箱的配置。
type Config struct {
	Root          string        // artifact_root：jobs\、probe.json、secrets\ 在这里
	Controller    string        // host:port，金丝雀以任务账户连它，必须被防火墙拦下（10013）
	ReadyTimeout  time.Duration // 主进程恢复运行后多久内必须发就绪；0 = 30 秒
	Grace         time.Duration // 主进程审计连接断开后多久内进程必须退出；0 = 5 秒
	CanaryTimeout time.Duration // 每次金丝雀最多多久；0 = 2 分钟
	SysEnv        []string      // 探针自己的环境（只取系统变量）；nil = os.Environ()
}

func (c Config) readyTimeout() time.Duration  { return orDefault(c.ReadyTimeout, 30*time.Second) }
func (c Config) grace() time.Duration         { return orDefault(c.Grace, 5*time.Second) }
func (c Config) canaryTimeout() time.Duration { return orDefault(c.CanaryTimeout, 2*time.Minute) }

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Box 是沙箱的编排和出错即拒（docs/jobs-sandbox.md 第 6 节）。系统调用都在 Platform 里。
type Box struct {
	P Platform
	Config

	mu        sync.Mutex
	health    string // 健康检查不过；下一次通过就清
	soft      string // 登录失败、系统控制金丝雀不符；下一次健康检查通过就清
	hard      string // 有进程逃出作业对象、收不回权限：重启前一直停
	recovered bool
}

// NewBox 建好以后要先 Check 一次才接任务。
func NewBox(p Platform, c Config) *Box {
	return &Box{P: p, Config: c, health: "还没做健康检查"}
}

// New 是探针用的：这个系统上有真实现就返回 *Box，没有（或建不起来）就返回 Unavailable。
func New(c Config) Sandbox {
	p, err := newPlatform(c)
	if err != nil {
		return Unavailable{Reason: err.Error()}
	}
	return NewBox(p, c)
}

// Unavailable 是没有沙箱：一个任务都不跑。
type Unavailable struct{ Reason string }

func (u Unavailable) Check() error   { return errors.New(u.Reason) }
func (u Unavailable) Halted() string { return u.Reason }
func (u Unavailable) Run(context.Context, Job) (Result, error) {
	return Result{}, rejectf("本机没有沙箱: %s", u.Reason)
}

// Halted 非空表示本机停接任务（原因给人看）。
func (b *Box) Halted() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range []string{b.hard, b.health, b.soft} {
		if s != "" {
			return s
		}
	}
	return ""
}

func (b *Box) setSoft(s string) { b.mu.Lock(); b.soft = s; b.mu.Unlock() }
func (b *Box) setHard(s string) {
	b.mu.Lock()
	if b.hard == "" {
		b.hard = s
	}
	b.mu.Unlock()
}

// Check 做一次健康检查。第一次还会把 jobs\* 都收回一遍、清掉任务账户的进程（探针上次可能是崩掉的）。
func (b *Box) Check() error {
	err := b.P.Health()
	b.mu.Lock()
	first := !b.recovered
	b.recovered = true
	b.mu.Unlock()
	if first {
		b.recover()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.health = "健康检查不过，重跑 install.ps1（开沙箱）: " + err.Error()
		return err
	}
	b.health, b.soft = "", ""
	return nil
}

func (b *Box) recover() {
	ents, _ := os.ReadDir(filepath.Join(b.Root, "jobs"))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if err := b.P.Revoke(filepath.Join(b.Root, "jobs", e.Name())); err != nil {
			b.setHard(fmt.Sprintf("启动时收回任务目录 %s 的权限失败: %v", e.Name(), err))
		}
	}
	if n, err := b.P.Sweep(); err != nil || n > 0 {
		b.setHard(fmt.Sprintf("启动时发现任务账户的进程还活着（%d 个，%v），重启前不接任务", n, err))
	}
}

func (b *Box) sysEnv() []string {
	if b.SysEnv != nil {
		return b.SysEnv
	}
	return os.Environ()
}

func (b *Box) canaryConfig(j Job, env []string) (string, error) {
	sysRoot := `C:\Windows`
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == "SystemRoot" {
			sysRoot = v
		}
	}
	return CanaryConfig{JobDir: j.Dir, EnvDir: j.EnvDir, Root: b.Root, Controller: b.Controller, SystemRoot: sysRoot}.args()
}

// Run 跑一个任务：设 ACL → 系统控制金丝雀 → 钩子金丝雀 → 清空 tmp\ output\ → 任务 → 清场 → 收回 ACL。
// 一行用户代码都没跑就拒了的返回 *RejectError；撤销返回 ctx 的错误；其余（含运行中审计管道断开）照常返回结果。
func (b *Box) Run(ctx context.Context, j Job) (res Result, err error) {
	if h := b.Halted(); h != "" {
		return res, rejectf("本机停接任务: %s", h)
	}
	if err := b.P.Grant(j.Dir); err != nil {
		os.RemoveAll(j.Dir)
		return res, rejectf("设任务目录权限失败: %v", err)
	}
	defer func() {
		if n, serr := b.P.Sweep(); serr != nil || n > 0 {
			msg := fmt.Sprintf("任务结束后还有任务账户的进程活着（%d 个，%v）：有进程逃出了作业对象，重启前不接任务", n, serr)
			b.setHard(msg)
			res.Notes = append(res.Notes, msg)
		}
		if rerr := b.P.Revoke(j.Dir); rerr != nil {
			msg := "收回任务目录权限失败（不收回下一个任务就能读这一份输出），重启前不接任务: " + rerr.Error()
			b.setHard(msg)
			res.Notes = append(res.Notes, msg)
		}
	}()
	env := JobEnv(j.Dir, j.EnvDir, b.sysEnv())
	cfg, err := b.canaryConfig(j, env)
	if err != nil {
		return res, rejectf("%v", err)
	}
	if err := b.resetScratch(j.Dir); err != nil {
		return res, rejectf("准备 tmp\\: %v", err)
	}
	cf, err := writeCanaryFiles(j.Dir, cfg)
	if err != nil {
		return res, rejectf("写金丝雀: %v", err)
	}
	out, err := b.sysCanary(ctx, j, env, cf)
	if err != nil {
		return res, err
	}
	if err := CheckCanary(out, SysChecks); err != nil {
		b.setSoft("系统控制金丝雀不符（本机配置漂移，重跑 install.ps1）: " + err.Error())
		return res, rejectf("系统控制金丝雀不符（本机配置漂移，不是任务的问题）: %v", err)
	}
	out, err = b.hookCanary(ctx, j, env, cf)
	if err != nil {
		return res, err
	}
	if err := CheckCanary(out, hookWant); err != nil {
		return res, rejectf("环境层 %s 的审计钩子检查不符: %v", filepath.Base(j.EnvDir), err)
	}
	if err := b.resetScratch(j.Dir); err != nil {
		return res, rejectf("清空 tmp\\: %v", err)
	}
	return b.runJob(ctx, j, env)
}

// hookWant 是钩子金丝雀的单子加上探针从审计管道核对的三项。
var hookWant = append(append([]string{}, HookChecks...), "ready_main", "ready_in_layer", "ready_child")

// resetScratch 清空 tmp\ 和 output\（金丝雀留下的），建好 home 和缓存目录。
func (b *Box) resetScratch(dir string) error {
	for _, d := range Writable {
		ents, err := os.ReadDir(filepath.Join(dir, d))
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := os.RemoveAll(filepath.Join(dir, d, e.Name())); err != nil {
				return err
			}
		}
	}
	for _, h := range HomeDirs {
		if err := os.MkdirAll(filepath.Join(dir, "tmp", filepath.FromSlash(strings.ReplaceAll(h, `\`, "/"))), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// startFailed 把起不来的错误变成 rejected；登录类的还要停接任务。
func (b *Box) startFailed(err error) error {
	var le *LogonError
	if errors.As(err, &le) {
		b.setSoft(le.Error() + "，重跑 install.ps1")
		return rejectf("%v（本机停接任务）", le)
	}
	return rejectf("起不来: %v", err)
}

// launch 起一个金丝雀、等它结束（最多 CanaryTimeout），返回它写的 stdout。
func (b *Box) launch(ctx context.Context, j Job, env, args []string, onStart func(int)) ([]byte, error) {
	path := filepath.Join(j.Dir, "canary.out")
	f, err := os.Create(path)
	if err != nil {
		return nil, rejectf("建 canary.out: %v", err)
	}
	defer f.Close()
	l := jobrun.Launch{Path: j.Interp, Args: args, Dir: filepath.Join(j.Dir, "code"), Env: env, Log: f}
	if err := checkCmdLine(l); err != nil {
		return nil, rejectf("金丝雀: %v", err)
	}
	p, err := b.P.Start(l)
	if err != nil {
		return nil, b.startFailed(err)
	}
	defer p.Close()
	if onStart != nil {
		onStart(p.Pid())
	}
	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	t := time.NewTimer(b.canaryTimeout())
	defer t.Stop()
	select {
	case <-done:
	case <-ctx.Done():
		p.Kill()
		<-done
		return nil, ctx.Err()
	case <-t.C:
		p.Kill()
		<-done
		return nil, rejectf("金丝雀 %s 内没跑完", b.canaryTimeout())
	}
	f.Close()
	return os.ReadFile(path)
}

func (b *Box) sysCanary(ctx context.Context, j Job, env []string, cf canaryPaths) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return b.launch(ctx, j, env, []string{"-I", "-S", "-c", canaryBoot, cf.sys, cf.cfg}, nil)
}

func (b *Box) hookCanary(ctx context.Context, j Job, env []string, cf canaryPaths) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	log := NewLog(AuditMax)
	srv, err := b.P.Audit()
	if err != nil {
		return nil, rejectf("建审计管道: %v", err)
	}
	w := newWatcher(log, b.readyTimeout(), b.grace(), j.Dir)
	stop := serveAudit(srv, w)
	main := 0
	args := append(append([]string{}, envlayer.Flags...), "-c", canaryBoot, cf.hook, cf.cfg)
	out, err := b.launch(ctx, j, env, args, func(pid int) { main = pid; w.Start(pid) })
	stop()
	if err != nil {
		return nil, err
	}
	var extra strings.Builder
	line := func(name string, ok bool, detail string) {
		st := "fail"
		if ok {
			st = "ok"
		}
		fmt.Fprintf(&extra, "CANARY %s %s %s\n", st, name, detail)
	}
	r, ok := log.ReadyOf(main)
	line("ready_main", ok, "主进程的就绪记录（没有 = 环境层没有审计钩子）")
	line("ready_in_layer", ok && within(r.File, j.EnvDir), "sitecustomize 要在环境层里: "+r.File)
	line("ready_child", log.ChildReady(main), "multiprocessing 子进程的就绪记录")
	return append(out, extra.String()...), nil
}

// winNorm 是 Windows 规则的比较形式：不分大小写，/ 和 \ 一样，去掉结尾的分隔符。
func winNorm(s string) string {
	return strings.TrimRight(strings.ToLower(strings.ReplaceAll(s, "/", `\`)), `\`)
}

// sameDir 按 Windows 规则判断两个目录是不是同一个（空的不算）。
func sameDir(a, b string) bool { return a != "" && winNorm(a) == winNorm(b) }

// within 按 Windows 规则判断 p 在不在 dir 下（不分大小写，/ 和 \ 一样）。
func within(p, dir string) bool {
	p, dir = winNorm(p), winNorm(dir)
	return dir != "" && strings.HasPrefix(p, dir+`\`)
}

func (b *Box) runJob(ctx context.Context, j Job, env []string) (Result, error) {
	log := NewLog(AuditMax)
	srv, err := b.P.Audit()
	if err != nil {
		return Result{}, rejectf("建审计管道: %v", err)
	}
	w := newWatcher(log, b.readyTimeout(), b.grace(), j.Dir)
	stop := serveAudit(srv, w)
	main := 0
	r, err := jobrun.Run(ctx, jobrun.Spec{Dir: j.Dir, Interp: j.Interp, Entry: j.Entry, Timeout: j.Timeout, DiskMaxMB: j.DiskMaxMB,
		Env: j.Env, CheckEvery: j.CheckEvery, Start: limitStarter{b.P}, BaseEnv: env,
		OnStart: func(pid int) { main = pid; w.Start(pid) }, Abort: w.Abort()})
	stop()
	res := Result{Result: r, Audit: log.Summary(main), AuditLog: log.Bytes()}
	if err != nil {
		return res, b.startFailed(err)
	}
	switch {
	case r.Killed == AbortNoReady:
		return res, rejectf("审计钩子没装上：主进程 %s 内没发就绪，整树杀", b.readyTimeout())
	case r.Killed == "" && !res.Audit.Ready:
		return res, rejectf("审计钩子没装上：主进程没发就绪就退出了（退出码 %d）", r.ExitCode)
	}
	return res, nil
}

// serveAudit 收连接交给 watcher。返回的 stop 在进程树结束后调：不再收新连接，
// 等已有连接读完（进程都死了，管道会 EOF；最多 3 秒，逃出作业的进程攥着也不等），再关掉。
// Serve 在 watcher 停了以后也接着读完，所以最后几条记录不会丢。
func serveAudit(srv AuditServer, w *watcher) (stop func()) {
	var (
		mu    sync.Mutex
		conns []io.ReadCloser
		wg    sync.WaitGroup
		acc   = make(chan struct{})
	)
	go func() {
		defer close(acc)
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			wg.Add(1)
			mu.Unlock()
			go func() { defer wg.Done(); w.Serve(c) }()
		}
	}()
	return func() {
		srv.Close()
		<-acc
		drained := make(chan struct{})
		go func() { wg.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(3 * time.Second):
		}
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		select { // 关了还读不完（Windows 上同步 ReadFile 不一定被叫醒）：不等了，统计已经够用
		case <-drained:
		case <-time.After(2 * time.Second):
		}
		w.Stop()
	}
}
