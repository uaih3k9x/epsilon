//go:build windows

package main

// limited：以探针同样的身份（Users、Limited 令牌；run.ps1 用临时计划任务起）在真机上逐项实测。
// 尽量走探针自己的代码：jobbox.New 的 Platform（Health、Grant、Start、Audit、Procs、Sweep、Revoke）和 Box.Run（两次金丝雀、钩子、清场、收回）。
// 每一项的判定在 judge.go（Mac 上测）；这里只量数。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"epsilon/envlayer"
	"epsilon/jobbox"
	"epsilon/jobrun"
	"epsilon/probe"
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	wtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")

	procCreateProcessWithLogonW = advapi32.NewProc("CreateProcessWithLogonW")
	procCryptUnprotectData      = crypt32.NewProc("CryptUnprotectData")
	procLocalFree               = kernel32.NewProc("LocalFree")
	procIsProcessInJob          = kernel32.NewProc("IsProcessInJob")
	procWTSEnumerateProcessesEx = wtsapi32.NewProc("WTSEnumerateProcessesExW")
	procWTSFreeMemoryEx         = wtsapi32.NewProc("WTSFreeMemoryExW")
)

const (
	createSuspended         = 0x00000004
	startfUseShowWindow     = 0x00000001
	processQueryLimited     = 0x1000
	fileWriteData           = 0x0002
	cryptProtectUIForbidden = 0x1
	tokenElevation          = 20
)

type checker struct {
	o     limitedOpts
	w     *ResultWriter
	cfg   probe.Config
	bc    jobbox.Config
	root  string
	sys32 string
	cmd   string
}

func (c *checker) add(ch Check)      { c.w.Add(ch) }
func (c *checker) addAll(cs []Check) { c.w.AddAll(cs) }

func (c *checker) interp() string { return filepath.Join(c.o.EnvDir, envlayer.Interpreter) }

func runLimited(o limitedOpts) (code int) {
	os.MkdirAll(o.Work, 0o755)
	w, closeW, err := OpenResults(filepath.Join(o.Work, "limited.jsonl"), "helper")
	if err != nil {
		fmt.Fprintln(os.Stderr, "open results:", err)
		return 2
	}
	defer func() {
		closeW()
		os.WriteFile(filepath.Join(o.Work, "limited.done"), []byte(time.Now().Format(time.RFC3339)), 0o644)
	}()
	defer func() {
		if r := recover(); r != nil {
			w.Add(Check{ID: "0.helper_panic", Status: FAIL, Evidence: fmt.Sprintf("%v\n%s", r, debug.Stack())})
			code = 3
		}
	}()
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	c := &checker{o: o, w: w, sys32: filepath.Join(sysRoot, "System32")}
	c.cmd = filepath.Join(c.sys32, "cmd.exe")
	c.add(Check{ID: "0.helper_identity", Status: PASS, Evidence: identity()})
	cfg, err := probe.LoadConfig(o.Config)
	if err != nil {
		c.add(Check{ID: "0.config", Status: FAIL, Evidence: err.Error()})
		return 1
	}
	bc, err := probe.SandboxConfig(cfg)
	if err != nil {
		c.add(Check{ID: "0.config", Status: FAIL, Evidence: err.Error()})
		return 1
	}
	c.cfg, c.bc, c.root = cfg, bc, cfg.ArtifactRoot

	selftestRan := false
	if !o.HealthOnly {
		selftestRan = c.selftest()
	}
	b, ok := jobbox.New(bc).(*jobbox.Box)
	if !ok {
		c.add(Check{ID: "0.sandbox", Status: FAIL, Evidence: "没有沙箱: " + jobbox.New(bc).Halted()})
		return 1
	}
	t0 := time.Now()
	herr := b.Check()
	if o.HealthOnly {
		c.add(JudgeAfterRestore(herr))
		return 0
	}
	if herr != nil {
		for _, id := range []string{"2.winsta_limited", "8.dpapi_limited", "16.winsta_rebuild"} {
			c.add(Check{ID: id, Status: FAIL, Evidence: "健康检查不过: " + herr.Error()})
		}
		c.add(Check{ID: "0.rest", Status: FAIL, Evidence: "健康检查不过，后面要任务账户的检查都没跑"})
		return 1
	}
	took := time.Since(t0).Round(time.Millisecond)
	c.add(Check{ID: "2.winsta_limited", Status: PASS, Evidence: fmt.Sprintf("以探针的身份建好了窗口站和桌面 %s（健康检查 %s）", jobbox.Desktop, took)})
	c.add(Check{ID: "8.dpapi_limited", Status: PASS, Evidence: "探针的身份解得开 install.ps1（SYSTEM）写的密码文件，SID 对得上"})
	if selftestRan {
		c.add(Check{ID: "16.winsta_rebuild", Status: PASS, Evidence: "上一个进程（-sandbox-selftest）建过窗口站并退出以后，新进程又建出来了"})
	} else {
		c.add(Check{ID: "16.winsta_rebuild", Status: SKIP, Evidence: "自检没跑，没有\"上一个探针\""})
	}
	if h := b.Halted(); h != "" {
		c.add(Check{ID: "0.halted_after_check", Status: FAIL, Evidence: h})
	}
	b2, ok := jobbox.New(bc).(*jobbox.Box)
	if ok {
		c.add(JudgeCreateOnly(b2.P.Health()))
	}
	p := b.P
	c.cmdLines()
	c.startStdout(p)
	c.add(c.priorJob())
	c.procs(p)
	c.sweepTiming(p)
	envIDs := []string{"6.exit97_without_pipe", "5.blocked_controller", "5.blocked_testnet", "5.loopback_open", "13.scan", "14.inventory",
		"3.task.run", "15.treereset_locked_child", "15.mkdir700"}
	if o.EnvDir == "" {
		for _, id := range envIDs {
			c.add(Check{ID: id, Status: SKIP, Evidence: "没有环境层（D:\\epsilon\\envs\\<名字>@2，带 sitecustomize.py）"})
		}
	} else {
		c.exit97(p) // 要在审计管道测试之前：那时一个管道实例都没有
	}
	c.pipeWake(p)
	if o.EnvDir != "" {
		c.netChecks(p)
		c.scan(p)
		c.inventory(p)
		c.task(p)
		c.lockdir(p)
		c.mkdir700(p)
	}
	n, err := p.Sweep()
	st := PASS
	if err != nil || n > 0 {
		st = FAIL
	}
	c.add(Check{ID: "0.final_sweep", Status: st, Evidence: fmt.Sprintf("收尾时任务账户还有 %d 个进程（%v）", n, err)})
	return 0
}

// identity 是这个进程的用户和是否提升（报告里说明是以什么身份测的）。
func identity() string {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err.Error()
	}
	defer tok.Close()
	user := "?"
	if u, err := tok.GetTokenUser(); err == nil {
		if a, d, _, err := u.User.Sid.LookupAccount(""); err == nil {
			user = d + `\` + a
		}
	}
	var elev, n uint32
	syscall.GetTokenInformation(tok, tokenElevation, (*byte)(unsafe.Pointer(&elev)), 4, &n)
	return fmt.Sprintf("helper 以 %s 运行，提升=%v（要和探针一样：false）", user, elev != 0)
}

// selftest 跑 epsilon-probe -sandbox-selftest，把 sandbox-selftest.txt 拷进工作目录（report 逐行解析）。
func (c *checker) selftest() bool {
	if c.o.ProbeExe == "" || c.o.EnvDir == "" {
		c.add(Check{ID: "0.selftest", Status: SKIP, Evidence: "没有 epsilon-probe.exe 或环境层，-sandbox-selftest 没跑"})
		return false
	}
	out := filepath.Join(c.root, "sandbox-selftest.txt")
	os.Remove(out)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	t0 := time.Now()
	cmd := exec.CommandContext(ctx, c.o.ProbeExe, "-sandbox-selftest", c.o.EnvDir, "-config", c.o.Config,
		"-log", filepath.Join(c.o.Work, "selftest-probe.log"))
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	b, rerr := os.ReadFile(out)
	if rerr != nil {
		c.add(Check{ID: "0.selftest", Status: FAIL, Evidence: fmt.Sprintf("退出码 %d（%v），没有 %s: %v", code, err, out, rerr)})
		return true
	}
	os.WriteFile(filepath.Join(c.o.Work, "sandbox-selftest.txt"), b, 0o644)
	st := PASS
	if ctx.Err() != nil {
		st = FAIL
	}
	c.add(Check{ID: "0.selftest", Status: st, Evidence: fmt.Sprintf("退出码 %d，%s（逐项见 selftest.* 各行）", code, time.Since(t0).Round(time.Second))})
	return true
}

// prepDir 建一个测试任务目录 jobs\_check-<name>（和 jobrun.Prepare 展开的一样），code\main.py 是 job_check.py。
func (c *checker) prepDir(name string, extra map[string]string) (string, error) {
	dir := filepath.Join(c.root, "jobs", "_check-"+name)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	for _, d := range []string{"code", "data", "output", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return "", err
		}
	}
	files := map[string]string{filepath.Join(dir, "params.json"): "{}\n", filepath.Join(dir, "code", "main.py"): jobCheckSrc}
	for k, v := range extra {
		files[filepath.Join(dir, "code", k)] = v
	}
	for p, s := range files {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			return "", err
		}
	}
	for _, h := range jobbox.HomeDirs {
		os.MkdirAll(filepath.Join(dir, "tmp", h), 0o755)
	}
	return dir, nil
}

// withJobDir：建目录、Grant，跑完收回、删掉。
func (c *checker) withJobDir(p jobbox.Platform, name string, extra map[string]string, fn func(dir string)) {
	dir, err := c.prepDir(name, extra)
	if err != nil {
		c.add(Check{ID: "0.prep_" + name, Status: FAIL, Evidence: err.Error()})
		return
	}
	if err := p.Grant(dir); err != nil {
		c.add(Check{ID: "4.grant_" + name, Status: FAIL, Evidence: err.Error()})
		p.Revoke(dir)
		os.RemoveAll(dir)
		return
	}
	defer func() {
		if err := p.Revoke(dir); err != nil {
			c.add(Check{ID: "0.revoke_" + name, Status: FAIL, Evidence: err.Error()})
		}
		os.RemoveAll(dir)
	}()
	fn(dir)
}

func (c *checker) launchEnv(dir string) []string {
	env := c.o.EnvDir
	if env == "" {
		env = c.sys32
	}
	return jobbox.JobEnv(dir, env, os.Environ())
}

// start 以任务账户起进程（Platform.Start：CreateProcessWithLogonW 挂起 → 作业对象 → 恢复），输出写 dir\check.out。
func (c *checker) start(p jobbox.Platform, dir, exe string, args []string) (jobrun.Proc, *os.File, error) {
	f, err := os.Create(filepath.Join(dir, "check.out"))
	if err != nil {
		return nil, nil, err
	}
	pr, err := p.Start(jobrun.Launch{Path: exe, Args: args, Dir: filepath.Join(dir, "code"), Env: c.launchEnv(dir), Log: f})
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return pr, f, nil
}

func waitProc(pr jobrun.Proc, timeout time.Duration) (int, error) {
	done := make(chan int, 1)
	go func() { code, _ := pr.Wait(); done <- code }()
	select {
	case code := <-done:
		return code, nil
	case <-time.After(timeout):
		pr.Kill()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		return -1, fmt.Errorf("%s 内没结束，杀了", timeout)
	}
}

// launch 起、等、收输出。
func (c *checker) launch(p jobbox.Platform, dir, exe string, args []string, timeout time.Duration) (int, string, time.Duration, error) {
	t0 := time.Now()
	pr, f, err := c.start(p, dir, exe, args)
	if err != nil {
		return -1, "", 0, err
	}
	code, err := waitProc(pr, timeout)
	pr.Close()
	f.Close()
	out, _ := os.ReadFile(filepath.Join(dir, "check.out"))
	return code, string(out), time.Since(t0), err
}

// cmdLines（第 18 项）：两次金丝雀和测试任务在真机路径下的命令行长度。
func (c *checker) cmdLines() {
	if c.o.EnvDir == "" {
		c.add(Check{ID: "18.cmdline_len", Status: SKIP, Evidence: "没有环境层，算不了真机路径下的长度"})
		return
	}
	j := jobbox.Job{Dir: filepath.Join(c.root, "jobs", "_check-task"), EnvDir: c.o.EnvDir, Interp: c.interp()}
	sys, hook := jobbox.CanaryCmdLines(j)
	task := jobbox.CmdLine(j.Interp, append(append([]string{}, envlayer.Flags...), "main.py", "task"))
	// 真任务的 job_id 最长多少由主控定；按 64 个字符的目录名再算一次金丝雀
	j.Dir = filepath.Join(c.root, "jobs", strings.Repeat("x", 64))
	sys64, hook64 := jobbox.CanaryCmdLines(j)
	c.add(JudgeCmdLines(map[string]int{"sys": jobbox.CmdLen(sys), "hook": jobbox.CmdLen(hook), "task": jobbox.CmdLen(task),
		"sys_id64": jobbox.CmdLen(sys64), "hook_id64": jobbox.CmdLen(hook64)}, jobbox.MaxCmdLine))
}

// startStdout（第 1 项）：挂起起来、输出重定向到文件、放进作业对象、恢复以后跑完。
func (c *checker) startStdout(p jobbox.Platform) {
	const marker = "EPSILON-CHECK-STDOUT"
	c.withJobDir(p, "start", nil, func(dir string) {
		code, out, d, err := c.launch(p, dir, c.cmd, []string{"/d", "/c", "echo", marker}, time.Minute)
		ch := Check{ID: "1.start_stdout", Status: PASS, Evidence: fmt.Sprintf("退出码 %d，%s，输出 %q", code, d.Round(time.Millisecond), trunc(out, 200))}
		if err != nil || code != 0 || !strings.Contains(out, marker) {
			ch.Status = FAIL
			if err != nil {
				ch.Evidence = err.Error() + "；" + ch.Evidence
			}
		}
		c.add(ch)
	})
}

// readPassword 和探针的健康检查一样读密码文件、DPAPI 解密（第 8 项也用它）。
func readPassword(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "secrets", jobbox.SecretFile))
	if err != nil {
		return "", err
	}
	_, blob, err := jobbox.ParseSecret(b)
	if err != nil {
		return "", err
	}
	type dataBlob struct {
		size uint32
		data *byte
	}
	ent := []byte(jobbox.SecretEntropy)
	in := dataBlob{uint32(len(blob)), &blob[0]}
	e := dataBlob{uint32(len(ent)), &ent[0]}
	var out dataBlob
	r, _, cerr := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&e)), 0, 0,
		cryptProtectUIForbidden, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return "", fmt.Errorf("CryptUnprotectData: %v", cerr)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	return string(unsafe.Slice(out.data, out.size)), nil
}

func utf16p(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// priorJob（第 1 项）：seclogon 起的挂起进程在探针指派作业之前是不是已经在某个作业里了。
func (c *checker) priorJob() Check {
	ch := Check{ID: "1.prior_job"}
	pw, err := readPassword(c.root)
	if err != nil {
		ch.Status, ch.Evidence = FAIL, "读密码: "+err.Error()
		return ch
	}
	cmdline, _ := syscall.UTF16FromString(`"` + c.cmd + `" /d /c exit 0`)
	si := syscall.StartupInfo{Desktop: utf16p(jobbox.Desktop), Flags: startfUseShowWindow}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	r, _, cerr := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(utf16p(jobbox.JobUser))), uintptr(unsafe.Pointer(utf16p("."))), uintptr(unsafe.Pointer(utf16p(pw))),
		0, uintptr(unsafe.Pointer(utf16p(c.cmd))), uintptr(unsafe.Pointer(&cmdline[0])), createSuspended, 0,
		uintptr(unsafe.Pointer(utf16p(c.sys32))), uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		ch.Status, ch.Evidence = FAIL, fmt.Sprintf("CreateProcessWithLogonW: %v", cerr)
		return ch
	}
	var in int32
	r, _, ierr := procIsProcessInJob.Call(uintptr(pi.Process), 0, uintptr(unsafe.Pointer(&in)))
	syscall.TerminateProcess(pi.Process, 1)
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)
	switch {
	case r == 0:
		ch.Status, ch.Evidence = FAIL, fmt.Sprintf("IsProcessInJob: %v", ierr)
	case in == 0:
		ch.Status, ch.Evidence = PASS, "seclogon 起的挂起进程不在任何作业里，探针的作业对象是第一个"
	default:
		ch.Status, ch.Evidence = MANUAL, "seclogon 已经把它放进了一个作业（嵌套作业）：探针的指派仍然成功（见 1.start_stdout），但外层作业的限制不归探针管"
	}
	return ch
}

// wtsStats 是 WTSEnumerateProcessesExW 的原始统计：一共几个进程、几个查不到 SID（pUserSid 为空），pid 是不是其中之一。
func wtsStats(pid int) (total, nilSID int, pidNil bool, err error) {
	type info struct {
		SessionID, ProcessID uint32
		ProcessName          *uint16
		UserSid              *syscall.SID
		Threads, Handles     uint32
		PagefileUsage        uint32
		PeakPagefileUsage    uint32
		WorkingSetSize       uint32
		PeakWorkingSetSize   uint32
		UserTime, KernelTime int64
	}
	level := uint32(1)
	var p unsafe.Pointer
	var n uint32
	if r, _, e := procWTSEnumerateProcessesEx.Call(0, uintptr(unsafe.Pointer(&level)), 0xfffffffe, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n))); r == 0 {
		return 0, 0, false, e
	}
	defer procWTSFreeMemoryEx.Call(1, uintptr(p), uintptr(n))
	for _, pr := range unsafe.Slice((*info)(p), n) {
		total++
		if pr.UserSid == nil {
			nilSID++
			if int(pr.ProcessID) == pid {
				pidNil = true
			}
		}
	}
	return total, nilSID, pidNil, nil
}

// inJob（第 1 项）：起来的任务进程确实在作业里。
func inJob(pid int) Check {
	ch := Check{ID: "1.in_job"}
	h, err := syscall.OpenProcess(processQueryLimited, false, uint32(pid))
	if err != nil {
		ch.Status, ch.Evidence = SKIP, fmt.Sprintf("探针打不开任务进程查询（%v）", err)
		return ch
	}
	defer syscall.CloseHandle(h)
	var in int32
	if r, _, e := procIsProcessInJob.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&in))); r == 0 {
		ch.Status, ch.Evidence = FAIL, fmt.Sprintf("IsProcessInJob: %v", e)
		return ch
	}
	if in == 0 {
		ch.Status, ch.Evidence = FAIL, "任务进程不在作业里"
	} else {
		ch.Status, ch.Evidence = PASS, "任务进程在作业里"
	}
	return ch
}

// procs（第 10 项）：非管理员的探针列得出任务账户的进程、结束得了。
func (c *checker) procs(p jobbox.Platform) {
	c.withJobDir(p, "procs", nil, func(dir string) {
		// 要一个稳稳活 30 秒的进程：有环境层用 python sleep，没有就让 cmd 空转（ping 回环可能被拦、马上退出）
		exe, args := c.cmd, []string{"/d", "/c", "for /l %i in (1,1,2000000000) do @rem"}
		if c.o.EnvDir != "" {
			exe, args = c.interp(), []string{"-I", "-S", "-c", "import time; time.sleep(30)"}
		}
		pr, f, err := c.start(p, dir, exe, args)
		if err != nil {
			c.add(Check{ID: "10.visible", Status: FAIL, Evidence: "起不来: " + err.Error()})
			return
		}
		defer f.Close()
		defer pr.Close()
		time.Sleep(1500 * time.Millisecond)
		pids, perr := p.Procs()
		total, nilSID, pidNil, werr := wtsStats(pr.Pid())
		ev := fmt.Sprintf("任务账户的进程 %v（主进程 %d，%v）；全部 %d 个进程里 %d 个查不到 SID（%v），主进程查不到 SID=%v",
			pids, pr.Pid(), perr, total, nilSID, werr, pidNil)
		st := PASS
		if perr != nil || !slices.Contains(pids, pr.Pid()) {
			st = FAIL
		}
		c.add(Check{ID: "10.visible", Status: st, Evidence: ev})
		c.add(inJob(pr.Pid()))
		t0 := time.Now()
		n, serr := p.Sweep()
		_, werr = waitProc(pr, 10*time.Second)
		st = PASS
		if serr != nil || n < 1 || werr != nil {
			st = FAIL
		}
		c.add(Check{ID: "10.terminate", Status: st, Evidence: fmt.Sprintf("Sweep 找到 %d 个（%v），主进程 %v，%s", n, serr, werr, time.Since(t0).Round(time.Millisecond))})
	})
}

// sweepTiming（第 10 项）：普通进程退出、作业关掉以后，多久从枚举里消失（探针宽限 3 秒）。
func (c *checker) sweepTiming(p jobbox.Platform) {
	grace := 3 * time.Second
	measure := func(dir, exe string, args []string) (time.Duration, error) {
		pr, f, err := c.start(p, dir, exe, args)
		if err != nil {
			return 0, err
		}
		_, werr := waitProc(pr, time.Minute)
		pr.Close()
		f.Close()
		if werr != nil {
			return 0, werr
		}
		t0 := time.Now()
		for {
			pids, err := p.Procs()
			if err != nil {
				return 0, err
			}
			if len(pids) == 0 || time.Since(t0) > 10*time.Second {
				return time.Since(t0), nil
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	c.withJobDir(p, "sweep", nil, func(dir string) {
		run := func(id, exe string, args []string, n int) {
			var ds []time.Duration
			var ferr error
			for i := 0; i < n; i++ {
				d, err := measure(dir, exe, args)
				if err != nil {
					ferr = err
					break
				}
				ds = append(ds, d)
			}
			c.add(JudgeSweepTimes(id, ds, grace, ferr))
		}
		run("10.sweep_after_exit_cmd", c.cmd, []string{"/d", "/c", "exit 0"}, 5)
		if c.o.EnvDir != "" {
			run("10.sweep_after_exit_python", c.interp(), []string{"-I", "-S", "-c", "pass"}, 3)
		}
	})
}

// exit97（第 6 项）：没有审计管道时 sitecustomize 退出 97，用户代码一行都不跑。
func (c *checker) exit97(p jobbox.Platform) {
	c.withJobDir(p, "exit97", nil, func(dir string) {
		const marker = "USER CODE RAN"
		code, out, _, err := c.launch(p, dir, c.interp(), append(append([]string{}, envlayer.Flags...), "-c", "print('"+marker+"')"), 2*time.Minute)
		ch := JudgeExit97(code, err)
		if strings.Contains(out, marker) {
			ch.Status = FAIL
		}
		ch.Evidence += "；输出 " + trunc(oneLine(out), 300)
		c.add(ch)
	})
}

// pipeWake（第 11 项）：服务端关连接时挂着的 ReadFile 醒不醒；Close 时挂着的 ConnectNamedPipe 醒不醒。
func (c *checker) pipeWake(p jobbox.Platform) {
	srv, err := p.Audit()
	if err != nil {
		c.add(Check{ID: "11.audit_pipe", Status: FAIL, Evidence: err.Error()})
		return
	}
	type acc struct {
		c   io.ReadCloser
		err error
	}
	ch := make(chan acc, 1)
	go func() { r, err := srv.Accept(); ch <- acc{r, err} }()
	var h syscall.Handle
	for i := 0; i < 50; i++ {
		h, err = syscall.CreateFile(utf16p(jobbox.AuditPipe), fileWriteData, 0, nil, syscall.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		c.add(Check{ID: "11.client_connect", Status: FAIL, Evidence: err.Error()})
		srv.Close()
		return
	}
	var a acc
	select {
	case a = <-ch:
	case <-time.After(5 * time.Second):
		a.err = errors.New("Accept 5 秒没返回")
	}
	if a.err != nil {
		c.add(Check{ID: "11.accept", Status: FAIL, Evidence: a.err.Error()})
		syscall.CloseHandle(h)
		srv.Close()
		return
	}
	readDone := make(chan struct{})
	go func() { a.c.Read(make([]byte, 64)); close(readDone) }()
	time.Sleep(300 * time.Millisecond)
	t0 := time.Now()
	go a.c.Close()
	woke := false
	select {
	case <-readDone:
		woke = true
	case <-time.After(5 * time.Second):
	}
	c.add(JudgeWake("11.read_wakes_on_close", woke, time.Since(t0), 2*time.Second))
	syscall.CloseHandle(h)

	ch2 := make(chan acc, 1)
	go func() { r, err := srv.Accept(); ch2 <- acc{r, err} }()
	time.Sleep(300 * time.Millisecond)
	t0 = time.Now()
	srv.Close()
	woke = false
	select {
	case a2 := <-ch2:
		woke = true
		if a2.c != nil {
			a2.c.Close()
		}
	case <-time.After(6 * time.Second):
	}
	c.add(JudgeWake("11.accept_wakes_on_close", woke, time.Since(t0), 3*time.Second))
}

// ownIPv4 是本机第一个在用的非回环 IPv4 地址（"本机自己的地址也按回环处理"）。
func ownIPv4() string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return n.IP.String()
			}
		}
	}
	return ""
}

// listen 在 addr 上开一个监听，数一共收到几个连接。
func listen(addr string) (net.Listener, *atomic.Int32, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, nil, err
	}
	n := new(atomic.Int32)
	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			cn.Close()
		}
	}()
	return ln, n, nil
}

func (c *checker) runPy(p jobbox.Platform, dir, mode string, cfg any, timeout time.Duration) (string, error) {
	args := []string{"-I", "-S", filepath.Join(dir, "code", "main.py"), mode}
	if cfg != nil {
		b, _ := json.Marshal(cfg)
		path := filepath.Join(dir, "code", mode+".json")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return "", err
		}
		args = append(args, path)
	}
	_, out, _, err := c.launch(p, dir, c.interp(), args, timeout)
	return out, err
}

// netChecks（第 5 项）：任务账户（不加载钩子）连外面必须 10013；回环、本机地址照常。
func (c *checker) netChecks(p jobbox.Platform) {
	host, port, _ := net.SplitHostPort(c.bc.Controller)
	ctlPort, _ := strconv.Atoi(port)
	lo, nLo, err := listen("127.0.0.1:0")
	if err != nil {
		c.add(Check{ID: "5.loopback_open", Status: FAIL, Evidence: "探针这边开不了回环监听: " + err.Error()})
		return
	}
	defer lo.Close()
	type target struct {
		ID      string `json:"id"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Expect  string `json:"expect"`
		Timeout int    `json:"timeout"`
	}
	ts := []target{
		{"5.blocked_controller", host, ctlPort, "blocked", 5},
		{"5.blocked_testnet", "192.0.2.1", 9, "blocked", 5}, // TEST-NET-1：防火墙不拦的话是超时
		{"5.loopback_open", "127.0.0.1", lo.Addr().(*net.TCPAddr).Port, "open", 5},
	}
	want := []string{"5.blocked_controller", "5.blocked_testnet", "5.loopback_open"}
	var nOwn *atomic.Int32
	if ip := ownIPv4(); ip != "" {
		if own, n, err := listen(ip + ":0"); err == nil {
			defer own.Close()
			nOwn = n
			ts = append(ts, target{"5.own_address", ip, own.Addr().(*net.TCPAddr).Port, "either", 5})
			want = append(want, "5.own_address")
		}
	}
	c.withJobDir(p, "net", nil, func(dir string) {
		out, err := c.runPy(p, dir, "net", map[string]any{"targets": ts}, 3*time.Minute)
		why := fmt.Sprint(err)
		c.addAll(ExpectChecks(ParseCheckLines([]byte(out), "job"), want, why+" "+trunc(oneLine(out), 300)))
	})
	got := fmt.Sprintf("探针这边回环监听收到 %d 个连接", nLo.Load())
	if nOwn != nil {
		got += fmt.Sprintf("，本机地址监听收到 %d 个", nOwn.Load())
	}
	st := PASS
	if nLo.Load() == 0 {
		st = FAIL
	}
	c.add(Check{ID: "5.loopback_seen_by_probe", Status: st, Evidence: got})
	// 对照：探针自己连 TEST-NET 不能是 10013（不然拦的不是按 SID）
	_, derr := net.DialTimeout("tcp4", "192.0.2.1:9", 3*time.Second)
	ctl := Check{ID: "5.probe_not_blocked", Status: PASS, Evidence: fmt.Sprintf("探针自己连 192.0.2.1:9: %v", derr)}
	var se *os.SyscallError
	if errors.As(derr, &se) && se.Err == syscall.Errno(10013) {
		ctl.Status = FAIL
	}
	c.add(ctl)
}

// scan（第 13 项）：run.ps1 盘点的监听，任务账户绕过钩子连得上哪些。
func (c *checker) scan(p jobbox.Platform) {
	if c.o.Listeners == "" {
		c.add(Check{ID: "13.scan", Status: SKIP, Evidence: "run.ps1 没给监听清单"})
		return
	}
	b, err := os.ReadFile(c.o.Listeners)
	var ls []Listener
	if err == nil {
		ls, err = ScanTargets(b)
	}
	if err != nil {
		c.add(Check{ID: "13.scan", Status: FAIL, Evidence: "监听清单: " + err.Error()})
		return
	}
	c.withJobDir(p, "scan", nil, func(dir string) {
		out, err := c.runPy(p, dir, "scan", map[string]any{"ports": ls}, 10*time.Minute)
		c.addAll(ExpectChecks(ParseCheckLines([]byte(out), "job"), []string{"13.scan"}, fmt.Sprint(err)+" "+trunc(oneLine(out), 300)))
	})
}

// inventory（第 14 项）：任务账户读得到的 C:\ProgramData、C:\Users\Public；清单写进工作目录。
func (c *checker) inventory(p jobbox.Platform) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		pub = `C:\Users\Public`
	}
	c.withJobDir(p, "inventory", nil, func(dir string) {
		out, err := c.runPy(p, dir, "inventory", map[string]any{"roots": []string{pd, pub}, "max_lines": 5000, "max_seconds": 480}, 10*time.Minute)
		inv := ParseInventory([]byte(out))
		path := filepath.Join(c.o.Work, "inventory.txt")
		os.WriteFile(path, []byte(strings.Join(inv, "\r\n")+"\r\n"), 0o644)
		cs := ExpectChecks(ParseCheckLines([]byte(out), "job"), []string{"14.inventory"}, fmt.Sprint(err)+" "+trunc(oneLine(out), 300))
		for i := range cs {
			if cs[i].ID == "14.inventory" {
				cs[i].Evidence += "；清单 " + path
			}
		}
		c.addAll(cs)
	})
}

// boxRun 用 Box.Run 跑一个测试任务（两次金丝雀、钩子、清场、收回，和真任务一模一样）。
// 收不回、被改名隔离的目录挪进工作目录的 quarantine\（下一个 Box 启动时的收回会再改一次名，run.ps1 就找不到了）。
// inspect（可以为 nil）在删目录之前调，参数是目录现在的位置。
func (c *checker) boxRun(p jobbox.Platform, name, mode string, extra map[string]string, timeout time.Duration, inspect func(where string)) (res jobbox.Result, log string, err error) {
	dir, err := c.prepDir(name, extra)
	if err != nil {
		return res, "", err
	}
	b := jobbox.NewBox(p, c.bc)
	if err := b.Check(); err != nil {
		return res, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Minute)
	defer cancel()
	res, err = b.Run(ctx, jobbox.Job{Dir: dir, EnvDir: c.o.EnvDir, Interp: c.interp(), Entry: []string{"python", "main.py", mode}, Timeout: timeout})
	where := dir
	if res.Dir != "" {
		q := filepath.Join(c.o.Work, "quarantine", name)
		os.MkdirAll(filepath.Dir(q), 0o755)
		if merr := os.Rename(res.Dir, q); merr == nil {
			res.Dir, where = q, q
		} else {
			where = res.Dir
			c.add(Check{ID: "0.quarantine_move_" + name, Status: FAIL, Evidence: fmt.Sprintf("%s 挪不进工作目录（%v），要手工删", res.Dir, merr)})
		}
	}
	lb, _ := os.ReadFile(filepath.Join(where, "job.log"))
	os.WriteFile(filepath.Join(c.o.Work, name+"-job.log"), lb, 0o644)
	os.WriteFile(filepath.Join(c.o.Work, name+"-audit.log"), res.AuditLog, 0o644)
	for _, n := range res.Notes {
		c.add(Check{ID: "0.note_" + name, Status: PASS, Evidence: n})
	}
	if inspect != nil {
		inspect(where)
	}
	if res.Dir == "" {
		os.RemoveAll(dir)
	}
	return res, string(lb), err
}

// task（第 2、3、4、6、7、16 项）：Low IL 下 user32、文件操作、multiprocessing、torch/CUDA/cuDNN/DataLoader。
func (c *checker) task(p jobbox.Platform) {
	res, log, err := c.boxRun(p, "task", "task", map[string]string{"sitecustomize.py": shadowSitecustomize}, 20*time.Minute, nil)
	c.addAll(JudgeRun(3, "task", res, err))
	if err == nil {
		c.addAll(ExpectChecks(ParseCheckLines([]byte(log), "job"), taskChecks, "任务没跑完，看工作目录的 task-job.log"))
	}
}

// lockdir（第 15 项）：任务在 output\ 下建只给自己的受保护目录，看收回时 TreeResetNamedSecurityInfoW 怎么办。
func (c *checker) lockdir(p jobbox.Platform) {
	// 收回报了成功的话，探针现在应该读得了锁住的子目录；读不了就是 TreeReset 跳过了它
	var lerr error
	res, log, err := c.boxRun(p, "lockdir", "lockdir", nil, 5*time.Minute, func(where string) {
		_, lerr = os.ReadDir(filepath.Join(where, "output", "locked"))
	})
	c.addAll(JudgeRun(15, "lockdir", res, err))
	c.addAll(ParseCheckLines([]byte(log), "job"))
	if res.Dir != "" {
		lerr = nil
	}
	c.add(JudgeTreeReset(res.Dir, lerr, err))
}

// mkdir700（第 15 项）：os.mkdir(0o700) 之后收回。
func (c *checker) mkdir700(p jobbox.Platform) {
	res, log, err := c.boxRun(p, "mkdir700", "mkdir700", nil, 5*time.Minute, nil)
	c.addAll(JudgeRun(15, "mkdir700", res, err))
	lines := ParseCheckLines([]byte(log), "job")
	c.addAll(lines)
	ver := "?"
	for _, l := range lines {
		if l.ID == "15.mkdir700_made" {
			ver = strings.TrimPrefix(l.Evidence, "Python ")
		}
	}
	c.add(JudgeMkdir700(ver, res.Dir, err))
}
