package jobbox

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"epsilon/envlayer"
)

// 金丝雀（docs/jobs-sandbox.md 第 5 节）：每个任务都跑两次，平台代码打包在探针里。

//go:embed py/canary_sys.py
var canarySysSrc string

//go:embed py/canary_hook.py
var canaryHookSrc string

// canaryBoot 是两次金丝雀的引导（-c 的参数）。源码有几 KB，命令行装不下（CreateProcessWithLogonW 最多 1024 个字符），
// 所以源码和配置由探针写进任务目录的 canary\（任务只读），命令行只带路径：argv[1] 源码、argv[2] 配置。
// 先去掉 sys.path 里的 ”：-c 时它是当前目录 code\，任务包里的 shutil.py、socket.py 会抢在标准库前面被金丝雀导入。
const canaryBoot = `import sys;p=sys.argv.pop(1);sys.path[:]=[x for x in sys.path if x];exec(compile(open(p,'rb').read(),p,'exec'))`

// canaryFiles 是 canary\ 下的文件：探针每次任务都重写（金丝雀和任务都只能读）。
const (
	canaryDir      = "canary"
	canarySysFile  = "sys.txt" // 不叫 .py：钩子拦 code\ 和环境层以外的 .py
	canaryHookFile = "hook.txt"
	canaryCfgFile  = "cfg.json"
)

// canaryPaths 是 canary\\ 下两份源码和配置的路径。
type canaryPaths struct{ sys, hook, cfg string }

func canaryFilePaths(jobDir string) canaryPaths {
	d := filepath.Join(jobDir, canaryDir)
	return canaryPaths{filepath.Join(d, canarySysFile), filepath.Join(d, canaryHookFile), filepath.Join(d, canaryCfgFile)}
}

func sysCanaryArgs(cf canaryPaths) []string {
	return []string{"-I", "-S", "-c", canaryBoot, cf.sys, cf.cfg}
}
func hookCanaryArgs(cf canaryPaths) []string {
	return append(append([]string{}, envlayer.Flags...), "-c", canaryBoot, cf.hook, cf.cfg)
}

// CanaryCmdLines 是两次金丝雀交给 CreateProcessWithLogonW 的命令行（真机验证套件 cmd/epsilon-sandbox-check 按真机路径核对长度）。
func CanaryCmdLines(j Job) (sys, hook string) {
	cf := canaryFilePaths(j.Dir)
	return CmdLine(j.Interp, sysCanaryArgs(cf)), CmdLine(j.Interp, hookCanaryArgs(cf))
}

// writeCanaryFiles 写 canary\\ 的三个文件（在 Grant 之后写，继承根上任务账户的只读）。
func writeCanaryFiles(jobDir, cfg string) (canaryPaths, error) {
	cf := canaryFilePaths(jobDir)
	if err := os.MkdirAll(filepath.Dir(cf.sys), 0o755); err != nil {
		return cf, err
	}
	for path, body := range map[string]string{cf.sys: canarySysSrc, cf.hook: canaryHookSrc, cf.cfg: cfg} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return cf, err
		}
	}
	return cf, nil
}

// Desktop 是任务进程的窗口站\桌面。不指定的话 seclogon 会把任务账户加进 WinSta0\Default，任务就能截学生的屏、读剪贴板。
const Desktop = `epsilon-job\Default`

// SysChecks 是系统控制检查（python -I -S，不加载钩子）每一项都必须 ok 的单子；和 py/canary_sys.py 一一对应。
var SysChecks = []string{
	"integrity_low", "privileges_dropped", "desktop", "winsta0_denied", "token_groups",
	"read_probe_json", "read_secrets", "read_data_disk", "exec_artifact_root", "hardlink_probe_json", "chdir_tmp",
	"write_code", "write_params", "delete_params", "write_job_root", "write_sitecustomize", "write_env",
	"write_tmp", "write_output",
	"exec_tmp", "load_tmp_dll", "set_dacl_own_file",
	"write_programdata", "write_windows_temp", "write_users_public",
	"connect_controller", "socketpair",
}

// HookChecks 是钩子检查（python -E -s -B，经过 sitecustomize）的单子；和 py/canary_hook.py 一一对应。
// 另外探针自己从审计管道核对：主进程的就绪记录、sitecustomize 在环境层里、multiprocessing 子进程也发了就绪。
var HookChecks = []string{
	"hook_installed", "subprocess_blocked", "spawn_flags_blocked", "connect_blocked", "dns_blocked",
	"unc_blocked", "unc_paths_blocked", "env_tamper_blocked", "tmp_py_blocked", "rename_py_blocked", "dlopen_tmp_blocked",
	"loopback_blocked", "socketpair_ok", "tamper_globals_blocked", "mp_child",
}

// CanaryLine 是金丝雀输出的一行。
type CanaryLine struct {
	Name   string
	OK     bool
	Detail string
}

// ParseCanary 只认 "CANARY ok|fail 名字 [原因]" 的行，别的（Traceback 之类）跳过。
func ParseCanary(out []byte) []CanaryLine {
	var ls []CanaryLine
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.SplitN(strings.TrimRight(line, "\r"), " ", 4)
		if len(f) < 3 || f[0] != "CANARY" || (f[1] != "ok" && f[1] != "fail") || f[2] == "" {
			continue
		}
		l := CanaryLine{Name: f[2], OK: f[1] == "ok"}
		if len(f) == 4 {
			l.Detail = strings.TrimSpace(f[3])
		}
		ls = append(ls, l)
	}
	return ls
}

// CheckCanary 对照预期：want 里每一项恰好报一次且 ok；任何 fail 行（包括单子外的）都算不符。
func CheckCanary(out []byte, want []string) error {
	seen := map[string]int{}
	var bad []string
	for _, l := range ParseCanary(out) {
		seen[l.Name]++
		if !l.OK {
			bad = append(bad, l.Name+"（"+l.Detail+"）")
		}
	}
	for _, n := range want {
		switch seen[n] {
		case 0:
			bad = append(bad, n+"（没报）")
		case 1:
		default:
			bad = append(bad, n+"（报了多次）")
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("金丝雀不符: %s", strings.Join(bad, "；"))
	}
	return nil
}

// CanaryConfig 是传给金丝雀的路径和主控地址（argv[1]，JSON）。
type CanaryConfig struct {
	JobDir, EnvDir string
	Root           string // artifact_root：probe.json、secrets\ 在这里
	Controller     string // host:port
	SystemRoot     string
}

// volumeRoot 是 artifact_root 所在卷的根（D:\）：任务账户在那里必须什么都列不出来。
func volumeRoot(p string) string {
	if len(p) >= 2 && p[1] == ':' {
		return p[:2] + `\`
	}
	return ""
}

func (c CanaryConfig) args() (string, error) {
	host, port, err := net.SplitHostPort(c.Controller)
	if err != nil {
		return "", fmt.Errorf("主控地址 %q: %v", c.Controller, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("主控端口 %q: %v", port, err)
	}
	b, err := json.Marshal(map[string]any{
		"job_dir": c.JobDir, "env_dir": c.EnvDir,
		"probe_json": winJoin(c.Root, "probe.json"), "secrets_dir": winJoin(c.Root, "secrets"),
		"data_root": volumeRoot(c.Root), "boot_exe": winJoin(c.Root, "epsilon-boot.exe"),
		"ctl_host": host, "ctl_port": p, "system_root": c.SystemRoot, "desktop": Desktop,
	})
	return string(b), err
}
