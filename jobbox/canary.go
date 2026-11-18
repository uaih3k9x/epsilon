package jobbox

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// 金丝雀（docs/jobs-sandbox.md 第 5 节）：每个任务都跑两次，平台代码打包在探针里。

//go:embed py/canary_sys.py
var canarySysSrc string

//go:embed py/canary_hook.py
var canaryHookSrc string

// Desktop 是任务进程的窗口站\桌面。不指定的话 seclogon 会把任务账户加进 WinSta0\Default，任务就能截学生的屏、读剪贴板。
const Desktop = `epsilon-job\Default`

// SysChecks 是系统控制检查（python -I -S，不加载钩子）每一项都必须 ok 的单子；和 py/canary_sys.py 一一对应。
var SysChecks = []string{
	"integrity_low", "desktop",
	"read_probe_json", "read_secrets",
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
	"unc_blocked", "env_tamper_blocked", "tmp_py_blocked", "dlopen_tmp_blocked", "mp_child",
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
		"ctl_host": host, "ctl_port": p, "system_root": c.SystemRoot, "desktop": Desktop,
	})
	return string(b), err
}
