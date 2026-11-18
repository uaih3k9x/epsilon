package jobbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func okLines(names []string) string {
	var b strings.Builder
	for _, n := range names {
		b.WriteString("CANARY ok " + n + " \n")
	}
	return b.String()
}

func TestCheckCanaryAllOK(t *testing.T) {
	out := "Traceback noise\n" + okLines(SysChecks) + "something else\n"
	if err := CheckCanary([]byte(out), SysChecks); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCanaryEveryMismatchRejects(t *testing.T) {
	for i, name := range SysChecks {
		lines := strings.Split(strings.TrimSpace(okLines(SysChecks)), "\n")
		// 一项失败
		failed := append([]string{}, lines...)
		failed[i] = "CANARY fail " + name + " 写进去了"
		if err := CheckCanary([]byte(strings.Join(failed, "\n")), SysChecks); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s 失败要拒并写明: %v", name, err)
		}
		// 一项没报（金丝雀中途崩了）
		missing := append(append([]string{}, lines[:i]...), lines[i+1:]...)
		if err := CheckCanary([]byte(strings.Join(missing, "\n")), SysChecks); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s 没报要拒: %v", name, err)
		}
		// 一项报了两次（有人往 stdout 里塞）
		dup := append(append([]string{}, lines...), "CANARY ok "+name)
		if err := CheckCanary([]byte(strings.Join(dup, "\n")), SysChecks); err == nil {
			t.Fatalf("%s 报两次要拒", name)
		}
	}
}

func TestCheckCanaryUnknownFailRejects(t *testing.T) {
	out := okLines(SysChecks) + "CANARY fail extra 什么\n"
	if err := CheckCanary([]byte(out), SysChecks); err == nil {
		t.Fatal("不认识的失败项也要拒")
	}
}

func TestParseCanaryDetail(t *testing.T) {
	ls := ParseCanary([]byte("CANARY fail write_tmp PermissionError: [WinError 5] 拒绝访问\r\nCANARY ok desktop epsilon-job\\Default\n"))
	if len(ls) != 2 || ls[0].Name != "write_tmp" || ls[0].OK || !strings.Contains(ls[0].Detail, "WinError 5") || !ls[1].OK || ls[1].Detail != `epsilon-job\Default` {
		t.Fatalf("%+v", ls)
	}
}

// 真跑一遍 Python 金丝雀（Mac 上每项都失败）：名字要和 Go 这边的单子一一对上，一项不能漏
func TestCanaryScriptsReportEveryCheck(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("没有 python3")
	}
	for _, c := range []struct {
		src  string
		want []string
	}{{canarySysSrc, SysChecks}, {canaryHookSrc, HookChecks}} {
		// 和 Box 一样：源码、配置写成文件，经引导执行
		dir := t.TempDir()
		src, cfg := filepath.Join(dir, "src.txt"), filepath.Join(dir, "cfg.json")
		os.WriteFile(src, []byte(c.src), 0o644)
		os.WriteFile(cfg, []byte("{}"), 0o644)
		cmd := exec.Command(py, "-I", "-S", "-c", canaryBoot, src, cfg)
		cmd.Dir = dir
		out, _ := cmd.CombinedOutput()
		got := map[string]int{}
		for _, l := range ParseCanary(out) {
			got[l.Name]++
		}
		for _, n := range c.want {
			if got[n] != 1 {
				t.Fatalf("金丝雀没报（或报了多次）%s:\n%s", n, out)
			}
		}
		if len(got) != len(c.want) {
			t.Fatalf("金丝雀报了单子外的项: %v", got)
		}
		if CheckCanary(out, c.want) == nil {
			t.Fatal("Mac 上不可能全过")
		}
	}
}

func TestLowerIntegrityCodeIsIdenticalInHookAndCanary(t *testing.T) {
	block := func(s string) string {
		i, j := strings.Index(s, "# ---- winsec begin"), strings.Index(s, "# ---- winsec end ----")
		if i < 0 || j < i {
			t.Fatal("缺 winsec 标记")
		}
		return s[i:j]
	}
	site, err := os.ReadFile("py/sitecustomize.py")
	if err != nil {
		t.Fatal(err)
	}
	if block(string(site)) != block(canarySysSrc) {
		t.Fatal("sitecustomize.py 和 canary_sys.py 的降级代码不一样了")
	}
}

func TestCanaryConfigJSON(t *testing.T) {
	c := CanaryConfig{JobDir: `D:\epsilon\jobs\a`, EnvDir: `D:\epsilon\envs\x@2`, Root: `D:\epsilon`, Controller: "ctl.example:8090", SystemRoot: `C:\Windows`}
	m, err := c.args()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"probe_json":"D:\\epsilon\\probe.json"`, `"secrets_dir":"D:\\epsilon\\secrets"`, `"ctl_host":"ctl.example"`, `"ctl_port":8090`, `"desktop":"epsilon-job\\Default"`} {
		if !strings.Contains(m, want) {
			t.Fatalf("缺 %s: %s", want, m)
		}
	}
	if _, err := (CanaryConfig{Controller: "nohost"}).args(); err == nil {
		t.Fatal("主控地址要有端口")
	}
}
