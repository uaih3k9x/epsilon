package jobbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEscapeArgWindowsRules(t *testing.T) {
	for in, want := range map[string]string{
		"":                `""`,
		`C:\a\python.exe`: `C:\a\python.exe`,
		`C:\a b\x`:        `"C:\a b\x"`,
		`a"b`:             `a\"b`,
		`a b\`:            `"a b\\"`,
		`{"k":"v"}`:       `{\"k\":\"v\"}`,
		"tab\there":       "\"tab\there\"",
	} {
		if got := escapeArg(in); got != want {
			t.Fatalf("escapeArg(%q) = %s，要 %s", in, got, want)
		}
	}
	if got := CmdLine(`C:\p y\python.exe`, []string{"-c", "x y"}); got != `"C:\p y\python.exe" -c "x y"` {
		t.Fatal(got)
	}
}

// CreateProcessWithLogonW 的 lpCommandLine 最多 1024 个字符：金丝雀源码（几 KB）不能放在命令行上
func TestEveryLaunchFitsCreateProcessWithLogonW(t *testing.T) {
	r := newRig(t, nil)
	if _, err := r.run(); err != nil {
		t.Fatal(err)
	}
	if len(r.p.launches) != 3 {
		t.Fatalf("要起三次（两次金丝雀、一次任务）: %d", len(r.p.launches))
	}
	for _, l := range r.p.launches {
		if n := cmdLen(CmdLine(l.Path, l.Args)); n > MaxCmdLine {
			t.Fatalf("命令行 %d 个字符，超过 %d: %v", n, MaxCmdLine, l.Args)
		}
	}
}

func TestTooLongCommandLineIsRejected(t *testing.T) {
	r := newRig(t, nil)
	r.job.Entry = []string{"python", "main.py", strings.Repeat("x", MaxCmdLine)}
	_, err := r.run()
	expectReject(t, err, "命令行")
	if r.b.Halted() != "" {
		t.Fatalf("是这个任务的问题，不停接: %q", r.b.Halted())
	}
	if strings.Contains(r.calls(), "start-job") {
		t.Fatal("超长的不交给系统")
	}
}

// 金丝雀源码和配置写在任务目录的 canary\ 里（任务只读），引导去掉 sys.path 里的 ”：code\ 里的同名模块抢不到标准库
func TestCanaryBootIgnoresShadowingModulesInCwd(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("没有 python3")
	}
	dir := t.TempDir()
	code := filepath.Join(dir, "code")
	os.MkdirAll(code, 0o755)
	os.WriteFile(filepath.Join(code, "json.py"), []byte("print('CANARY ok hook_installed 伪造')\nraise SystemExit(0)\n"), 0o644)
	src := filepath.Join(dir, "src.txt")
	cfg := filepath.Join(dir, "cfg.json")
	os.WriteFile(src, []byte("import json, sys\nprint('ran', json.loads(open(sys.argv[1]).read())['k'], __name__)\n"), 0o644)
	os.WriteFile(cfg, []byte(`{"k":"v"}`), 0o644)
	cmd := exec.Command(py, "-E", "-s", "-B", "-c", canaryBoot, src, cfg)
	cmd.Dir = code
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ran v __main__" {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestCanaryFilesWrittenUnderJobDir(t *testing.T) {
	r := newRig(t, nil)
	if _, err := r.run(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"sys.txt", "hook.txt", "cfg.json"} {
		if _, err := os.Stat(filepath.Join(r.job.Dir, "canary", f)); err != nil {
			t.Fatalf("canary\\%s: %v", f, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(r.job.Dir, "canary", "sys.txt"))
	if string(b) != canarySysSrc {
		t.Fatal("sys.txt 要是打包在探针里的源码")
	}
}
