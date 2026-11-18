package jobrun

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"epsilon/winproc"
)

// 测试二进制冒充解释器：参数是 -E -B <脚本> ...，脚本内容就是要干什么。
func TestMain(m *testing.M) {
	if os.Getenv("JOBRUN_FAKE_PY") == "1" {
		os.Exit(fakePython(os.Args[1:]))
	}
	os.Exit(m.Run())
}

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
	cmd := strings.Fields(string(b))
	switch cmd[0] {
	case "ok":
		p, _ := os.ReadFile("../params.json")
		os.WriteFile("../output/RESULT.json", p, 0o644)
		fmt.Println("hello from job", strings.Join(args[3:], " "))
		return 0
	case "exit":
		n, _ := strconv.Atoi(cmd[1])
		return n
	case "tree": // 起一个孙进程，把 pid 写下来，然后都睡着
		c := exec.Command(os.Args[0], "-E", "-B", "sleep.py")
		c.Env = os.Environ()
		os.WriteFile("sleep.py", []byte("sleep"), 0o644)
		if err := c.Start(); err != nil {
			return 92
		}
		os.WriteFile("../output/child.pid", []byte(strconv.Itoa(c.Process.Pid)), 0o644)
		time.Sleep(time.Hour)
	case "sleep":
		time.Sleep(time.Hour)
	case "fill": // 往 tmp 里写 2 MB
		os.WriteFile("../tmp/big", make([]byte, 2<<20), 0o644)
		time.Sleep(time.Hour)
	}
	return 0
}

func makeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	p := filepath.Join(t.TempDir(), "code.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func prepared(t *testing.T, script string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "jobs", "j1")
	if err := Prepare(dir, makeZip(t, map[string]string{"main.py": script, "lib/x.py": "pass"}), []byte(`{"lr":0.1}`)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func spec(dir string) Spec {
	return Spec{Dir: dir, Interp: os.Args[0], Entry: []string{"python", "main.py", "--flag"}, Timeout: time.Minute,
		Env: []string{"JOBRUN_FAKE_PY=1"}, CheckEvery: 50 * time.Millisecond}
}

func TestPrepareLayout(t *testing.T) {
	dir := prepared(t, "ok")
	for _, p := range []string{"code/main.py", "code/lib/x.py", "params.json"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("缺 %s", p)
		}
	}
	for _, d := range []string{"code", "data", "output", "tmp"} {
		if fi, err := os.Stat(filepath.Join(dir, d)); err != nil || !fi.IsDir() {
			t.Errorf("缺目录 %s", d)
		}
	}
	// 重跑从头来：旧的输出不能留下
	os.WriteFile(filepath.Join(dir, "output", "stale"), []byte("x"), 0o644)
	if err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok"}), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "output", "stale")); err == nil {
		t.Fatal("上一次的输出还在")
	}
	if _, err := os.Stat(filepath.Join(dir, "code", "lib", "x.py")); err == nil {
		t.Fatal("上一次的代码还在")
	}
}

func TestPrepareRejectsBadZip(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"路径穿越":  {"../evil.py": "x"},
		"绝对路径":  {"/evil.py": "x"},
		"盘符":    {"C:/evil.py": "x"},
		"大小写冲突": {"a.py": "x", "A.py": "y"},
	} {
		dir := filepath.Join(t.TempDir(), "j")
		if err := Prepare(dir, makeZip(t, files), []byte(`{}`)); err == nil {
			t.Errorf("%s: 应该拒", name)
		}
	}
}

func TestRunOK(t *testing.T) {
	dir := prepared(t, "ok")
	res, err := Run(context.Background(), spec(dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.Killed != "" {
		t.Fatalf("结果不对: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "output", "RESULT.json")); string(b) != `{"lr":0.1}` {
		t.Fatalf("脚本没读到 params.json: %q", b)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "job.log"))
	if !strings.Contains(string(log), "hello from job --flag") {
		t.Fatalf("job.log 里没有输出: %q", log)
	}
}

func TestRunExitCode(t *testing.T) {
	res, err := Run(context.Background(), spec(prepared(t, "exit 7")))
	if err != nil || res.ExitCode != 7 || res.Killed != "" {
		t.Fatalf("要退出码 7: %+v %v", res, err)
	}
}

func waitDead(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "output", "child.pid"))
	if err != nil {
		t.Fatal("孙进程没起来")
	}
	pid, _ := strconv.Atoi(string(b))
	deadline := time.Now().Add(5 * time.Second)
	for winproc.Alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("孙进程 %d 没被杀", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRunTimeoutKillsTree(t *testing.T) {
	dir := prepared(t, "tree")
	s := spec(dir)
	s.Timeout = 700 * time.Millisecond
	start := time.Now()
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Killed != "timeout" {
		t.Fatalf("应该超时被杀: %+v", res)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("超时后等太久")
	}
	waitDead(t, dir)
}

func TestRunCancelKillsTree(t *testing.T) {
	dir := prepared(t, "tree")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			if _, err := os.Stat(filepath.Join(dir, "output", "child.pid")); err == nil {
				cancel()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	res, err := Run(ctx, spec(dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.Killed != "cancelled" {
		t.Fatalf("应该是撤销: %+v", res)
	}
	waitDead(t, dir)
}

func TestRunDiskLimit(t *testing.T) {
	dir := prepared(t, "fill")
	s := spec(dir)
	s.DiskMaxMB = 1
	res, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Killed != "disk" {
		t.Fatalf("写超了应该被杀: %+v", res)
	}
}

func TestRunNoShell(t *testing.T) {
	// entry 里的东西原样当参数传，不经 shell：分号、管道都只是字符串
	dir := prepared(t, "ok")
	s := spec(dir)
	s.Entry = []string{"python", "main.py", "a; touch pwned", "|", "$(x)"}
	if _, err := Run(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "job.log"))
	if !strings.Contains(string(log), "hello from job a; touch pwned | $(x)") {
		t.Fatalf("参数没原样传: %q", log)
	}
	if _, err := os.Stat(filepath.Join(dir, "code", "pwned")); err == nil {
		t.Fatal("经过了 shell")
	}
}

func TestRunStartFails(t *testing.T) {
	s := spec(prepared(t, "ok"))
	s.Interp = filepath.Join(t.TempDir(), "no-such-python")
	if _, err := Run(context.Background(), s); err == nil {
		t.Fatal("解释器不存在应该报错")
	}
}

func TestWrittenBytes(t *testing.T) {
	dir := prepared(t, "ok")
	os.WriteFile(filepath.Join(dir, "output", "a"), make([]byte, 1000), 0o644)
	os.MkdirAll(filepath.Join(dir, "output", "_runner"), 0o755)
	os.WriteFile(filepath.Join(dir, "output", "_runner", "s"), make([]byte, 50), 0o644)
	if n := OutputBytes(dir); n != 1000 {
		t.Fatalf("output 应该 1000 字节（不算 _runner），是 %d", n)
	}
}
