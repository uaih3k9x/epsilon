package jobrun

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
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

// 测试二进制冒充解释器：参数是 -E -s -B <脚本> ...，脚本内容就是要干什么。
func TestMain(m *testing.M) {
	if os.Getenv("JOBRUN_FAKE_PY") == "1" {
		os.Exit(fakePython(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakePython(args []string) int {
	if len(args) < 4 || args[0] != "-E" || args[1] != "-s" || args[2] != "-B" {
		fmt.Fprintln(os.Stderr, "参数不对:", args)
		return 90
	}
	args = args[1:] // 下面按 [-B, 脚本, 参数...] 用
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
		c := exec.Command(os.Args[0], "-E", "-s", "-B", "sleep.py")
		c.Env = os.Environ()
		os.WriteFile("sleep.py", []byte("sleep"), 0o644)
		if err := c.Start(); err != nil {
			return 92
		}
		os.WriteFile("../output/child.pid", []byte(strconv.Itoa(c.Process.Pid)), 0o644)
		time.Sleep(time.Hour)
	case "sleep":
		time.Sleep(time.Hour)
	case "args": // 把解释器收到的参数写下来
		os.WriteFile("../output/args", []byte(strings.Join(os.Args[1:], " ")), 0o644)
		return 0
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

func TestRunDisablesUserSite(t *testing.T) {
	// -E 不关用户 site-packages：%APPDATA%\Python\...\site-packages 里的 .pth 每次启动都会执行，
	// 一个任务埋下的东西会跑进以后每个任务。必须带 -s。
	dir := prepared(t, "args")
	if _, err := Run(context.Background(), spec(dir)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "output", "args"))
	if !strings.HasPrefix(string(b), "-E -s -B main.py") {
		t.Fatalf("解释器参数要以 -E -s -B 开头: %q", b)
	}
}

func TestPrepareRejectsWindowsNames(t *testing.T) {
	bad := []string{"nul", "CON.py", "lib/aux.txt", "Com1.log", "lpt9", "conin$", "helper.py.", "lib./x.py", "a /b.py", "x.py "}
	for _, name := range bad {
		dir := filepath.Join(t.TempDir(), "j")
		if err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok", name: "x"}), []byte(`{}`)); err == nil {
			t.Errorf("%q: Windows 上落不了盘或会变名，应该拒", name)
		}
	}
	good := []string{"console.py", "nul_utils.py", "com10.py", "auxiliary/x.py", "con1x.txt", ".hidden"}
	for _, name := range good {
		dir := filepath.Join(t.TempDir(), "j")
		if err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok", name: "x"}), []byte(`{}`)); err != nil {
			t.Errorf("%q 应该能用: %v", name, err)
		}
	}
}

func TestPrepareRejectsLongPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "j")
	long := strings.Repeat("a", 100) + "/" + strings.Repeat("b", 100) + "/" + strings.Repeat("c", 100) + ".py"
	if err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok", long: "x"}), []byte(`{}`)); err == nil {
		t.Fatal("路径总长超过 260 应该拒")
	}
}

func TestPrepareRejectsOversizeZip(t *testing.T) {
	old := codeMaxBytes
	codeMaxBytes = 100
	defer func() { codeMaxBytes = old }()
	dir := filepath.Join(t.TempDir(), "j")
	err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok", "big.bin": strings.Repeat("x", 200)}), []byte(`{}`))
	if err == nil {
		t.Fatal("解压后超过上限应该在解压前拒")
	}
	if _, serr := os.Stat(filepath.Join(dir, "code")); serr == nil {
		t.Fatal("超限要在动手之前拒，不能先解一半")
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

func TestPrepareRejectsSiteCustomize(t *testing.T) {
	// 环境层的审计钩子就是 sitecustomize；代码包里同名文件虽然导入顺序上抢不到，也一律不收
	for _, name := range []string{"sitecustomize.py", "lib/SiteCustomize.py", "usercustomize.py", "a/b/usercustomize.py"} {
		dir := filepath.Join(t.TempDir(), "j")
		if err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok", name: "x"}), []byte(`{}`)); err == nil {
			t.Errorf("%q 应该拒", name)
		}
	}
	dir := filepath.Join(t.TempDir(), "j")
	if err := Prepare(dir, makeZip(t, map[string]string{"main.py": "ok", "my_sitecustomize.py": "x"}), []byte(`{}`)); err != nil {
		t.Errorf("名字只是包含它的可以: %v", err)
	}
}

type fakeProc struct {
	pid    int
	code   int
	done   chan struct{}
	killed bool
	closed bool
}

func (p *fakeProc) Pid() int { return p.pid }
func (p *fakeProc) Wait() (int, error) {
	<-p.done
	if p.killed {
		return -1, nil
	}
	return p.code, nil
}
func (p *fakeProc) Kill() {
	if !p.killed {
		p.killed = true
		close(p.done)
	}
}
func (p *fakeProc) Close() { p.closed = true }

type fakeStarter struct {
	got  Launch
	proc *fakeProc
	err  error
}

func (f *fakeStarter) Start(l Launch) (Proc, error) {
	f.got = l
	if f.err != nil {
		return nil, f.err
	}
	return f.proc, nil
}

func TestRunUsesStarterWithBaseEnv(t *testing.T) {
	dir := prepared(t, "ok")
	p := &fakeProc{pid: 4242, code: 3, done: make(chan struct{})}
	close(p.done)
	f := &fakeStarter{proc: p}
	s := spec(dir)
	s.Start = f
	s.BaseEnv = []string{"SystemRoot=C:\\Windows", "TMP=x"}
	var started int
	s.OnStart = func(pid int) { started = pid }
	res, err := Run(context.Background(), s)
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	if started != 4242 || !p.closed {
		t.Fatalf("OnStart 拿到 pid、结束后 Close: %d %v", started, p.closed)
	}
	if f.got.Path != os.Args[0] || strings.Join(f.got.Args, " ") != "-E -s -B main.py --flag" || f.got.Dir != filepath.Join(dir, "code") || f.got.Log == nil {
		t.Fatalf("%+v", f.got)
	}
	// 给了 BaseEnv 就不继承探针的环境
	if strings.Join(f.got.Env, "|") != "SystemRoot=C:\\Windows|TMP=x|JOBRUN_FAKE_PY=1" {
		t.Fatalf("环境: %v", f.got.Env)
	}
}

type startErr struct{}

func (startErr) Error() string { return "1326" }

func TestRunStartErrorIsWrapped(t *testing.T) {
	s := spec(prepared(t, "ok"))
	s.Start = &fakeStarter{err: startErr{}}
	_, err := Run(context.Background(), s)
	var se startErr
	if !errors.As(err, &se) {
		t.Fatalf("起不来的原因要能取出来（判断要不要停接任务）: %v", err)
	}
}

func TestRunAbortKillsTree(t *testing.T) {
	dir := prepared(t, "tree")
	s := spec(dir)
	abort := make(chan string, 1)
	s.Abort = abort
	go func() {
		for {
			if _, err := os.Stat(filepath.Join(dir, "output", "child.pid")); err == nil {
				abort <- "audit"
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	res, err := Run(context.Background(), s)
	if err != nil || res.Killed != "audit" {
		t.Fatalf("要按中止原因杀: %+v %v", res, err)
	}
	waitDead(t, dir)
}
