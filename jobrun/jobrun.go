// Package jobrun 是批任务在学生机上的执行器（设计书 22.4、手册 5.3）：展开任务目录、按 entry 起进程、整树监管。
//
// 任务目录 <artifact_root>/jobs/<id>/：
//
//	code/        code.zip 解压出来，工作目录
//	data/        数据集（这一版还不挂，见 docs/jobs.md）
//	params.json  主控填、探针核过的参数
//	output/      结果，结束后回传；output/_runner/ 是平台保留
//	tmp/         临时文件，不回传
//	job.log      stdout + stderr
//
// 怎么起进程由 Spec.Start 决定：探针在 Windows 上用 jobbox 的沙箱（专用账户、ACL、独立桌面、作业对象，
// docs/jobs-sandbox.md）；Plain 是不受限的 exec + 作业对象，只给测试和 Mac 上的假沙箱用。
package jobrun

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"epsilon/chunk"
	"epsilon/envlayer"
	"epsilon/winproc"
)

// Runner 是 output/ 下的平台保留目录（运行摘要、日志副本）。
const Runner = "_runner"

// codeMaxBytes 是代码包解压后的总大小上限（设计书 20.4 第 4 条，防压缩炸弹）。测试里改小。
var codeMaxBytes int64 = 256 << 20

// maxPath 是 Windows 不开长路径时的上限（MAX_PATH 260，含结尾的 NUL），按 UTF-16 计。
const maxPath = 259

// Prepare 从头展开任务目录：旧的整个删掉（重跑从头来），解压代码包，写 params.json。
// 代码包先整个查一遍再写（设计书 20.4、20.5）：路径穿越、链接、大小写冲突、Windows 保留名、
// 段尾点和空格、路径总长、解压后总大小，有一条不过就整包拒。
func Prepare(dir, codeZip string, params []byte) error {
	zr, err := zip.OpenReader(codeZip)
	if err != nil {
		return fmt.Errorf("代码包打不开: %v", err)
	}
	defer zr.Close()
	if err := checkZip(zr.File); err != nil {
		return err
	}
	for _, f := range zr.File {
		p := filepath.Join(dir, "code", filepath.FromSlash(strings.TrimSuffix(f.Name, "/")))
		if len(utf16.Encode([]rune(p))) > maxPath {
			return fmt.Errorf("代码包里的路径展开后超过 %d 字符: %q", maxPath, f.Name)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, d := range []string{"code", "data", "output", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return err
		}
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		path := filepath.Join(dir, "code", filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeEntry(f, path); err != nil {
			return fmt.Errorf("解压 %s: %v", f.Name, err)
		}
	}
	return os.WriteFile(filepath.Join(dir, "params.json"), params, 0o644)
}

func checkZip(files []*zip.File) error {
	seen := map[string]bool{}
	var total uint64
	for _, f := range files {
		name := strings.TrimSuffix(f.Name, "/")
		if !chunk.SafePath(name) || !chunk.WindowsSafe(name) {
			return fmt.Errorf("代码包里的路径不合法: %q", f.Name)
		}
		// 声明的大小由 archive/zip 在读的时候核对（多读一个字节就报错），所以加起来就是实际要写的
		if total += f.UncompressedSize64; total > uint64(codeMaxBytes) {
			return fmt.Errorf("代码包解压后超过 %d MB", codeMaxBytes>>20)
		}
		if f.Mode()&os.ModeType != 0 && !f.Mode().IsDir() {
			return fmt.Errorf("代码包里不许有链接或特殊文件: %q", f.Name)
		}
		switch strings.ToLower(name[strings.LastIndex(name, "/")+1:]) {
		case "sitecustomize.py", "usercustomize.py": // 审计钩子的位置（docs/jobs-sandbox.md 第 5 节）
			return fmt.Errorf("代码包里不许有 %q", f.Name)
		}
		key := strings.ToLower(name) // Windows 不分大小写，同名不同写法会互相覆盖
		if seen[key] {
			return fmt.Errorf("代码包里有大小写冲突的路径: %q", f.Name)
		}
		seen[key] = true
	}
	return nil
}

func writeEntry(f *zip.File, path string) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return err
}

// Launch 是起一个进程要的东西。Args 不含 argv[0]。
type Launch struct {
	Path string
	Args []string
	Dir  string
	Env  []string
	Log  *os.File // stdout 和 stderr 都写这里
}

// Proc 是起来的进程（连同它以后起的整棵树）。
type Proc interface {
	Pid() int
	Wait() (exitCode int, err error) // 主进程结束
	Kill()                           // 杀整棵树，可以重复调
	Close()                          // 主进程结束后调：杀掉树里剩下的、释放句柄
}

// Starter 起进程。
type Starter interface {
	Start(Launch) (Proc, error)
}

// Plain 不受限：exec.Cmd + winproc.StartTree（以探针自己的账户运行）。探针在 Windows 上不用它。
var Plain Starter = plainStarter{}

type plainStarter struct{}

type plainProc struct {
	cmd  *exec.Cmd
	tree *winproc.Tree
}

func (plainStarter) Start(l Launch) (Proc, error) {
	cmd := exec.Command(l.Path, l.Args...)
	cmd.Dir, cmd.Env = l.Dir, l.Env
	cmd.Stdout, cmd.Stderr = l.Log, l.Log
	tree, err := winproc.StartTree(cmd)
	if err != nil {
		return nil, err
	}
	return &plainProc{cmd: cmd, tree: tree}, nil
}

func (p *plainProc) Pid() int { return p.cmd.Process.Pid }
func (p *plainProc) Wait() (int, error) {
	err := p.cmd.Wait()
	return p.cmd.ProcessState.ExitCode(), err
}
func (p *plainProc) Kill()  { p.tree.Kill() }
func (p *plainProc) Close() { p.tree.Close() }

// Spec 是一次运行。Entry 是 job.json 的 entry（已经过 jobsign 校验）：entry[0] 换成环境层的解释器，
// 前面固定加 envlayer.Flags（-E -s -B）。
type Spec struct {
	Dir        string
	Interp     string
	Entry      []string
	Timeout    time.Duration // max_hours
	DiskMaxMB  int           // output/ + tmp/ + job.log 超过就杀；0 = 不查
	Env        []string      // 追加的环境变量
	CheckEvery time.Duration // 多久查一次磁盘；0 = 10 秒

	Start   Starter       // nil = Plain
	BaseEnv []string      // 非 nil 时用它打底（沙箱从零拼的环境块），不继承探针的环境
	OnStart func(pid int) // 进程起来（已恢复运行）后调一次
	Abort   <-chan string // 收到原因就杀整棵树，Result.Killed = 这个原因（审计管道断了之类）
}

// Result 是运行结果。Killed 非空表示被杀：timeout / disk / cancelled，这时 ExitCode 没有意义。
type Result struct {
	ExitCode int
	Killed   string
	Seconds  float64
}

// Run 起进程（不经 shell）、整棵进程树放进作业对象，等它结束；超时、超磁盘、ctx 取消都杀整棵树。
// 主进程退出后树里剩下的进程也一起杀掉。只有起不来才返回错误。
func Run(ctx context.Context, s Spec) (Result, error) {
	if len(s.Entry) < 2 {
		return Result{}, errors.New("entry 不完整")
	}
	if s.CheckEvery <= 0 {
		s.CheckEvery = 10 * time.Second
	}
	logf, err := os.OpenFile(filepath.Join(s.Dir, "job.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return Result{}, err
	}
	defer logf.Close()
	args := append(append([]string{}, envlayer.Flags...), s.Entry[1:]...)
	fmt.Fprintf(logf, "===== %s 启动 %s %q\n", time.Now().Format("2006-01-02 15:04:05"), s.Interp, args)
	env := s.BaseEnv
	if env == nil {
		tmp := filepath.Join(s.Dir, "tmp")
		env = append(os.Environ(), "TMP="+tmp, "TEMP="+tmp, "TMPDIR="+tmp, "PYTHONDONTWRITEBYTECODE=1")
	}
	env = append(append([]string{}, env...), s.Env...)
	starter := s.Start
	if starter == nil {
		starter = Plain
	}
	start := time.Now()
	p, err := starter.Start(Launch{Path: s.Interp, Args: args, Dir: filepath.Join(s.Dir, "code"), Env: env, Log: logf})
	if err != nil {
		fmt.Fprintf(logf, "===== 起不来: %v\n", err)
		return Result{}, fmt.Errorf("起不来: %w", err)
	}
	defer p.Close()
	if s.OnStart != nil {
		s.OnStart(p.Pid())
	}
	done := make(chan struct{})
	code := -1
	go func() { code, _ = p.Wait(); close(done) }()

	timeout := time.NewTimer(s.Timeout)
	defer timeout.Stop()
	check := time.NewTicker(s.CheckEvery)
	defer check.Stop()
	killed := ""
	for killed == "" {
		select {
		case <-done:
			res := Result{ExitCode: code, Seconds: time.Since(start).Seconds()}
			fmt.Fprintf(logf, "===== 退出码 %d，%.1f 秒\n", res.ExitCode, res.Seconds)
			return res, nil
		case <-ctx.Done():
			killed = "cancelled"
		case <-timeout.C:
			killed = "timeout"
		case r := <-s.Abort:
			killed = r
		case <-check.C:
			if s.DiskMaxMB > 0 && WrittenBytes(s.Dir) > int64(s.DiskMaxMB)<<20 {
				killed = "disk"
			}
		}
	}
	p.Kill()
	<-done
	res := Result{ExitCode: -1, Killed: killed, Seconds: time.Since(start).Seconds()}
	fmt.Fprintf(logf, "===== 被杀（%s），%.1f 秒\n", killed, res.Seconds)
	return res, nil
}

func dirBytes(dir string, skip string) int64 {
	var n int64
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && skip != "" && p == skip {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// WrittenBytes 是任务自己写的：output/ + tmp/ + job.log。
func WrittenBytes(dir string) int64 {
	n := dirBytes(filepath.Join(dir, "output"), "") + dirBytes(filepath.Join(dir, "tmp"), "")
	if fi, err := os.Stat(filepath.Join(dir, "job.log")); err == nil {
		n += fi.Size()
	}
	return n
}

// OutputBytes 是 output/ 的大小，不算平台的 _runner/。
func OutputBytes(dir string) int64 {
	out := filepath.Join(dir, "output")
	return dirBytes(out, filepath.Join(out, Runner))
}
