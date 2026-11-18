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
// 上线前必须做（issue #1 第 4 步，这里还没有）：任务进程现在以探针的账户运行（教室机上是 Administrator），
// 要改成专用低权限账户 epsilon-job；code/ 只读、output/ tmp/ 可写不可执行（NTFS ACL）；出站防火墙。
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

	"epsilon/chunk"
	"epsilon/winproc"
)

// Runner 是 output/ 下的平台保留目录（运行摘要、日志副本）。
const Runner = "_runner"

// Prepare 从头展开任务目录：旧的整个删掉（重跑从头来），解压代码包，写 params.json。
// 代码包先整个查一遍再写：路径穿越、链接、大小写冲突都拒。
func Prepare(dir, codeZip string, params []byte) error {
	zr, err := zip.OpenReader(codeZip)
	if err != nil {
		return fmt.Errorf("代码包打不开: %v", err)
	}
	defer zr.Close()
	if err := checkZip(zr.File); err != nil {
		return err
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
	for _, f := range files {
		name := strings.TrimSuffix(f.Name, "/")
		if !chunk.SafePath(name) {
			return fmt.Errorf("代码包里的路径不合法: %q", f.Name)
		}
		if f.Mode()&os.ModeType != 0 && !f.Mode().IsDir() {
			return fmt.Errorf("代码包里不许有链接或特殊文件: %q", f.Name)
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

// Spec 是一次运行。Entry 是 job.json 的 entry（已经过 jobsign 校验）：entry[0] 换成环境层的解释器，前面固定加 -E -B。
type Spec struct {
	Dir        string
	Interp     string
	Entry      []string
	Timeout    time.Duration // max_hours
	DiskMaxMB  int           // output/ + tmp/ + job.log 超过就杀；0 = 不查
	Env        []string      // 追加的环境变量
	CheckEvery time.Duration // 多久查一次磁盘；0 = 10 秒
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
	args := append([]string{"-E", "-B"}, s.Entry[1:]...)
	fmt.Fprintf(logf, "===== %s 启动 %s %q\n", time.Now().Format("2006-01-02 15:04:05"), s.Interp, args)
	cmd := exec.Command(s.Interp, args...)
	cmd.Dir = filepath.Join(s.Dir, "code")
	tmp := filepath.Join(s.Dir, "tmp")
	cmd.Env = append(os.Environ(), "TMP="+tmp, "TEMP="+tmp, "TMPDIR="+tmp, "PYTHONDONTWRITEBYTECODE=1")
	cmd.Env = append(cmd.Env, s.Env...)
	cmd.Stdout, cmd.Stderr = logf, logf
	start := time.Now()
	tree, err := winproc.StartTree(cmd)
	if err != nil {
		fmt.Fprintf(logf, "===== 起不来: %v\n", err)
		return Result{}, fmt.Errorf("起不来: %v", err)
	}
	defer tree.Close()
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()

	timeout := time.NewTimer(s.Timeout)
	defer timeout.Stop()
	check := time.NewTicker(s.CheckEvery)
	defer check.Stop()
	killed := ""
	for killed == "" {
		select {
		case <-done:
			res := Result{ExitCode: cmd.ProcessState.ExitCode(), Seconds: time.Since(start).Seconds()}
			fmt.Fprintf(logf, "===== 退出码 %d，%.1f 秒\n", res.ExitCode, res.Seconds)
			return res, nil
		case <-ctx.Done():
			killed = "cancelled"
		case <-timeout.C:
			killed = "timeout"
		case <-check.C:
			if s.DiskMaxMB > 0 && WrittenBytes(s.Dir) > int64(s.DiskMaxMB)<<20 {
				killed = "disk"
			}
		}
	}
	tree.Kill()
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
