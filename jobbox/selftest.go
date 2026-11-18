package jobbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"epsilon/envlayer"
)

// SelfTest 是 epsilon-probe -sandbox-selftest：建一个空任务目录，只跑一遍健康检查和两次金丝雀，
// 逐项打印结果表（方便截屏、OCR），然后清场、收回权限、删掉目录。有一项不过（含清场和收回）就返回错误。
// 最后的清场会杀掉任务账户的所有进程，所以有任务账户的进程在跑（探针正在跑任务）时不做。
func (b *Box) SelfTest(ctx context.Context, envDir string, w io.Writer) (err error) {
	if pids, perr := b.P.Procs(); perr != nil || len(pids) > 0 {
		return fmt.Errorf("任务账户有进程在跑（%v，%v）：先停探针（计划任务 epsilon-probe）再自检", pids, perr)
	}
	var failed []string
	row := func(name string, ok bool, detail string) {
		st := "OK  "
		if !ok {
			st = "FAIL"
			failed = append(failed, name)
		}
		fmt.Fprintf(w, "%s  %-22s %s\n", st, name, detail)
	}
	fmt.Fprintln(w, "== 健康检查")
	if herr := b.P.Health(); herr != nil {
		row("health", false, herr.Error())
	} else {
		row("health", true, "")
	}
	dir := filepath.Join(b.Root, "jobs", "_selftest")
	os.RemoveAll(dir)
	for _, d := range []string{"code", "data", "output", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "params.json"), []byte("{}\n"), 0o644); err != nil {
		return err
	}
	defer func() {
		fmt.Fprintln(w, "== 收尾")
		n, serr := b.leftover()
		row("sweep", serr == nil && n == 0, fmt.Sprintf("剩下 %d 个进程 %v", n, serr))
		if rerr := b.P.Revoke(dir); rerr != nil {
			row("revoke", false, rerr.Error())
		} else {
			row("revoke", true, "")
		}
		os.RemoveAll(dir)
		if err == nil && len(failed) > 0 {
			err = errors.New("自检没过: " + fmt.Sprint(failed))
		}
	}()
	j := Job{Dir: dir, EnvDir: envDir, Interp: filepath.Join(envDir, envlayer.Interpreter)}
	if gerr := b.P.Grant(dir); gerr != nil {
		row("grant", false, gerr.Error())
		return nil
	}
	env := JobEnv(dir, envDir, b.sysEnv())
	cfg, err := b.canaryConfig(j, env)
	if err != nil {
		return err
	}
	table := func(title string, out []byte, err error, want []string) {
		fmt.Fprintln(w, "== "+title)
		if err != nil {
			row("start", false, err.Error())
			return
		}
		got := map[string]CanaryLine{}
		for _, l := range ParseCanary(out) {
			got[l.Name] = l
		}
		for _, n := range want {
			l, ok := got[n]
			if !ok {
				row(n, false, "没报")
				continue
			}
			row(n, l.OK, l.Detail)
		}
	}
	if err := b.resetScratch(dir); err != nil {
		return err
	}
	cf, err := writeCanaryFiles(dir, cfg)
	if err != nil {
		return err
	}
	out, cerr := b.sysCanary(ctx, j, env, cf)
	table("系统控制（python -I -S，不加载钩子）", out, cerr, SysChecks)
	if err := b.resetScratch(dir); err != nil {
		return err
	}
	out, cerr = b.hookCanary(ctx, j, env, cf)
	table("审计钩子（python -E -s -B，环境层 "+filepath.Base(envDir)+"）", out, cerr, hookWant)
	return nil
}
