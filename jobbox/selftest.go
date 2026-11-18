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
// 逐项打印结果表（方便截屏、OCR），然后收回权限、删掉目录。有一项不过就返回错误。
func (b *Box) SelfTest(ctx context.Context, envDir string, w io.Writer) error {
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
	if err := b.P.Health(); err != nil {
		row("health", false, err.Error())
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
	defer os.RemoveAll(dir)
	j := Job{Dir: dir, EnvDir: envDir, Interp: filepath.Join(envDir, envlayer.Interpreter)}
	if err := b.P.Grant(dir); err != nil {
		row("grant", false, err.Error())
		return fmt.Errorf("自检没过: %v", failed)
	}
	defer func() {
		n, err := b.P.Sweep()
		row("sweep", err == nil && n == 0, fmt.Sprintf("剩下 %d 个进程 %v", n, err))
		if err := b.P.Revoke(dir); err != nil {
			row("revoke", false, err.Error())
		}
	}()
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
	out, err := b.sysCanary(ctx, j, env, cf)
	table("系统控制（python -I -S，不加载钩子）", out, err, SysChecks)
	if err := b.resetScratch(dir); err != nil {
		return err
	}
	out, err = b.hookCanary(ctx, j, env, cf)
	table("审计钩子（python -E -s -B，环境层 "+filepath.Base(envDir)+"）", out, err, hookWant)
	if len(failed) > 0 {
		return errors.New("自检没过: " + fmt.Sprint(failed))
	}
	return nil
}
