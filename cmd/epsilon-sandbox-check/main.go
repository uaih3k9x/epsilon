// epsilon-sandbox-check：批任务沙箱的真机验证套件（docs/jobs-sandbox.md 第 7 节）的 Go 一侧。
// 由 tools/sandbox-check/run.ps1 调用，不单独用：
//
//	epsilon-sandbox-check limited -config D:\epsilon\probe.json -work <目录> [-env <环境层>] [-probe <epsilon-probe.exe>] [-listeners <json>] [-health-only]
//	    以探针同样的身份（Users、Limited 令牌，run.ps1 用临时计划任务起）跑：先跑一遍 epsilon-probe -sandbox-selftest，
//	    再逐项实测，结果追加到 <目录>\limited.jsonl，最后写 <目录>\limited.done。只在 Windows 上有。
//	epsilon-sandbox-check report -work <目录> -out <路径前缀>
//	    把 <目录> 里的 *.jsonl 和 sandbox-selftest.txt 汇总成 <前缀>.json 和 <前缀>.txt；有 FAIL 退出码 1。
//
// 控制台只打英文（PowerShell 5.1 读中文会乱码），中文证据只进文件。
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "limited":
		fs := flag.NewFlagSet("limited", flag.ExitOnError)
		var o limitedOpts
		fs.StringVar(&o.Config, "config", `D:\epsilon\probe.json`, "probe.json")
		fs.StringVar(&o.Work, "work", "", "work dir (results go here)")
		fs.StringVar(&o.EnvDir, "env", "", `env layer dir (D:\epsilon\envs\<name@ver>); empty = skip python checks`)
		fs.StringVar(&o.ProbeExe, "probe", "", "epsilon-probe.exe for -sandbox-selftest; empty = skip")
		fs.StringVar(&o.Listeners, "listeners", "", "listening TCP ports (json from run.ps1) for item 13")
		fs.BoolVar(&o.HealthOnly, "health-only", false, "after a C: restore: only the health check (item 8)")
		fs.Parse(os.Args[2:])
		if o.Work == "" {
			usage()
		}
		os.Exit(runLimited(o))
	case "report":
		fs := flag.NewFlagSet("report", flag.ExitOnError)
		work := fs.String("work", "", "work dir with *.jsonl and sandbox-selftest.txt")
		out := fs.String("out", "", "output path prefix (.json and .txt are added)")
		fs.Parse(os.Args[2:])
		if *work == "" || *out == "" {
			usage()
		}
		os.Exit(report(*work, *out))
	}
	usage()
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: epsilon-sandbox-check limited -work DIR [-config probe.json] [-env DIR] [-probe EXE] [-listeners JSON] [-health-only]")
	fmt.Fprintln(os.Stderr, "       epsilon-sandbox-check report -work DIR -out PREFIX")
	os.Exit(2)
}

// limitedOpts 是 limited 子命令的参数。
type limitedOpts struct {
	Config, Work, EnvDir, ProbeExe, Listeners string
	HealthOnly                                bool
}

func report(work, out string) int {
	checks, err := readAll(work)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read results:", err)
		return 2
	}
	host, _ := os.Hostname()
	r := Build(checks, host, time.Now())
	j, err := r.JSON()
	if err == nil {
		err = os.WriteFile(out+".json", j, 0o644)
	}
	if err == nil {
		// 带 BOM：老版本记事本才认得出 UTF-8
		err = os.WriteFile(out+".txt", append([]byte("\xef\xbb\xbf"), r.Text()...), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
		return 2
	}
	fmt.Printf("overall %s: PASS %d FAIL %d MANUAL %d SKIP %d -> %s.txt\n", r.Overall, r.Counts[PASS], r.Counts[FAIL], r.Counts[MANUAL], r.Counts[SKIP], out)
	if r.Overall == FAIL {
		return 1
	}
	return 0
}
