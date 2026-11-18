// epsilon-probe: 学生机上的探针。用法: epsilon-probe [-config probe.json]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"epsilon/boot"
	"epsilon/chunk"
	"epsilon/jobbox"
	"epsilon/loader"
	"epsilon/probe"
	"epsilon/proto"
)

var version = "0.4.0"

func main() {
	exe, _ := os.Executable()
	cfgPath := flag.String("config", filepath.Join(filepath.Dir(exe), "probe.json"), "本机配置")
	ctl := flag.String("controller", "", "主控地址，覆盖 probe.json 里的（现场换主控不用改配置）")
	logPath := flag.String("log", filepath.Join(filepath.Dir(exe), "probe.log"), "日志文件（Windows 版没有控制台窗口）")
	// 下面三个由引导器传：本体在槽目录里，本机配置和日志在槽外面
	workloads := flag.String("workloads", filepath.Join(filepath.Dir(exe), "workloads.json"), "随本体发布的工作负载表，覆盖本机配置里的同名项")
	confirm := flag.String("confirm", "", "第一次心跳成功后创建这个文件，告诉引导器这个版本能用")
	bootArg := flag.String("boot", "", "引导器版本/槽位，原样上报；有它才在后台跑 loader")
	root := flag.String("root", "", "引导器根目录（A/B 槽、boot-state.json）；默认 probe.json 所在目录")
	seedOnly := flag.Bool("seed", false, "安装、救援用：跑一轮 loader 把版本放进槽就退出")
	selftest := flag.String("sandbox-selftest", "", `只跑一遍批任务沙箱的健康检查和两次金丝雀，打印逐项结果就退出；参数是环境层目录（D:\epsilon\envs\<名字@版本>）`)
	flag.Parse()
	probe.RotateLog(*logPath, probe.ProbeLogMax) // 超了留一份 .1 再从头记；运行中由 Agent 每分钟再查
	if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}

	cfg, err := probe.LoadConfig(*cfgPath, *workloads)
	if err != nil {
		log.Fatal(err)
	}
	if *ctl != "" {
		cfg.Controller = strings.TrimRight(*ctl, "/")
	}
	if *selftest != "" {
		os.Exit(sandboxSelftest(cfg, *selftest))
	}
	l, err := newLoader(cfg, *cfgPath, *root)
	if err != nil {
		log.Fatal(err)
	}
	if *seedOnly {
		os.Exit(seed(context.Background(), l, *bootArg, log.Writer())) // 原因同时进日志
	}
	log.Printf("epsilon-probe %s 节点 %s 主控 %s 引导 %q", version, cfg.Node, cfg.Controller, *bootArg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *bootArg != "" {
		if l.BootVersion, err = bootVersion(*bootArg); err != nil {
			log.Printf("不跑 loader: %v", err)
		} else {
			go l.Run(ctx, 10*time.Minute)
		}
	}

	a := probe.NewAgent(cfg, probe.RealSystem{}, version)
	a.Boot = *bootArg
	a.LogPath = *logPath
	a.JobRoots = l.Keys // 任务钥匙环和本体发布同一套根公钥（docs/jobs.md）
	if cfg.Jobs {
		// 任务一律经沙箱（docs/jobs-sandbox.md）；非 Windows 构建、或沙箱建不起来时是 Unavailable，心跳报 jobs:false
		if bc, err := probe.SandboxConfig(cfg); err != nil {
			a.JobBox = jobbox.Unavailable{Reason: err.Error()}
		} else {
			a.JobBox = jobbox.New(bc)
		}
		log.Printf("批任务执行已开（能力 32），经沙箱运行；上线前先在真机上过一遍 docs/jobs-sandbox.md 第 7 节")
	}
	if *confirm != "" {
		a.OnOnline = func() {
			if err := os.WriteFile(*confirm, []byte(version), 0o644); err != nil {
				log.Printf("写确认文件: %v", err)
			}
		}
	}
	store, err := chunk.NewStore(cfg.ChunkDir, cfg.ChunkQuotaGB<<30)
	if err != nil {
		log.Fatal(err)
	}
	a.Chunks = store
	a.Ready = chunk.Ready
	a.Assemble = func(m proto.Manifest, root string) error { return chunk.Assemble(m, store, root) }
	if err := a.ListenP2P(); err != nil { // 要在 Run 之前：登记时要报端口
		log.Printf("分块服务没起来（只拉不供）: %v", err)
	}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; close(stop) }()
	a.Run(stop, time.Second)
	cancel()
	a.Shutdown()
}

func newLoader(cfg probe.Config, cfgPath, root string) (*loader.Loader, error) {
	if root == "" {
		root = filepath.Dir(cfgPath)
	}
	keys, err := loader.ParseKeys(loader.PublicKeys)
	if err != nil {
		return nil, err
	}
	return &loader.Loader{Root: root, Node: cfg.Node, Controller: cfg.Controller, Token: cfg.Token, Keys: keys}, nil
}

// bootVersion 从 "-boot <版本>/<槽>" 里取引导器版本。
func bootVersion(s string) (int, error) {
	v, _, ok := strings.Cut(s, "/")
	n, err := strconv.Atoi(v)
	if !ok || err != nil || n <= 0 {
		return 0, fmt.Errorf("-boot %q 不是 <版本>/<槽>", s)
	}
	return n, nil
}

// seedBootVersion：救援时 boot 传 -boot <版本>/R，按它；安装脚本不传，装的 boot 和本体同一版，用编进来的 boot.Version。
func seedBootVersion(bootArg string) (int, error) {
	if bootArg == "" {
		return boot.Version, nil
	}
	return bootVersion(bootArg)
}

// seed 是 -seed（安装、救援）：按 seed 的选槽规则跑一轮 Stage。
func seed(ctx context.Context, l *loader.Loader, bootArg string, w io.Writer) int {
	v, err := seedBootVersion(bootArg)
	if err != nil {
		fmt.Fprintf(w, "seed 失败: %v\n", err)
		return 1
	}
	l.BootVersion, l.Seed = v, true
	staged, err := l.Stage(ctx)
	if err != nil {
		fmt.Fprintf(w, "seed 失败: %v\n", err)
		return 1
	}
	if staged {
		fmt.Fprintln(w, "seed: 已放进槽，等引导器启动")
	} else {
		fmt.Fprintln(w, "seed: 没有要放的（已备好、已是当前版本，或两个槽都占着）")
	}
	return 0
}

// sandboxSelftest 是 -sandbox-selftest：结果同时打印和写进 <artifact_root>\sandbox-selftest.txt（Windows 版没有控制台，方便截屏、OCR）。
func sandboxSelftest(cfg probe.Config, envDir string) int {
	var out strings.Builder
	w := io.MultiWriter(os.Stdout, &out)
	defer func() {
		os.WriteFile(filepath.Join(cfg.ArtifactRoot, "sandbox-selftest.txt"), []byte(out.String()), 0o644)
	}()
	bc, err := probe.SandboxConfig(cfg)
	if err != nil {
		fmt.Fprintln(w, err)
		return 1
	}
	b, ok := jobbox.New(bc).(*jobbox.Box)
	if !ok {
		fmt.Fprintln(w, "没有沙箱:", jobbox.New(bc).Halted())
		return 1
	}
	fmt.Fprintf(w, "epsilon-probe %s 沙箱自检 %s 环境层 %s\n", version, time.Now().Format("2006-01-02 15:04:05"), envDir)
	if err := b.SelfTest(context.Background(), envDir, w); err != nil {
		fmt.Fprintln(w, err)
		return 1
	}
	fmt.Fprintln(w, "全部通过")
	return 0
}
