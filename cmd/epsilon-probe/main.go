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
	"epsilon/loader"
	"epsilon/probe"
	"epsilon/proto"
)

var version = "0.3.1"

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
	seedOnly := flag.Bool("seed", false, "安装用：跑一轮 loader 把第一个版本放进槽就退出")
	flag.Parse()
	if st, err := os.Stat(*logPath); err == nil && st.Size() > 10<<20 {
		os.Remove(*logPath) // 超过 10 MB 就从头记
	}
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
	l, err := newLoader(cfg, *cfgPath, *root)
	if err != nil {
		log.Fatal(err)
	}
	if *seedOnly {
		os.Exit(seed(context.Background(), l, log.Writer())) // 原因同时进日志
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

// seed 是安装时的 -seed：跑一轮 Stage。装的 boot 和本体同一版，所以引导器版本用编进来的 boot.Version。
func seed(ctx context.Context, l *loader.Loader, w io.Writer) int {
	l.BootVersion = boot.Version
	staged, err := l.Stage(ctx)
	if err != nil {
		fmt.Fprintf(w, "seed 失败: %v\n", err)
		return 1
	}
	if staged {
		fmt.Fprintln(w, "seed: 已放进槽，等引导器启动")
	} else {
		fmt.Fprintln(w, "seed: 没有要放的（已备好，或已是当前版本）")
	}
	return 0
}
