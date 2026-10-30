// epsilon-probe: 学生机上的探针。用法: epsilon-probe [-config probe.json]
package main

import (
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"epsilon/chunk"
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
	boot := flag.String("boot", "", "引导器版本/槽位，原样上报")
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
	log.Printf("epsilon-probe %s 节点 %s 主控 %s 引导 %q", version, cfg.Node, cfg.Controller, *boot)

	a := probe.NewAgent(cfg, probe.RealSystem{}, version)
	a.Boot = *boot
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
	a.Shutdown()
}
