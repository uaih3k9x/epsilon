// epsilon-boot: 引导器（设计书 11.9，docs/boot.md）。计划任务启动它；它只做本地事：
// 从 A/B 槽里挑一个验过签的本体启动、试启动、看护、回退。不联网，下载新版本是本体里 loader 的事。
// 用法: epsilon-boot [-root D:\epsilon]
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"epsilon/boot"
	"epsilon/winproc"
)

type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *proc) Exited() <-chan struct{} { return p.done }
func (p *proc) Kill()                   { p.cmd.Process.Kill() }
func (p *proc) ExitCode() int           { return p.cmd.ProcessState.ExitCode() } // Exited 之后才调

// spawn 在 root 下不弹窗地启动 exe，并绑进作业对象：引导器被杀，它（连同它的工作负载）一起走。
func spawn(root, exe string, args ...string) (boot.Proc, error) {
	cmd := exec.Command(exe, args...)
	cmd.Dir = root
	winproc.Hide(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	winproc.Bind(cmd.Process.Pid)
	p := &proc{cmd: cmd, done: make(chan struct{})}
	go func() { cmd.Wait(); close(p.done) }()
	log.Printf("启动 %s pid %d", exe, cmd.Process.Pid)
	return p, nil
}

func main() {
	exe, _ := os.Executable()
	root := flag.String("root", filepath.Dir(exe), "放 probe.json、日志、状态文件和 A/B 槽的目录")
	flag.Parse()

	logPath := filepath.Join(*root, "boot.log")
	if st, err := os.Stat(logPath); err == nil && st.Size() > 5<<20 {
		os.Remove(logPath)
	}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}

	// 同一时间只许一个引导器：占一个本机端口当锁
	lock, err := net.Listen("tcp", "127.0.0.1:47199")
	if err != nil {
		log.Fatalf("已经有一个引导器在跑: %v", err)
	}
	defer lock.Close()

	var keys []ed25519.PublicKey
	for _, k := range publicKeys {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			log.Fatalf("公钥坏了: %q", k)
		}
		keys = append(keys, b)
	}
	log.Printf("epsilon-boot %d 目录 %s", boot.Version, *root)

	b := &boot.Boot{Root: *root, Keys: keys,
		ConfirmWithin: 3 * time.Minute, Backoff: 30 * time.Second, Poll: 2 * time.Second,
		RescueWithin: 30 * time.Minute, RescueGap: 10 * time.Minute,
		Start: func(slotDir, confirm string) (boot.Proc, error) {
			// 命令行是冻结契约（docs/boot.md），本体以后的版本都得认这些参数
			return spawn(*root, filepath.Join(slotDir, "epsilon-probe.exe"),
				"-config", filepath.Join(*root, "probe.json"), "-log", filepath.Join(*root, "probe.log"),
				"-workloads", filepath.Join(slotDir, "workloads.json"), "-confirm", confirm,
				"-boot", fmt.Sprintf("%d/%s", boot.Version, filepath.Base(slotDir)), "-root", *root)
		},
		Rescue: func(slotDir string) (boot.Proc, error) {
			// 同样是冻结契约（docs/boot.md "救援槽 R"）：跑一轮 loader 就退出
			return spawn(*root, filepath.Join(slotDir, "epsilon-probe.exe"),
				"-seed", "-config", filepath.Join(*root, "probe.json"), "-root", *root,
				"-boot", fmt.Sprintf("%d/%s", boot.Version, boot.RescueSlot))
		}}
	b.Run(make(chan struct{}))
}
