// epsilon-boot: 引导器（设计书 11.9）。计划任务启动它，它从主控取签名的本体放进 A/B 槽、试启动、看护。
// 用法: epsilon-boot [-root D:\epsilon] [-controller http://<controller>:8090]
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"epsilon/boot"
	"epsilon/winproc"
)

// local 是本机配置 probe.json 里引导器要用的几项。
type local struct {
	Node       string `json:"node"`
	Controller string `json:"controller"`
	Token      string `json:"token"`
}

type source struct {
	base, node, token string
	client            *http.Client
}

func (s *source) get(path string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, s.base+path+"?node="+url.QueryEscape(s.node), nil)
	req.Header.Set("Authorization", "Bearer "+s.token)
	r, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		return nil, fmt.Errorf("%s: %s", path, r.Status)
	}
	return r, nil
}

func (s *source) Release() (boot.Signed, error) {
	var rel boot.Signed
	r, err := s.get("/v1/boot/release")
	if err != nil {
		return rel, err
	}
	defer r.Body.Close()
	err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rel)
	return rel, err
}

func (s *source) Fetch(name string, w io.Writer) error {
	r, err := s.get("/v1/boot/files/" + name)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	_, err = io.Copy(w, r.Body)
	return err
}

func (s *source) report(kind, detail string) {
	b, _ := json.Marshal(map[string]string{"node": s.node, "kind": kind, "detail": detail})
	req, _ := http.NewRequest(http.MethodPost, s.base+"/v1/events", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json")
	if r, err := s.client.Do(req); err == nil {
		r.Body.Close()
	}
}

type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *proc) Exited() <-chan struct{} { return p.done }
func (p *proc) Kill()                   { p.cmd.Process.Kill() }

func main() {
	exe, _ := os.Executable()
	root := flag.String("root", filepath.Dir(exe), "放 probe.json、日志和 A/B 槽的目录")
	ctl := flag.String("controller", "", "主控地址，覆盖 probe.json 里的")
	check := flag.Duration("check", 10*time.Minute, "多久问一次主控有没有新版本")
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

	var cfg local
	raw, err := os.ReadFile(filepath.Join(*root, "probe.json"))
	if err == nil {
		err = json.Unmarshal(raw, &cfg)
	}
	if err != nil {
		log.Fatalf("probe.json: %v", err)
	}
	if *ctl != "" {
		cfg.Controller = *ctl
	}
	cfg.Controller = strings.TrimRight(cfg.Controller, "/")
	if cfg.Node == "" {
		cfg.Node, _ = os.Hostname()
	}

	var keys []ed25519.PublicKey
	for _, k := range publicKeys {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			log.Fatalf("公钥坏了: %q", k)
		}
		keys = append(keys, b)
	}

	src := &source{base: cfg.Controller, node: cfg.Node, token: cfg.Token, client: &http.Client{
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second}}}
	log.Printf("epsilon-boot %d 节点 %s 主控 %s 目录 %s", boot.Version, cfg.Node, cfg.Controller, *root)

	b := &boot.Boot{Root: *root, Keys: keys, Src: src, Report: src.report,
		ConfirmWithin: 3 * time.Minute, CheckEvery: *check, Backoff: 30 * time.Second, Poll: 2 * time.Second,
		Start: func(slotDir, confirm string) (boot.Proc, error) {
			slot := filepath.Base(slotDir)
			cmd := exec.Command(filepath.Join(slotDir, "epsilon-probe.exe"),
				"-config", filepath.Join(*root, "probe.json"), "-log", filepath.Join(*root, "probe.log"),
				"-workloads", filepath.Join(slotDir, "workloads.json"), "-confirm", confirm,
				"-boot", fmt.Sprintf("%d/%s", boot.Version, slot), "-controller", cfg.Controller)
			cmd.Dir = *root
			winproc.Hide(cmd)
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			winproc.Bind(cmd.Process.Pid) // 引导器被杀，本体连同它的工作负载一起走
			p := &proc{cmd: cmd, done: make(chan struct{})}
			go func() { cmd.Wait(); close(p.done) }()
			log.Printf("启动槽 %s pid %d", slot, cmd.Process.Pid)
			return p, nil
		}}
	b.Run(make(chan struct{}))
}
