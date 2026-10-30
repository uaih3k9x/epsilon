// Package loader 随本体发布（docs/boot.md）：问主控有没有新版本，下载到空闲槽、验过，写 staged.json 交给 boot；
// 顺便把 boot 记在本地的事件转发给主控。boot 不联网，联网的事都在这里。
package loader

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"epsilon/boot"
)

// OfflineBoot 是不联网的引导器从哪个版本起（docs/boot.md）。更旧的引导器自己下载，loader 不插手。
const OfflineBoot = 2

type Loader struct {
	Root        string // boot 的根目录：A\ B\ boot-state.json staged.json …
	Node        string
	Controller  string
	Token       string
	Keys        []ed25519.PublicKey
	BootVersion int          // 本机 boot 的版本，发布的 min_boot 不能比它大
	Seed        bool         // -seed（安装、救援）：pending 非空、current 空时也放，目标是 pending 以外的槽
	Client      *http.Client // 空 = 默认（不走代理）
}

var defaultClient = &http.Client{Transport: &http.Transport{Proxy: nil,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	ResponseHeaderTimeout: 30 * time.Second}}

func (l *Loader) client() *http.Client {
	if l.Client != nil {
		return l.Client
	}
	return defaultClient
}

func (l *Loader) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.Controller+path+"?node="+url.QueryEscape(l.Node), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+l.Token)
	r, err := l.client().Do(req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		r.Body.Close()
		return nil, fmt.Errorf("%s: %s", path, r.Status)
	}
	return r, nil
}

func other(slot string) string {
	if slot == "A" {
		return "B"
	}
	return "A"
}

// Stage 按 docs/boot.md "loader 的步骤"走一轮：有新版本就下到 current 以外的槽、验过、写 staged.json。
// 返回这一轮是否写了 staged.json。没新东西、或者 boot 正在试 / 还没消费上一次的，什么都不做。
func (l *Loader) Stage(ctx context.Context) (bool, error) {
	if l.BootVersion < OfflineBoot {
		return false, nil // 旧引导器自己会下载，插手就会和它抢同一个空闲槽
	}
	st, err := boot.ReadState(l.Root)
	if err != nil {
		return false, fmt.Errorf("读 %s: %w", boot.StateFile, err)
	}
	target, ok := l.target(st)
	if !ok {
		return false, nil // boot 正在试新版本（seed：两个槽都占着）
	}
	// 上一次备好的还没被 boot 拿走（同版本就是已经做完了；别的版本也等 boot 先消费，staged.json 只有 boot 删）
	if _, err := os.Stat(filepath.Join(l.Root, boot.StagedFile)); err == nil {
		return false, nil
	}

	rel, m, err := l.release(ctx)
	if err != nil {
		return false, err
	}
	if m.Version == st.Bad || m.Version == st.Versions[st.Current] || st.Pending != "" && m.Version == st.Versions[st.Pending] {
		return false, nil // pending 就是这个版本：换个槽再试也一样
	}
	dir := filepath.Join(l.Root, target)
	if err := l.fill(ctx, dir, rel, m); err != nil {
		os.RemoveAll(dir)
		return false, fmt.Errorf("槽 %s: %w", target, err)
	}
	// 下载要好一会儿：期间 boot 可能因为 current 坏了改跑 good，目标槽就成了 current。
	// 再读一次 state，按同样的规则算出的目标槽变了就不交接（槽里的东西不删：它可能已是 current，boot 会按版本核对发现不对）。
	if st2, err := boot.ReadState(l.Root); err != nil || !l.sameTarget(st2, target) {
		return false, fmt.Errorf("下载期间 boot 换了槽（current=%q pending=%q），这次不交接", st2.Current, st2.Pending)
	}
	raw, _ := json.Marshal(boot.Staged{Slot: target, Version: m.Version})
	if err := writeAtomic(filepath.Join(l.Root, boot.StagedFile), raw); err != nil {
		os.RemoveAll(dir)
		return false, err
	}
	log.Printf("版本 %s 放进槽 %s，等引导器切换", m.Version, target)
	return true, nil
}

// target 按 docs/boot.md 选目标槽：绝不是 current，也不是正在试的 pending。ok=false 就什么都不做。
func (l *Loader) target(st boot.State) (string, bool) {
	switch {
	case st.Pending == "" && st.Current == "":
		return "A", true
	case st.Pending == "":
		return other(st.Current), true
	case l.Seed && st.Current == "": // 首次安装的版本坏了：换另一个槽，boot 在两次试启动之间接受
		return other(st.Pending), true
	}
	return "", false
}

func (l *Loader) sameTarget(st boot.State, target string) bool {
	t, ok := l.target(st)
	return ok && t == target
}

// release 取主控的签名发布并验过：签名、min_boot。
func (l *Loader) release(ctx context.Context) (boot.Signed, boot.Manifest, error) {
	var rel boot.Signed
	r, err := l.get(ctx, "/v1/boot/release")
	if err != nil {
		return rel, boot.Manifest{}, err
	}
	err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&rel)
	r.Body.Close()
	if err != nil {
		return rel, boot.Manifest{}, fmt.Errorf("发布: %w", err)
	}
	m, err := rel.Verify(l.Keys)
	if err != nil {
		return rel, m, fmt.Errorf("主控给的发布: %w", err)
	}
	if m.MinBoot > l.BootVersion {
		return rel, m, fmt.Errorf("版本 %s 要引导器 %d，本机是 %d", m.Version, m.MinBoot, l.BootVersion)
	}
	return rel, m, nil
}

// fill 清空槽、下载每个文件、最后写 release.json，再按 boot 的规则整槽验一遍。
func (l *Loader) fill(ctx context.Context, dir string, rel boot.Signed, m boot.Manifest) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range m.Files {
		if err := l.fetchFile(ctx, f, filepath.Join(dir, f.Path)); err != nil {
			return fmt.Errorf("下载 %s: %w", f.Path, err)
		}
	}
	raw, _ := json.Marshal(rel)
	if err := writeAtomic(filepath.Join(dir, boot.ReleaseFile), raw); err != nil {
		return err
	}
	got, err := boot.VerifySlotFor(dir, l.Keys, l.BootVersion)
	if err == nil && got.Version != m.Version {
		err = fmt.Errorf("槽里是 %s，要的是 %s", got.Version, m.Version)
	}
	return err
}

func (l *Loader) fetchFile(ctx context.Context, f boot.File, path string) error {
	r, err := l.get(ctx, "/v1/boot/files/"+f.Path)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	tmp := path + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // 本体要能执行（Unix 上测试用）
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r.Body, f.Size+1))
	if err == nil {
		err = out.Sync()
	}
	out.Close()
	if err == nil && (n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256) {
		err = fmt.Errorf("大小或哈希不对（%d 字节）", n)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// writeAtomic：临时文件 → 刷盘 → 改名。
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Run 每 every 一轮：Stage + ForwardEvents，出错只打日志。第一轮马上跑。
func (l *Loader) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := l.Stage(ctx); err != nil && ctx.Err() == nil {
			log.Printf("备新版本: %v", err)
		}
		if err := l.ForwardEvents(ctx); err != nil && ctx.Err() == nil {
			log.Printf("转发引导器事件: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (l *Loader) post(ctx context.Context, path string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.Controller+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.Token)
	r, err := l.client().Do(req)
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, r.StatusCode)
	}
	return nil
}
