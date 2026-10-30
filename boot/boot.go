package boot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxTries 是新版本最多试启动几次，到了就回退。
const MaxTries = 3

// Source 是主控：给当前该跑的发布，以及发布里的文件。
type Source interface {
	Release() (Signed, error)
	Fetch(name string, w io.Writer) error
}

// Proc 是跑起来的本体。
type Proc interface {
	Exited() <-chan struct{}
	Kill()
}

// State 存在 <Root>\boot-state.json，原子写。
type State struct {
	Current  string            `json:"current"`  // 已确认能用的槽
	Pending  string            `json:"pending"`  // 待试的槽
	Tries    int               `json:"tries"`    // 待试槽已经试了几次（先记再启动，防断电）
	Good     string            `json:"good"`     // 上一个好槽
	Bad      string            `json:"bad"`      // 试过不行的版本，不再下载
	Versions map[string]string `json:"versions"` // 槽 -> 版本
}

type Boot struct {
	Root   string
	Keys   []ed25519.PublicKey
	Src    Source
	Start  func(slotDir, confirmFile string) (Proc, error)
	Report func(kind, detail string)

	ConfirmWithin time.Duration // 新版本多久内要确认
	CheckEvery    time.Duration // 多久问一次主控有没有新版本
	Backoff       time.Duration // 本体崩溃后等多久再起
	Poll          time.Duration

	mu sync.Mutex // 保护状态文件，测试里会并发读
}

const releaseFile = "release.json" // 槽里存一份签名清单，启动前对着它验文件

func other(slot string) string {
	if slot == "A" {
		return "B"
	}
	return "A"
}

func (b *Boot) statePath() string { return filepath.Join(b.Root, "boot-state.json") }

func (b *Boot) state() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	var s State
	if raw, err := os.ReadFile(b.statePath()); err == nil {
		json.Unmarshal(raw, &s)
	}
	if s.Versions == nil {
		s.Versions = map[string]string{}
	}
	return s
}

func (b *Boot) save(s State) {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw, _ := json.MarshalIndent(s, "", "  ")
	if err := writeAtomic(b.statePath(), raw); err != nil {
		log.Printf("写 boot-state 失败: %v", err)
	}
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

func (b *Boot) report(kind, format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	log.Printf("%s: %s", kind, msg)
	if b.Report != nil {
		b.Report(kind, msg)
	}
}

func sumFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

// verifySlot 验槽里的清单签名和每个文件的哈希。
func (b *Boot) verifySlot(slot string) (Manifest, error) {
	dir := filepath.Join(b.Root, slot)
	raw, err := os.ReadFile(filepath.Join(dir, releaseFile))
	if err != nil {
		return Manifest{}, err
	}
	var s Signed
	if err := json.Unmarshal(raw, &s); err != nil {
		return Manifest{}, err
	}
	m, err := s.Verify(b.Keys)
	if err != nil {
		return m, err
	}
	for _, f := range m.Files {
		n, sum, err := sumFile(filepath.Join(dir, f.Path))
		if err != nil || n != f.Size || sum != f.SHA256 {
			return m, fmt.Errorf("%s 对不上清单", f.Path)
		}
	}
	return m, nil
}

// Stage 问主控要发布；是新版本就下到非当前槽、验过，记为待试。返回是否有新东西待试。
func (b *Boot) Stage() (bool, error) {
	s, err := b.Src.Release()
	if err != nil {
		return false, err
	}
	m, err := s.Verify(b.Keys)
	if err != nil {
		b.report("boot_verify_failed", "主控给的发布: %v", err)
		return false, err
	}
	if m.MinBoot > Version {
		return false, fmt.Errorf("版本 %s 要引导器 %d，本机是 %d", m.Version, m.MinBoot, Version)
	}
	st := b.state()
	if m.Version == st.Bad || m.Version == st.Versions[st.Current] && st.Pending == "" ||
		st.Pending != "" && m.Version == st.Versions[st.Pending] {
		return false, nil
	}
	target := "A"
	if st.Current != "" {
		target = other(st.Current)
	}
	if st.Good == target { // 要覆盖它了，它不再是能退回去的好槽
		st.Good = ""
		b.save(st)
	}
	dir := filepath.Join(b.Root, target)
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	for _, f := range m.Files {
		if err := fetchFile(b.Src, f, filepath.Join(dir, f.Path)); err != nil {
			os.RemoveAll(dir)
			return false, fmt.Errorf("下载 %s: %w", f.Path, err)
		}
	}
	raw, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(dir, releaseFile), raw, 0o644); err != nil {
		return false, err
	}
	st = b.state()
	st.Pending, st.Tries = target, 0
	st.Versions[target] = m.Version
	b.save(st)
	b.report("boot_staged", "版本 %s 放进槽 %s，待试", m.Version, target)
	return true, nil
}

func fetchFile(src Source, f File, path string) error {
	tmp := path + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // 本体要能执行（Unix 上测试用）
	if err != nil {
		return err
	}
	h := sha256.New()
	cw := &countWriter{}
	err = src.Fetch(f.Path, io.MultiWriter(out, h, cw))
	out.Close()
	if err == nil && (cw.n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256) {
		err = fmt.Errorf("大小或哈希不对（%d 字节）", cw.n)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// Pick 决定这次启动哪个槽；trial 表示是在试新版本。没有能用的槽返回空。
func (b *Boot) Pick() (slot string, trial bool) {
	st := b.state()
	if st.Pending != "" {
		if _, err := b.verifySlot(st.Pending); err != nil {
			// 文件坏了多半是本机的事（断电、被还原），不算版本坏；丢掉待试槽，下一轮重下
			b.report("boot_slot_bad", "待试槽 %s: %v", st.Pending, err)
			st.Pending, st.Tries = "", 0
			b.save(st)
		} else if st.Tries >= MaxTries && st.Current != "" {
			b.giveUp(st, fmt.Sprintf("试了 %d 次没确认", st.Tries))
		} else {
			// 没有好版本可退（刚装好）时一直试：多半是主控暂时连不上，不是版本坏
			if st.Tries >= MaxTries {
				st.Tries = 0
			}
			st.Tries++
			b.save(st)
			return st.Pending, true
		}
		st = b.state()
	}
	for _, s := range []string{st.Current, st.Good} {
		if s == "" {
			continue
		}
		if _, err := b.verifySlot(s); err != nil {
			b.report("boot_slot_bad", "槽 %s: %v", s, err)
			continue
		}
		if s != st.Current {
			st.Current, st.Good = s, ""
			b.save(st)
		}
		return s, false
	}
	return "", false
}

func (b *Boot) giveUp(st State, why string) {
	v := st.Versions[st.Pending]
	b.report("boot_rollback", "版本 %s（槽 %s）%s，回到 %q", v, st.Pending, why, st.Current)
	st.Bad, st.Pending, st.Tries = v, "", 0
	b.save(st)
}

func (b *Boot) promote() {
	st := b.state()
	if st.Pending == "" {
		return
	}
	st.Good, st.Current = st.Current, st.Pending
	st.Pending, st.Tries = "", 0
	b.save(st)
	b.report("boot_promoted", "版本 %s（槽 %s）转正", st.Versions[st.Current], st.Current)
}

func (b *Boot) sleep(stop <-chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return false
	case <-time.After(d):
		return true
	}
}

// Run 一直跑到 stop：取发布、选槽、启动本体、看护，有新版本就切。
func (b *Boot) Run(stop <-chan struct{}) {
	lastCheck := time.Time{}
	for {
		select {
		case <-stop:
			return
		default:
		}
		if time.Since(lastCheck) >= b.CheckEvery {
			lastCheck = time.Now()
			if _, err := b.Stage(); err != nil {
				log.Printf("取发布: %v", err)
			}
		}
		slot, trial := b.Pick()
		if slot == "" {
			if !b.sleep(stop, b.Backoff) {
				return
			}
			continue
		}
		confirm := filepath.Join(b.Root, "confirm-"+slot)
		os.Remove(confirm)
		p, err := b.Start(filepath.Join(b.Root, slot), confirm)
		if err != nil {
			b.report("boot_start_failed", "槽 %s: %v", slot, err)
			if !b.sleep(stop, b.Backoff) {
				return
			}
			continue
		}
		if !b.watch(stop, p, trial, confirm, &lastCheck) {
			p.Kill()
			return
		}
	}
}

// watch 看护一次运行；返回 false 表示要整个退出。
func (b *Boot) watch(stop <-chan struct{}, p Proc, trial bool, confirm string, lastCheck *time.Time) bool {
	started := time.Now()
	tick := time.NewTicker(b.Poll)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return false
		case <-p.Exited():
			if trial {
				return true // 次数在 Pick 里已经记过
			}
			b.report("boot_probe_exited", "本体退出，%s 后重启", b.Backoff)
			return b.sleep(stop, b.Backoff)
		case <-tick.C:
		}
		if trial {
			if _, err := os.Stat(confirm); err == nil {
				b.promote()
				trial = false
			} else if time.Since(started) > b.ConfirmWithin {
				b.report("boot_unconfirmed", "%s 内没确认，停掉重试", b.ConfirmWithin)
				p.Kill()
				return true
			}
			continue
		}
		if time.Since(*lastCheck) >= b.CheckEvery {
			*lastCheck = time.Now()
			staged, err := b.Stage()
			if err != nil {
				log.Printf("取发布: %v", err)
			}
			if staged {
				p.Kill()
				<-p.Exited()
				return true
			}
		}
	}
}
