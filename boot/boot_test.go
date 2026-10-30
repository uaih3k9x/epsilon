package boot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeSource 是假主控：发布一个版本，文件内容在内存里。
type fakeSource struct {
	mu    sync.Mutex
	rel   Signed
	files map[string][]byte
	fails int // 前几次 Fetch 失败
}

func (f *fakeSource) Release() (Signed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rel.Manifest == "" {
		return Signed{}, errors.New("no release")
	}
	return f.rel, nil
}

func (f *fakeSource) Fetch(name string, w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return errors.New("network down")
	}
	_, err := w.Write(f.files[name])
	return err
}

func (f *fakeSource) publish(t *testing.T, priv ed25519.PrivateKey, version string, files map[string]string) {
	t.Helper()
	m := Manifest{Version: version, MinBoot: 1}
	f.mu.Lock()
	f.files = map[string][]byte{}
	for name, body := range files {
		sum := sha256.Sum256([]byte(body))
		m.Files = append(m.Files, File{Path: name, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
		f.files[name] = []byte(body)
	}
	f.mu.Unlock()
	s, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rel = s
	f.mu.Unlock()
}

type fakeProc struct {
	exited chan struct{}
	once   sync.Once
	slot   string
}

func (p *fakeProc) Exited() <-chan struct{} { return p.exited }
func (p *fakeProc) Kill()                   { p.once.Do(func() { close(p.exited) }) }

// fakeRunner 记录启动了哪个槽；behave 决定本体起来后干什么。
type fakeRunner struct {
	mu     sync.Mutex
	starts []string
	behave func(slot, confirm string, p *fakeProc)
}

func (r *fakeRunner) start(slotDir, confirm string) (Proc, error) {
	slot := filepath.Base(slotDir)
	r.mu.Lock()
	r.starts = append(r.starts, slot)
	r.mu.Unlock()
	p := &fakeProc{exited: make(chan struct{}), slot: slot}
	if r.behave != nil {
		go r.behave(slot, confirm, p)
	}
	return p, nil
}

func (r *fakeRunner) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.starts...)
}

func newBoot(t *testing.T) (*Boot, *fakeSource, ed25519.PrivateKey, *fakeRunner) {
	t.Helper()
	pub, priv := keys(t)
	src := &fakeSource{}
	r := &fakeRunner{}
	var mu sync.Mutex
	var reports bytes.Buffer
	b := &Boot{Root: t.TempDir(), Keys: []ed25519.PublicKey{pub}, Src: src, Start: r.start,
		Report:        func(kind, detail string) { mu.Lock(); fmt.Fprintf(&reports, "%s %s\n", kind, detail); mu.Unlock() },
		ConfirmWithin: 300 * time.Millisecond, CheckEvery: 50 * time.Millisecond,
		Backoff: 20 * time.Millisecond, Poll: 5 * time.Millisecond}
	return b, src, priv, r
}

func confirmAfterStart(slot, confirm string, p *fakeProc) {
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(confirm, nil, 0o644)
}

func TestFirstInstall(t *testing.T) {
	b, src, priv, _ := newBoot(t)
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	ok, err := b.Stage()
	if err != nil || !ok {
		t.Fatalf("stage: %v %v", ok, err)
	}
	st := b.state()
	if st.Pending != "A" || st.Versions["A"] != "0.2.0" {
		t.Fatalf("state %+v", st)
	}
	if body, _ := os.ReadFile(filepath.Join(b.Root, "A", "epsilon-probe.exe")); string(body) != "v2" {
		t.Fatalf("file %q", body)
	}
	if ok, _ := b.Stage(); ok {
		t.Fatal("same version staged twice")
	}
}

func TestStageRejectsBadFile(t *testing.T) {
	b, src, priv, _ := newBoot(t)
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	src.files["epsilon-probe.exe"] = []byte("evil") // 清单签名没问题，文件被换了
	if ok, err := b.Stage(); ok || err == nil {
		t.Fatalf("staged a tampered file: %v %v", ok, err)
	}
	if st := b.state(); st.Pending != "" {
		t.Fatalf("pending set: %+v", st)
	}
}

func TestStageRejectsNewerBoot(t *testing.T) {
	b, src, priv, _ := newBoot(t)
	s, _ := Sign(Manifest{Version: "9", MinBoot: Version + 1}, priv)
	src.rel = s
	if ok, err := b.Stage(); ok || err == nil {
		t.Fatal("staged a release that needs a newer boot")
	}
}

func TestPickVerifiesSlot(t *testing.T) {
	b, src, priv, _ := newBoot(t)
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	b.Stage()
	os.WriteFile(filepath.Join(b.Root, "A", "epsilon-probe.exe"), []byte("evil"), 0o644)
	if slot, _ := b.Pick(); slot != "" {
		t.Fatalf("picked tampered slot %q", slot)
	}
}

func TestTrialPromoteThenUpgrade(t *testing.T) {
	b, src, priv, r := newBoot(t)
	r.behave = confirmAfterStart
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { b.Run(stop); close(done) }()

	waitFor(t, "A promoted", func() bool { st := b.state(); return st.Current == "A" && st.Pending == "" })
	src.publish(t, priv, "0.3.0", map[string]string{"epsilon-probe.exe": "v3"})
	waitFor(t, "B promoted", func() bool { st := b.state(); return st.Current == "B" && st.Good == "A" })
	close(stop)
	<-done
	if got := r.list(); len(got) < 2 || got[0] != "A" || got[len(got)-1] != "B" {
		t.Fatalf("starts %v", got)
	}
}

func TestBadVersionRollsBack(t *testing.T) {
	b, src, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {
		if slot == "A" {
			confirmAfterStart(slot, confirm, p)
			return
		}
		p.Kill() // B 一起来就崩
	}
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { b.Run(stop); close(done) }()
	waitFor(t, "A promoted", func() bool { return b.state().Current == "A" })

	src.publish(t, priv, "0.3.0", map[string]string{"epsilon-probe.exe": "broken"})
	waitFor(t, "rolled back", func() bool { st := b.state(); return st.Bad == "0.3.0" && st.Pending == "" })
	time.Sleep(100 * time.Millisecond) // 坏版本不会被反复重下重试
	close(stop)
	<-done

	st := b.state()
	if st.Current != "A" {
		t.Fatalf("state %+v", st)
	}
	n := 0
	for _, s := range r.list() {
		if s == "B" {
			n++
		}
	}
	if n != MaxTries {
		t.Fatalf("B tried %d times, want %d: %v", n, MaxTries, r.list())
	}
}

// 刚装好就连不上主控：本体一直确认不了，但也没有别的版本可退。
func TestUnconfirmedTrialIsKilled(t *testing.T) {
	b, src, priv, r := newBoot(t)
	r.behave = func(slot, confirm string, p *fakeProc) {} // 不崩也不确认：卡住
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { b.Run(stop); close(done) }()
	waitFor(t, "kept trying", func() bool { return len(r.list()) > MaxTries })
	close(stop)
	<-done
	if st := b.state(); st.Bad != "" || st.Pending != "A" {
		t.Fatalf("with nothing to fall back to the only version must not be marked bad: %+v", st)
	}
}

func TestCrashOfGoodVersionRestarts(t *testing.T) {
	b, src, priv, r := newBoot(t)
	var mu sync.Mutex
	n := 0
	r.behave = func(slot, confirm string, p *fakeProc) {
		confirmAfterStart(slot, confirm, p)
		mu.Lock()
		n++
		crash := n == 1
		mu.Unlock()
		if crash { // 转正以后再崩
			time.Sleep(30 * time.Millisecond)
			p.Kill()
		}
	}
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { b.Run(stop); close(done) }()
	waitFor(t, "restarted after crash", func() bool { return len(r.list()) >= 2 })
	close(stop)
	<-done
	if st := b.state(); st.Current != "A" || st.Bad != "" {
		t.Fatalf("a crash of the good version must not mark it bad: %+v", st)
	}
}

func TestStopKillsProbe(t *testing.T) {
	b, src, priv, r := newBoot(t)
	var p *fakeProc
	var mu sync.Mutex
	r.behave = func(slot, confirm string, fp *fakeProc) {
		mu.Lock()
		p = fp
		mu.Unlock()
		confirmAfterStart(slot, confirm, fp)
	}
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { b.Run(stop); close(done) }()
	waitFor(t, "running", func() bool { mu.Lock(); defer mu.Unlock(); return p != nil })
	close(stop)
	<-done
	select {
	case <-p.Exited():
	default:
		t.Fatal("probe still running after stop")
	}
}

func TestFetchRetriedNextRound(t *testing.T) {
	b, src, priv, _ := newBoot(t)
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	src.fails = 1
	if ok, err := b.Stage(); ok || err == nil {
		t.Fatal("first stage should fail")
	}
	if ok, err := b.Stage(); !ok || err != nil {
		t.Fatalf("retry: %v %v", ok, err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestStagingOverGoodSlotForgetsIt(t *testing.T) {
	b, src, priv, _ := newBoot(t)
	src.publish(t, priv, "0.2.0", map[string]string{"epsilon-probe.exe": "v2"})
	b.save(State{Current: "B", Good: "A", Versions: map[string]string{"A": "0.1.0", "B": "0.1.5"}})
	if ok, err := b.Stage(); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if st := b.state(); st.Pending != "A" || st.Good != "" {
		t.Fatalf("A was overwritten but is still the fallback: %+v", st)
	}
}
