package loader

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"epsilon/boot"
	"epsilon/proto"
)

// fakeCtl 是假主控：发一个签名发布和里面的文件，收事件。
type fakeCtl struct {
	mu         sync.Mutex
	rel        boot.Signed
	files      map[string][]byte
	events     []proto.Event
	evFail     bool   // 事件接口返回 500
	evFailKind string // 这一类事件返回 500
	fetches    int    // 文件下载次数
	token      string
	onFetch    func() // 每次发文件前调（模拟下载期间 boot 改了 state）
}

func (f *fakeCtl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/boot/release":
		if r.URL.Query().Get("node") != "pc-test" {
			http.Error(w, "no node", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(f.rel)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/boot/files/"):
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/v1/boot/files/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		f.fetches++
		if f.onFetch != nil {
			f.onFetch()
		}
		w.Write(b)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/events":
		var e proto.Event
		json.NewDecoder(r.Body).Decode(&e)
		if f.evFail || e.Kind == f.evFailKind && e.Kind != "" {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		f.events = append(f.events, e)
		w.Write([]byte("{}"))
	default:
		http.NotFound(w, r)
	}
}

type env struct {
	t    *testing.T
	ctl  *fakeCtl
	priv ed25519.PrivateKey
	l    *Loader
}

func newEnv(t *testing.T) *env {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ctl := &fakeCtl{token: "tok"}
	srv := httptest.NewServer(ctl)
	t.Cleanup(srv.Close)
	e := &env{t: t, ctl: ctl, priv: priv, l: &Loader{Root: t.TempDir(), Node: "pc-test", Controller: srv.URL,
		Token: "tok", Keys: []ed25519.PublicKey{pub}, BootVersion: boot.Version}}
	e.publish("0.4.0", 1, map[string]string{"epsilon-probe.exe": "probe 0.4.0", "workloads.json": "{}"})
	return e
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// publish 用 priv 签一个发布放到假主控上。
func (e *env) publish(version string, minBoot int, files map[string]string) {
	m := boot.Manifest{Version: version, MinBoot: minBoot}
	e.ctl.mu.Lock()
	defer e.ctl.mu.Unlock()
	e.ctl.files = map[string][]byte{}
	for name, body := range files {
		m.Files = append(m.Files, boot.File{Path: name, Size: int64(len(body)), SHA256: sum([]byte(body))})
		e.ctl.files[name] = []byte(body)
	}
	s, err := boot.Sign(m, e.priv)
	if err != nil {
		e.t.Fatal(err)
	}
	e.ctl.rel = s
}

func (e *env) state(s boot.State) {
	raw, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(e.l.Root, boot.StateFile), raw, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// slot 放一个旧内容，用来看有没有被动过。
func (e *env) slot(name, marker string) {
	dir := filepath.Join(e.l.Root, name)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "marker"), []byte(marker), 0o644)
}

func (e *env) marker(name string) string {
	b, _ := os.ReadFile(filepath.Join(e.l.Root, name, "marker"))
	return string(b)
}

func (e *env) staged() (boot.Staged, bool) {
	var s boot.Staged
	raw, err := os.ReadFile(filepath.Join(e.l.Root, boot.StagedFile))
	if err != nil {
		return s, false
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		e.t.Fatalf("staged.json 坏了: %v", err)
	}
	return s, true
}

func (e *env) noStaged() {
	e.t.Helper()
	if _, ok := e.staged(); ok {
		e.t.Fatal("不该有 staged.json")
	}
}

func (e *env) stage() (bool, error) { return e.l.Stage(context.Background()) }

func TestStageFresh(t *testing.T) {
	e := newEnv(t)
	ok, err := e.stage()
	if err != nil || !ok {
		t.Fatalf("Stage = %v %v", ok, err)
	}
	s, found := e.staged()
	if !found || s.Slot != "A" || s.Version != "0.4.0" {
		t.Fatalf("staged = %+v %v", s, found)
	}
	m, err := boot.VerifySlot(filepath.Join(e.l.Root, "A"), e.l.Keys)
	if err != nil || m.Version != "0.4.0" {
		t.Fatalf("槽 A 验不过: %v %v", m.Version, err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.l.Root, "A", "epsilon-probe.exe")); string(b) != "probe 0.4.0" {
		t.Fatalf("文件内容 %q", b)
	}
	left, _ := filepath.Glob(filepath.Join(e.l.Root, "*", "*.part"))
	tmp, _ := filepath.Glob(filepath.Join(e.l.Root, "*.tmp"))
	if len(left)+len(tmp) > 0 {
		t.Fatalf("留了临时文件 %v %v", left, tmp)
	}
}

func TestStageOtherSlot(t *testing.T) {
	e := newEnv(t)
	e.state(boot.State{Current: "A", Versions: map[string]string{"A": "0.3.1"}})
	e.slot("A", "old-a")
	if ok, err := e.stage(); err != nil || !ok {
		t.Fatalf("Stage = %v %v", ok, err)
	}
	if s, _ := e.staged(); s.Slot != "B" {
		t.Fatalf("staged = %+v", s)
	}
	if e.marker("A") != "old-a" {
		t.Fatal("current 槽被动了")
	}
}

// current=B 时写 A，绝不碰 B。
func TestStageNeverTouchesCurrent(t *testing.T) {
	e := newEnv(t)
	e.state(boot.State{Current: "B", Good: "A", Versions: map[string]string{"A": "0.3.0", "B": "0.3.1"}})
	e.slot("A", "old-a")
	e.slot("B", "old-b")
	if ok, err := e.stage(); err != nil || !ok {
		t.Fatalf("Stage = %v %v", ok, err)
	}
	if s, _ := e.staged(); s.Slot != "A" || s.Version != "0.4.0" {
		t.Fatalf("staged = %+v", s)
	}
	if e.marker("B") != "old-b" {
		t.Fatal("current 槽 B 被动了")
	}
	if e.marker("A") != "" {
		t.Fatal("目标槽没清空")
	}
}

func TestStageSkips(t *testing.T) {
	cases := map[string]boot.State{
		"pending 非空":   {Current: "A", Pending: "B", Versions: map[string]string{"A": "0.3.1", "B": "0.3.9"}},
		"等于 bad":       {Current: "A", Bad: "0.4.0", Versions: map[string]string{"A": "0.3.1"}},
		"等于 current":   {Current: "A", Versions: map[string]string{"A": "0.4.0"}},
		"current=B 同版": {Current: "B", Versions: map[string]string{"B": "0.4.0"}},
	}
	for name, st := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.state(st)
			e.slot("A", "old-a")
			e.slot("B", "old-b")
			if ok, err := e.stage(); err != nil || ok {
				t.Fatalf("Stage = %v %v，应该什么都不做", ok, err)
			}
			e.noStaged()
			if e.marker("A") != "old-a" || e.marker("B") != "old-b" {
				t.Fatal("槽被动了")
			}
			if e.ctl.fetches != 0 {
				t.Fatalf("下载了 %d 个文件", e.ctl.fetches)
			}
		})
	}
}

// 已经备好同版本（boot 还没消费）：不重下。重复调用幂等。
func TestStageIdempotent(t *testing.T) {
	e := newEnv(t)
	if ok, err := e.stage(); err != nil || !ok {
		t.Fatalf("Stage = %v %v", ok, err)
	}
	n := e.ctl.fetches
	for i := 0; i < 3; i++ {
		if ok, err := e.stage(); err != nil || ok {
			t.Fatalf("第 %d 次 Stage = %v %v", i+2, ok, err)
		}
	}
	if e.ctl.fetches != n {
		t.Fatalf("重复下载：%d → %d", n, e.ctl.fetches)
	}
	if _, err := boot.VerifySlot(filepath.Join(e.l.Root, "A"), e.l.Keys); err != nil {
		t.Fatalf("槽 A 被弄坏: %v", err)
	}
}

// 有别的版本的 staged.json（boot 还没消费）：等 boot 处理，不动槽、不改 staged.json。
func TestStageWaitsForBootToConsume(t *testing.T) {
	e := newEnv(t)
	if ok, err := e.stage(); err != nil || !ok {
		t.Fatalf("Stage = %v %v", ok, err)
	}
	e.publish("0.5.0", 1, map[string]string{"epsilon-probe.exe": "probe 0.5.0"})
	if ok, err := e.stage(); err != nil || ok {
		t.Fatalf("Stage = %v %v", ok, err)
	}
	if s, _ := e.staged(); s.Version != "0.4.0" {
		t.Fatalf("staged = %+v", s)
	}
}

func TestStageBadFileHash(t *testing.T) {
	e := newEnv(t)
	e.ctl.mu.Lock()
	e.ctl.files["workloads.json"] = []byte("{ 被改过 }")
	e.ctl.mu.Unlock()
	if _, err := e.stage(); err == nil {
		t.Fatal("哈希不对应该报错")
	}
	e.noStaged()
	if _, err := os.Stat(filepath.Join(e.l.Root, "A")); !os.IsNotExist(err) {
		t.Fatalf("目标槽没清掉: %v", err)
	}
}

func TestStageMissingFile(t *testing.T) {
	e := newEnv(t)
	e.ctl.mu.Lock()
	delete(e.ctl.files, "epsilon-probe.exe")
	e.ctl.mu.Unlock()
	if _, err := e.stage(); err == nil {
		t.Fatal("文件 404 应该报错")
	}
	e.noStaged()
	if _, err := os.Stat(filepath.Join(e.l.Root, "A")); !os.IsNotExist(err) {
		t.Fatalf("目标槽没清掉: %v", err)
	}
}

// 发布本身不能用（签名不对、min_boot 太大）：在动手之前就拒绝，目标槽原样保留（它可能是回退用的好槽），不写 staged.json。
func TestStageRejectsRelease(t *testing.T) {
	cases := map[string]func(e *env){
		"签名不对": func(e *env) {
			_, other, _ := ed25519.GenerateKey(nil)
			e.priv = other
			e.publish("0.4.0", 1, map[string]string{"epsilon-probe.exe": "x"})
		},
		"清单被改": func(e *env) {
			e.ctl.mu.Lock()
			e.ctl.rel.Manifest = strings.Replace(e.ctl.rel.Manifest, "0.4.0", "0.4.1", 1)
			e.ctl.mu.Unlock()
		},
		"min_boot 太大": func(e *env) { e.publish("0.4.0", e.l.BootVersion+1, map[string]string{"epsilon-probe.exe": "x"}) },
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.state(boot.State{Current: "B", Good: "A", Versions: map[string]string{"A": "0.3.0", "B": "0.3.1"}})
			e.slot("A", "old-a")
			e.slot("B", "old-b")
			bad(e)
			if _, err := e.stage(); err == nil {
				t.Fatal("应该报错")
			}
			e.noStaged()
			if e.marker("A") != "old-a" || e.marker("B") != "old-b" {
				t.Fatal("槽被动了")
			}
		})
	}
}

func TestStageBadToken(t *testing.T) {
	e := newEnv(t)
	e.l.Token = "wrong"
	if _, err := e.stage(); err == nil {
		t.Fatal("token 不对应该报错")
	}
	e.noStaged()
}

// 非法文件名在验签时就被拒（不会写到槽外面）。
func TestStageUnsafeName(t *testing.T) {
	e := newEnv(t)
	e.publish("0.4.0", 1, map[string]string{"../evil": "x"})
	if _, err := e.stage(); err == nil {
		t.Fatal("应该报错")
	}
	e.noStaged()
	if _, err := os.Stat(filepath.Join(e.l.Root, "evil")); !os.IsNotExist(err) {
		t.Fatal("写到槽外面了")
	}
}

func TestStageCanceled(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.l.Stage(ctx); err == nil {
		t.Fatal("取消了还成功")
	}
	e.noStaged()
}

// 本机 boot 比编进本体的 boot 包新：按本机的版本判断 min_boot（-boot 参数传进来的），不然会拒掉能装的发布。
func TestStageUsesRunningBootVersion(t *testing.T) {
	e := newEnv(t)
	e.l.BootVersion = boot.Version + 1
	e.publish("0.5.0", boot.Version+1, map[string]string{"epsilon-probe.exe": "probe 0.5.0"})
	if ok, err := e.stage(); !ok || err != nil {
		t.Fatalf("本机 boot 够新就该装上: %v %v", ok, err)
	}
}

// 下载期间 boot 换了 current（比如 current 坏了改跑 good），目标槽变成了 current：不交接。
func TestStageRechecksStateBeforeStaging(t *testing.T) {
	e := newEnv(t)
	e.state(boot.State{Current: "A", Good: "B", Versions: map[string]string{"A": "0.3.0", "B": "0.2.0"}})
	e.ctl.onFetch = func() { e.state(boot.State{Current: "B", Versions: map[string]string{"B": "0.2.0"}}) }
	if ok, err := e.stage(); ok || err == nil {
		t.Fatalf("目标槽成了 current 还交接: %v %v", ok, err)
	}
	e.noStaged()
}

// 旧引导器（版本 1）自己会下载：新本体在它下面跑时 loader 不插手，免得抢同一个空闲槽。
func TestStageIdleUnderOldBoot(t *testing.T) {
	e := newEnv(t)
	e.l.BootVersion = 1
	if ok, err := e.stage(); ok || err != nil {
		t.Fatalf("旧引导器下不该动: %v %v", ok, err)
	}
	e.noStaged()
	if e.ctl.fetches != 0 {
		t.Fatalf("旧引导器下不该下载: %d", e.ctl.fetches)
	}
}
