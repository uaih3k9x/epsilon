package main

import (
	"bytes"
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
	"testing"

	"epsilon/boot"
	"epsilon/loader"
	"epsilon/probe"
)

func TestBootVersion(t *testing.T) {
	for in, want := range map[string]int{"1/A": 1, "12/B": 12} {
		if v, err := bootVersion(in); err != nil || v != want {
			t.Fatalf("bootVersion(%q) = %d %v", in, v, err)
		}
	}
	for _, in := range []string{"", "A", "x/A", "/B"} {
		if _, err := bootVersion(in); err == nil {
			t.Fatalf("bootVersion(%q) 应该报错", in)
		}
	}
}

func TestNewLoader(t *testing.T) {
	cfg := probe.Config{Node: "pc-test", Controller: "http://ctl.invalid:8090", Token: "tok"}
	cfgPath := filepath.Join("some", "dir", "probe.json")
	l, err := newLoader(cfg, cfgPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if l.Root != filepath.Join("some", "dir") || l.Node != "pc-test" || l.Controller != cfg.Controller || l.Token != "tok" {
		t.Fatalf("loader = %+v", l)
	}
	if len(l.Keys) != len(loader.PublicKeys) {
		t.Fatalf("公钥 %d 个", len(l.Keys))
	}
	if l, _ := newLoader(cfg, cfgPath, "other"); l.Root != "other" {
		t.Fatalf("-root 没生效: %q", l.Root)
	}
}

// -seed：跑一轮 Stage 就退出，成功 0、失败非 0 并说原因。
func TestSeed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := []byte("probe 0.4.0")
	h := sha256.Sum256(body)
	rel, _ := boot.Sign(boot.Manifest{Version: "0.4.0", MinBoot: boot.Version,
		Files: []boot.File{{Path: "epsilon-probe.exe", Size: int64(len(body)), SHA256: hex.EncodeToString(h[:])}}}, priv)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/boot/release":
			json.NewEncoder(w).Encode(rel)
		case "/v1/boot/files/epsilon-probe.exe":
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	l := &loader.Loader{Root: root, Node: "pc-test", Controller: srv.URL, Keys: []ed25519.PublicKey{pub}}
	var out bytes.Buffer
	if code := seed(context.Background(), l, "", &out); code != 0 {
		t.Fatalf("seed = %d: %s", code, out.String())
	}
	if l.BootVersion != boot.Version {
		t.Fatalf("BootVersion = %d", l.BootVersion)
	}
	raw, err := os.ReadFile(filepath.Join(root, boot.StagedFile))
	if err != nil || !strings.Contains(string(raw), `"A"`) {
		t.Fatalf("staged.json: %s %v", raw, err)
	}
	// 再跑一次：已经备好，也算成功
	if code := seed(context.Background(), l, "", &out); code != 0 {
		t.Fatalf("第二次 seed = %d: %s", code, out.String())
	}

	out.Reset()
	wrong, _, _ := ed25519.GenerateKey(nil)
	bad := &loader.Loader{Root: t.TempDir(), Node: "pc-test", Controller: srv.URL, Keys: []ed25519.PublicKey{wrong}}
	if code := seed(context.Background(), bad, "", &out); code == 0 || out.Len() == 0 {
		t.Fatalf("验签不过应该非 0 并说原因: %d %q", code, out.String())
	}
}

// -seed 的引导器版本：带 -boot（救援，boot 传 "<版本>/R"）用它；没带（安装脚本）用编进来的 boot.Version。
func TestSeedBootVersion(t *testing.T) {
	if v, err := seedBootVersion(""); err != nil || v != boot.Version {
		t.Fatalf("没带 -boot: %d %v", v, err)
	}
	if v, err := seedBootVersion("3/R"); err != nil || v != 3 {
		t.Fatalf("-boot 3/R: %d %v", v, err)
	}
	if _, err := seedBootVersion("x/R"); err == nil {
		t.Fatal("-boot 不对应该报错")
	}
}

// 救援：-boot 3/R 时按 3 判断 min_boot，并且用 seed 规则（首装版本坏了也放到另一个槽）。
func TestSeedRescue(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := []byte("probe 0.4.0")
	h := sha256.Sum256(body)
	rel, _ := boot.Sign(boot.Manifest{Version: "0.4.0", MinBoot: 3,
		Files: []boot.File{{Path: "epsilon-probe.exe", Size: int64(len(body)), SHA256: hex.EncodeToString(h[:])}}}, priv)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/boot/release":
			json.NewEncoder(w).Encode(rel)
		case "/v1/boot/files/epsilon-probe.exe":
			w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	root := t.TempDir()
	raw, _ := json.Marshal(boot.State{Pending: "A", Tries: 3, Versions: map[string]string{"A": "0.3.9"}})
	os.WriteFile(filepath.Join(root, boot.StateFile), raw, 0o644)
	l := &loader.Loader{Root: root, Node: "pc-01", Controller: srv.URL, Keys: []ed25519.PublicKey{pub}}
	var out bytes.Buffer
	if code := seed(context.Background(), l, "3/R", &out); code != 0 {
		t.Fatalf("seed = %d: %s", code, out.String())
	}
	if l.BootVersion != 3 || !l.Seed {
		t.Fatalf("loader = %+v", l)
	}
	if raw, err := os.ReadFile(filepath.Join(root, boot.StagedFile)); err != nil || !strings.Contains(string(raw), `"B"`) {
		t.Fatalf("staged.json: %s %v", raw, err)
	}
	if code := seed(context.Background(), l, "R", &out); code == 0 {
		t.Fatal("-boot 不对应该失败")
	}
}
