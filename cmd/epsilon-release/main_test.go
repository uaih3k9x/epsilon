package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"epsilon/boot"
)

// releaseFixture 在 tmp 里放一把钥匙和一份工作负载表，返回钥匙路径、目录和公钥。
func releaseFixture(t *testing.T) (string, string, ed25519.PublicKey) {
	t.Helper()
	d := t.TempDir()
	key := filepath.Join(d, "release.key")
	pubB64, err := cmdKeygen(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(pubB64)
	if err := os.WriteFile(filepath.Join(d, "workloads.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	return key, d, ed25519.PublicKey(pub)
}

// F1：清单里没有 epsilon-probe.exe 的发布所有引导器都会拒，发版时就要拦下，不留任何产出。
func TestReleaseRefusesWithoutProbe(t *testing.T) {
	key, d, _ := releaseFixture(t)
	out := filepath.Join(d, "out")
	// 大小写不同也不算（VerifySlot 按字节比）
	if err := os.WriteFile(filepath.Join(d, "Epsilon-Probe.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, files := range [][]string{
		{filepath.Join(d, "workloads.json")},
		{filepath.Join(d, "workloads.json"), filepath.Join(d, "Epsilon-Probe.exe")},
	} {
		args := append([]string{"-key", key, "-version", "0.2.0", "-out", out}, files...)
		if err := runRelease(args); err == nil {
			t.Fatalf("%v: 缺 %s 应该报错", files, boot.ProbeExe)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%v: 报错时不该产出 -out 目录（stat err=%v）", files, err)
		}
	}
}

// 已有的 -out 目录（上一版的产出）在报错时也不该被清掉。
func TestReleaseRefusesWithoutProbeKeepsOldOutput(t *testing.T) {
	key, d, _ := releaseFixture(t)
	out := filepath.Join(d, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(out, boot.ReleaseFile)
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runRelease([]string{"-key", key, "-version", "0.2.0", "-out", out, filepath.Join(d, "workloads.json")}); err == nil {
		t.Fatal("缺本体应该报错")
	}
	if b, err := os.ReadFile(old); err != nil || string(b) != "old" {
		t.Fatalf("旧产出被动了: %q %v", b, err)
	}
}

func TestReleaseWithProbeSigns(t *testing.T) {
	key, d, pub := releaseFixture(t)
	probe := filepath.Join(d, boot.ProbeExe)
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(d, "out")
	if err := runRelease([]string{"-key", key, "-version", "0.2.0", "-out", out, probe, filepath.Join(d, "workloads.json")}); err != nil {
		t.Fatal(err)
	}
	m, err := boot.VerifySlot(out, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("签出来的发布引导器不收: %v", err)
	}
	if m.Version != "0.2.0" || len(m.Files) != 2 {
		t.Fatalf("清单不对: %+v", m)
	}
}
