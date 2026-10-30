package boot

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerify(t *testing.T) {
	pub, priv := keys(t)
	m := Manifest{Version: "0.2.0", MinBoot: 1, Files: []File{{Path: "epsilon-probe.exe", Size: 3, SHA256: "ab"}}}
	s, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify([]ed25519.PublicKey{pub})
	if err != nil || got.Version != "0.2.0" || len(got.Files) != 1 {
		t.Fatalf("verify: %v %+v", err, got)
	}
}

func TestVerifyAcceptsBackupKey(t *testing.T) {
	main, _ := keys(t)
	backup, priv := keys(t)
	s, _ := Sign(Manifest{Version: "1"}, priv)
	if _, err := s.Verify([]ed25519.PublicKey{main, backup}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := keys(t)
	_, other := keys(t)
	good, _ := Sign(Manifest{Version: "1"}, priv)

	tampered := good
	tampered.Manifest = strings.Replace(good.Manifest, `"1"`, `"2"`, 1)
	wrongKey, _ := Sign(Manifest{Version: "1"}, other)
	badPath, _ := Sign(Manifest{Version: "1", Files: []File{{Path: `..\x.exe`}}}, priv)

	for name, s := range map[string]Signed{"tampered": tampered, "wrong key": wrongKey, "bad path": badPath, "empty": {}} {
		if _, err := s.Verify([]ed25519.PublicKey{pub}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
