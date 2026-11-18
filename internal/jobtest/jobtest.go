// Package jobtest 给批任务的测试搭现场：根钥匙、审核钥匙、钥匙环、环境层、代码包、签好的任务包。只给测试用。
package jobtest

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"epsilon/chunk"
	"epsilon/jobsign"
)

const (
	EnvName  = "py-test@1"
	Reviewer = "reviewer-a"
)

type Fixture struct {
	Dir         string
	ChunksDir   string // 主控 chunks_dir：环境层和代码包的清单、块
	PackagesDir string // 主控 job_packages_dir
	KeyringPath string // 主控 job_keyring
	RootPub     ed25519.PublicKey
	RootPriv    ed25519.PrivateKey
	RevPriv     ed25519.PrivateKey
	Ring        jobsign.Keyring // 最近一次写出去的钥匙环
}

func key(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// New 搭好现场：一层只有 python.exe 的假环境层、版本 1 的钥匙环（一把审核钥匙，30 天后过期，最多 20 台）。
func New(t testing.TB) *Fixture {
	t.Helper()
	f := &Fixture{Dir: t.TempDir()}
	f.ChunksDir = filepath.Join(f.Dir, "chunks")
	f.PackagesDir = filepath.Join(f.Dir, "packages")
	f.KeyringPath = filepath.Join(f.Dir, "job-keyring.json")
	os.MkdirAll(f.PackagesDir, 0o755)
	f.RootPub, f.RootPriv = key(t)
	revPub, revPriv := key(t)
	f.RevPriv = revPriv

	zipPath := filepath.Join(f.Dir, "src", "envs", EnvName+".zip")
	os.MkdirAll(filepath.Dir(zipPath), 0o755)
	os.WriteFile(zipPath, Zip(t, map[string]string{"python.exe": "fake", "Lib/os.py": ""}), 0o644)
	if _, err := chunk.Build(EnvName, filepath.Join(f.Dir, "src"), []string{"envs/" + EnvName + ".zip"}, 1<<20, f.ChunksDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.ChunksDir, EnvName+".json"))
	if err != nil {
		t.Fatal(err)
	}
	f.Ring = jobsign.Keyring{
		Version: 1,
		Issued:  time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		Keys: []jobsign.Key{{Name: Reviewer, Pub: base64.StdEncoding.EncodeToString(revPub),
			Expires: time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			Limits:  jobsign.Limits{MaxHours: 4, MaxNodes: 20}}},
		EnvLayers: map[string]string{EnvName: Sum(raw)},
	}
	f.WriteKeyring(t, f.Ring)
	return f
}

// Sum 是小写十六进制 SHA-256。
func Sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Zip 按文件名排序打一个 zip。
func Zip(t testing.TB, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[n]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// WriteKeyring 用根钥匙签 ring，写到主控的 job_keyring。
func (f *Fixture) WriteKeyring(t testing.TB, ring jobsign.Keyring) {
	t.Helper()
	s, err := jobsign.SignKeyring(ring, f.RootPriv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if err := os.WriteFile(f.KeyringPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	f.Ring = ring
}

// Job 是一份能签的 job.json（纯 CPU，entry = python main.py）。CodeSHA256 由 Package 填。
func Job(name string) jobsign.Job {
	no := false
	return jobsign.Job{Schema: 1, Name: name, Version: "1.0.0", Description: "测试", Owner: "tester",
		Entry: []string{"python", "main.py"}, Env: EnvName, GPU: &no, MaxHours: 1, DiskMaxMB: 100, OutputMaxMB: 10,
		Params: map[string]json.RawMessage{"sleep_ms": json.RawMessage(`{"type":"int","min":0,"max":60000,"default":0}`)}}
}

// CodeID 是代码包的清单 ID（docs/jobs.md）：code-<code_sha256>，里面只有一个文件 jobcode/<code_sha256>.zip。
func CodeID(sha string) string { return "code-" + sha }

// Code 把代码包切块放进 chunks_dir，返回 code.zip 的 SHA-256。
func (f *Fixture) Code(t testing.TB, code map[string]string) string {
	t.Helper()
	z := Zip(t, code)
	sha := Sum(z)
	src := filepath.Join(f.Dir, "src")
	p := filepath.Join(src, "jobcode", sha+".zip")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, z, 0o644)
	if _, err := chunk.Build(CodeID(sha), src, []string{"jobcode/" + sha + ".zip"}, 1<<20, f.ChunksDir); err != nil {
		t.Fatal(err)
	}
	return sha
}

// Package 放好代码包、签任务包，写到 job_packages_dir/<name>@<version>.json，返回 "name@version"。
func (f *Fixture) Package(t testing.TB, j jobsign.Job, code map[string]string) string {
	t.Helper()
	if j.CodeSHA256 == "" {
		j.CodeSHA256 = f.Code(t, code)
	}
	return f.Sign(t, j, f.RevPriv)
}

// Sign 用 priv 签 j（名字按 Reviewer），写进 job_packages_dir。
func (f *Fixture) Sign(t testing.TB, j jobsign.Job, priv ed25519.PrivateKey) string {
	t.Helper()
	text, _ := json.MarshalIndent(j, "", "  ")
	s, err := jobsign.SignJob(text, Reviewer, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	pkg := j.Name + "@" + j.Version
	if err := os.WriteFile(filepath.Join(f.PackagesDir, pkg+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return pkg
}

// BadKey 是一把不在钥匙环里的钥匙（冒充审核人）。
func BadKey(t testing.TB) ed25519.PrivateKey { _, p := key(t); return p }
