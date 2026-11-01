package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"epsilon/jobsign"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readKeyPub(t *testing.T, keyPath string) string {
	t.Helper()
	priv, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

var testLayers = map[string]string{"py311-base@1": strings.Repeat("cd", 32)}

func demoJob(sum string) map[string]any {
	return map[string]any{
		"schema": 1, "name": "demo-job", "version": "1.0.0", "description": "演示", "owner": "tester",
		"entry": []string{"python", "train.py"}, "env": "py311-base@1", "gpu_mem_mb": 1000, "max_hours": 1,
		"disk_max_mb": 128, "output_max_mb": 64, "code_sha256": sum,
	}
}

// 整条链: 生成根钥匙和审核钥匙 -> 签钥匙环 -> 签任务包 -> 探针侧验过
func TestJobChainEndToEnd(t *testing.T) {
	d := t.TempDir()
	root, rev := filepath.Join(d, "root.key"), filepath.Join(d, "rev.key")
	if _, err := cmdKeygen(root); err != nil {
		t.Fatal(err)
	}
	if _, err := cmdKeygen(rev); err != nil {
		t.Fatal(err)
	}
	if _, err := cmdKeygen(rev); err == nil {
		t.Fatal("keygen 不该覆盖已有的钥匙文件")
	}
	src := filepath.Join(d, "keyring-src.json")
	writeJSON(t, src, jobsign.Keyring{Version: 1, Keys: []jobsign.Key{{
		Name: "reviewer-a", Pub: readKeyPub(t, rev), Expires: time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339),
		Limits: jobsign.Limits{MaxHours: 4, MaxNodes: 10},
	}}, EnvLayers: testLayers})
	ring := filepath.Join(d, "job-keyring.json")
	if err := cmdKeyring(root, src, ring); err != nil {
		t.Fatal(err)
	}

	code := filepath.Join(d, "code.zip")
	os.WriteFile(code, []byte("PK fake zip"), 0o644)
	sum := sha256.Sum256([]byte("PK fake zip"))
	job := filepath.Join(d, "job.json")
	writeJSON(t, job, demoJob(hex.EncodeToString(sum[:])))
	out := filepath.Join(d, "job.signed.json")
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out); err != nil {
		t.Fatal(err)
	}

	// 探针侧: 根公钥验钥匙环, 再验任务包
	var skr jobsign.SignedKeyring
	b, _ := os.ReadFile(ring)
	json.Unmarshal(b, &skr)
	rootPriv, _ := loadKey(root)
	kr, err := jobsign.VerifyKeyring(skr, []ed25519.PublicKey{rootPriv.Public().(ed25519.PublicKey)}, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var sj jobsign.SignedJob
	b, _ = os.ReadFile(out)
	json.Unmarshal(b, &sj)
	if _, _, err := jobsign.VerifyJob(sj, kr, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestKeyringFillsIssuedAndRefusesRollback(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root.key")
	cmdKeygen(root)
	src, ring := filepath.Join(d, "src.json"), filepath.Join(d, "ring.json")
	writeJSON(t, src, jobsign.Keyring{Version: 2})
	if err := cmdKeyring(root, src, ring); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(ring)
	if !strings.Contains(string(b), `issued`) {
		t.Fatal("没填签发时间")
	}
	writeJSON(t, src, jobsign.Keyring{Version: 2}) // 同版本重签 = 回滚风险
	if err := cmdKeyring(root, src, ring); err == nil {
		t.Fatal("版本号没变也让签了")
	}
	writeJSON(t, src, jobsign.Keyring{Version: 3})
	if err := cmdKeyring(root, src, ring); err != nil {
		t.Fatalf("版本号增大应该能签: %v", err)
	}
}

func TestSignJobRefusesMismatches(t *testing.T) {
	d := t.TempDir()
	root, rev, other := filepath.Join(d, "root.key"), filepath.Join(d, "rev.key"), filepath.Join(d, "other.key")
	cmdKeygen(root)
	cmdKeygen(rev)
	cmdKeygen(other)
	src, ring := filepath.Join(d, "src.json"), filepath.Join(d, "ring.json")
	writeJSON(t, src, jobsign.Keyring{Version: 1, Keys: []jobsign.Key{{
		Name: "reviewer-a", Pub: readKeyPub(t, rev), Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Limits: jobsign.Limits{MaxHours: 4},
	}}, EnvLayers: testLayers})
	cmdKeyring(root, src, ring)
	code := filepath.Join(d, "code.zip")
	os.WriteFile(code, []byte("zip"), 0o644)
	job := filepath.Join(d, "job.json")
	writeJSON(t, job, demoJob(strings.Repeat("0", 64)))
	out := filepath.Join(d, "o.json")
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out); err == nil {
		t.Fatal("code.zip 哈希对不上也让签了")
	}
	sum := sha256.Sum256([]byte("zip"))
	writeJSON(t, job, demoJob(hex.EncodeToString(sum[:])))
	if err := cmdSignJob(other, "reviewer-a", ring, job, code, out); err == nil {
		t.Fatal("私钥跟钥匙环里的公钥对不上也让签了")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("签名失败时不该留下输出文件")
	}
}

func TestSignJobSignsOriginalBytes(t *testing.T) {
	d := t.TempDir()
	root, rev := filepath.Join(d, "root.key"), filepath.Join(d, "rev.key")
	cmdKeygen(root)
	cmdKeygen(rev)
	src, ring := filepath.Join(d, "src.json"), filepath.Join(d, "ring.json")
	writeJSON(t, src, jobsign.Keyring{Version: 1, Keys: []jobsign.Key{{
		Name: "reviewer-a", Pub: readKeyPub(t, rev), Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Limits: jobsign.Limits{MaxHours: 4},
	}}, EnvLayers: testLayers})
	if err := cmdKeyring(root, src, ring); err != nil {
		t.Fatal(err)
	}
	code := filepath.Join(d, "code.zip")
	os.WriteFile(code, []byte("zip"), 0o644)
	sum := sha256.Sum256([]byte("zip"))
	// 手册 5.2 的键序 (schema 在最后)、空 data、显式 false、<>& 和中文: 过一遍 job.signed.json 也要逐字节不变
	text := `{
  "name": "demo-job",
  "version": "1.0.0",
  "entry": ["python", "train.py"],
  "env": "py311-base@1",
  "data": [],
  "params": {"trial": "int", "device": "string"},
  "gpu_mem_mb": 1000,
  "max_hours": 1,
  "code_sha256": "` + hex.EncodeToString(sum[:]) + `",
  "description": "演示 <a&b>",
  "owner": "tester",
  "disk_max_mb": 128,
  "output_max_mb": 64,
  "network": false,
  "gpu": true,
  "schema": 1
}
`
	job, out := filepath.Join(d, "job.json"), filepath.Join(d, "o.json")
	os.WriteFile(job, []byte(text), 0o644)
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out); err != nil {
		t.Fatal(err)
	}
	var sj jobsign.SignedJob
	b, _ := os.ReadFile(out)
	if err := json.Unmarshal(b, &sj); err != nil {
		t.Fatal(err)
	}
	if sj.Job != text {
		t.Fatalf("签的不是 job.json 原文:\n%s", sj.Job)
	}

	os.Remove(out)
	os.WriteFile(job, append([]byte("\xef\xbb\xbf"), text...), 0o644)
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out); err == nil {
		t.Fatal("带 BOM 的 job.json 竟然签了 (手册要求无 BOM)")
	}
}

func TestSignJobRecordsWarnings(t *testing.T) {
	d := t.TempDir()
	root, rev := filepath.Join(d, "root.key"), filepath.Join(d, "rev.key")
	cmdKeygen(root)
	cmdKeygen(rev)
	src, ring := filepath.Join(d, "src.json"), filepath.Join(d, "ring.json")
	writeJSON(t, src, jobsign.Keyring{Version: 1, Keys: []jobsign.Key{{
		Name: "reviewer-a", Pub: readKeyPub(t, rev), Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Limits: jobsign.Limits{MaxHours: 4},
	}}, EnvLayers: testLayers})
	if err := cmdKeyring(root, src, ring); err != nil {
		t.Fatal(err)
	}
	code := filepath.Join(d, "code.zip")
	os.WriteFile(code, []byte("zip"), 0o644)
	sum := sha256.Sum256([]byte("zip"))
	m := demoJob(hex.EncodeToString(sum[:]))
	delete(m, "description")
	job, out := filepath.Join(d, "job.json"), filepath.Join(d, "o.json")
	writeJSON(t, job, m)
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out); err != nil {
		t.Fatal(err)
	}
	var sj jobsign.SignedJob
	b, _ := os.ReadFile(out)
	json.Unmarshal(b, &sj)
	if len(sj.Warnings) == 0 {
		t.Fatal("warning 要留在 job.signed.json 里, 事后能查")
	}
}
