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

	"epsilon/chunk"
	"epsilon/controller"
	"epsilon/jobsign"
	"epsilon/probe"
	"epsilon/proto"
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
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out, filepath.Join(d, "chunks")); err != nil {
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
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out, filepath.Join(d, "chunks")); err == nil {
		t.Fatal("code.zip 哈希对不上也让签了")
	}
	sum := sha256.Sum256([]byte("zip"))
	writeJSON(t, job, demoJob(hex.EncodeToString(sum[:])))
	if err := cmdSignJob(other, "reviewer-a", ring, job, code, out, filepath.Join(d, "chunks")); err == nil {
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
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out, filepath.Join(d, "chunks")); err != nil {
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
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out, filepath.Join(d, "chunks")); err == nil {
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
	if err := cmdSignJob(rev, "reviewer-a", ring, job, code, out, filepath.Join(d, "chunks")); err != nil {
		t.Fatal(err)
	}
	var sj jobsign.SignedJob
	b, _ := os.ReadFile(out)
	json.Unmarshal(b, &sj)
	if len(sj.Warnings) == 0 {
		t.Fatal("warning 要留在 job.signed.json 里, 事后能查")
	}
}

// signRig: 根钥匙、审核钥匙、钥匙环、code.zip、job.json 都备好，chunks 目录空着。
type signRig struct {
	d, rev, ring, job, code, out, chunks, sum string
	zip                                       []byte
}

func newSignRig(t *testing.T) signRig {
	t.Helper()
	d := t.TempDir()
	r := signRig{d: d, rev: filepath.Join(d, "rev.key"), ring: filepath.Join(d, "ring.json"), job: filepath.Join(d, "job.json"),
		code: filepath.Join(d, "code.zip"), out: filepath.Join(d, "o.json"), chunks: filepath.Join(d, "chunks"),
		zip: []byte("PK fake zip, long enough for several tiny chunks")}
	root := filepath.Join(d, "root.key")
	cmdKeygen(root)
	cmdKeygen(r.rev)
	src := filepath.Join(d, "src.json")
	writeJSON(t, src, jobsign.Keyring{Version: 1, Keys: []jobsign.Key{{
		Name: "reviewer-a", Pub: readKeyPub(t, r.rev), Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Limits: jobsign.Limits{MaxHours: 4},
	}}, EnvLayers: testLayers})
	if err := cmdKeyring(root, src, r.ring); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(r.code, r.zip, 0o644)
	s := sha256.Sum256(r.zip)
	r.sum = hex.EncodeToString(s[:])
	writeJSON(t, r.job, demoJob(r.sum))
	return r
}

func (r signRig) sign() error {
	return cmdSignJob(r.rev, "reviewer-a", r.ring, r.job, r.code, r.out, r.chunks)
}

func (r signRig) manifestPath() string {
	return filepath.Join(r.chunks, controller.CodeManifestID(r.sum)+".json")
}

// prebuild 按 chunk.Build 的格式手工出一份代码包清单（内容可以和 code.zip 不一样）。
func (r signRig) prebuild(t *testing.T, content []byte, chunkSize int64) []byte {
	t.Helper()
	src := filepath.Join(r.d, "pre")
	p := filepath.Join(src, filepath.FromSlash(probe.CodePath(r.sum)))
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, content, 0o644)
	if _, err := chunk.Build(controller.CodeManifestID(r.sum), src, []string{probe.CodePath(r.sum)}, chunkSize, r.chunks); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(r.manifestPath())
	return b
}

// 没有清单: sign-job 生成，格式就是探针 prepareCode 要的（code-<sha>，只有 jobcode/<sha>.zip），块能拼回原文件。
func TestSignJobWritesCodeManifest(t *testing.T) {
	r := newSignRig(t)
	if err := r.sign(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.manifestPath())
	if err != nil {
		t.Fatalf("没生成代码包清单: %v", err)
	}
	var m proto.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.ID != controller.CodeManifestID(r.sum) || len(m.Files) != 1 || m.Files[0].Path != probe.CodePath(r.sum) ||
		m.Files[0].SHA256 != r.sum || m.Files[0].Size != int64(len(r.zip)) {
		t.Fatalf("清单格式不是探针要的: %+v", m)
	}
	s, err := chunk.NewStore(r.chunks, 0)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(r.d, "probe-root")
	if err := chunk.Assemble(m, s, dst); err != nil {
		t.Fatalf("块拼不回来: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, filepath.FromSlash(probe.CodePath(r.sum)))); string(got) != string(r.zip) {
		t.Fatal("拼出来的和 code.zip 不一样")
	}
}

// 已有清单而且和 code.zip 对得上（块大小不同也算）：照用，一个字节都不改。
func TestSignJobKeepsMatchingManifest(t *testing.T) {
	r := newSignRig(t)
	before := r.prebuild(t, r.zip, 7)
	if err := r.sign(); err != nil {
		t.Fatalf("对得上的清单不该拒: %v", err)
	}
	if after, _ := os.ReadFile(r.manifestPath()); string(after) != string(before) {
		t.Fatal("已有清单被改写了")
	}
}

// 已有清单和 code.zip 对不上 / 坏了：报错，不覆盖，不出签名文件。
func TestSignJobRefusesStaleManifest(t *testing.T) {
	for name, mk := range map[string]func(r signRig, t *testing.T) []byte{
		"内容不同": func(r signRig, t *testing.T) []byte { return r.prebuild(t, []byte("PK older code.zip"), 7) },
		"块对不上": func(r signRig, t *testing.T) []byte {
			b := r.prebuild(t, r.zip, 7)
			var m proto.Manifest
			json.Unmarshal(b, &m)
			m.Files[0].Chunks[0] = strings.Repeat("ab", 32)
			b, _ = json.MarshalIndent(m, "", "  ")
			os.WriteFile(r.manifestPath(), b, 0o644)
			return b
		},
		"格式坏了": func(r signRig, t *testing.T) []byte {
			os.MkdirAll(r.chunks, 0o755)
			os.WriteFile(r.manifestPath(), []byte("{not json"), 0o644)
			return []byte("{not json")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSignRig(t)
			before := mk(r, t)
			if err := r.sign(); err == nil {
				t.Fatal("和 code.zip 对不上的清单竟然签了")
			}
			if after, _ := os.ReadFile(r.manifestPath()); string(after) != string(before) {
				t.Fatal("对不上的清单被静默覆盖了")
			}
			if _, err := os.Stat(r.out); err == nil {
				t.Fatal("清单对不上时不该留下签名文件")
			}
		})
	}
}

// chunkFiles 列出块目录里所有块文件（相对路径），清单不算。
func chunkFiles(t *testing.T, dir string) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() && !strings.HasSuffix(p, ".json") {
			rel, _ := filepath.Rel(dir, p)
			got[rel] = true
		}
		return nil
	})
	return got
}

// 已有清单对不上：先比对再写块，块目录里不能多出孤儿块。
func TestSignJobStaleManifestLeavesNoOrphanChunks(t *testing.T) {
	r := newSignRig(t)
	r.prebuild(t, []byte("PK older code.zip"), 7)
	before := chunkFiles(t, r.chunks)
	if err := r.sign(); err == nil {
		t.Fatal("对不上的清单竟然签了")
	}
	if after := chunkFiles(t, r.chunks); len(after) != len(before) {
		t.Fatalf("比对失败还往块目录写了块: 之前 %d 个, 之后 %d 个", len(before), len(after))
	}
}

// 块目录里已有的块文件坏了（截断、改过）：sign-job 要发现，不能只核对清单。
func TestSignJobRefusesCorruptExistingChunk(t *testing.T) {
	for name, prebuilt := range map[string]bool{"有清单": true, "没清单": false} {
		t.Run(name, func(t *testing.T) {
			r := newSignRig(t)
			r.prebuild(t, r.zip, 7)
			var m proto.Manifest
			b, _ := os.ReadFile(r.manifestPath())
			json.Unmarshal(b, &m)
			h := m.Files[0].Chunks[1]
			if !prebuilt {
				// 块大小改成默认值才会撞上同一个块：直接用默认块大小重做一份，再删清单
				os.RemoveAll(r.chunks)
				f, err := chunk.BuildFile(r.chunks, r.code, 0)
				if err != nil {
					t.Fatal(err)
				}
				h = f.Chunks[0]
			}
			if err := os.WriteFile(filepath.Join(r.chunks, h[:2], h), []byte("PK"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := r.sign(); err == nil || !strings.Contains(err.Error(), h) {
				t.Fatalf("坏块没被发现（或报错没指出是哪个块）: %v", err)
			}
			if _, err := os.Stat(r.out); err == nil {
				t.Fatal("块坏了不该留下签名文件")
			}
		})
	}
}

// 钥匙环源文件：limits 里必须显式写 max_nodes（防漏写、键名写错被当成 0 = 不限制）；写 0 给 warning。
func TestKeyringSourceMaxNodes(t *testing.T) {
	for name, tc := range map[string]struct {
		src  string
		ok   bool
		warn bool
	}{
		"漏写":        {`{"version":1,"keys":[{"name":"a","limits":{"max_hours":1}}]}`, false, false},
		"键名写错":      {`{"version":1,"keys":[{"name":"a","limits":{"max_hours":1,"maxNodes":5}}]}`, false, false},
		"没有 limits": {`{"version":1,"keys":[{"name":"a"}]}`, false, false},
		"写 0":       {`{"version":1,"keys":[{"name":"a","limits":{"max_hours":1,"max_nodes":0}}]}`, true, true},
		"写具体数":      {`{"version":1,"keys":[{"name":"a","limits":{"max_hours":1,"max_nodes":5}}]}`, true, false},
		"没有钥匙":      {`{"version":1}`, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			w, err := keyringSourceWarnings([]byte(tc.src))
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v, 要的是 ok=%v", err, tc.ok)
			}
			if (len(w) > 0) != tc.warn {
				t.Fatalf("warnings=%v, 要的是 warn=%v", w, tc.warn)
			}
		})
	}
	// cmdKeyring 也要拒漏写的源文件，而且不出钥匙环
	d := t.TempDir()
	root, src, ring := filepath.Join(d, "root.key"), filepath.Join(d, "src.json"), filepath.Join(d, "ring.json")
	cmdKeygen(root)
	os.WriteFile(src, []byte(`{"version":1,"keys":[{"name":"a","pub":"x","expires":"2099-01-01T00:00:00Z","limits":{"max_hours":1}}]}`), 0o644)
	if err := cmdKeyring(root, src, ring); err == nil {
		t.Fatal("漏写 max_nodes 的源文件竟然签了")
	}
	if _, err := os.Stat(ring); err == nil {
		t.Fatal("拒签时不该留下钥匙环")
	}
}
