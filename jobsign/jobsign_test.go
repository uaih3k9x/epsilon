package jobsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func b64(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }

// 一套固定的场景: 根钥匙 + 审核人钥匙 + 一份钥匙环
type fixture struct {
	rootPub  ed25519.PublicKey
	rootPriv ed25519.PrivateKey
	revPub   ed25519.PublicKey
	revPriv  ed25519.PrivateKey
	ring     Keyring
	signedKR SignedKeyring
	roots    []ed25519.PublicKey
}

func setup(t *testing.T) fixture {
	t.Helper()
	var f fixture
	f.rootPub, f.rootPriv = newKey(t)
	f.revPub, f.revPriv = newKey(t)
	f.ring = Keyring{
		Version: 3,
		Issued:  t0.Add(-time.Hour).Format(time.RFC3339),
		Keys: []Key{{
			Name: "reviewer-a", Pub: b64(f.revPub),
			Expires: t0.Add(30 * 24 * time.Hour).Format(time.RFC3339),
			Limits:  Limits{MaxHours: 4, MaxNodes: 20, Rooms: []string{"R1", "R2"}, Network: false},
		}},
	}
	var err error
	f.signedKR, err = SignKeyring(f.ring, f.rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	f.roots = []ed25519.PublicKey{f.rootPub}
	return f
}

func goodJob() Job {
	return Job{
		Schema: 1, Name: "cifar10-hpsearch", Version: "1.0.0", Description: "网格搜索", Owner: "zhangsan",
		Entry: []string{"python", "train.py"}, Env: "py311-torch2.5-cu124@3", Data: []string{"cifar10@1"},
		Params:   map[string]json.RawMessage{"trial": json.RawMessage(`{"type":"int","min":0,"max":23}`)},
		GPUMemMB: 3500, MaxHours: 2, DiskMaxMB: 1024, OutputMaxMB: 100,
		CodeSHA256: strings.Repeat("ab", 32),
	}
}

// ------------------------------------------------------------------ 钥匙环

func TestKeyringRoundTrip(t *testing.T) {
	f := setup(t)
	kr, err := VerifyKeyring(f.signedKR, f.roots, 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if kr.Version != 3 || len(kr.Keys) != 1 || kr.Keys[0].Name != "reviewer-a" {
		t.Fatalf("钥匙环内容不对: %+v", kr)
	}
}

func TestKeyringTamperedRejected(t *testing.T) {
	f := setup(t)
	s := f.signedKR
	s.Keyring = strings.Replace(s.Keyring, `"max_hours": 4`, `"max_hours": 400`, 1)
	if _, err := VerifyKeyring(s, f.roots, 0, t0); err == nil {
		t.Fatal("改过的钥匙环竟然验过了")
	}
}

func TestKeyringSignedByNonRootRejected(t *testing.T) {
	f := setup(t)
	s, _ := SignKeyring(f.ring, f.revPriv) // 审核人钥匙不能签钥匙环
	if _, err := VerifyKeyring(s, f.roots, 0, t0); err == nil {
		t.Fatal("非根钥匙签的钥匙环竟然验过了")
	}
}

func TestKeyringRollbackRejected(t *testing.T) {
	f := setup(t)
	if _, err := VerifyKeyring(f.signedKR, f.roots, 4, t0); err == nil {
		t.Fatal("比见过的旧的钥匙环 (回滚) 竟然收了")
	}
	if _, err := VerifyKeyring(f.signedKR, f.roots, 3, t0); err != nil {
		t.Fatalf("同版本应该能收 (重启后再读一次): %v", err)
	}
}

func TestKeyringFromFutureRejected(t *testing.T) {
	f := setup(t)
	ring := f.ring
	ring.Issued = t0.Add(48 * time.Hour).Format(time.RFC3339)
	s, _ := SignKeyring(ring, f.rootPriv)
	if _, err := VerifyKeyring(s, f.roots, 0, t0); err == nil {
		t.Fatal("签发时间远在未来的钥匙环 (本机时钟不对或伪造) 竟然收了")
	}
}

func TestKeyringStructuralChecks(t *testing.T) {
	f := setup(t)
	cases := map[string]func(*Keyring){
		"版本号为 0":     func(k *Keyring) { k.Version = 0 },
		"钥匙名重复":      func(k *Keyring) { k.Keys = append(k.Keys, k.Keys[0]) },
		"公钥不是 32 字节": func(k *Keyring) { k.Keys[0].Pub = base64.StdEncoding.EncodeToString([]byte("short")) },
		"过期时间格式坏":    func(k *Keyring) { k.Keys[0].Expires = "明年" },
		"钥匙名非法":      func(k *Keyring) { k.Keys[0].Name = "../x" },
		"权限时长非正":     func(k *Keyring) { k.Keys[0].Limits.MaxHours = 0 },
	}
	for name, mut := range cases {
		ring := f.ring
		ring.Keys = append([]Key(nil), f.ring.Keys...)
		mut(&ring)
		s, _ := SignKeyring(ring, f.rootPriv)
		if _, err := VerifyKeyring(s, f.roots, 0, t0); err == nil {
			t.Errorf("%s: 竟然验过了", name)
		}
	}
}

func TestKeyringUnknownFieldsIgnored(t *testing.T) {
	// 格式冻结后只增不改: 新版本加的字段, 旧探针要能忽略
	f := setup(t)
	var m map[string]any
	json.Unmarshal([]byte(f.signedKR.Keyring), &m)
	m["future_field"] = "x"
	m["keys"].([]any)[0].(map[string]any)["future_limit"] = 7
	b, _ := json.MarshalIndent(m, "", "  ")
	s := SignedKeyring{Keyring: string(b), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(f.rootPriv, b))}
	if _, err := VerifyKeyring(s, f.roots, 0, t0); err != nil {
		t.Fatalf("带未知字段的钥匙环应该能收: %v", err)
	}
}

func TestBackupRootKeyWorks(t *testing.T) {
	f := setup(t)
	backupPub, backupPriv := newKey(t)
	s, _ := SignKeyring(f.ring, backupPriv)
	if _, err := VerifyKeyring(s, []ed25519.PublicKey{f.rootPub, backupPub}, 0, t0); err != nil {
		t.Fatalf("备用根钥匙签的应该能收: %v", err)
	}
}

// ------------------------------------------------------------------ 任务包

func TestJobRoundTrip(t *testing.T) {
	f := setup(t)
	sj, err := SignJob(goodJob(), "reviewer-a", f.revPriv)
	if err != nil {
		t.Fatal(err)
	}
	job, key, err := VerifyJob(sj, f.ring, t0)
	if err != nil {
		t.Fatal(err)
	}
	if job.Name != "cifar10-hpsearch" || key.Name != "reviewer-a" || key.Limits.MaxNodes != 20 {
		t.Fatalf("结果不对: %+v %+v", job, key)
	}
}

func TestJobTamperedRejected(t *testing.T) {
	f := setup(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", f.revPriv)
	sj.Job = strings.Replace(sj.Job, `"train.py"`, `"evil.py"`, 1)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("改过的任务包竟然验过了")
	}
}

func TestJobUnknownSignerRejected(t *testing.T) {
	f := setup(t)
	_, otherPriv := newKey(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", otherPriv) // 冒用名字
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("冒名签的任务包竟然验过了")
	}
	sj, _ = SignJob(goodJob(), "nobody", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("钥匙环里没有的钥匙名竟然验过了")
	}
}

func TestJobExpiredKeyRejected(t *testing.T) {
	f := setup(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0.Add(31*24*time.Hour)); err == nil {
		t.Fatal("钥匙过期后签的任务包竟然还能跑")
	}
}

func TestJobRevokedKeyRejected(t *testing.T) {
	// 吊销钥匙 = 发一份不含它的新钥匙环
	f := setup(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", f.revPriv)
	ring := f.ring
	ring.Version = 4
	ring.Keys = nil
	if _, _, err := VerifyJob(sj, ring, t0); err == nil {
		t.Fatal("钥匙被移出钥匙环后, 它签的任务包竟然还能跑")
	}
}

func TestJobRevokedPackageRejected(t *testing.T) {
	f := setup(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", f.revPriv)
	ring := f.ring
	ring.RevokedJobs = []string{JobDigest(sj)}
	if _, _, err := VerifyJob(sj, ring, t0); err == nil {
		t.Fatal("被吊销的任务包竟然还能跑")
	}
}

func TestJobExceedsKeyLimits(t *testing.T) {
	f := setup(t)
	j := goodJob()
	j.MaxHours = 5 // 钥匙上限 4
	sj, _ := SignJob(j, "reviewer-a", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("超过钥匙时长上限的任务包竟然验过了")
	}
	j = goodJob()
	j.Network = true // 钥匙不许联网
	sj, _ = SignJob(j, "reviewer-a", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("钥匙不许联网, 要联网的任务包竟然验过了")
	}
}

func TestJobFieldChecks(t *testing.T) {
	f := setup(t)
	cases := map[string]func(*Job){
		"名字带空格":       func(j *Job) { j.Name = "Bad Name" },
		"版本号不是 x.y.z": func(j *Job) { j.Version = "v1" },
		"入口经 shell":   func(j *Job) { j.Entry = []string{"cmd", "/c", "x"} },
		"python -c":   func(j *Job) { j.Entry = []string{"python", "-c", "print(1)"} },
		"入口只有解释器":     func(j *Job) { j.Entry = []string{"python"} },
		"脚本路径越界":      func(j *Job) { j.Entry = []string{"python", "../x.py"} },
		"环境层名不合规":     func(j *Job) { j.Env = "py311" },
		"哈希不是 64 位":   func(j *Job) { j.CodeSHA256 = "abc" },
		"显存超 7168":    func(j *Job) { j.GPUMemMB = 8000 },
		"时长非正":        func(j *Job) { j.MaxHours = 0 },
		"schema 不认识":  func(j *Job) { j.Schema = 2 },
	}
	for name, mut := range cases {
		j := goodJob()
		mut(&j)
		sj, _ := SignJob(j, "reviewer-a", f.revPriv)
		if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
			t.Errorf("%s: 竟然验过了", name)
		}
	}
}

func TestJobSignatureCoversExactBytes(t *testing.T) {
	// 签名对的是原文字节: 哪怕只是重新排版也算改动
	f := setup(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", f.revPriv)
	var m map[string]any
	json.Unmarshal([]byte(sj.Job), &m)
	b, _ := json.Marshal(m) // 紧凑格式, 内容一样
	sj.Job = string(b)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("重新排版后签名竟然还对")
	}
}

func TestJobDigestStable(t *testing.T) {
	f := setup(t)
	sj, _ := SignJob(goodJob(), "reviewer-a", f.revPriv)
	if d := JobDigest(sj); len(d) != 64 || d != JobDigest(sj) {
		t.Fatalf("摘要不稳定: %q", d)
	}
}
