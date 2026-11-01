package jobsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		EnvLayers: map[string]string{"py311-torch2.5-cu124@3": strings.Repeat("cd", 32)},
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

func signStruct(j Job, name string, priv ed25519.PrivateKey) (SignedJob, error) {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return SignedJob{}, err
	}
	return SignJob(b, name, priv)
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
	sj, err := signStruct(goodJob(), "reviewer-a", f.revPriv)
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
	sj, _ := signStruct(goodJob(), "reviewer-a", f.revPriv)
	sj.Job = strings.Replace(sj.Job, `"train.py"`, `"evil.py"`, 1)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("改过的任务包竟然验过了")
	}
}

func TestJobUnknownSignerRejected(t *testing.T) {
	f := setup(t)
	_, otherPriv := newKey(t)
	sj, _ := signStruct(goodJob(), "reviewer-a", otherPriv) // 冒用名字
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("冒名签的任务包竟然验过了")
	}
	sj, _ = signStruct(goodJob(), "nobody", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("钥匙环里没有的钥匙名竟然验过了")
	}
}

func TestJobExpiredKeyRejected(t *testing.T) {
	f := setup(t)
	sj, _ := signStruct(goodJob(), "reviewer-a", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0.Add(31*24*time.Hour)); err == nil {
		t.Fatal("钥匙过期后签的任务包竟然还能跑")
	}
}

func TestJobRevokedKeyRejected(t *testing.T) {
	// 吊销钥匙 = 发一份不含它的新钥匙环
	f := setup(t)
	sj, _ := signStruct(goodJob(), "reviewer-a", f.revPriv)
	ring := f.ring
	ring.Version = 4
	ring.Keys = nil
	if _, _, err := VerifyJob(sj, ring, t0); err == nil {
		t.Fatal("钥匙被移出钥匙环后, 它签的任务包竟然还能跑")
	}
}

func TestJobRevokedPackageRejected(t *testing.T) {
	f := setup(t)
	sj, _ := signStruct(goodJob(), "reviewer-a", f.revPriv)
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
	sj, _ := signStruct(j, "reviewer-a", f.revPriv)
	if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
		t.Fatal("超过钥匙时长上限的任务包竟然验过了")
	}
	j = goodJob()
	j.Network = true // 钥匙不许联网
	sj, _ = signStruct(j, "reviewer-a", f.revPriv)
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
		"解释器参数不在白名单":  func(j *Job) { j.Entry = []string{"python", "-X", "importtime", "train.py"} },
		"参数后面藏 -c":    func(j *Job) { j.Entry = []string{"python", "-B", "-c", "print(1)"} },
		"只有解释器参数":     func(j *Job) { j.Entry = []string{"python", "-B", "-u"} },
		"owner 只有空白":  func(j *Job) { j.Owner = "  " },
		"环境层不在钥匙环里":   func(j *Job) { j.Env = "py311-evil@1" },
		"磁盘预算为 0":     func(j *Job) { j.DiskMaxMB = 0 },
		"输出预算为 0":     func(j *Job) { j.OutputMaxMB = 0 },
		"GPU 任务没声明显存": func(j *Job) { j.GPUMemMB = 0 },
	}
	for name, mut := range cases {
		j := goodJob()
		mut(&j)
		sj, _ := signStruct(j, "reviewer-a", f.revPriv)
		if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
			t.Errorf("%s: 竟然验过了", name)
		}
	}
}

func TestJobSignatureCoversExactBytes(t *testing.T) {
	// 签名对的是原文字节: 哪怕只是重新排版也算改动
	f := setup(t)
	sj, _ := signStruct(goodJob(), "reviewer-a", f.revPriv)
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
	sj, _ := signStruct(goodJob(), "reviewer-a", f.revPriv)
	if d := JobDigest(sj); len(d) != 64 || d != JobDigest(sj) {
		t.Fatalf("摘要不稳定: %q", d)
	}
}

func TestSignJobKeepsExactBytes(t *testing.T) {
	// 审核人读到的就是被签名的: 键序、空数组、false、未知字段都原样保留
	f := setup(t)
	text := []byte(`{"name":"cifar10-hpsearch","version":"1.0.0","entry":["python","train.py"],"env":"py311-torch2.5-cu124@3",
"data":[],"params":{"trial":"int","device":"string"},"gpu_mem_mb":3500,"max_hours":2,"code_sha256":"` + strings.Repeat("ab", 32) + `",
"description":"网格搜索","owner":"CHEN_ZILUE","disk_max_mb":128,"output_max_mb":64,"network":false,"gpu":true,"schema":1,"future_field":"x"}
`)
	sj, err := SignJob(text, "reviewer-a", f.revPriv)
	if err != nil {
		t.Fatal(err)
	}
	if sj.Job != string(text) {
		t.Fatalf("签名内容和原文不一致:\n%s", sj.Job)
	}
	sum := sha256.Sum256(text)
	if JobDigest(sj) != hex.EncodeToString(sum[:]) {
		t.Fatal("摘要应该等于 job.json 原文的 SHA-256")
	}
	if _, _, err := VerifyJob(sj, f.ring, t0); err != nil {
		t.Fatal(err)
	}
}

func TestSignJobRefusesInvalidUTF8(t *testing.T) {
	// JSON 字符串装不下非 UTF-8 字节: 写进 job.signed.json 会被替换, 到探针那边验签必败
	f := setup(t)
	if _, err := SignJob([]byte("{\"description\":\"\xd6\xd0\"}"), "reviewer-a", f.revPriv); err == nil {
		t.Fatal("非 UTF-8 的 job.json 竟然签了")
	}
}

func TestJobRequiredFields(t *testing.T) {
	// 手册附录 B 的必填字段: 缺了或写 null 都不行 (Go 会把它们当零值放过去, EXP-029 草稿就是 null)
	f := setup(t)
	for _, field := range []string{"schema", "name", "version", "owner", "entry", "env",
		"gpu_mem_mb", "max_hours", "disk_max_mb", "output_max_mb", "code_sha256"} {
		for _, null := range []bool{false, true} {
			base, _ := json.Marshal(goodJob())
			var m map[string]any
			json.Unmarshal(base, &m)
			if null {
				m[field] = nil
			} else {
				delete(m, field)
			}
			b, _ := json.Marshal(m)
			sj, err := SignJob(b, "reviewer-a", f.revPriv)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyJob(sj, f.ring, t0); err == nil {
				t.Errorf("%s (null=%v): 竟然验过了", field, null)
			}
		}
	}
}

func TestJobGPUDefaultsToTrue(t *testing.T) {
	f := setup(t)
	j := goodJob() // 没写 gpu
	sj, _ := signStruct(j, "reviewer-a", f.revPriv)
	got, _, err := VerifyJob(sj, f.ring, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NeedsGPU() {
		t.Fatal("没写 gpu 应该按 true 算 (手册 5.2)")
	}

	// 纯 CPU 任务: 明确写 false, 显存可以声明 0, 而且 false 不能在签名时丢掉
	cpu := false
	j.GPU, j.GPUMemMB = &cpu, 0
	sj, _ = signStruct(j, "reviewer-a", f.revPriv)
	got, _, err = VerifyJob(sj, f.ring, t0)
	if err != nil {
		t.Fatalf("纯 CPU 任务显存写 0 应该能过: %v", err)
	}
	if got.NeedsGPU() {
		t.Fatal(`明确写了 "gpu": false 却被当成 GPU 任务`)
	}
}

func TestEntryAllowsHarmlessInterpreterFlags(t *testing.T) {
	// -B / -u 不影响执行什么代码, 放行 (EXP-029 的 entry 原样能过)
	f := setup(t)
	for _, entry := range [][]string{
		{"python", "-B", "train.py"},
		{"python", "-u", "-B", "train.py"},
		{"python3", "train.py", "--epochs", "3"},
	} {
		j := goodJob()
		j.Entry = entry
		sj, _ := signStruct(j, "reviewer-a", f.revPriv)
		if _, _, err := VerifyJob(sj, f.ring, t0); err != nil {
			t.Errorf("%q 应该能过: %v", entry, err)
		}
	}
}

func TestJobWarningsDoNotBlock(t *testing.T) {
	// 只影响可读性和追溯质量的问题: 签名时提醒审核人, 探针不拒
	f := setup(t)
	if w := JobWarnings(goodJob()); len(w) != 0 {
		t.Fatalf("干净的任务包不该有 warning: %q", w)
	}
	cases := map[string]func(*Job){
		"没写描述":        func(j *Job) { j.Description = "" },
		"描述超长":        func(j *Job) { j.Description = strings.Repeat("字", 201) },
		"owner 格式不规范": func(j *Job) { j.Owner = "张 三" },
	}
	for name, mut := range cases {
		j := goodJob()
		mut(&j)
		if len(JobWarnings(j)) == 0 {
			t.Errorf("%s: 该有 warning", name)
		}
		sj, _ := signStruct(j, "reviewer-a", f.revPriv)
		if _, _, err := VerifyJob(sj, f.ring, t0); err != nil {
			t.Errorf("%s: 只该 warning, 却被拒了: %v", name, err)
		}
	}
}

func TestKeyringEnvLayersChecked(t *testing.T) {
	f := setup(t)
	for name, layers := range map[string]map[string]string{
		"层名不合规": {"py311": strings.Repeat("cd", 32)},
		"摘要不合规": {"py311-torch@1": "abc"},
	} {
		ring := f.ring
		ring.EnvLayers = layers
		s, _ := SignKeyring(ring, f.rootPriv)
		if _, err := VerifyKeyring(s, f.roots, 0, t0); err == nil {
			t.Errorf("%s: 竟然验过了", name)
		}
	}
}

func TestEnvLayerDigestComesFromKeyring(t *testing.T) {
	// 探针只认根钥匙签的摘要: 主控换清单时, 摘要对不上
	f := setup(t)
	if d, ok := f.ring.EnvLayerDigest("py311-torch2.5-cu124@3"); !ok || d != strings.Repeat("cd", 32) {
		t.Fatalf("查不到钥匙环里的环境层: %q %v", d, ok)
	}
	if _, ok := f.ring.EnvLayerDigest("py311-evil@1"); ok {
		t.Fatal("钥匙环里没有的环境层竟然查到了")
	}
}
