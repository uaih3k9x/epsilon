// Package jobsign 是批任务的信任链（设计书第 22.2–22.3 节，issue #1）：
// 根钥匙（发布钥匙，离线）签任务钥匙环；钥匙环里的钥匙签任务包；探针两层都验过才跑。
//
// 和 boot 的发布签名同一套做法：原文字节原样保存，签名对的是这段字节，不重新序列化。
// 格式一旦发布只增不改：未知字段忽略（encoding/json 默认如此）。
package jobsign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ClockSkew 是钥匙环签发时间允许比本机时钟“超前”多少。超过就拒：要么本机时钟坏了，要么是伪造的。
const ClockSkew = 24 * time.Hour

// MaxGPUMemMB 是单个任务能声明的显存上限（8 GB 卡留 1 GB 给驱动）。
const MaxGPUMemMB = 7168

// Limits 是一把钥匙能批的任务的上限。MaxNodes、Rooms 由主控派活时执行，探针只核对时长和联网。
type Limits struct {
	MaxHours float64  `json:"max_hours"`
	MaxNodes int      `json:"max_nodes"`
	Rooms    []string `json:"rooms,omitempty"` // 空 = 不限
	Network  bool     `json:"network"`
}

// Key 是钥匙环里的一把审核钥匙。
type Key struct {
	Name    string `json:"name"`
	Pub     string `json:"pub"`     // base64(ed25519 公钥)
	Expires string `json:"expires"` // RFC3339
	Limits  Limits `json:"limits"`
}

// Keyring 由根钥匙签发。Version 单调递增，探针记住见过的最高版本、拒收更旧的。
// 吊销一把钥匙 = 发一份不含它的新版本；吊销某个任务包 = 把它的摘要写进 RevokedJobs。
type Keyring struct {
	Version     int      `json:"version"`
	Issued      string   `json:"issued"` // RFC3339
	Keys        []Key    `json:"keys"`
	RevokedJobs []string `json:"revoked_jobs,omitempty"` // JobDigest 列表
	// EnvLayers 是 "名字@版本" → 环境层清单（proto.Manifest 原文）的 SHA-256。
	// 主控只分发字节，探针拿这张根钥匙签的表核对，主控换不了环境层。
	EnvLayers map[string]string `json:"env_layers,omitempty"`
}

// EnvLayerDigest 返回环境层清单应有的 SHA-256；不在表里的环境层不能用。
func (k Keyring) EnvLayerDigest(name string) (string, bool) {
	d, ok := k.EnvLayers[name]
	return d, ok
}

type SignedKeyring struct {
	Keyring string `json:"keyring"`
	Sig     string `json:"sig"`
}

// Job 是 job.json（提交手册第 5.2 节）。Params 只保留原文，参数值的类型校验是主控提交时的事。
type Job struct {
	Schema      int                        `json:"schema"`
	Name        string                     `json:"name"`
	Version     string                     `json:"version"`
	Description string                     `json:"description,omitempty"`
	Owner       string                     `json:"owner,omitempty"`
	Entry       []string                   `json:"entry"`
	Env         string                     `json:"env"`
	Data        []string                   `json:"data,omitempty"`
	Params      map[string]json.RawMessage `json:"params,omitempty"`
	GPUMemMB    int                        `json:"gpu_mem_mb"`
	MaxHours    float64                    `json:"max_hours"`
	DiskMaxMB   int                        `json:"disk_max_mb,omitempty"`
	OutputMaxMB int                        `json:"output_max_mb,omitempty"`
	Network     bool                       `json:"network,omitempty"`
	GPU         *bool                      `json:"gpu,omitempty"` // 不写 = true（手册 5.2），用 NeedsGPU 读
	CodeSHA256  string                     `json:"code_sha256"`
}

// NeedsGPU：只有明确写了 "gpu": false 才是纯 CPU 任务。
func (j Job) NeedsGPU() bool { return j.GPU == nil || *j.GPU }

type SignedJob struct {
	Job string `json:"job"`
	Sig string `json:"sig"`
	Key string `json:"key"` // 签名钥匙在钥匙环里的名字
	// Warnings 是签名时的提醒，只为事后可查。不受签名保护，可以从 Job 原文用 JobWarnings 重算，别拿它做判断。
	Warnings []string `json:"warnings,omitempty"`
}

var (
	keyName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)
	jobName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$`)
	semver    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	layerName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*@[0-9]+$`)
	sha256hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	scriptRel = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*\.py$`)
	ownerName = regexp.MustCompile(`^[A-Za-z0-9_.-]{2,32}$`)
)

// requiredJobFields 是探针判断安全、调度和追溯要用的字段。缺了或写 null，encoding/json 都会留下零值，只能看原文。
// description 不在内：缺了只影响可读性，见 JobWarnings。
var requiredJobFields = []string{"schema", "name", "version", "owner", "entry", "env",
	"gpu_mem_mb", "max_hours", "disk_max_mb", "output_max_mb", "code_sha256"}

// harmlessFlags 是脚本前面允许出现的解释器参数：都不影响执行什么代码。
var harmlessFlags = map[string]bool{"-B": true, "-u": true}

// interpreters 是 entry[0] 允许的值：只能是环境层里的解释器，不能是 shell。
var interpreters = map[string]bool{"python": true, "python3": true}

func sign(v any, priv ed25519.PrivateKey) (string, string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", "", err
	}
	return string(b), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)), nil
}

func verifyAny(text, sig64 string, keys []ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil || text == "" {
		return false
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, []byte(text), sig) {
			return true
		}
	}
	return false
}

// SignKeyring 用根钥匙签钥匙环（只在离线的 Mac 上跑）。
func SignKeyring(k Keyring, rootPriv ed25519.PrivateKey) (SignedKeyring, error) {
	text, sig, err := sign(k, rootPriv)
	return SignedKeyring{Keyring: text, Sig: sig}, err
}

// VerifyKeyring 验根签名、版本不回滚（minVersion = 本机见过的最高版本）、签发时间不在远未来、结构合法。
// 调用方验过以后要把 Version 持久化成新的 minVersion。
func VerifyKeyring(s SignedKeyring, roots []ed25519.PublicKey, minVersion int, now time.Time) (Keyring, error) {
	var k Keyring
	if !verifyAny(s.Keyring, s.Sig, roots) {
		return k, errors.New("钥匙环验签失败")
	}
	if err := json.Unmarshal([]byte(s.Keyring), &k); err != nil {
		return k, fmt.Errorf("钥匙环格式坏了: %v", err)
	}
	if k.Version < 1 {
		return k, errors.New("钥匙环版本号要从 1 开始")
	}
	if k.Version < minVersion {
		return k, fmt.Errorf("钥匙环版本 %d 比见过的 %d 旧（回滚？）", k.Version, minVersion)
	}
	issued, err := time.Parse(time.RFC3339, k.Issued)
	if err != nil {
		return k, fmt.Errorf("签发时间格式坏了: %q", k.Issued)
	}
	if issued.After(now.Add(ClockSkew)) {
		return k, fmt.Errorf("签发时间 %s 远在本机时间之后（时钟不对或伪造）", k.Issued)
	}
	seen := map[string]bool{}
	for _, key := range k.Keys {
		if !keyName.MatchString(key.Name) {
			return k, fmt.Errorf("钥匙名不合规: %q", key.Name)
		}
		if seen[key.Name] {
			return k, fmt.Errorf("钥匙名重复: %q", key.Name)
		}
		seen[key.Name] = true
		if _, err := pubOf(key); err != nil {
			return k, err
		}
		if _, err := time.Parse(time.RFC3339, key.Expires); err != nil {
			return k, fmt.Errorf("钥匙 %s 过期时间格式坏了: %q", key.Name, key.Expires)
		}
		if key.Limits.MaxHours <= 0 || key.Limits.MaxNodes < 0 {
			return k, fmt.Errorf("钥匙 %s 的权限上限不合法", key.Name)
		}
	}
	for _, d := range k.RevokedJobs {
		if !sha256hex.MatchString(d) {
			return k, fmt.Errorf("吊销表里的摘要不合规: %q", d)
		}
	}
	for name, d := range k.EnvLayers {
		if !layerName.MatchString(name) || !sha256hex.MatchString(d) {
			return k, fmt.Errorf("环境层表不合规: %q -> %q", name, d)
		}
	}
	return k, nil
}

func pubOf(key Key) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(key.Pub)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("钥匙 %s 的公钥坏了", key.Name)
	}
	return b, nil
}

// SignJob 用审核钥匙签 job.json 原文：审核人读到的字节就是被签名的字节，不解析、不重新序列化。
// keyName 要和钥匙环里这把钥匙的名字一致。
func SignJob(text []byte, keyName string, priv ed25519.PrivateKey) (SignedJob, error) {
	// job.signed.json 把原文存成 JSON 字符串，非 UTF-8 字节写进去会被替换，到探针那边验签必败。
	if !utf8.Valid(text) {
		return SignedJob{}, errors.New("job.json 不是合法的 UTF-8")
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, text))
	return SignedJob{Job: string(text), Sig: sig, Key: keyName}, nil
}

// JobDigest 是任务包原文的 SHA-256，吊销表和事件记录里用它指代一个签过名的任务包。
func JobDigest(s SignedJob) string {
	h := sha256.Sum256([]byte(s.Job))
	return hex.EncodeToString(h[:])
}

// VerifyJob 核对: 签名钥匙在钥匙环里且没过期、签名对、没被吊销、字段合法、不超过钥匙的时长和联网权限。
// 返回任务和签名钥匙（主控据此执行 MaxNodes / Rooms）。kr 必须是 VerifyKeyring 验过的。
func VerifyJob(s SignedJob, kr Keyring, now time.Time) (Job, Key, error) {
	var j Job
	var key Key
	found := false
	for _, k := range kr.Keys {
		if k.Name == s.Key {
			key, found = k, true
		}
	}
	if !found {
		return j, key, fmt.Errorf("钥匙环里没有钥匙 %q（没发过或已吊销）", s.Key)
	}
	exp, err := time.Parse(time.RFC3339, key.Expires)
	if err != nil || !now.Before(exp) {
		return j, key, fmt.Errorf("钥匙 %s 已过期（%s）", key.Name, key.Expires)
	}
	pub, err := pubOf(key)
	if err != nil {
		return j, key, err
	}
	if !verifyAny(s.Job, s.Sig, []ed25519.PublicKey{pub}) {
		return j, key, errors.New("任务包验签失败")
	}
	d := JobDigest(s)
	for _, r := range kr.RevokedJobs {
		if r == d {
			return j, key, fmt.Errorf("任务包 %s 已被吊销", d[:12])
		}
	}
	if err := json.Unmarshal([]byte(s.Job), &j); err != nil {
		return j, key, fmt.Errorf("job.json 格式坏了: %v", err)
	}
	if err := checkRequired(s.Job); err != nil {
		return j, key, err
	}
	if err := checkJob(j); err != nil {
		return j, key, err
	}
	if j.MaxHours > key.Limits.MaxHours {
		return j, key, fmt.Errorf("max_hours %.1f 超过钥匙 %s 的上限 %.1f", j.MaxHours, key.Name, key.Limits.MaxHours)
	}
	if j.Network && !key.Limits.Network {
		return j, key, fmt.Errorf("任务要联网，钥匙 %s 没有联网权限", key.Name)
	}
	if _, ok := kr.EnvLayerDigest(j.Env); !ok {
		return j, key, fmt.Errorf("环境层 %s 不在钥匙环里", j.Env)
	}
	return j, key, nil
}

// JobWarnings 列出不影响安全和调度、但审核人该知道的问题。签名时打印并留痕，探针不据此拒绝。
func JobWarnings(j Job) []string {
	var w []string
	if strings.TrimSpace(j.Description) == "" {
		w = append(w, "没写 description")
	} else if utf8.RuneCountInString(j.Description) > 200 {
		w = append(w, "description 超过 200 字")
	}
	if !ownerName.MatchString(j.Owner) {
		w = append(w, fmt.Sprintf("owner %q 不是学号或内部用户名的格式", j.Owner))
	}
	return w
}

// scriptIndex 返回 entry 里脚本的位置：解释器后面跳过白名单参数。没有脚本返回 len(entry)。
func scriptIndex(entry []string) int {
	i := 1
	for i < len(entry) && harmlessFlags[entry[i]] {
		i++
	}
	return i
}

func checkRequired(text string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return fmt.Errorf("job.json 格式坏了: %v", err)
	}
	for _, f := range requiredJobFields {
		if v, ok := m[f]; !ok || string(v) == "null" {
			return fmt.Errorf("job.json 缺必填字段 %s", f)
		}
	}
	return nil
}

func checkJob(j Job) error {
	script := scriptIndex(j.Entry)
	switch {
	case j.Schema != 1:
		return fmt.Errorf("不认识的 schema %d", j.Schema)
	case !jobName.MatchString(j.Name):
		return fmt.Errorf("任务名不合规: %q", j.Name)
	case !semver.MatchString(j.Version):
		return fmt.Errorf("版本号要是 x.y.z: %q", j.Version)
	case len(j.Entry) < 2 || !interpreters[j.Entry[0]]:
		return fmt.Errorf("entry 要是 [解释器, 脚本, ...]，解释器只能是 python: %q", j.Entry)
	case script >= len(j.Entry):
		return fmt.Errorf("entry 里没有脚本: %q", j.Entry)
	case !scriptRel.MatchString(j.Entry[script]) || strings.Contains(j.Entry[script], ".."):
		return fmt.Errorf("entry 的脚本要是 code\\ 下的相对 .py 路径: %q", j.Entry[script])
	case !layerName.MatchString(j.Env):
		return fmt.Errorf("环境层名要是 名字@版本: %q", j.Env)
	case !sha256hex.MatchString(j.CodeSHA256):
		return fmt.Errorf("code_sha256 要是 64 位小写十六进制")
	case j.GPUMemMB < 0 || j.GPUMemMB > MaxGPUMemMB:
		return fmt.Errorf("gpu_mem_mb %d 超出 0–%d", j.GPUMemMB, MaxGPUMemMB)
	case j.MaxHours <= 0:
		return errors.New("max_hours 要大于 0")
	case j.NeedsGPU() && j.GPUMemMB == 0:
		return errors.New("GPU 任务要声明 gpu_mem_mb；纯 CPU 任务写 \"gpu\": false")
	case strings.TrimSpace(j.Owner) == "":
		return errors.New("owner 不能为空：出事要能找到人")
	case j.DiskMaxMB < 1 || j.OutputMaxMB < 1:
		return errors.New("disk_max_mb 和 output_max_mb 要至少为 1")
	}
	for _, a := range j.Entry[script+1:] {
		if a == "-c" || a == "-m" {
			return fmt.Errorf("entry 里不许出现 %s", a)
		}
	}
	for _, d := range j.Data {
		if !layerName.MatchString(d) {
			return fmt.Errorf("数据集名要是 名字@版本: %q", d)
		}
	}
	return nil
}
