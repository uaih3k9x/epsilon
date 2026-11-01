package main

// 批任务的签名子命令（设计书 22.2、22.7，issue #1）。不带子命令时 main 照旧做本体发布签名。
//
//   epsilon-release keygen   -out dist/keys/reviewer-a.key
//   epsilon-release keyring  -key dist/keys/release-main.key -in keyring-src.json -out job-keyring.json
//   epsilon-release sign-job -key dist/keys/reviewer-a.key -name reviewer-a -keyring job-keyring.json \
//                            -job job.json -code code.zip -out job.signed.json

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"epsilon/jobsign"
)

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: 私钥格式不对", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// cmdKeygen 生成一把新钥匙（base64 种子，权限 600），返回 base64 公钥。不覆盖已有文件。
func cmdKeygen(out string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// cmdKeyring 用根钥匙签钥匙环。in 是人手写的钥匙环 JSON；没写 issued 就填现在。
// out 已存在时要求新版本号更大（同号重签等于给回滚留口子）。签完立刻自验。
func cmdKeyring(keyPath, in, out string) error {
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	var k jobsign.Keyring
	if err := readJSON(in, &k); err != nil {
		return err
	}
	if k.Issued == "" {
		k.Issued = time.Now().UTC().Format(time.RFC3339)
	}
	prev := 0
	if b, err := os.ReadFile(out); err == nil {
		var s jobsign.SignedKeyring
		var old jobsign.Keyring
		if json.Unmarshal(b, &s) == nil && json.Unmarshal([]byte(s.Keyring), &old) == nil {
			prev = old.Version
		}
	}
	if k.Version <= prev {
		return fmt.Errorf("版本号 %d 要大于现有钥匙环的 %d", k.Version, prev)
	}
	s, err := jobsign.SignKeyring(k, priv)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := jobsign.VerifyKeyring(s, []ed25519.PublicKey{pub}, prev, time.Now()); err != nil {
		return fmt.Errorf("签完自验没过: %v", err)
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeFileAtomic(out, b)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cmdSignJob 签任务包: code.zip 哈希要和 job.json 一致, 私钥要和钥匙环里同名钥匙的公钥一致,
// 签完用钥匙环按探针的规则验一遍, 过了才写 out。
func cmdSignJob(keyPath, name, ringPath, jobPath, codePath, out string) error {
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	var s jobsign.SignedKeyring
	if err := readJSON(ringPath, &s); err != nil {
		return err
	}
	var kr jobsign.Keyring
	if err := json.Unmarshal([]byte(s.Keyring), &kr); err != nil {
		return fmt.Errorf("钥匙环格式坏了: %v", err)
	}
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	match := false
	for _, k := range kr.Keys {
		match = match || (k.Name == name && k.Pub == pub)
	}
	if !match {
		return fmt.Errorf("钥匙环里没有名叫 %q、公钥和这把私钥对得上的钥匙", name)
	}
	text, err := os.ReadFile(jobPath)
	if err != nil {
		return err
	}
	var j jobsign.Job
	if err := json.Unmarshal(text, &j); err != nil {
		return fmt.Errorf("%s 格式坏了: %v", jobPath, err)
	}
	sum, err := fileSHA256(codePath)
	if err != nil {
		return err
	}
	if sum != j.CodeSHA256 {
		return fmt.Errorf("code.zip 的 SHA-256 是 %s, job.json 里写的是 %s", sum, j.CodeSHA256)
	}
	sj, err := jobsign.SignJob(text, name, priv)
	if err != nil {
		return err
	}
	if _, _, err := jobsign.VerifyJob(sj, kr, time.Now()); err != nil {
		return fmt.Errorf("签完按探针规则验没过: %v", err)
	}
	sj.Warnings = jobsign.JobWarnings(j)
	for _, w := range sj.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	b, _ := json.MarshalIndent(sj, "", "  ")
	return writeFileAtomic(out, b)
}

// runJobCommand 处理子命令; 不是子命令返回 false, main 走原来的发布流程。
func runJobCommand(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "keygen":
		out := fs.String("out", "", "新钥匙文件（不覆盖已有文件）")
		if err := fs.Parse(args[1:]); err != nil {
			return true, err
		}
		if *out == "" {
			return true, errors.New("要 -out")
		}
		pub, err := cmdKeygen(*out)
		if err == nil {
			fmt.Printf("公钥（写进钥匙环 keys[].pub）: %s\n", pub)
		}
		return true, err
	case "keyring":
		key := fs.String("key", "dist/keys/release-main.key", "根钥匙（发布钥匙）")
		in := fs.String("in", "", "手写的钥匙环 JSON")
		out := fs.String("out", "job-keyring.json", "签好的钥匙环")
		if err := fs.Parse(args[1:]); err != nil {
			return true, err
		}
		if *in == "" {
			return true, errors.New("要 -in")
		}
		return true, cmdKeyring(*key, *in, *out)
	case "sign-job":
		key := fs.String("key", "", "审核钥匙")
		name := fs.String("name", "", "这把钥匙在钥匙环里的名字")
		ring := fs.String("keyring", "job-keyring.json", "签好的钥匙环")
		job := fs.String("job", "job.json", "任务包清单")
		code := fs.String("code", "code.zip", "代码包")
		out := fs.String("out", "job.signed.json", "签好的任务包")
		if err := fs.Parse(args[1:]); err != nil {
			return true, err
		}
		if *key == "" || *name == "" {
			return true, errors.New("要 -key 和 -name")
		}
		return true, cmdSignJob(*key, *name, *ring, *job, *code, *out)
	}
	return false, nil
}
