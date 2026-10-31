// epsilon-release: 在 Mac 上给本体发布签名。
// 用法: epsilon-release -key dist/keys/release-main.key -version 0.2.0 -out dist/release epsilon-probe.exe workloads.json
// 把 -out 目录整个传到主控 files_dir 下的 release/（或 release-canary/ 先灰度）。
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"epsilon/boot"
)

func main() {
	if handled, err := runJobCommand(os.Args[1:]); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	keyPath := flag.String("key", "dist/keys/release-main.key", "私钥（base64 种子）")
	version := flag.String("version", "", "版本号；试坏过的版本号引导器不会再下，修好要换新号")
	minBoot := flag.Int("min-boot", 2, "这版本体至少要哪个版本的引导器（只在本体真的依赖新引导器时调高：调高后旧引导器的机器装不了）")
	out := flag.String("out", "dist/release", "输出目录")
	flag.Parse()
	if *version == "" || flag.NArg() == 0 {
		log.Fatal("要 -version 和至少一个文件")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatal("私钥格式不对")
	}
	priv := ed25519.NewKeyFromSeed(seed)

	os.RemoveAll(*out)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	m := boot.Manifest{Version: *version, MinBoot: *minBoot}
	for _, src := range flag.Args() {
		name := filepath.Base(src)
		in, err := os.Open(src)
		if err != nil {
			log.Fatal(err)
		}
		dst, err := os.Create(filepath.Join(*out, name))
		if err != nil {
			log.Fatal(err)
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(dst, h), in)
		in.Close()
		dst.Close()
		if err != nil {
			log.Fatal(err)
		}
		m.Files = append(m.Files, boot.File{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
	}
	s, err := boot.Sign(m, priv)
	if err != nil {
		log.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := s.Verify([]ed25519.PublicKey{pub}); err != nil {
		log.Fatal(err)
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "release.json"), b, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("版本 %s，%d 个文件 -> %s", *version, len(m.Files), *out)
}
