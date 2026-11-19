// epsilon-release: 在 Mac 上给本体发布签名。
// 用法: epsilon-release -key dist/keys/release-main.key -version 0.2.0 -out dist/release epsilon-probe.exe workloads.json
// 把 -out 目录整个传到主控 files_dir 下的 release/（或 release-canary/ 先灰度）。
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"epsilon/boot"
)

func main() {
	if handled, err := runJobCommand(os.Args[1:]); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runRelease(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// runRelease 做本体发布签名。出错时不改 -out：检查都在清空输出目录之前。
func runRelease(args []string) error {
	fs := flag.NewFlagSet("epsilon-release", flag.ContinueOnError)
	keyPath := fs.String("key", "dist/keys/release-main.key", "私钥（base64 种子）")
	version := fs.String("version", "", "版本号；试坏过的版本号引导器不会再下，修好要换新号")
	minBoot := fs.Int("min-boot", 2, "这版本体至少要哪个版本的引导器（只在本体真的依赖新引导器时调高：调高后旧引导器的机器装不了）")
	out := fs.String("out", "dist/release", "输出目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || fs.NArg() == 0 {
		return errors.New("要 -version 和至少一个文件")
	}
	// F1：引导器只收清单里有本体的槽，漏传会签出一份所有机器都拒的发布。按字节比，和 VerifySlot 一致。
	// 同名文件会在 -out 里互相覆盖，清单却留两条同名 path，引导器也会拒。
	hasProbe, seen := false, map[string]bool{}
	for _, src := range fs.Args() {
		name := filepath.Base(src)
		if seen[name] {
			return fmt.Errorf("文件名 %s 重复：产出会互相覆盖，引导器会拒收这份发布", name)
		}
		seen[name] = true
		hasProbe = hasProbe || name == boot.ProbeExe
	}
	if !hasProbe {
		return fmt.Errorf("要签入的文件里没有 %s：引导器会拒收这份发布", boot.ProbeExe)
	}
	priv, err := loadKey(*keyPath)
	if err != nil {
		return err
	}

	os.RemoveAll(*out)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	m := boot.Manifest{Version: *version, MinBoot: *minBoot}
	for _, src := range fs.Args() {
		f, err := copyHashed(src, filepath.Join(*out, filepath.Base(src)))
		if err != nil {
			return err
		}
		m.Files = append(m.Files, f)
	}
	s, err := boot.Sign(m, priv)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := s.Verify([]ed25519.PublicKey{pub}); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, boot.ReleaseFile), b, 0o644); err != nil {
		return err
	}
	log.Printf("版本 %s，%d 个文件 -> %s", *version, len(m.Files), *out)
	return nil
}

// copyHashed 把 src 拷到 dst，顺手算大小和 sha256。
func copyHashed(src, dst string) (boot.File, error) {
	in, err := os.Open(src)
	if err != nil {
		return boot.File{}, err
	}
	defer in.Close()
	w, err := os.Create(dst)
	if err != nil {
		return boot.File{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), in)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return boot.File{}, err
	}
	return boot.File{Path: filepath.Base(src), Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
