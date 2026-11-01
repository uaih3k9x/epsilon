// Package envlayer 是批任务的环境层（设计书 22.3、手册第 7 节）。
//
// 一层就是一个 zip，走现有的分块分发（docs/p2p.md）。主控只分发字节：清单的 SHA-256 写在根钥匙签的
// 钥匙环里（jobsign.Keyring.EnvLayers），探针先核对摘要再拼 zip，所以主控换不了环境层。
package envlayer

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"epsilon/chunk"
	"epsilon/proto"
)

const (
	stampName   = ".epsilon-env-ok"
	Interpreter = "python.exe" // 环境层根目录下的解释器（Windows embeddable 布局）
)

// Result 是一次安装的结果。Files = 0 表示之前已经装好，这次什么都没做。
type Result struct {
	Dir   string
	Files int
}

// Dir 是环境层解压后的目录。
func Dir(root, name string) string { return filepath.Join(root, "envs", name) }

func zipPath(name string) string { return "envs/" + name + ".zip" }

// Parse 核对清单原文的摘要，再检查它确实是 name 这一层：只有一个文件 envs/<name>.zip。
func Parse(raw []byte, name, digest string) (proto.Manifest, error) {
	var m proto.Manifest
	h := sha256.Sum256(raw)
	if got := hex.EncodeToString(h[:]); got != digest {
		return m, fmt.Errorf("环境层 %s 的清单摘要是 %s，钥匙环里是 %s", name, got, digest)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("环境层 %s 的清单格式坏了: %v", name, err)
	}
	if m.ID != name {
		return m, fmt.Errorf("清单是 %q，要的是 %q", m.ID, name)
	}
	if len(m.Files) != 1 || m.Files[0].Path != zipPath(name) {
		return m, fmt.Errorf("环境层 %s 的清单只能有一个文件 %s", name, zipPath(name))
	}
	return m, nil
}

// Ready 判断 dir 是否已经完整解压了摘要为 digest 的环境层（只看 stamp 和解释器，不重算哈希）。
func Ready(dir, digest string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, stampName))
	if err != nil {
		return false
	}
	var st stamp
	if json.Unmarshal(raw, &st) != nil || st.Digest != digest {
		return false
	}
	fi, err := os.Stat(filepath.Join(dir, Interpreter))
	return err == nil && fi.Mode().IsRegular()
}

type stamp struct {
	Digest string `json:"digest"`
	Files  int    `json:"files"`
}

// Install 把一层装好：核对摘要 → 从块缓存拼 zip → 解压 → 删 zip（块缓存里还有）。已经装好就什么都不做。
func Install(raw []byte, name, digest string, s *chunk.Store, root string) (Result, error) {
	m, err := Parse(raw, name, digest)
	if err != nil {
		return Result{}, err
	}
	dir := Dir(root, name)
	if Ready(dir, digest) {
		return Result{Dir: dir}, nil
	}
	if err := chunk.Assemble(m, s, root); err != nil {
		return Result{}, err
	}
	z := filepath.Join(root, filepath.FromSlash(m.Files[0].Path))
	n, err := Expand(z, dir, digest)
	if err != nil {
		return Result{}, err
	}
	os.Remove(z)
	os.Remove(z + chunk.StampSuffix)
	return Result{Dir: dir, Files: n}, nil
}

// checkEntries 在写任何东西之前查完整个 zip。解压进任务账户能执行的目录，所以路径和类型都要干净。
func checkEntries(files []*zip.File) error {
	seen := map[string]bool{}
	hasPython := false
	for _, f := range files {
		name := f.Name
		isDir := strings.HasSuffix(name, "/")
		if !chunk.SafePath(strings.TrimSuffix(name, "/")) {
			return fmt.Errorf("环境层里的路径不合法: %q", name)
		}
		if f.Mode()&os.ModeType != 0 && !f.Mode().IsDir() {
			return fmt.Errorf("环境层里不许有链接或特殊文件: %q", name)
		}
		if isDir {
			continue
		}
		// Windows 不分大小写：同名不同写法会互相覆盖
		key := strings.ToLower(name)
		if seen[key] {
			return fmt.Errorf("环境层里有大小写冲突的文件: %q", name)
		}
		seen[key] = true
		hasPython = hasPython || name == Interpreter
	}
	if !hasPython {
		return fmt.Errorf("环境层根目录下没有 %s", Interpreter)
	}
	return nil
}

// Expand 解压到 dir：先全部写进同级临时目录并校验（CRC 由 archive/zip 核对），写好 stamp 再改名，
// 所以 dir 要么没有，要么完整。上次的残留会先清掉。返回文件数。
func Expand(zipFile, dir, digest string) (int, error) {
	zr, err := zip.OpenReader(zipFile)
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	if err := checkEntries(zr.File); err != nil {
		return 0, err
	}
	stale, _ := filepath.Glob(dir + ".tmp-*")
	for _, p := range stale {
		if err := os.RemoveAll(p); err != nil {
			return 0, err
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return 0, err
	}
	parent, base := filepath.Split(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return 0, err
	}
	tmp, err := os.MkdirTemp(parent, base+".tmp-")
	if err != nil {
		return 0, err
	}
	n, err := extract(zr.File, tmp, digest)
	if err == nil {
		err = renameRetry(tmp, dir)
	}
	if err != nil {
		os.RemoveAll(tmp)
		return 0, err
	}
	return n, nil
}

func extract(files []*zip.File, tmp, digest string) (int, error) {
	n := 0
	for _, f := range files {
		path := filepath.Join(tmp, filepath.FromSlash(strings.TrimSuffix(f.Name, "/")))
		if strings.HasSuffix(f.Name, "/") {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return 0, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return 0, err
		}
		if err := writeEntry(f, path); err != nil {
			return 0, fmt.Errorf("%s: %w", f.Name, err)
		}
		n++
	}
	raw, _ := json.Marshal(stamp{Digest: digest, Files: n})
	return n, os.WriteFile(filepath.Join(tmp, stampName), raw, 0o644)
}

func writeEntry(f *zip.File, path string) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return err
}

// renameRetry：刚写完的目录可能正被 Defender 扫描，Windows 上改名会短暂失败。
func renameRetry(from, to string) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	return err
}
