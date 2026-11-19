// Package chunk 是第 2 阶段 P2P 分发的分块层：切块出清单（Build）、本地块缓存（Store）、按清单拼回文件（Assemble）。
// 契约见 docs/p2p.md。块 ID = 块内容的 sha256；全部流式处理，不把整块读进内存。
package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"epsilon/proto"
)

// DefaultChunkSize 是默认块大小，64 MiB。
const DefaultChunkSize = 64 << 20

// ErrHashMismatch 表示收到的内容和声明的 sha256 对不上。
var ErrHashMismatch = errors.New("sha256 对不上")

// ValidHash 判断 h 是不是 64 位小写十六进制。
func ValidHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// SafePath 判断清单里的相对路径能不能落盘：非空、正斜杠分隔、
// 不是绝对路径、不带盘符（不许冒号）、没有空段 / "." / ".." 段、没有反斜杠和 NUL。
func SafePath(p string) bool {
	if p == "" || strings.ContainsAny(p, "\\:\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// WindowsSafe 判断相对路径（已过 SafePath）在 Windows 上能不能原样落盘（设计书 20.5）：
// 不许保留设备名（CON、NUL、COM1、LPT9…，带扩展名也算，不分大小写），段尾不许是点或空格
// （Win32 会悄悄去掉，"x.py." 落盘成 x.py）。
func WindowsSafe(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return false
		}
		base, _, _ := strings.Cut(seg, ".")
		if winReserved[strings.ToLower(strings.TrimRight(base, " "))] {
			return false
		}
	}
	return true
}

var winReserved = func() map[string]bool {
	m := map[string]bool{"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true}
	for _, d := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
		m["com"+d], m["lpt"+d] = true, true
	}
	return m
}()

// validID 判断清单 ID 能不能当文件名用（<id>.json）。
func validID(id string) bool {
	return id != "" && !strings.Contains(id, "/") && SafePath(id)
}

func chunkPath(dir, h string) string { return filepath.Join(dir, h[:2], h) }

// writeAtomic 写临时文件再改名；临时文件名唯一，并发写同一路径也安全。
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// Build 把 root 下的 paths（相对路径）切块：块写进 outDir/<h[:2]>/<h>（已存在就跳过），
// 清单写 outDir/<id>.json，返回清单。chunkSize<=0 用 DefaultChunkSize。
func Build(id, root string, paths []string, chunkSize int64, outDir string) (proto.Manifest, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	m := proto.Manifest{ID: id, ChunkSize: chunkSize, Files: []proto.ManifestFile{}}
	if !validID(id) {
		return m, fmt.Errorf("清单 ID 不合法: %q", id)
	}
	if len(paths) == 0 {
		return m, errors.New("没有文件")
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !SafePath(p) {
			return m, fmt.Errorf("路径不合法: %q", p)
		}
		if seen[p] {
			return m, fmt.Errorf("路径重复: %s", p)
		}
		seen[p] = true
	}
	s, err := NewStore(outDir, 0)
	if err != nil {
		return m, err
	}
	for _, p := range paths {
		f, err := buildFile(s.ingest, filepath.Join(root, filepath.FromSlash(p)), chunkSize)
		if err != nil {
			return m, fmt.Errorf("%s: %w", p, err)
		}
		f.Path = p
		m.Files = append(m.Files, f)
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	return m, writeAtomic(filepath.Join(outDir, id+".json"), raw)
}

// BuildFile 把单个文件 src 切块写进 outDir，返回清单里的这一项（Path 留给调用方填，不写清单）。
// chunkSize<=0 用 DefaultChunkSize。
func BuildFile(outDir, src string, chunkSize int64) (proto.ManifestFile, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	s, err := NewStore(outDir, 0)
	if err != nil {
		return proto.ManifestFile{}, err
	}
	return buildFile(s.ingest, src, chunkSize)
}

// HashFile 和 BuildFile 算出同样的清单项，但只算哈希、不写块。用来先比对、对上了再写。
func HashFile(src string, chunkSize int64) (proto.ManifestFile, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return buildFile(func(r io.Reader, _ string) (string, int64, error) {
		h := sha256.New()
		n, err := io.Copy(h, r)
		return hex.EncodeToString(h.Sum(nil)), n, err
	}, src, chunkSize)
}

// VerifyChunks 逐个重算 dir 里这些块文件的 SHA-256，缺了或对不上就报错（报错里带块哈希）。
// Store 只按文件名认块，已有的坏块（截断、改过）要靠这个发现。
func VerifyChunks(dir string, hashes []string) error {
	for _, want := range hashes {
		if !ValidHash(want) {
			return fmt.Errorf("块哈希不合法: %q", want)
		}
		f, err := os.Open(chunkPath(dir, want))
		if err != nil {
			return fmt.Errorf("块 %s: %w", want, err)
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("块 %s: %w", want, err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("块文件 %s 内容坏了（实际 SHA-256 %s）: %w", chunkPath(dir, want), got, ErrHashMismatch)
		}
	}
	return nil
}

func buildFile(ingest func(io.Reader, string) (string, int64, error), path string, chunkSize int64) (proto.ManifestFile, error) {
	mf := proto.ManifestFile{Chunks: []string{}}
	f, err := os.Open(path)
	if err != nil {
		return mf, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return mf, err
	}
	if !fi.Mode().IsRegular() {
		return mf, errors.New("不是普通文件")
	}
	whole := sha256.New()
	r := io.TeeReader(f, whole)
	var total int64
	for total < fi.Size() {
		h, n, err := ingest(io.LimitReader(r, chunkSize), "")
		if err != nil {
			return mf, err
		}
		if n == 0 {
			break
		}
		total += n
		mf.Chunks = append(mf.Chunks, h)
	}
	if n, _ := io.Copy(io.Discard, r); n > 0 || total != fi.Size() {
		return mf, errors.New("切块时文件大小变了")
	}
	mf.Size = total
	mf.SHA256 = hex.EncodeToString(whole.Sum(nil))
	return mf, nil
}
