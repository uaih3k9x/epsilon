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
		f, err := buildFile(s, filepath.Join(root, filepath.FromSlash(p)), chunkSize)
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

func buildFile(s *Store, path string, chunkSize int64) (proto.ManifestFile, error) {
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
		h, n, err := s.ingest(io.LimitReader(r, chunkSize), "")
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
