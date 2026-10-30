package chunk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"epsilon/proto"
)

// StampSuffix 是拼好的文件旁边的校验记录后缀。
const StampSuffix = ".epsilon-ok"

// stamp 记录拼好时的整文件 sha256、大小、修改时间；开机核对大小和修改时间一致就不重算哈希。
type stamp struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime_ns"`
}

func checkFile(f proto.ManifestFile) error {
	if !SafePath(f.Path) {
		return fmt.Errorf("路径不合法: %q", f.Path)
	}
	if !ValidHash(f.SHA256) || f.Size < 0 {
		return fmt.Errorf("%s: 清单里的哈希或大小不合法", f.Path)
	}
	for _, h := range f.Chunks {
		if !ValidHash(h) {
			return fmt.Errorf("%s: 块哈希不合法: %q", f.Path, h)
		}
	}
	return nil
}

func dest(root string, f proto.ManifestFile) string {
	return filepath.Join(root, filepath.FromSlash(f.Path))
}

// stampOK 看 path 的 stamp 是否和文件现状、清单对得上。
func stampOK(path string, f proto.ManifestFile) bool {
	raw, err := os.ReadFile(path + StampSuffix)
	if err != nil {
		return false
	}
	var st stamp
	if json.Unmarshal(raw, &st) != nil {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	return st.SHA256 == f.SHA256 && st.Size == f.Size &&
		fi.Size() == f.Size && fi.ModTime().UnixNano() == st.ModTime
}

// Ready 判断清单里所有文件都已拼好落在 root 下（只看 stamp，不重算哈希）。
func Ready(m proto.Manifest, root string) bool {
	for _, f := range m.Files {
		if checkFile(f) != nil || !stampOK(dest(root, f), f) {
			return false
		}
	}
	return true
}

// Assemble 把清单里每个文件从块拼到 root/<path>：写临时文件、校验整文件 sha256 和大小、改名，
// 再写 <文件>.epsilon-ok。stamp 对得上的文件跳过。动手前先查齐块，缺块直接报错、什么都不写。
func Assemble(m proto.Manifest, s *Store, root string) error {
	var todo []proto.ManifestFile
	for _, f := range m.Files {
		if err := checkFile(f); err != nil {
			return err
		}
		if stampOK(dest(root, f), f) {
			continue
		}
		for _, h := range f.Chunks {
			if !s.Has(h) {
				return fmt.Errorf("%s: 缺块 %s", f.Path, h)
			}
		}
		todo = append(todo, f)
	}
	for _, f := range todo {
		if err := assembleFile(f, s, dest(root, f)); err != nil {
			return fmt.Errorf("%s: %w", f.Path, err)
		}
	}
	return nil
}

func assembleFile(f proto.ManifestFile, s *Store, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	err = copyChunks(out, f.Chunks, s, f.Size, f.SHA256)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		os.Remove(path + StampSuffix) // 先删旧 stamp，免得改名后新文件配上旧记录
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(stamp{SHA256: f.SHA256, Size: fi.Size(), ModTime: fi.ModTime().UnixNano()})
	return writeAtomic(path+StampSuffix, raw)
}

func copyChunks(w io.Writer, chunks []string, s *Store, size int64, sum string) error {
	hs := sha256.New()
	mw := io.MultiWriter(w, hs)
	var n int64
	for _, h := range chunks {
		rc, _, err := s.Open(h)
		if err != nil {
			return err
		}
		k, err := io.Copy(mw, rc)
		rc.Close()
		n += k
		if err != nil {
			return err
		}
	}
	if n != size {
		return fmt.Errorf("大小 %d，清单说 %d", n, size)
	}
	if hex.EncodeToString(hs.Sum(nil)) != sum {
		return fmt.Errorf("整文件: %w", ErrHashMismatch)
	}
	return nil
}
