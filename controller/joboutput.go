package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"epsilon/chunk"
	"epsilon/proto"
)

// 任务输出回传（docs/jobs.md）：探针先按块 HEAD / PUT，最后 PUT 清单。块哈希保证内容，
// 整文件哈希由 chunk.Assemble 核对，全部过了才写 manifest.json。写了 manifest.json 就是完成，之后不可改。

const defaultJobOutputMaxMB = 2048

func (c *Controller) jobOutputLimit() int64 {
	if c.cfg.JobOutputMaxMB > 0 {
		return int64(c.cfg.JobOutputMaxMB) << 20
	}
	return defaultJobOutputMaxMB << 20
}

func (c *Controller) jobDir(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !manifestName.MatchString(id) {
		http.NotFound(w, r)
		return "", false
	}
	return filepath.Join(c.cfg.JobsDir, id), true
}

func readJobManifest(dir string) ([]byte, proto.Manifest, error) {
	var m proto.Manifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, m, err
	}
	return b, m, json.Unmarshal(b, &m)
}

func manifestHasChunk(m proto.Manifest, h string) bool {
	for _, f := range m.Files {
		for _, x := range f.Chunks {
			if x == h {
				return true
			}
		}
	}
	return false
}

func (c *Controller) jobChunkHead(w http.ResponseWriter, r *http.Request) {
	dir, ok := c.jobDir(w, r)
	h := r.PathValue("hash")
	if !ok || !chunk.ValidHash(h) {
		if ok {
			http.NotFound(w, r)
		}
		return
	}
	if _, m, err := readJobManifest(dir); err == nil {
		if manifestHasChunk(m, h) {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat(filepath.Join(dir, "chunks", h[:2], h)); err != nil {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func dirBytes(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

func (c *Controller) jobChunkPut(w http.ResponseWriter, r *http.Request) {
	dir, ok := c.jobDir(w, r)
	if !ok {
		return
	}
	h := r.PathValue("hash")
	if !chunk.ValidHash(h) {
		http.Error(w, "bad chunk hash", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
		http.Error(w, "这个任务的输出已经完成，不能再改", http.StatusConflict)
		return
	}
	chunks := filepath.Join(dir, "chunks")
	left := c.jobOutputLimit() - dirBytes(chunks)
	if r.ContentLength > left {
		http.Error(w, "超过任务输出上限", http.StatusRequestEntityTooLarge)
		return
	}
	s, err := chunk.NewStore(chunks, 0)
	if err != nil {
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	if err := s.Put(h, http.MaxBytesReader(w, r.Body, left)); err != nil {
		var tooBig *http.MaxBytesError
		switch {
		case errors.Is(err, chunk.ErrHashMismatch):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.As(err, &tooBig):
			http.Error(w, "超过任务输出上限", http.StatusRequestEntityTooLarge)
		default:
			http.Error(w, "store", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}

func checkJobManifest(m proto.Manifest, id string, limit int64) error {
	if m.ID != id {
		return fmt.Errorf("清单是 %q，任务是 %q", m.ID, id)
	}
	seen := map[string]bool{}
	var total int64
	for _, f := range m.Files {
		if !chunk.SafePath(f.Path) || strings.HasSuffix(f.Path, chunk.StampSuffix) {
			return fmt.Errorf("路径不合法: %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("路径重复: %q", f.Path)
		}
		seen[f.Path] = true
		if f.Size < 0 || total+f.Size > limit {
			return errors.New("超过任务输出上限")
		}
		total += f.Size
	}
	return nil
}

func (c *Controller) jobOutputPut(w http.ResponseWriter, r *http.Request) {
	dir, ok := c.jobDir(w, r)
	if !ok {
		return
	}
	var m proto.Manifest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&m); err != nil {
		http.Error(w, "bad manifest", http.StatusBadRequest)
		return
	}
	if err := checkJobManifest(m, r.PathValue("id"), c.jobOutputLimit()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	c.jobMu.Lock()
	defer c.jobMu.Unlock()
	if old, _, err := readJobManifest(dir); err == nil {
		if !bytes.Equal(old, raw) {
			http.Error(w, "这个任务的输出已经完成，内容不同，不能覆盖", http.StatusConflict)
			return
		}
		w.Write([]byte("{}"))
		return
	}
	s, err := chunk.NewStore(filepath.Join(dir, "chunks"), 0)
	if err != nil {
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	if err := chunk.Assemble(m, s, filepath.Join(dir, "output")); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	tmp := filepath.Join(dir, "manifest.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err == nil {
		err = os.Rename(tmp, filepath.Join(dir, "manifest.json"))
		if err != nil {
			os.Remove(tmp)
		}
	}
	if _, _, err := readJobManifest(dir); err != nil {
		http.Error(w, "store", http.StatusInternalServerError)
		return
	}
	os.RemoveAll(filepath.Join(dir, "chunks")) // 完成了就不用留两份
	w.Write([]byte("{}"))
}

func (c *Controller) jobOutputGet(w http.ResponseWriter, r *http.Request) {
	dir, ok := c.jobDir(w, r)
	if !ok {
		return
	}
	b, _, err := readJobManifest(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, bytes.NewReader(b))
}

// jobFileGet 只发清单里列出的文件，路径不是拿来拼的。
func (c *Controller) jobFileGet(w http.ResponseWriter, r *http.Request) {
	dir, ok := c.jobDir(w, r)
	if !ok {
		return
	}
	_, m, err := readJobManifest(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	want := r.PathValue("path")
	for _, f := range m.Files {
		if f.Path == want {
			http.ServeFile(w, r, filepath.Join(dir, "output", filepath.FromSlash(f.Path)))
			return
		}
	}
	http.NotFound(w, r)
}
