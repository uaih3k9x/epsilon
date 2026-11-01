// Package joboutput 把任务的 output/ 传回主控（契约见 docs/jobs.md）。
//
// 不落本地块：边读文件边算哈希，主控没有的块才传，所以断了重跑一遍就是续传。
package joboutput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"epsilon/chunk"
	"epsilon/proto"
)

const attempts = 3

var retryDelay = time.Second

type client struct {
	ctx      context.Context
	hc       *http.Client
	base     string
	token    string
	id       string
	chunkMax int64
}

// Upload 传 dir 下的全部文件，返回清单。主控校验通过后才算完成；中途失败返回错误，重新调用即可续传。
func Upload(ctx context.Context, hc *http.Client, base, token, id, dir string, chunkSize int64) (proto.Manifest, error) {
	if chunkSize <= 0 {
		chunkSize = chunk.DefaultChunkSize
	}
	c := &client{ctx: ctx, hc: hc, base: strings.TrimRight(base, "/"), token: token, id: id, chunkMax: chunkSize}
	m := proto.Manifest{ID: id, ChunkSize: chunkSize, Files: []proto.ManifestFile{}}
	buf := make([]byte, chunkSize)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: 不是普通文件", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		f, err := c.uploadFile(path, buf)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		f.Path = filepath.ToSlash(rel)
		m.Files = append(m.Files, f)
		return nil
	})
	if err != nil {
		return m, err
	}
	if len(m.Files) == 0 {
		return m, errors.New("没有输出文件")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	return m, c.do(http.MethodPut, "/output", raw, nil)
}

func (c *client) uploadFile(path string, buf []byte) (proto.ManifestFile, error) {
	mf := proto.ManifestFile{Chunks: []string{}}
	in, err := os.Open(path)
	if err != nil {
		return mf, err
	}
	defer in.Close()
	whole := sha256.New()
	for {
		n, err := io.ReadFull(in, buf)
		if n > 0 {
			whole.Write(buf[:n])
			sum := sha256.Sum256(buf[:n])
			h := hex.EncodeToString(sum[:])
			if err := c.putChunk(h, buf[:n]); err != nil {
				return mf, err
			}
			mf.Chunks = append(mf.Chunks, h)
			mf.Size += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return mf, err
		}
	}
	mf.SHA256 = hex.EncodeToString(whole.Sum(nil))
	return mf, nil
}

func (c *client) putChunk(h string, data []byte) error {
	var have bool
	if err := c.do(http.MethodHead, "/chunks/"+h, nil, &have); err != nil {
		return err
	}
	if have {
		return nil
	}
	return c.do(http.MethodPut, "/chunks/"+h, data, nil)
}

// do 对网络错误和 5xx 重试；4xx 是确定的拒绝，直接返回。found 非空时 404 不算错，写进 *found。
func (c *client) do(method, suffix string, body []byte, found *bool) error {
	u := c.base + "/v1/jobs/" + url.PathEscape(c.id) + suffix
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(retryDelay):
			case <-c.ctx.Done():
				return c.ctx.Err()
			}
		}
		q, err := http.NewRequestWithContext(c.ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if c.token != "" {
			q.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.hc.Do(q)
		if err != nil {
			last = err
			continue
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			if found != nil {
				*found = true
			}
			return nil
		case resp.StatusCode == http.StatusNotFound && found != nil:
			*found = false
			return nil
		case resp.StatusCode < 500:
			return fmt.Errorf("%s %s: %d %s", method, suffix, resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		last = fmt.Errorf("%s %s: %d", method, suffix, resp.StatusCode)
	}
	return last
}
