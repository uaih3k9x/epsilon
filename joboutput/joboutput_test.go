package joboutput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"epsilon/controller"
	"epsilon/proto"
)

type rig struct {
	t    *testing.T
	srv  *httptest.Server
	jobs string
	src  string
}

func newRig(t *testing.T, maxMB int) *rig {
	t.Helper()
	jobs := t.TempDir()
	c := controller.New(controller.Config{ProbeToken: "tok", APIKeys: []string{"key"}, JobsDir: jobs, JobOutputMaxMB: maxMB, StaleSeconds: 30})
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	src := t.TempDir()
	return &rig{t: t, srv: srv, jobs: jobs, src: src}
}

func (r *rig) write(rel string, data []byte) {
	r.t.Helper()
	p := filepath.Join(r.src, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) req(method, path, auth string, body []byte) (int, []byte) {
	r.t.Helper()
	q, _ := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(body))
	if auth != "" {
		q.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(q)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestUploadAndDownload(t *testing.T) {
	r := newRig(t, 16)
	big := bytes.Repeat([]byte("0123456789"), 1000) // 跨多个块
	r.write("RESULT.json", []byte(`{"ok":true}`))
	r.write("source/train.py", []byte("print(1)\n"))
	r.write("big.bin", big)
	r.write("empty.txt", nil)
	m, err := Upload(context.Background(), http.DefaultClient, r.srv.URL, "tok", "exp029-t0", r.src, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 4 {
		t.Fatalf("文件数 %d", len(m.Files))
	}
	code, b := r.req("GET", "/v1/jobs/exp029-t0/output", "key", nil)
	if code != 200 {
		t.Fatalf("取清单 %d %s", code, b)
	}
	var got proto.Manifest
	json.Unmarshal(b, &got)
	if len(got.Files) != 4 {
		t.Fatalf("清单 %+v", got)
	}
	code, b = r.req("GET", "/v1/jobs/exp029-t0/files/big.bin", "key", nil)
	if code != 200 || sum(b) != sum(big) {
		t.Fatalf("下载 big.bin: %d, %d 字节", code, len(b))
	}
	code, b = r.req("GET", "/v1/jobs/exp029-t0/files/source/train.py", "key", nil)
	if code != 200 || string(b) != "print(1)\n" {
		t.Fatalf("下载子目录文件: %d %q", code, b)
	}
	if code, b = r.req("GET", "/v1/jobs/exp029-t0/files/empty.txt", "key", nil); code != 200 || len(b) != 0 {
		t.Fatalf("下载空文件: %d %q", code, b)
	}
}

// 第 n 个 PUT 块之后网络全断
type dropAfter struct {
	n    int32
	puts atomic.Int32
}

func (d *dropAfter) RoundTrip(q *http.Request) (*http.Response, error) {
	if q.Method == http.MethodPut && strings.Contains(q.URL.Path, "/chunks/") {
		if d.puts.Add(1) > d.n {
			return nil, errors.New("网断了")
		}
	}
	return http.DefaultTransport.RoundTrip(q)
}

func TestResumeAfterInterruption(t *testing.T) {
	r := newRig(t, 16)
	data := make([]byte, 4096*6)
	for i := range data {
		data[i] = byte(i * 31 >> 3)
	}
	for i := 0; i < 6; i++ { // 每块内容不同
		copy(data[i*4096:], []byte{byte(i), 0xAB, byte(i * 7)})
	}
	r.write("big.bin", data)
	broken := &dropAfter{n: 3}
	retryDelay = 0
	if _, err := Upload(context.Background(), &http.Client{Transport: broken}, r.srv.URL, "tok", "j1", r.src, 4096); err == nil {
		t.Fatal("网断了竟然成功")
	}
	if code, _ := r.req("GET", "/v1/jobs/j1/output", "key", nil); code != 404 {
		t.Fatalf("没传完不该有清单: %d", code)
	}
	counter := &dropAfter{n: 1000}
	if _, err := Upload(context.Background(), &http.Client{Transport: counter}, r.srv.URL, "tok", "j1", r.src, 4096); err != nil {
		t.Fatal(err)
	}
	if got := counter.puts.Load(); got != 3 {
		t.Fatalf("续传应该只传剩下的 3 块, 传了 %d", got)
	}
	code, b := r.req("GET", "/v1/jobs/j1/files/big.bin", "key", nil)
	if code != 200 || sum(b) != sum(data) {
		t.Fatalf("续传后内容不对: %d", code)
	}
}

func TestUploadIsIdempotentAndFrozen(t *testing.T) {
	r := newRig(t, 16)
	r.write("a.txt", []byte("v1"))
	if _, err := Upload(context.Background(), http.DefaultClient, r.srv.URL, "tok", "j1", r.src, 4096); err != nil {
		t.Fatal(err)
	}
	counter := &dropAfter{n: 1000}
	if _, err := Upload(context.Background(), &http.Client{Transport: counter}, r.srv.URL, "tok", "j1", r.src, 4096); err != nil {
		t.Fatalf("重复上传同样内容应该成功: %v", err)
	}
	if counter.puts.Load() != 0 {
		t.Fatal("已完成的任务不该再传块")
	}
	r.write("a.txt", []byte("v2"))
	if _, err := Upload(context.Background(), http.DefaultClient, r.srv.URL, "tok", "j1", r.src, 4096); err == nil {
		t.Fatal("完成后换内容竟然覆盖了")
	}
	_, b := r.req("GET", "/v1/jobs/j1/files/a.txt", "key", nil)
	if string(b) != "v1" {
		t.Fatalf("已完成的输出被改了: %q", b)
	}
}

func TestOverLimitRefused(t *testing.T) {
	r := newRig(t, 1)
	r.write("big.bin", make([]byte, 2<<20))
	if _, err := Upload(context.Background(), http.DefaultClient, r.srv.URL, "tok", "j1", r.src, 1<<20); err == nil {
		t.Fatal("超上限竟然传上去了")
	}
	if code, _ := r.req("GET", "/v1/jobs/j1/output", "key", nil); code != 404 {
		t.Fatal("超上限不该有清单")
	}
}

func TestChunkHashChecked(t *testing.T) {
	r := newRig(t, 16)
	h := sum([]byte("real"))
	if code, _ := r.req("PUT", "/v1/jobs/j1/chunks/"+h, "tok", []byte("fake")); code != 400 {
		t.Fatalf("块内容对不上应该 400: %d", code)
	}
	if code, _ := r.req("HEAD", "/v1/jobs/j1/chunks/"+h, "tok", nil); code != 404 {
		t.Fatalf("坏块不该留下: %d", code)
	}
	if code, _ := r.req("PUT", "/v1/jobs/j1/chunks/"+h, "tok", []byte("real")); code != 200 {
		t.Fatalf("好块应该 200: %d", code)
	}
	if code, _ := r.req("HEAD", "/v1/jobs/j1/chunks/"+h, "tok", nil); code != 200 {
		t.Fatalf("好块 HEAD 应该 200: %d", code)
	}
}

func TestManifestValidated(t *testing.T) {
	r := newRig(t, 16)
	h := sum([]byte("real"))
	r.req("PUT", "/v1/jobs/j1/chunks/"+h, "tok", []byte("real"))
	good := proto.ManifestFile{Path: "a.txt", Size: 4, SHA256: h, Chunks: []string{h}}
	for name, m := range map[string]proto.Manifest{
		"路径穿越":     {ID: "j1", Files: []proto.ManifestFile{{Path: "../evil", Size: 4, SHA256: h, Chunks: []string{h}}}},
		"绝对路径":     {ID: "j1", Files: []proto.ManifestFile{{Path: "/evil", Size: 4, SHA256: h, Chunks: []string{h}}}},
		"冒充 stamp": {ID: "j1", Files: []proto.ManifestFile{{Path: "a.txt.epsilon-ok", Size: 4, SHA256: h, Chunks: []string{h}}}},
		"ID 对不上":   {ID: "other", Files: []proto.ManifestFile{good}},
		"大小对不上":    {ID: "j1", Files: []proto.ManifestFile{{Path: "a.txt", Size: 5, SHA256: h, Chunks: []string{h}}}},
		"哈希对不上":    {ID: "j1", Files: []proto.ManifestFile{{Path: "a.txt", Size: 4, SHA256: strings.Repeat("0", 64), Chunks: []string{h}}}},
		"缺块":       {ID: "j1", Files: []proto.ManifestFile{{Path: "a.txt", Size: 4, SHA256: h, Chunks: []string{strings.Repeat("e", 64)}}}},
		"路径重复":     {ID: "j1", Files: []proto.ManifestFile{good, good}},
	} {
		b, _ := json.Marshal(m)
		if code, resp := r.req("PUT", "/v1/jobs/j1/output", "tok", b); code < 400 {
			t.Errorf("%s: 竟然收了 (%d %s)", name, code, resp)
		}
		if code, _ := r.req("GET", "/v1/jobs/j1/output", "key", nil); code != 404 {
			t.Errorf("%s: 校验失败不该留下清单", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.jobs), "evil")); err == nil {
		t.Fatal("写到目录外面了")
	}
}

func TestAuthAndBadIDs(t *testing.T) {
	r := newRig(t, 16)
	h := sum([]byte("x"))
	if code, _ := r.req("PUT", "/v1/jobs/j1/chunks/"+h, "wrong", []byte("x")); code != 401 {
		t.Fatalf("错 token: %d", code)
	}
	if code, _ := r.req("GET", "/v1/jobs/j1/output", "tok", nil); code != 401 {
		t.Fatalf("下载要 api key, 探针 token 不行: %d", code)
	}
	for _, id := range []string{"..", ".hidden", "..%2f..%2fetc"} {
		if code, _ := r.req("PUT", "/v1/jobs/"+id+"/chunks/"+h, "tok", []byte("x")); code < 400 {
			t.Errorf("任务 ID %q 竟然收了: %d", id, code)
		}
	}
	if code, _ := r.req("PUT", "/v1/jobs/j1/chunks/notahash", "tok", []byte("x")); code < 400 {
		t.Errorf("坏块名竟然收了: %d", code)
	}
}

func TestDownloadOnlyListedFiles(t *testing.T) {
	r := newRig(t, 16)
	r.write("a.txt", []byte("v1"))
	if _, err := Upload(context.Background(), http.DefaultClient, r.srv.URL, "tok", "j1", r.src, 4096); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a.txt.epsilon-ok", "nope", "../manifest.json", "..%2fmanifest.json"} {
		if code, _ := r.req("GET", "/v1/jobs/j1/files/"+p, "key", nil); code == 200 {
			t.Errorf("不在清单里的 %q 竟然能下载", p)
		}
	}
}

func TestDisabledWithoutJobsDir(t *testing.T) {
	srv := httptest.NewServer(controller.New(controller.Config{ProbeToken: "tok", StaleSeconds: 30}).Handler())
	defer srv.Close()
	q, _ := http.NewRequest("PUT", srv.URL+"/v1/jobs/j1/output", strings.NewReader("{}"))
	q.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("没配 jobs_dir 应该 404: %d", resp.StatusCode)
	}
}
