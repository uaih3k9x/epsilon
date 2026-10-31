package probe

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"epsilon/proto"
)

func TestRotateLogUnderLimitLeavesItAlone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(p, []byte("short\n"), 0o644)
	if RotateLog(p, 100) {
		t.Fatal("没超也轮转了")
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("不该有 .1")
	}
}

// 正在被追加写的文件：复制成 .1、原文件截断；写的一方接着写，从头开始。
func TestRotateLogCopiesThenTruncatesWhileOpen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	os.WriteFile(p+".1", []byte("更早的\n"), 0o644)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(strings.Repeat("旧的一行\n", 20))
	if !RotateLog(p, 50) {
		t.Fatal("超了没轮转")
	}
	old, _ := os.ReadFile(p + ".1")
	if !strings.HasPrefix(string(old), "旧的一行") || strings.Contains(string(old), "更早的") {
		t.Fatalf(".1 应该是刚才的内容并覆盖更早的: %q", old)
	}
	f.WriteString("新的\n")
	cur, _ := os.ReadFile(p)
	if string(cur) != "新的\n" {
		t.Fatalf("截断后接着写应该从头开始，得到 %q", cur)
	}
}

func TestRotateLogMissingFile(t *testing.T) {
	if RotateLog(filepath.Join(t.TempDir(), "nope.log"), 1) {
		t.Fatal("文件不存在不该算轮转")
	}
}

// 探针每分钟查一次自己的日志和正在跑的工作负载日志；不到一分钟不重复查。
func TestAgentRotatesLogsWhileRunning(t *testing.T) {
	fc := &fakeController{desired: proto.DesiredState{Workload: "fake", HeartbeatSeconds: 1}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	dir := t.TempDir()
	w := fakeWorkload(t, false)
	w.Log = filepath.Join(dir, "fake.log")
	a := NewAgent(Config{Node: "pc-01", Controller: srv.URL, Workloads: map[string]Workload{"fake": w}}, &fakeSys{idle: 9999}, "test")
	defer a.sup.Stop()
	a.LogPath = filepath.Join(dir, "probe.log")
	a.logMax, a.workloadLogMax = 100, 100

	now := time.Now()
	a.Step(now)                      // 登记、心跳拿到期望状态；也是第一次查日志
	a.Step(now.Add(2 * time.Second)) // 按期望状态起工作负载
	waitFor(t, "workload running", func() bool { return a.sup.Status().Name == "fake" })
	big := strings.Repeat("x", 500)
	os.WriteFile(a.LogPath, []byte(big), 0o644)
	os.WriteFile(w.Log, []byte(big), 0o644)

	a.Step(now.Add(30 * time.Second))
	if st, _ := os.Stat(a.LogPath); st.Size() != 500 {
		t.Fatal("不到一分钟就轮转了")
	}
	a.Step(now.Add(61 * time.Second))
	for _, p := range []string{a.LogPath, w.Log} {
		if st, _ := os.Stat(p); st.Size() != 0 {
			t.Fatalf("%s 没轮转: %d", p, st.Size())
		}
		if b, _ := os.ReadFile(p + ".1"); string(b) != big {
			t.Fatalf("%s.1 不对", p)
		}
	}
}
