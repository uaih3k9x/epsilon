package probe

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"epsilon/proto"
)

func put(t *testing.T, path string, n int) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// D:\epsilon 按顶层分类：models / chunks / slots（A、B、R）/ logs / other；符号链接不跟。
func TestDiskUsageClassifies(t *testing.T) {
	root := t.TempDir()
	const mb = 1 << 20
	put(t, filepath.Join(root, "models", "m.gguf"), 3*mb)
	put(t, filepath.Join(root, "chunks", "ab", "abcd"), 2*mb)
	put(t, filepath.Join(root, "A", "epsilon-probe.exe"), mb)
	put(t, filepath.Join(root, "R", "epsilon-probe.exe"), mb)
	put(t, filepath.Join(root, "probe.log"), mb)
	put(t, filepath.Join(root, "q27-rpc.log.1"), mb)
	put(t, filepath.Join(root, "llama", "llama-server.exe"), 4*mb)
	outside := t.TempDir()
	put(t, filepath.Join(outside, "big"), 50*mb)
	if err := os.Symlink(outside, filepath.Join(root, "models", "link")); err != nil {
		t.Skip("建不了符号链接:", err)
	}

	u, complete := diskUsage(root, filepath.Join(root, "chunks"), time.Minute)
	if !complete {
		t.Fatal("没统计完")
	}
	want := map[string]int64{"models": 3, "chunks": 2, "slots": 2, "logs": 2, "other": 4}
	for k, v := range want {
		if u[k] != v {
			t.Errorf("%s = %d MB，要 %d（全部 %v）", k, u[k], v, u)
		}
	}
}

// 块目录配在 artifact_root 外面也要算进 chunks。
func TestDiskUsageChunkDirElsewhere(t *testing.T) {
	root, cd := t.TempDir(), t.TempDir()
	put(t, filepath.Join(cd, "ab", "abcd"), 3<<20)
	u, _ := diskUsage(root, cd, time.Minute)
	if u["chunks"] != 3 {
		t.Fatalf("chunks = %d", u["chunks"])
	}
}

func TestDiskUsageGivesUpAfterBudget(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "models", "m"), 10)
	if _, complete := diskUsage(root, "", 0); complete {
		t.Fatal("预算 0 还算完了")
	}
}

// 心跳带盘总量 / 剩余（每次取）和分项占用（后台算好的）。
func TestHeartbeatCarriesDisk(t *testing.T) {
	fc := &fakeController{desired: proto.DesiredState{HeartbeatSeconds: 1}}
	srv := httptest.NewServer(fc.handler())
	defer srv.Close()
	root := t.TempDir()
	put(t, filepath.Join(root, "models", "m.gguf"), 5<<20)
	a := NewAgent(Config{Node: "pc-01", Controller: srv.URL, ArtifactRoot: root, ChunkDir: filepath.Join(root, "chunks")},
		&fakeSys{idle: 9999}, "test")
	defer a.Shutdown()
	a.beatEvery = 100 * time.Millisecond
	stop := make(chan struct{})
	go a.Run(stop, 20*time.Millisecond)
	defer close(stop)
	waitFor(t, "disk in heartbeat", func() bool {
		d := fc.last().Disk
		return d != nil && d.TotalMB == 100000 && d.FreeMB == 4000 && d.UsageMB["models"] == 5 && d.Complete
	})
}
