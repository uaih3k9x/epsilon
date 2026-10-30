package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "probe.json")
	os.WriteFile(p, []byte(`{
	  "controller": "http://10.0.0.1:8090/",
	  "token": "t",
	  "workloads": {
	    "qwen3.5-4b": {"exe": "D:\\epsilon\\llama-server.exe", "args": ["-m", "x.gguf", "--port", "8080"],
	                   "port": 8080, "model": "qwen3.5-4b"}
	  }
	}`), 0o600)
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Controller != "http://10.0.0.1:8090" {
		t.Errorf("trailing slash not trimmed: %q", c.Controller)
	}
	if c.Node == "" {
		t.Error("node should default to hostname")
	}
	w := c.Workloads["qwen3.5-4b"]
	if w.Log != filepath.Join(filepath.Dir(p), "qwen3.5-4b.log") {
		t.Errorf("log default: %q", w.Log)
	}
	if w.Health != "/health" || w.StartTimeoutSec != 300 {
		t.Errorf("defaults not applied: %+v", w)
	}
}

func TestLoadConfigRejectsBadWorkload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "probe.json")
	os.WriteFile(p, []byte(`{"controller":"http://x","workloads":{"a":{"exe":"","port":8080}}}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Error("want error for workload without exe")
	}
	os.WriteFile(p, []byte(`{"workloads":{}}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Error("want error without controller")
	}
}

func TestParseNvidiaSmi(t *testing.T) {
	gpus := ParseGPUs("NVIDIA GeForce RTX 4060 Ti, 37, 6123, 8188, 61, 95.32\n")
	if len(gpus) != 1 || gpus[0].Util != 37 || gpus[0].MemUsed != 6123 || gpus[0].PowerW != 95 {
		t.Fatalf("got %+v", gpus)
	}
	if len(ParseGPUs("")) != 0 || len(ParseGPUs("garbage\n")) != 0 {
		t.Error("garbage should give no gpus")
	}
	// 某些字段驱动给 [N/A]
	if g := ParseGPUs("RTX, 5, 100, 8188, 40, [N/A]\n"); len(g) != 1 || g[0].PowerW != 0 {
		t.Errorf("N/A power: %+v", g)
	}
}

func TestForeignGPUApps(t *testing.T) {
	out := "1234, C:\\epsilon\\llama-server.exe, 5000\n" +
		"5678, C:\\Games\\game.exe, 3000\n" +
		"[N/A], [N/A], [N/A]\n"
	got := ForeignApps(out, 1234)
	if len(got) != 1 || got[0] != "game.exe" {
		t.Fatalf("got %v", got)
	}
}

func TestLoadConfigMergesSlotWorkloads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "probe.json")
	os.WriteFile(p, []byte(`{"controller":"http://x","token":"t","workloads":{
	  "a":{"exe":"old.exe","port":8080},"b":{"exe":"b.exe","port":8081}}}`), 0o600)
	slot := filepath.Join(dir, "workloads.json")
	os.WriteFile(slot, []byte(`{"a":{"exe":"new.exe","port":8080},"rpc":{"exe":"rpc.exe","port":50052,"health":"tcp"}}`), 0o600)
	c, err := LoadConfig(p, slot, filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Workloads["a"].Exe != "new.exe" || c.Workloads["b"].Exe != "b.exe" || c.Workloads["rpc"].Health != "tcp" {
		t.Fatalf("merge: %+v", c.Workloads)
	}
	if c.Token != "t" || c.Workloads["rpc"].StartTimeoutSec != 300 {
		t.Fatalf("defaults: %+v", c)
	}
}
