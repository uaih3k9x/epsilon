package probe

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 测试二进制自己冒充 llama-server：EPSILON_FAKE_PORT 设了就起一个 /health 服务。
func TestMain(m *testing.M) {
	if port := os.Getenv("EPSILON_FAKE_PORT"); port != "" {
		if os.Getenv("EPSILON_FAKE_CRASH") == "1" {
			fmt.Fprintln(os.Stderr, "fake crashing")
			os.Exit(3)
		}
		http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"status":"ok"}`) })
		http.ListenAndServe("127.0.0.1:"+port, nil)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func fakeWorkload(t *testing.T, crash bool) Workload {
	port := freePort(t)
	env := []string{"EPSILON_FAKE_PORT=" + strconv.Itoa(port)}
	if crash {
		env = append(env, "EPSILON_FAKE_CRASH=1")
	}
	return Workload{Exe: os.Args[0], Port: port, Model: "fake", Health: "/health", StartTimeoutSec: 10, env: env}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSupervisorStartHealthyStop(t *testing.T) {
	s := NewSupervisor()
	defer s.Stop()
	w := fakeWorkload(t, false)
	s.Ensure("fake", w, true)
	waitFor(t, "healthy", func() bool { st := s.Status(); return st.Healthy })
	if st := s.Status(); st.Name != "fake" || st.PID == 0 {
		t.Fatalf("status %+v", st)
	}
	s.Ensure("fake", w, true) // 已经在跑：不重复起
	s.Ensure("", Workload{}, false)
	waitFor(t, "stopped", func() bool { return s.Status().Name == "" })
}

func TestSupervisorSwitchesWorkload(t *testing.T) {
	s := NewSupervisor()
	defer s.Stop()
	a, b := fakeWorkload(t, false), fakeWorkload(t, false)
	s.Ensure("a", a, true)
	waitFor(t, "a healthy", func() bool { return s.Status().Healthy })
	s.Ensure("b", b, true)
	waitFor(t, "b healthy", func() bool { st := s.Status(); return st.Name == "b" && st.Healthy })
}

func TestSupervisorWritesWorkloadLog(t *testing.T) {
	s := NewSupervisor()
	s.backoff = time.Hour
	defer s.Stop()
	w := fakeWorkload(t, true)
	w.Log = filepath.Join(t.TempDir(), "w.log")
	s.Ensure("bad", w, true)
	waitFor(t, "crash", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.crashes >= 1 })
	b, _ := os.ReadFile(w.Log)
	if !strings.Contains(string(b), "启动") || !strings.Contains(string(b), "fake crashing") {
		t.Fatalf("log: %q", b)
	}
}

func TestSupervisorCrashBacksOff(t *testing.T) {
	s := NewSupervisor()
	s.backoff = 300 * time.Millisecond
	defer s.Stop()
	w := fakeWorkload(t, true)
	w.Log = filepath.Join(t.TempDir(), "bad.log")
	s.Ensure("bad", w, true)
	var detail string
	waitFor(t, "crash event", func() bool {
		for _, e := range s.DrainEvents() {
			if e.Kind == "crash" {
				detail = e.Detail
				return true
			}
		}
		return false
	})
	if !strings.Contains(detail, "fake crashing") { // 远程看不到学生机上的日志，崩溃事件里带上末尾几行
		t.Errorf("crash event without log tail: %q", detail)
	}
	s.Ensure("bad", w, true) // 退避期内不重启
	if s.Status().Name != "" {
		t.Fatal("restarted inside backoff")
	}
	time.Sleep(350 * time.Millisecond)
	s.Ensure("bad", w, true)
	waitFor(t, "second crash", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.crashes >= 2 })
}
