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
	if os.Getenv("EPSILON_FAKE_PY") == "1" { // 冒充环境层的 python.exe（jobs_e2e_test.go）
		os.Exit(fakePython(os.Args[1:]))
	}
	if port := os.Getenv("EPSILON_FAKE_PORT"); port != "" {
		if os.Getenv("EPSILON_FAKE_CRASH") == "1" {
			fmt.Fprintln(os.Stderr, "fake crashing")
			os.Exit(3)
		}
		if os.Getenv("EPSILON_FAKE_HANG") == "1" { // 模型加载卡住：有输出，但永远不健康
			fmt.Fprintln(os.Stderr, "loading model: cudaMalloc failed: out of memory")
			time.Sleep(time.Hour) // 不能用 select{}：没有别的 goroutine 时运行时会判死锁直接退出
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

// 加载卡住超时：事件要带上工作负载日志末尾，不然只知道"没起来"，得跑去机器上看。
func TestSupervisorHealthFailedCarriesLogTail(t *testing.T) {
	s := NewSupervisor()
	s.backoff = time.Hour
	defer s.Stop()
	w := fakeWorkload(t, false)
	w.env = append(w.env, "EPSILON_FAKE_HANG=1")
	w.StartTimeoutSec = 1
	w.Log = filepath.Join(t.TempDir(), "w.log")
	s.Ensure("hang", w, true)
	var ev string
	waitFor(t, "health_failed", func() bool {
		for _, e := range s.DrainEvents() {
			if e.Kind == "health_failed" {
				ev = e.Detail
			}
		}
		return ev != ""
	})
	if !strings.Contains(ev, "out of memory") {
		t.Fatalf("health_failed 要带日志末尾: %q", ev)
	}
}

func TestSupervisorIdleOnlyAfterProcessExited(t *testing.T) {
	// Stop 先把 cmd 置空再等进程退出：Status 说"没在跑"时推理进程可能还占着 8080/50052（回环不过防火墙）
	s := NewSupervisor()
	if !s.Idle() {
		t.Fatal("没起过就是空的")
	}
	w := fakeWorkload(t, false)
	s.Ensure("fake", w, true)
	waitFor(t, "起来", func() bool { return s.Status().PID != 0 })
	if s.Idle() {
		t.Fatal("在跑就不空")
	}
	s.mu.Lock()
	done := s.done
	s.cmd, s.cur = nil, WorkloadStatus{} // Stop 的第一步：已经不算在跑，但进程还没退
	s.mu.Unlock()
	if s.Idle() {
		t.Fatal("进程还没退出就不算空")
	}
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	last.Process.Kill()
	<-done
	if !s.Idle() {
		t.Fatal("退出了就空")
	}
}
