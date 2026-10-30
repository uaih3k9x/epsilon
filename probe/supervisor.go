package probe

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"epsilon/proto"
	"epsilon/winproc"
)

// WorkloadStatus 是看护器眼里的工作负载。Name 为空 = 没在跑。
type WorkloadStatus struct {
	Name    string
	PID     int
	Healthy bool
	Model   string
	Port    int
}

// Supervisor 一次只看护一个工作负载（一张卡一个 llama-server）。
type Supervisor struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	cur     WorkloadStatus
	done    chan struct{}
	events  []proto.Event
	crashed time.Time // 上次崩溃时间，退避用
	crashes int
	backoff time.Duration
}

func NewSupervisor() *Supervisor {
	return &Supervisor{backoff: 30 * time.Second}
}

// Ensure 让现实对上愿望：want=false 就停；want=true 就保证 name 在跑（换了名字先停旧的）。
func (s *Supervisor) Ensure(name string, w Workload, want bool) {
	s.mu.Lock()
	running := s.cur.Name
	s.mu.Unlock()
	if !want || (running != "" && running != name) {
		s.Stop()
	}
	if !want || running == name {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur.Name != "" || time.Since(s.crashed) < s.backoff {
		return
	}
	cmd := exec.Command(w.Exe, w.Args...)
	cmd.Dir = w.Dir
	cmd.Env = append(os.Environ(), w.env...)
	if w.Log != "" {
		if st, err := os.Stat(w.Log); err == nil && st.Size() > 20<<20 {
			os.Remove(w.Log) // 超过 20 MB 从头记
		}
		if f, err := os.OpenFile(w.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "\n===== %s 启动 %s %v\n", time.Now().Format("2006-01-02 15:04:05"), w.Exe, w.Args)
			cmd.Stdout, cmd.Stderr = f, f
			defer f.Close() // 子进程拿到的是复制的句柄，父进程这边可以关
		}
	}
	winproc.Hide(cmd)
	if err := cmd.Start(); err != nil {
		s.crashed = time.Now()
		s.event("start_failed", fmt.Sprintf("%s: %v", name, err))
		return
	}
	winproc.Bind(cmd.Process.Pid)
	s.cmd, s.done = cmd, make(chan struct{})
	s.cur = WorkloadStatus{Name: name, PID: cmd.Process.Pid, Model: w.Model, Port: w.Port}
	go s.wait(cmd, s.done, name, w.Log)
	go s.health(cmd, w)
}

func (s *Supervisor) wait(cmd *exec.Cmd, done chan struct{}, name, logPath string) {
	err := cmd.Wait()
	close(done)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != cmd { // 是我们自己停的
		return
	}
	s.cmd, s.cur = nil, WorkloadStatus{}
	s.crashed = time.Now()
	s.crashes++
	s.event("crash", fmt.Sprintf("%s 退出: %v\n%s", name, err, tailFile(logPath, 1500)))
}

// tailFile 取文件末尾最多 n 字节，从完整的一行开始。
func tailFile(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	b := make([]byte, st.Size()-off)
	f.ReadAt(b, off)
	if i := bytes.IndexByte(b, '\n'); off > 0 && i >= 0 {
		b = b[i+1:]
	}
	return strings.ToValidUTF8(string(b), "?")
}

// health 轮询健康检查；起来之前每秒一次，起来之后每 5 秒一次，失败就标不健康（路由会跳过）。
func (s *Supervisor) health(cmd *exec.Cmd, w Workload) {
	client := &http.Client{Timeout: 3 * time.Second}
	start := time.Now()
	for {
		s.mu.Lock()
		if s.cmd != cmd {
			s.mu.Unlock()
			return
		}
		was := s.cur.Healthy
		s.mu.Unlock()

		ok := checkHealth(client, w)
		s.mu.Lock()
		if s.cmd != cmd {
			s.mu.Unlock()
			return
		}
		s.cur.Healthy = ok
		if ok && !was {
			s.crashes = 0
		}
		s.mu.Unlock()

		if !ok && !was && time.Since(start) > time.Duration(w.StartTimeoutSec)*time.Second {
			s.mu.Lock()
			s.event("health_failed", fmt.Sprintf("%s %d 秒内没通过健康检查", w.Model, w.StartTimeoutSec))
			s.crashed = time.Now()
			s.mu.Unlock()
			s.Stop()
			return
		}
		if ok {
			time.Sleep(5 * time.Second)
		} else {
			time.Sleep(time.Second)
		}
	}
}

// Stop 停掉当前工作负载并等它退出（最多 10 秒，之后不再等）。
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cmd, done := s.cmd, s.done
	s.cmd, s.cur = nil, WorkloadStatus{}
	s.mu.Unlock()
	if cmd == nil {
		return
	}
	cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

func (s *Supervisor) Status() WorkloadStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// DrainEvents 取走攒下的事件。
func (s *Supervisor) DrainEvents() []proto.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := s.events
	s.events = nil
	return ev
}

func (s *Supervisor) event(kind, detail string) {
	s.events = append(s.events, proto.Event{Kind: kind, Detail: detail})
}

func checkHealth(client *http.Client, w Workload) bool {
	if w.Health == "none" { // 进程退出由 wait 处理，这里不打扰它
		return true
	}
	if w.Health == "tcp" {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", w.Port), client.Timeout)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	r, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", w.Port, w.Health))
	if err != nil {
		return false
	}
	r.Body.Close()
	return r.StatusCode == http.StatusOK
}
