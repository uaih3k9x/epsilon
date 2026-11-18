package jobbox

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

const testJobDir = `D:\epsilon\jobs\demo-1`

func readyLine(pid, ppid int) string {
	return readyLineDir(pid, ppid, `D:\\epsilon\\jobs\\demo-1`)
}

func readyLineDir(pid, ppid int, jsonDir string) string {
	return fmt.Sprintf(`{"t":1,"ev":"ready","pid":%d,"ppid":%d,"il":"low","job_dir":"%s","file":"D:\\e\\Lib\\site-packages\\sitecustomize.py","layer":"D:\\e"}`, pid, ppid, jsonDir)
}

func TestLogParsesAndCounts(t *testing.T) {
	l := NewLog(1 << 20)
	lines := []string{
		readyLine(10, 1),
		`{"t":2,"pid":10,"ev":"subprocess.Popen","act":"block","args":"('cmd',)"}`,
		`{"t":3,"pid":10,"ev":"socket.connect","act":"block","args":"x"}`,
		`{"t":4,"pid":10,"ev":"exec","act":"log","args":"<string>"}`,
		`{"t":5,"pid":10,"ev":"ctypes.call_function","act":"count","n":1}`,
		`{"t":6,"pid":10,"ev":"ctypes.call_function","act":"count","n":1000}`,
		`{"t":7,"pid":10,"ev":"ctypes.call_function","act":"count","n":7}`, // 子进程自己从 1 数，取最大
	}
	for _, s := range lines {
		if _, err := l.Add([]byte(s)); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	s := l.Summary(10)
	if !s.Ready || s.Blocked != 2 || s.Truncated {
		t.Fatalf("%+v", s)
	}
	if s.ByEvent["subprocess.Popen"] != 1 || s.ByEvent["socket.connect"] != 1 || s.ByEvent["exec"] != 1 || s.ByEvent["ctypes.call_function"] != 1000 {
		t.Fatalf("by_event: %v", s.ByEvent)
	}
	if s.Logged != 1001 {
		t.Fatalf("logged = %d", s.Logged)
	}
	if got := strings.Count(string(l.Bytes()), "\n"); got != len(lines) {
		t.Fatalf("原文要一行一条: %d", got)
	}
	if l.Summary(11).Ready {
		t.Fatal("主进程 pid 不对就不算就绪")
	}
}

func TestLogRejectsMalformedRecords(t *testing.T) {
	for _, bad := range []string{
		"not json",
		`{"pid":1}`,                        // 没有 ev
		`{"ev":"x","act":"block"}`,         // 没有 pid
		`{"ev":"x","pid":1,"act":"allow"}`, // 不认识的 act
		`{"ev":"x","pid":1}`,               // 只有 ready 可以没有 act
		`[1,2]`,
		`{"ev":"` + strings.Repeat("a", maxRecord) + `","pid":1,"act":"log"}`,
	} {
		if _, err := NewLog(1 << 20).Add([]byte(bad)); err == nil {
			t.Fatalf("%.60s 应该算坏记录（篡改）", bad)
		}
	}
}

func TestLogTruncatesButKeepsCounting(t *testing.T) {
	line := `{"t":1,"pid":10,"ev":"socket.connect","act":"block","args":"` + strings.Repeat("x", 100) + `"}`
	l := NewLog(500)
	for i := 0; i < 20; i++ {
		if _, err := l.Add([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	s := l.Summary(10)
	if !s.Truncated || s.Blocked != 20 || len(l.Bytes()) > 500 {
		t.Fatalf("超上限只计数、标 truncated: %+v，%d 字节", s, len(l.Bytes()))
	}
	if !strings.HasSuffix(string(l.Bytes()), "\n") {
		t.Fatal("截断要按整条截")
	}
}

type conn struct {
	w *io.PipeWriter
	r *io.PipeReader
}

func newConn() conn { r, w := io.Pipe(); return conn{w, r} }

func (c conn) send(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(c.w, s+"\n"); err != nil {
		t.Fatal(err)
	}
}

func expectAbort(t *testing.T, w *watcher, want string, within time.Duration) {
	t.Helper()
	select {
	case got := <-w.Abort():
		if got != want {
			t.Fatalf("中止原因 %q，要的是 %q", got, want)
		}
	case <-time.After(within):
		t.Fatalf("%s 内没中止（要 %q）", within, want)
	}
}

func expectNoAbort(t *testing.T, w *watcher, d time.Duration) {
	t.Helper()
	select {
	case got := <-w.Abort():
		t.Fatalf("不该中止: %q", got)
	case <-time.After(d):
	}
}

func TestWatcherNoReadyInTime(t *testing.T) {
	w := newWatcher(NewLog(1<<20), 100*time.Millisecond, time.Second, testJobDir)
	defer w.Stop()
	w.Start(10)
	expectAbort(t, w, AbortNoReady, 2*time.Second)
}

func TestWatcherReadyFromMainOnly(t *testing.T) {
	w := newWatcher(NewLog(1<<20), 150*time.Millisecond, time.Second, testJobDir)
	defer w.Stop()
	c := newConn()
	go w.Serve(c.r)
	w.Start(10)
	c.send(t, readyLine(11, 10)) // 子进程的就绪不算主进程的
	expectAbort(t, w, AbortNoReady, 2*time.Second)
}

func TestWatcherHappyPathAndChildDisconnect(t *testing.T) {
	l := NewLog(1 << 20)
	w := newWatcher(l, 100*time.Millisecond, 100*time.Millisecond, testJobDir)
	defer w.Stop()
	main, child := newConn(), newConn()
	go w.Serve(main.r)
	go w.Serve(child.r)
	main.send(t, readyLine(10, 1)) // 主进程 pid 还没告诉 watcher 之前就连上了
	w.Start(10)
	child.send(t, readyLine(11, 10))
	child.send(t, `{"t":2,"pid":11,"ev":"socket.connect","act":"block","args":"x"}`)
	child.w.Close() // 子进程退出：正常
	expectNoAbort(t, w, 400*time.Millisecond)
	if s := l.Summary(10); !s.Ready || s.Blocked != 1 {
		t.Fatalf("%+v", s)
	}
	if !l.ChildReady(10) {
		t.Fatal("子进程（ppid = 主进程）发了就绪")
	}
}

func TestWatcherMainDisconnectWhileRunning(t *testing.T) {
	w := newWatcher(NewLog(1<<20), time.Second, 100*time.Millisecond, testJobDir)
	defer w.Stop()
	main := newConn()
	go w.Serve(main.r)
	w.Start(10)
	main.send(t, readyLine(10, 1))
	main.w.Close() // 主进程把管道关了，进程还在跑
	expectAbort(t, w, AbortAudit, 2*time.Second)
}

func TestWatcherMainDisconnectAtExitIsFine(t *testing.T) {
	// 进程退出时管道跟着断：宽限期内 Stop（Run 已经返回）就不算篡改
	w := newWatcher(NewLog(1<<20), time.Second, 300*time.Millisecond, testJobDir)
	main := newConn()
	go w.Serve(main.r)
	w.Start(10)
	main.send(t, readyLine(10, 1))
	main.w.Close()
	time.Sleep(50 * time.Millisecond)
	w.Stop()
	expectNoAbort(t, w, 500*time.Millisecond)
}

func TestWatcherMalformedIsTamper(t *testing.T) {
	for _, first := range []string{"garbage", `{"t":1,"pid":10,"ev":"exec","act":"log"}`} { // 第一条必须是就绪
		w := newWatcher(NewLog(1<<20), time.Second, time.Second, testJobDir)
		c := newConn()
		go w.Serve(c.r)
		w.Start(10)
		go io.WriteString(c.w, first+"\n")
		expectAbort(t, w, AbortAudit, 2*time.Second)
		w.Stop()
	}
}

func TestWatcherStopWithoutStart(t *testing.T) {
	w := newWatcher(NewLog(1<<20), time.Second, time.Second, testJobDir)
	w.Stop() // 起不来的时候：不阻塞、不中止
	w.Stop()
	expectNoAbort(t, w, 100*time.Millisecond)
}

func TestWatcherReadyJobDirMustMatch(t *testing.T) {
	// 子进程的 EPSILON_JOB_DIR 被换掉（_winapi.CreateProcess 自带环境块）：它的钩子按别的目录判，当篡改
	w := newWatcher(NewLog(1<<20), time.Second, time.Second, testJobDir)
	defer w.Stop()
	main, child := newConn(), newConn()
	go w.Serve(main.r)
	go w.Serve(child.r)
	w.Start(10)
	main.send(t, readyLine(10, 1))
	child.send(t, readyLineDir(11, 10, `D:\\epsilon\\jobs\\demo-1\\tmp`))
	expectAbort(t, w, AbortAudit, 2*time.Second)

	w = newWatcher(NewLog(1<<20), time.Second, time.Second, testJobDir)
	defer w.Stop()
	c := newConn()
	go w.Serve(c.r)
	w.Start(10)
	c.send(t, readyLineDir(10, 1, `d:/EPSILON/jobs/demo-1/`)) // 大小写、/ 和结尾的分隔符不算不同
	expectNoAbort(t, w, 300*time.Millisecond)
}
