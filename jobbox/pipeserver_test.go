package jobbox

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakePipe 是假的命名管道系统调用：记着哪些句柄还开着；connect 挂着直到有客户端（dial）或者 wake。
type fakePipe struct {
	mu       sync.Mutex
	nextH    uintptr
	open     map[uintptr]bool
	pending  map[uintptr]chan struct{} // 挂着的 connect
	queued   map[uintptr]bool          // 客户端已经连上了还没 connect 的实例（connect 马上返回 ERROR_PIPE_CONNECTED）
	released bool
}

func newFakePipe() *fakePipe {
	return &fakePipe{open: map[uintptr]bool{}, pending: map[uintptr]chan struct{}{}, queued: map[uintptr]bool{}}
}

func (f *fakePipe) create(first bool) (uintptr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if first && len(f.open) > 0 {
		return 0, errors.New("FILE_FLAG_FIRST_PIPE_INSTANCE: 管道名被占着")
	}
	f.nextH++
	f.open[f.nextH] = true
	return f.nextH, nil
}

func (f *fakePipe) connect(h uintptr) error {
	f.mu.Lock()
	if f.queued[h] {
		delete(f.queued, h)
		f.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	f.pending[h] = ch
	f.mu.Unlock()
	<-ch
	return nil
}

// dial 模拟一个客户端连到最新的实例上（真管道：连到任何一个在听的实例）。
func (f *fakePipe) dial() {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.nextH
	if !f.open[h] {
		return
	}
	if ch, ok := f.pending[h]; ok {
		delete(f.pending, h)
		close(ch)
		return
	}
	f.queued[h] = true
}

func (f *fakePipe) wake() { f.dial() }

func (f *fakePipe) closeHandle(h uintptr) {
	f.mu.Lock()
	delete(f.open, h)
	f.mu.Unlock()
}

func (f *fakePipe) conn(h uintptr) io.ReadCloser { return fakePipeConn{f, h} }

func (f *fakePipe) release() {
	f.mu.Lock()
	f.released = true
	f.mu.Unlock()
}

func (f *fakePipe) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.open)
}

type fakePipeConn struct {
	f *fakePipe
	h uintptr
}

func (c fakePipeConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c fakePipeConn) Close() error             { c.f.closeHandle(c.h); return nil }

func TestPipeCloseBetweenAcceptsDoesNotLeakInstance(t *testing.T) {
	// 审查 #17 第 6 条：Close 正好落在"上一次 Accept 刚返回、下一次还没进去"的空档，自连连到了 s.next 上；
	// 下一次 Accept 走 closed 分支直接返回，没人关它，管道名一直被占着，下一个任务建不了审计管道、本机停接
	f := newFakePipe()
	s, err := newPipeServer(f)
	if err != nil {
		t.Fatal(err)
	}
	f.dial()
	c, err := s.Accept()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := s.Accept(); err == nil {
		t.Fatal("关了以后 Accept 要报错")
	}
	c.Close()
	if n := f.openCount(); n != 0 {
		t.Fatalf("还开着 %d 个实例", n)
	}
	if _, err := newPipeServer(f); err != nil {
		t.Fatalf("下一个任务要建得出审计管道: %v", err)
	}
}

func TestPipeCloseWakesPendingAccept(t *testing.T) {
	f := newFakePipe()
	s, _ := newPipeServer(f)
	done := make(chan error, 1)
	go func() { _, err := s.Accept(); done <- err }()
	time.Sleep(20 * time.Millisecond)
	s.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close 叫醒的那次 Accept 要报错，不能当成一个连接")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close 没叫醒挂着的 Accept")
	}
	if n := f.openCount(); n != 0 || !f.released {
		t.Fatalf("还开着 %d 个实例，released=%v", n, f.released)
	}
}

func TestPipeServesSeveralClients(t *testing.T) {
	f := newFakePipe()
	s, _ := newPipeServer(f)
	var conns []io.ReadCloser
	for i := 0; i < 3; i++ {
		f.dial()
		c, err := s.Accept()
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	s.Close()
	s.Accept()
	for _, c := range conns {
		c.Close()
	}
	if n := f.openCount(); n != 0 {
		t.Fatalf("还开着 %d 个实例", n)
	}
}
