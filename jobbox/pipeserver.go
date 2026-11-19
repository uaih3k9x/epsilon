package jobbox

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// pipeOps 是审计管道服务端用到的系统调用。Windows 实现在 platform_windows.go（winPipeOps），
// 测试用假的（pipeserver_test.go）：实例怎么建、怎么关的逻辑在这里，Mac 上测得到。
type pipeOps interface {
	create(first bool) (uintptr, error) // CreateNamedPipeW；first 带 FILE_FLAG_FIRST_PIPE_INSTANCE（被人抢注就建不出来）
	connect(h uintptr) error            // ConnectNamedPipe；客户端已经连上（ERROR_PIPE_CONNECTED）算成功
	wake()                              // 自己当客户端连一下，叫醒挂着的 connect
	closeHandle(h uintptr)
	conn(h uintptr) io.ReadCloser // 连上的实例交给读的一方，之后由它关
	release()                     // Close 以后释放安全描述符
}

// pipeServer 一次接一个连接；每接一个就先建好下一个实例（子进程连得上）。
type pipeServer struct {
	ops    pipeOps
	mu     sync.Mutex
	next   uintptr
	closed bool
}

func newPipeServer(ops pipeOps) (*pipeServer, error) {
	h, err := ops.create(true)
	if err != nil {
		return nil, err
	}
	return &pipeServer{ops: ops, next: h}, nil
}

func (s *pipeServer) Accept() (io.ReadCloser, error) {
	s.mu.Lock()
	h, closed := s.next, s.closed
	if closed && h != 0 {
		// Close 落在两次 Accept 之间：它的自连连到了这个实例上。不关的话管道名一直被占着，
		// 下一个任务 FILE_FLAG_FIRST_PIPE_INSTANCE 建不出来，本机停接（审查 #17 第 6 条）
		s.ops.closeHandle(h)
		s.next = 0
	}
	s.mu.Unlock()
	if closed || h == 0 {
		return nil, errors.New("审计管道已关")
	}
	if err := s.ops.connect(h); err != nil {
		s.mu.Lock()
		s.next = 0
		s.mu.Unlock()
		s.ops.closeHandle(h)
		return nil, fmt.Errorf("ConnectNamedPipe: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed { // Close 自己连上来叫醒的
		s.next = 0
		s.ops.closeHandle(h)
		return nil, errors.New("审计管道已关")
	}
	if next, err := s.ops.create(false); err != nil {
		s.next = 0
	} else {
		s.next = next
	}
	return s.ops.conn(h), nil
}

func (s *pipeServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.ops.wake() // ConnectNamedPipe 阻塞着：自己当客户端连一下把它叫醒
	s.ops.release()
	return nil
}
