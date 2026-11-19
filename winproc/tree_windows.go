package winproc

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	ntdll              = syscall.NewLazyDLL("ntdll.dll")
	ntResumeProcess    = ntdll.NewProc("NtResumeProcess")
	terminateJobObject = kernel32job.NewProc("TerminateJobObject")
	getExitCodeProcess = kernel32job.NewProc("GetExitCodeProcess")
)

const (
	createSuspended          = 0x00000004
	createNoWindow           = 0x08000000
	processTerminate         = 0x0001
	processSetQuota          = 0x0100
	processSuspendResume     = 0x0800
	processQueryLimitedInfo  = 0x1000
	jobObjectKillOnJobClose  = 0x2000
	jobObjectExtendedLimitIn = 9
	stillActive              = 259
)

// Tree 是一棵进程树：Windows 上是作业对象，其他系统上是进程组。
// 每个批任务一个作业对象：结束、超时、撤销时 TerminateJobObject 整棵杀；探针自己死了句柄关闭，Windows 也会杀掉整棵。
type Tree struct{ job syscall.Handle }

// StartTree 以挂起方式启动 cmd，放进新建的作业对象后再恢复运行，所以它起的每个子进程都逃不出这棵树。
func StartTree(cmd *exec.Cmd) (*Tree, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createSuspended | createNoWindow
	h, _, _ := createJobObject.Call(0, 0)
	if h == 0 {
		return nil, errors.New("CreateJobObject 失败")
	}
	t := &Tree{job: syscall.Handle(h)}
	var lim jobLimits
	lim.LimitFlags = jobObjectKillOnJobClose
	if r, _, err := setInformationJobObject.Call(h, jobObjectExtendedLimitIn, uintptr(unsafe.Pointer(&lim)), unsafe.Sizeof(lim)); r == 0 {
		syscall.CloseHandle(t.job)
		return nil, fmt.Errorf("SetInformationJobObject: %v", err)
	}
	if err := cmd.Start(); err != nil {
		syscall.CloseHandle(t.job)
		return nil, err
	}
	fail := func(what string, err error) (*Tree, error) {
		cmd.Process.Kill() // 还挂着，没跑过一行
		syscall.CloseHandle(t.job)
		return nil, fmt.Errorf("%s: %v", what, err)
	}
	p, _, err := openProcess.Call(processTerminate|processSetQuota|processSuspendResume, 0, uintptr(cmd.Process.Pid))
	if p == 0 {
		return fail("OpenProcess", err)
	}
	defer syscall.CloseHandle(syscall.Handle(p))
	if r, _, err := assignProcessToJobObject.Call(h, p); r == 0 {
		return fail("AssignProcessToJobObject", err)
	}
	if r, _, _ := ntResumeProcess.Call(p); r != 0 { // NTSTATUS，0 = 成功
		return fail("NtResumeProcess", fmt.Errorf("status 0x%x", r))
	}
	return t, nil
}

// Kill 杀掉整棵树。可以重复调。
func (t *Tree) Kill() {
	if t.job != 0 {
		terminateJobObject.Call(uintptr(t.job), 1)
	}
}

// Close 在主进程结束后调：杀掉树里剩下的进程，释放作业对象。
func (t *Tree) Close() {
	if t.job != 0 {
		t.Kill()
		syscall.CloseHandle(t.job)
		t.job = 0
	}
}

// Alive 判断进程还在不在（测试用）。
func Alive(pid int) bool {
	p, _, _ := openProcess.Call(processQueryLimitedInfo, 0, uintptr(pid))
	if p == 0 {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(p))
	var code uint32
	r, _, _ := getExitCodeProcess.Call(p, uintptr(unsafe.Pointer(&code)))
	return r != 0 && code == stillActive
}
