package winproc

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// Hide: 工作负载不弹黑框，免得学生看见。
func Hide(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

var (
	kernel32job              = syscall.NewLazyDLL("kernel32.dll")
	createJobObject          = kernel32job.NewProc("CreateJobObjectW")
	setInformationJobObject  = kernel32job.NewProc("SetInformationJobObject")
	assignProcessToJobObject = kernel32job.NewProc("AssignProcessToJobObject")
	openProcess              = kernel32job.NewProc("OpenProcess")
	jobHandle                uintptr // 探针活着就一直攥着；探针一退出句柄关闭，Windows 杀掉作业里的所有进程
)

// JOBOBJECT_EXTENDED_LIMIT_INFORMATION（amd64 布局）
type jobLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
	IoInfo                  [6]uint64
	ProcessMemoryLimit      uintptr
	JobMemoryLimit          uintptr
	PeakProcessMemoryUsed   uintptr
	PeakJobMemoryUsed       uintptr
}

// Bind 把工作负载放进"探针退出就一起退出"的作业里，免得探针被杀后 llama-server 成孤儿占着端口和显存。
func Bind(pid int) {
	if jobHandle == 0 {
		h, _, _ := createJobObject.Call(0, 0)
		if h == 0 {
			return
		}
		var lim jobLimits
		lim.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if r, _, _ := setInformationJobObject.Call(h, 9, uintptr(unsafe.Pointer(&lim)), unsafe.Sizeof(lim)); r == 0 {
			syscall.CloseHandle(syscall.Handle(h))
			return
		}
		jobHandle = h
	}
	p, _, _ := openProcess.Call(0x0001|0x0100, 0, uintptr(pid)) // PROCESS_TERMINATE | PROCESS_SET_QUOTA
	if p == 0 {
		return
	}
	assignProcessToJobObject.Call(jobHandle, p)
	syscall.CloseHandle(syscall.Handle(p))
}
