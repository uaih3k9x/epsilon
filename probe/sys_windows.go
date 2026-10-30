package probe

import (
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	getLastInputInfo     = user32.NewProc("GetLastInputInfo")
	getTickCount         = kernel32.NewProc("GetTickCount")
	globalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// idleSeconds: GetLastInputInfo 只在用户会话里有效；探针以服务身份跑在会话 0 时拿到的不对，
// v0.1 由登录后的启动项运行，和学生在同一个会话里。
func idleSeconds() int {
	var info struct {
		cbSize uint32
		dwTime uint32
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, _ := getLastInputInfo.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return -1
	}
	now, _, _ := getTickCount.Call()
	return int((uint32(now) - info.dwTime) / 1000) // uint32 相减，49 天回绕也对
}

func memFreeMB() int {
	var m struct {
		dwLength                uint32
		dwMemoryLoad            uint32
		ullTotalPhys            uint64
		ullAvailPhys            uint64
		ullTotalPageFile        uint64
		ullAvailPageFile        uint64
		ullTotalVirtual         uint64
		ullAvailVirtual         uint64
		ullAvailExtendedVirtual uint64
	}
	m.dwLength = uint32(unsafe.Sizeof(m))
	if r, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 0
	}
	return int(m.ullAvailPhys >> 20)
}
