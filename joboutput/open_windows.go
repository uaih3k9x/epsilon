//go:build windows

package joboutput

import (
	"fmt"
	"os"
	"syscall"
)

const (
	fileFlagOpenReparsePoint = 0x00200000
	fileAttributeReparse     = 0x400
)

// openRegular 打开一个要回传的文件：FILE_FLAG_OPEN_REPARSE_POINT 不跟重解析点，
// 是重解析点、或者链接数不是 1（硬链接和原文件是同一个对象，比如任务链到 probe.json）就拒。
// 在同一个句柄上检查和读，中间换不了。没有在真机上跑过（docs/jobs-sandbox.md 第 7 节）。
func openRegular(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, fileFlagOpenReparsePoint, 0)
	if err != nil {
		return nil, err
	}
	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &d); err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	if d.FileAttributes&(fileAttributeReparse|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 || d.NumberOfLinks != 1 {
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("不是只有一个链接的普通文件（硬链接、重解析点不回传）: 属性 0x%x 链接 %d", d.FileAttributes, d.NumberOfLinks)
	}
	return os.NewFile(uintptr(h), path), nil
}
