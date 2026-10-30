//go:build !windows

// Package winproc: 子进程不弹窗、随父进程一起退出（Windows 作业对象）；其他系统上是空操作。
package winproc

import "os/exec"

func Hide(*exec.Cmd) {}

func Bind(int) {}
