//go:build !windows

// Package winproc: 子进程不弹窗、随父进程一起退出（Windows 作业对象）；其他系统上是空操作。
// 批任务的进程树（Tree）在其他系统上用进程组代替作业对象，供本机测试。
package winproc

import (
	"os/exec"
	"syscall"
)

func Hide(*exec.Cmd) {}

func Bind(int) {}

// Tree 是一棵进程树：Windows 上是作业对象，其他系统上是进程组。
type Tree struct{ pgid int }

// StartTree 启动 cmd，并让它和它以后起的所有子进程都在同一棵树里。
func StartTree(cmd *exec.Cmd) (*Tree, error) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Tree{pgid: cmd.Process.Pid}, nil
}

// Kill 杀掉整棵树。可以重复调。
func (t *Tree) Kill() { syscall.Kill(-t.pgid, syscall.SIGKILL) }

// Close 在主进程结束后调：杀掉树里剩下的进程，释放句柄。
func (t *Tree) Close() { t.Kill() }

// Alive 判断进程还在不在（测试用）。
func Alive(pid int) bool { return syscall.Kill(pid, 0) == nil }
