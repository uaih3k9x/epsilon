//go:build !windows

package probe

import "syscall"

// 非 Windows（开发机）上拿不到键鼠空闲，按"不知道"处理，不会因此让位。
func idleSeconds() int { return -1 }
func memFreeMB() int   { return 0 }

func diskMB(path string) (total, free int64) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0, 0
	}
	bs := int64(st.Bsize)
	return int64(st.Blocks) * bs >> 20, int64(st.Bavail) * bs >> 20
}
