//go:build !windows

package probe

// 非 Windows（开发机）上拿不到键鼠空闲，按"不知道"处理，不会因此让位。
func idleSeconds() int { return -1 }
func memFreeMB() int   { return 0 }
