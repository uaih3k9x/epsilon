//go:build !windows

package joboutput

import (
	"fmt"
	"os"
	"syscall"
)

// openRegular 打开一个要回传的文件：不跟链接，链接数必须是 1（硬链接和原文件是同一个对象）。
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); !ok || !st.Mode().IsRegular() || uint64(sys.Nlink) != 1 {
			err = fmt.Errorf("不是只有一个链接的普通文件（硬链接不回传）")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
