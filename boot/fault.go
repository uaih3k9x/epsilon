package boot

// 断电注入的缝（设计书 11.12 "断电模拟"）。boot 的每个写盘点都走这里的小包装；
// faultHook 在生产里永远是 nil，包装直接调 os.*，行为不变。只有测试会给它赋值。

import (
	"errors"
	"os"
)

// faultHook 在每个写盘动作之前被调用；返回非 nil 就让这个动作失败（不执行）。
// op 是 create / write / sync / rename / remove / openfile，path 是被写的文件（rename 是原路径）。
var faultHook func(op, path string) error

// errTorn 被 hook 返回的错误包着时，fsWrite 先写进一半再报错，模拟写到一半断电。
var errTorn = errors.New("撕裂写")

func fault(op, path string) error {
	if faultHook == nil {
		return nil
	}
	return faultHook(op, path)
}

func fsCreate(name string) (*os.File, error) {
	if err := fault("create", name); err != nil {
		return nil, err
	}
	return os.Create(name)
}

func fsOpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if err := fault("openfile", name); err != nil {
		return nil, err
	}
	return os.OpenFile(name, flag, perm)
}

func fsWrite(f *os.File, b []byte) (int, error) {
	if err := fault("write", f.Name()); err != nil {
		if errors.Is(err, errTorn) {
			n, _ := f.Write(b[:len(b)/2])
			return n, err
		}
		return 0, err
	}
	return f.Write(b)
}

func fsSync(f *os.File) error {
	if err := fault("sync", f.Name()); err != nil {
		return err
	}
	return f.Sync()
}

func fsRename(oldpath, newpath string) error {
	if err := fault("rename", oldpath); err != nil {
		return err
	}
	return os.Rename(oldpath, newpath)
}

func fsRemove(name string) error {
	if err := fault("remove", name); err != nil {
		return err
	}
	return os.Remove(name)
}
