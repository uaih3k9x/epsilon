package boot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 断电注入的公共设施（boot/fault.go 那道缝的测试端）。
//
// faultHook 是包级变量，测试一开始（TestMain）就装上一个分发器，之后不再改它，免得和
// 正在跑的 Boot 抢着读写。每个用例按自己的 Root 登记一个 hook，分发器按路径前缀找；
// 没登记的目录（现有测试）原样放行，和生产里 hook 为 nil 一样。
var faultRoots sync.Map // root(带结尾分隔符) -> func(op, path string) error

func TestMain(m *testing.M) {
	faultHook = func(op, path string) error {
		var h func(op, path string) error
		faultRoots.Range(func(k, v any) bool {
			if strings.HasPrefix(path, k.(string)) {
				h = v.(func(op, path string) error)
				return false
			}
			return true
		})
		if h == nil {
			return nil
		}
		return h(op, path)
	}
	os.Exit(m.Run())
}

// onFault 给 root 下的写盘点登记 hook，测试结束自动注销。
func onFault(t *testing.T, root string, h func(op, path string) error) {
	t.Helper()
	key := filepath.Clean(root) + string(filepath.Separator)
	faultRoots.Store(key, h)
	t.Cleanup(func() { faultRoots.Delete(key) })
}

var errPowerCut = errors.New("断电（注入）")

func TestFaultPassThrough(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	if err := writeAtomic(p, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != "hello" {
		t.Fatalf("%q", got)
	}
	if err := appendLine(p, []byte("l")); err != nil {
		t.Fatal(err)
	}
	if err := fsRemove(p); err != nil {
		t.Fatal(err)
	}
}

func TestFaultOps(t *testing.T) {
	dir := t.TempDir()
	var ops []string
	onFault(t, dir, func(op, path string) error {
		rel, _ := filepath.Rel(dir, path)
		ops = append(ops, op+" "+rel)
		return nil
	})
	p := filepath.Join(dir, "s")
	if err := writeAtomic(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := appendLine(filepath.Join(dir, "e"), []byte("y")); err != nil {
		t.Fatal(err)
	}
	fsRemove(p)
	want := "create s.tmp,write s.tmp,sync s.tmp,rename s.tmp,openfile e,write e,sync e,remove s"
	if got := strings.Join(ops, ","); got != want {
		t.Fatalf("写盘点\n got %s\nwant %s", got, want)
	}
}

func TestFaultFailsOp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	write(t, p, "old")
	onFault(t, dir, func(op, path string) error {
		if op == "rename" {
			return errPowerCut
		}
		return nil
	})
	if err := writeAtomic(p, []byte("new")); !errors.Is(err, errPowerCut) {
		t.Fatalf("err %v", err)
	}
	if got := readFile(t, p); got != "old" {
		t.Fatalf("改名失败了目标还是被改了: %q", got)
	}
}

// 撕裂写：hook 返回包着 errTorn 的错误时，只写进前一半就报错。
func TestFaultTornWrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "e")
	write(t, p, "a\n")
	onFault(t, dir, func(op, path string) error {
		if op == "write" {
			return errors.Join(errPowerCut, errTorn)
		}
		return nil
	})
	if err := appendLine(p, []byte("0123456789")); !errors.Is(err, errPowerCut) {
		t.Fatalf("err %v", err)
	}
	if got := readFile(t, p); got != "a\n01234" { // 一共 11 字节（带换行），写进一半 5 字节
		t.Fatalf("%q", got)
	}
}
