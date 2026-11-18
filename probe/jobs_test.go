package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyringVersionFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), keyringVersionFile)
	if v, err := readKeyringVersion(p); err != nil || v != 0 {
		t.Fatalf("没有文件 = 0: %d %v", v, err)
	}
	if err := writeKeyringVersion(p, 7); err != nil {
		t.Fatal(err)
	}
	if v, err := readKeyringVersion(p); err != nil || v != 7 {
		t.Fatalf("要读回 7: %d %v", v, err)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Fatal("临时文件没清掉")
	}
	for _, bad := range []string{"", "x", "-1", "3.5"} {
		os.WriteFile(p, []byte(bad), 0o644)
		if _, err := readKeyringVersion(p); err == nil {
			t.Errorf("%q 坏了要报错，不能当 0", bad)
		}
	}
}

func TestStrictNowTakesLaterClock(t *testing.T) {
	a := NewAgent(Config{}, &fakeSys{}, "t")
	a.noteDate("Mon, 02 Jan 2006 15:04:05 GMT") // 主控时间比本机早：不管
	if a.ctlSkew != 0 {
		t.Fatalf("主控慢了不往回拨: %v", a.ctlSkew)
	}
	a.noteDate("Mon, 02 Jan 2206 15:04:05 GMT")
	if a.ctlSkew <= 0 {
		t.Fatal("主控快了按主控算（只会多拒）")
	}
	a.noteDate("坏的")
	if a.ctlSkew <= 0 {
		t.Fatal("解析不了的 Date 不动")
	}
}
