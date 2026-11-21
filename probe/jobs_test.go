package probe

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"epsilon/jobrun"
	"epsilon/jobsign"
	"epsilon/proto"
)

func TestKeyringNotServedLoggedOnce(t *testing.T) {
	// 主控没配批任务：/v1/job-keyring 是 404。能力 33 默认开，但不能每 10 分钟报一次错
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	a := NewAgent(Config{Controller: srv.URL, ArtifactRoot: t.TempDir()}, &fakeSys{}, "t")
	defer a.Shutdown()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	now := time.Now()
	for i := 0; i < 3; i++ {
		a.refreshKeyring(now.Add(time.Duration(i) * keyringRefresh))
		waitFor(t, "后台拉完", func() bool { return !a.krBusy.Load() })
	}
	n := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "job-keyring") {
			n++
		}
	}
	if n > 1 {
		t.Fatalf("404 最多记一次，记了 %d 次:\n%s", n, buf.String())
	}
}

func TestWriteSummaryReportsErrors(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "output"), []byte("不是目录"), 0o644)
	a := NewAgent(Config{}, &fakeSys{}, "t")
	err := a.writeSummary(dir, proto.JobAssign{ID: "x-1", Attempt: 1}, jobsign.Job{}, "k", "d", nil, jobrun.Result{})
	if err == nil {
		t.Fatal("摘要写不进去要报错（不能悄悄回传没有摘要的输出）")
	}

}

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
