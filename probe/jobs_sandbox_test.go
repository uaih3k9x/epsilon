package probe

// 探针和沙箱（jobbox）接在一起的部分：联网任务直接拒、沙箱拒了记 rejected、停接任务时心跳报 jobs:false、
// 审计汇总进运行摘要、运行中审计管道断开记 failed 照常回传。沙箱本身的测试在 jobbox/。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"epsilon/jobbox"
	"epsilon/jobsign"
	"epsilon/proto"
)

func TestJobE2ENetworkTaskRejected(t *testing.T) {
	e := newE2E(t, 30)
	ring := e.f.Ring
	ring.Keys[0].Limits.Network = true // 钥匙有联网权限也不跑：任务账户的出站全部拦掉
	e.f.WriteKeyring(t, ring)
	e.probe("pc-01", nil)
	pkg := e.pkg("net", "ok", func(j *jobsign.Job) { j.Network = true })
	id := e.submit(map[string]any{"package": pkg})[0]
	expectRejected(t, e.wait(id), "联网任务这一版不跑")
}

func TestJobE2ESandboxRejectIsRejected(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", func(a *Agent) {
		a.JobBox = &passBox{reject: "系统控制金丝雀不符: write_programdata（写进去了）"}
	})
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	expectRejected(t, e.wait(id), "write_programdata")
}

func TestJobE2ENoSandboxNoJobs(t *testing.T) {
	e := newE2E(t, 30)
	p := e.probe("pc-01", func(a *Agent) { a.JobBox = nil })
	if p.a.jobsOK() {
		t.Fatal("没有沙箱就不能报 jobs:true")
	}
	j := &jobRun{assign: proto.JobAssign{ID: "x-1", Attempt: 1}}
	if st := p.a.runJob(t.Context(), j); st.State != proto.JobRejected || !strings.Contains(st.Detail, "沙箱") {
		t.Fatalf("没有沙箱要拒: %+v", st)
	}
}

func TestJobE2EHaltedSandboxGetsNoJobs(t *testing.T) {
	e := newE2E(t, 30)
	box := &passBox{halt: "健康检查不过，重跑 install.ps1（开沙箱）: 找不到账户"}
	p := e.probe("pc-01", func(a *Agent) { a.JobBox = box })
	if p.a.jobsOK() {
		t.Fatal("停接任务时心跳要报 jobs:false")
	}
	time.Sleep(300 * time.Millisecond)
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	time.Sleep(500 * time.Millisecond)
	if v := e.job(id); v.State != "queued" {
		t.Fatalf("停接任务的机器不该派到: %+v", v)
	}
	box.set(func(b *passBox) { b.halt = "" })
	if v := e.wait(id); v.State != proto.JobSucceeded {
		t.Fatalf("恢复后照常跑: %+v", v)
	}
}

func TestJobE2EAuditGoesIntoSummary(t *testing.T) {
	e := newE2E(t, 30)
	box := &passBox{audit: jobbox.Summary{Ready: true, Blocked: 2, Logged: 5, ByEvent: map[string]int{"socket.connect": 2}},
		auditLog: []byte(`{"t":1,"pid":9,"ev":"socket.connect","act":"block","args":"x"}` + "\n")}
	e.probe("pc-01", func(a *Agent) { a.JobBox = box })
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	v := e.wait(id)
	if v.State != proto.JobSucceeded {
		t.Fatalf("有拦截不自动判失败（交给人复查）: %+v", v)
	}
	_, files := e.output(id)
	var sum struct {
		Audit jobbox.Summary `json:"audit"`
	}
	json.Unmarshal(files["_runner/summary.json"], &sum)
	if sum.Audit.Blocked != 2 || sum.Audit.ByEvent["socket.connect"] != 2 || !sum.Audit.Ready {
		t.Fatalf("summary.json 要带审计汇总: %s", files["_runner/summary.json"])
	}
	if !strings.Contains(string(files["_runner/audit.log"]), "socket.connect") {
		t.Fatalf("audit.log 要随输出回传: %q", files["_runner/audit.log"])
	}
	waitFor(t, "结束事件标出有拦截", func() bool {
		_, b := e.api("GET", "/v1/events?kind=job", nil)
		return strings.Contains(string(b), "有拦截 2 次")
	})
}

func TestJobE2EAuditBrokenIsFailedAndUploaded(t *testing.T) {
	e := newE2E(t, 30)
	e.probe("pc-01", func(a *Agent) { a.JobBox = &passBox{killed: jobbox.AbortAudit} })
	id := e.submit(map[string]any{"package": e.pkg("demo", "ok", nil)})[0]
	v := e.wait(id)
	if v.State != proto.JobFailed || !strings.Contains(v.Detail, "审计管道") || !v.Output {
		t.Fatalf("运行中审计管道断开：failed、照常回传供复查: %+v", v)
	}
}

func TestRefreshBoxEveryTenMinutes(t *testing.T) {
	box := &passBox{}
	a := NewAgent(Config{Jobs: true, ArtifactRoot: t.TempDir()}, &fakeSys{}, "t")
	defer a.Shutdown()
	a.JobBox = box
	now := time.Now()
	for _, at := range []time.Duration{0, time.Minute, boxRefresh, boxRefresh + time.Second, 2 * boxRefresh} {
		a.refreshBox(now.Add(at))
		waitFor(t, "后台查完", func() bool { return !a.boxBusy.Load() })
	}
	box.mu.Lock()
	n := box.checks
	box.mu.Unlock()
	if n != 3 {
		t.Fatalf("第一次立刻查，之后每 10 分钟一次: 查了 %d 次", n)
	}
	off := NewAgent(Config{Jobs: false}, &fakeSys{}, "t")
	defer off.Shutdown()
	off.JobBox = box
	off.refreshBox(now)
	if off.boxBusy.Load() || off.jobsOK() {
		t.Fatal("没开能力 32 就不查、不报")
	}
}

func TestSandboxConfig(t *testing.T) {
	for in, want := range map[string]string{
		"http://ctl.example:8090":   "ctl.example:8090",
		"http://ctl.example/":       "ctl.example:80",
		"https://ctl.example":       "ctl.example:443",
		"http://[2001:db8::1]:8090": "[2001:db8::1]:8090",
	} {
		c, err := SandboxConfig(Config{Controller: in, ArtifactRoot: "D:/epsilon"})
		if err != nil || c.Controller != want || c.Root != "D:/epsilon" {
			t.Fatalf("%s: %+v %v", in, c, err)
		}
	}
	if _, err := SandboxConfig(Config{Controller: "::bad"}); err == nil {
		t.Fatal("主控地址不对要报错")
	}
}
