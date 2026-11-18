package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"epsilon/jobbox"
	"epsilon/jobrun"
)

func TestParseCheckLines(t *testing.T) {
	out := "===== 2026 启动 ...\r\n" +
		"CHECK 3.low_il PASS il=0x1000\r\n" +
		"CHECK 16.privileges FAIL SeShutdownPrivilege,SeChangeNotifyPrivilege\n" +
		"CHECK 3.cuda SKIP\n" +
		"CHECK broken\n" +
		"CHECK 7.x MAYBE y\n" +
		"Traceback (most recent call last):\n" +
		"INV KEY C:\\ProgramData\\x\\a.ini\n"
	got := ParseCheckLines([]byte(out), "job")
	if len(got) != 4 {
		t.Fatalf("%+v", got)
	}
	if got[0].Item != 3 || got[0].Status != PASS || got[0].Evidence != "il=0x1000" || got[0].Source != "job" {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Item != 16 || got[1].Status != FAIL {
		t.Fatalf("%+v", got[1])
	}
	if got[2].Status != SKIP || got[2].Evidence != "" {
		t.Fatalf("%+v", got[2])
	}
	if got[3].Status != FAIL || !strings.Contains(got[3].Evidence, "MAYBE") {
		t.Fatalf("不认识的状态算 FAIL: %+v", got[3])
	}
	inv := ParseInventory([]byte(out))
	if len(inv) != 1 || inv[0] != `KEY C:\ProgramData\x\a.ini` {
		t.Fatalf("%q", inv)
	}
}

func TestExpectChecksReportsMissing(t *testing.T) {
	got := ExpectChecks([]Check{{Item: 3, ID: "3.low_il", Status: PASS}}, []string{"3.low_il", "16.privileges"}, "任务没跑完")
	if len(got) != 2 || got[1].ID != "16.privileges" || got[1].Status != FAIL || !strings.Contains(got[1].Evidence, "任务没跑完") {
		t.Fatalf("%+v", got)
	}
}

func TestJudgeCmdLines(t *testing.T) {
	c := JudgeCmdLines(map[string]int{"sys": 300, "hook": 320}, 1023)
	if c.Status != PASS || c.Item != 18 || !strings.Contains(c.Evidence, "hook=320") {
		t.Fatalf("%+v", c)
	}
	if c := JudgeCmdLines(map[string]int{"sys": 300, "task": 1024}, 1023); c.Status != FAIL || !strings.Contains(c.Evidence, "task=1024") {
		t.Fatalf("%+v", c)
	}
}

func TestJudgeSweepTimes(t *testing.T) {
	ms := func(n ...int) []time.Duration {
		var d []time.Duration
		for _, x := range n {
			d = append(d, time.Duration(x)*time.Millisecond)
		}
		return d
	}
	if c := JudgeSweepTimes("10.sweep_after_exit", ms(50, 400, 120), 3*time.Second, nil); c.Status != PASS || !strings.Contains(c.Evidence, "max 400ms") {
		t.Fatalf("%+v", c)
	}
	if c := JudgeSweepTimes("10.sweep_after_exit", ms(50, 3500), 3*time.Second, nil); c.Status != FAIL {
		t.Fatalf("超过宽限：探针会判成逃出作业、停接: %+v", c)
	}
	if c := JudgeSweepTimes("10.sweep_after_exit", nil, 3*time.Second, errors.New("WTS 5")); c.Status != FAIL || !strings.Contains(c.Evidence, "WTS 5") {
		t.Fatalf("%+v", c)
	}
}

func TestJudgeWake(t *testing.T) {
	if c := JudgeWake("11.read_wakes", true, 30*time.Millisecond, 2*time.Second); c.Status != PASS || c.Item != 11 {
		t.Fatalf("%+v", c)
	}
	// 叫不醒不会卡住探针（只是少收尾几秒），但要人记下来
	if c := JudgeWake("11.read_wakes", false, 5*time.Second, 2*time.Second); c.Status != MANUAL {
		t.Fatalf("%+v", c)
	}
	if c := JudgeWake("11.read_wakes", true, 2500*time.Millisecond, 2*time.Second); c.Status != MANUAL {
		t.Fatalf("醒得比探针等的久: %+v", c)
	}
}

func TestJudgeCreateOnly(t *testing.T) {
	if c := JudgeCreateOnly(errors.New("建窗口站 epsilon-job（已经存在也算失败）: Access is denied.")); c.Status != PASS || c.Item != 16 {
		t.Fatalf("%+v", c)
	}
	if c := JudgeCreateOnly(nil); c.Status != FAIL {
		t.Fatalf("第二个实例建出来了 = 没有 CWF_CREATE_ONLY: %+v", c)
	}
	if c := JudgeCreateOnly(errors.New("读密码文件: 5")); c.Status != FAIL {
		t.Fatalf("别的原因失败不算: %+v", c)
	}
}

func TestJudgeExit97(t *testing.T) {
	if c := JudgeExit97(97, nil); c.Status != PASS || c.Item != 6 {
		t.Fatalf("%+v", c)
	}
	if c := JudgeExit97(0, nil); c.Status != FAIL {
		t.Fatalf("连不上管道还跑完了 = 钩子没出错即退: %+v", c)
	}
	if c := JudgeExit97(-1, errors.New("起不来")); c.Status != FAIL {
		t.Fatalf("%+v", c)
	}
}

func TestJudgeTreeReset(t *testing.T) {
	if c := JudgeTreeReset(`D:\epsilon\jobs\.q-ab`, nil, nil); c.Status != PASS || c.Item != 15 || !strings.Contains(c.Evidence, "中止") {
		t.Fatalf("收回报错、改名隔离：出错即拒: %+v", c)
	}
	if c := JudgeTreeReset("", errors.New("Access is denied."), nil); c.Status != FAIL || !strings.Contains(c.Evidence, "跳过") {
		t.Fatalf("收回\"成功\"但锁住的子目录还是读不了：要加抽查: %+v", c)
	}
	if c := JudgeTreeReset("", nil, nil); c.Status != MANUAL {
		t.Fatalf("收回成功、子目录也能读了：说明锁目录没建成，看任务输出: %+v", c)
	}
	if c := JudgeTreeReset("", nil, errors.New("任务被拒")); c.Status != FAIL {
		t.Fatalf("%+v", c)
	}
}

func TestJudgeMkdir700(t *testing.T) {
	if c := JudgeMkdir700("3.11.9", "", nil); c.Status != PASS {
		t.Fatalf("%+v", c)
	}
	if c := JudgeMkdir700("3.12.4", `D:\epsilon\jobs\.q-1`, nil); c.Status != MANUAL || !strings.Contains(c.Evidence, "3.12.4") {
		t.Fatalf("文档里说的风险成真了：要人决定钩子是不是改成拦: %+v", c)
	}
	if c := JudgeMkdir700("", "", errors.New("x")); c.Status != FAIL {
		t.Fatalf("%+v", c)
	}
}

func TestJudgeRun(t *testing.T) {
	log := `{"t":1,"pid":10,"ev":"ready","il":"low","job_dir":"D:\\j","file":"D:\\e\\sitecustomize.py"}` + "\n" +
		`{"t":2,"pid":10,"ev":"socket.connect","act":"block","args":"('192.0.2.1', 9)"}` + "\n"
	res := jobbox.Result{Result: jobrun.Result{ExitCode: 0, Seconds: 12.5}, Audit: jobbox.Summary{Ready: true, Blocked: 1}, AuditLog: []byte(log)}
	got := JudgeRun(3, "task", res, nil)
	by := map[string]Check{}
	for _, c := range got {
		by[c.ID] = c
	}
	if c := by["3.task.run"]; c.Status != PASS {
		t.Fatalf("%+v", got)
	}
	if c := by["3.task.ready"]; c.Status != PASS || !strings.Contains(c.Evidence, "il=low") {
		t.Fatalf("%+v", c)
	}
	if c := by["7.task.blocks"]; c.Status != MANUAL || !strings.Contains(c.Evidence, "socket.connect") {
		t.Fatalf("测试任务不做被拦的事：有拦截要人看是不是误拦: %+v", c)
	}
	if c := by["10.task.no_escape"]; c.Status != PASS {
		t.Fatalf("%+v", c)
	}
	res.Notes = []string{"任务结束 3s 后还有任务账户的进程活着（1 个，<nil>）：有进程逃出了作业对象"}
	res.Result.Killed = "timeout"
	for _, c := range JudgeRun(3, "task", res, nil) {
		if (c.ID == "10.task.no_escape" || c.ID == "3.task.run") && c.Status != FAIL {
			t.Fatalf("%+v", c)
		}
	}
	got = JudgeRun(3, "task", jobbox.Result{}, &jobbox.RejectError{Msg: "系统控制金丝雀不符"})
	if len(got) != 1 || got[0].Status != FAIL || !strings.Contains(got[0].Evidence, "金丝雀") {
		t.Fatalf("被拒就只有一条: %+v", got)
	}
}

func TestJudgeAfterRestore(t *testing.T) {
	if c := JudgeAfterRestore(errors.New("找不到账户 epsilon-job（C: 被还原了？）")); c.Status != PASS || c.Item != 8 {
		t.Fatalf("还原后健康检查不过 = 出错即拒（jobs:false）: %+v", c)
	}
	if c := JudgeAfterRestore(nil); c.Status != PASS || !strings.Contains(c.Evidence, "还能解") {
		t.Fatalf("%+v", c)
	}
}

func TestScanTargetsFromPowerShellListeners(t *testing.T) {
	// ConvertTo-Json 在 PowerShell 5.1 里只有一个元素时输出对象不是数组：两种都要认
	one := `{"addr":"0.0.0.0","port":135,"pid":900,"proc":"svchost"}`
	got, err := ScanTargets([]byte(one))
	if err != nil || len(got) != 1 || got[0].Addr != "127.0.0.1" || got[0].Port != 135 {
		t.Fatalf("%v %+v", err, got)
	}
	many := "\xef\xbb\xbf" + `[{"addr":"127.0.0.1","port":8080,"pid":1,"proc":"llama-server"},
		{"addr":"0.0.0.0","port":8080,"pid":1,"proc":"llama-server"},
		{"addr":"::","port":445,"pid":4,"proc":"System"},
		{"addr":"fe80::1%3","port":5355,"pid":5,"proc":"svchost"},
		{"addr":"::1","port":50052,"pid":6,"proc":"ggml-rpc-server"},
		{"addr":"10.0.0.8","port":47100,"pid":7,"proc":"epsilon-probe"}]`
	got, err = ScanTargets([]byte(many))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, l := range got {
		keys = append(keys, l.Addr+"|"+strings.TrimSpace(l.Proc))
	}
	want := "10.0.0.8|epsilon-probe 127.0.0.1|llama-server ::1|System ::1|ggml-rpc-server"
	if strings.Join(keys, " ") != want {
		t.Fatalf("通配地址换成回环、去重、跳过链路本地:\n%s\n%s", strings.Join(keys, " "), want)
	}
	if _, err := ScanTargets([]byte("[]")); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanTargets([]byte("nope")); err == nil {
		t.Fatal("坏 JSON 要报错")
	}
}

func TestEmbeddedJobCheckKnowsEveryMode(t *testing.T) {
	for _, m := range []string{`"task"`, `"lockdir"`, `"mkdir700"`, `"net"`, `"scan"`, `"inventory"`} {
		if !strings.Contains(jobCheckSrc, m) {
			t.Fatalf("job_check.py 缺模式 %s", m)
		}
	}
	for _, id := range taskChecks {
		if !strings.Contains(jobCheckSrc, `"`+id+`"`) {
			t.Fatalf("job_check.py 不报 %s", id)
		}
	}
}
