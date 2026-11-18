package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEveryItemHasTitleAndDoc(t *testing.T) {
	if len(Items) != 19 {
		t.Fatalf("要 0（运行与清理）加 18 项: %d", len(Items))
	}
	for i, it := range Items {
		if it.N != i || it.Title == "" || it.Doc == "" {
			t.Fatalf("第 %d 项不全: %+v", i, it)
		}
	}
}

func TestWorst(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, SKIP},
		{[]string{PASS, PASS}, PASS},
		{[]string{PASS, SKIP}, SKIP}, // 有一部分没验证到：这一项不算过
		{[]string{PASS, MANUAL, SKIP}, MANUAL},
		{[]string{MANUAL, FAIL, PASS}, FAIL},
	} {
		if got := Worst(c.in); got != c.want {
			t.Fatalf("Worst(%v) = %s，要 %s", c.in, got, c.want)
		}
	}
}

func TestReadJSONLToleratesBOMBadLinesAndNormalizes(t *testing.T) {
	in := "\xef\xbb\xbf" + `{"item":12,"id":"12.account","status":"pass","evidence":"ok"}` + "\r\n\n" +
		"not json\n" +
		`{"item":99,"id":"x","status":"PASS"}` + "\n" +
		`{"item":5,"id":"5.fw","status":"WHAT"}` + "\n" +
		`{"id":"7.mp","status":"MANUAL"}` + "\n"
	got := ReadJSONL(strings.NewReader(in), "ps")
	if len(got) != 5 {
		t.Fatalf("%d: %+v", len(got), got)
	}
	if got[0].Status != PASS || got[0].Item != 12 || got[0].Source != "ps" {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Status != FAIL || got[1].Item != 0 || !strings.Contains(got[1].Evidence, "not json") {
		t.Fatalf("坏行要记成第 0 项的 FAIL: %+v", got[1])
	}
	if got[2].Item != 0 {
		t.Fatalf("范围外的项号归第 0 项: %+v", got[2])
	}
	if got[3].Status != FAIL || !strings.Contains(got[3].Evidence, "WHAT") {
		t.Fatalf("不认识的状态算 FAIL: %+v", got[3])
	}
	if got[4].Item != 7 {
		t.Fatalf("没写 item 的按 id 前缀: %+v", got[4])
	}
}

const sampleSelftest = "epsilon-probe 0.4.0 沙箱自检 2026-11-18 10:00:00 环境层 D:\\epsilon\\envs\\py311@2\n" +
	"== 健康检查\n" +
	"OK    health                 \n" +
	"== 系统控制（python -I -S，不加载钩子）\n" +
	"OK    integrity_low          \n" +
	"FAIL  connect_controller     TimeoutError: timed out\n" +
	"FAIL  hardlink_probe_json    没报\n" +
	"== 审计钩子（python -E -s -B，环境层 py311@2）\n" +
	"FAIL  start                  起不来\n" +
	"OK    ready_child            multiprocessing 子进程的就绪记录\n" +
	"OK    brand_new_check        \n" +
	"== 收尾\n" +
	"OK    sweep                  剩下 0 个进程 <nil>\n" +
	"OK    revoke                 \n" +
	"自检没过: [connect_controller hardlink_probe_json start]\n"

func TestParseSelftestMapsRowsToItems(t *testing.T) {
	got := ParseSelftest([]byte(sampleSelftest))
	find := func(item int, id string) Check {
		for _, c := range got {
			if c.Item == item && c.ID == id {
				return c
			}
		}
		t.Fatalf("没有 %d %s: %+v", item, id, got)
		return Check{}
	}
	if c := find(5, "selftest.connect_controller"); c.Status != FAIL || !strings.Contains(c.Evidence, "timed out") {
		t.Fatalf("%+v", c)
	}
	find(8, "selftest.health")
	find(2, "selftest.health")
	find(17, "selftest.hardlink_probe_json")
	find(1, "selftest.start@审计钩子")
	find(7, "selftest.ready_child")
	find(10, "selftest.sweep")
	find(15, "selftest.revoke")
	if c := find(0, "selftest.brand_new_check"); c.Status != PASS {
		t.Fatalf("单子外的行归第 0 项、照原样: %+v", c)
	}
	for _, c := range got {
		if c.Source != "selftest" {
			t.Fatalf("%+v", c)
		}
	}
}

func TestParseSelftestEmptyIsFail(t *testing.T) {
	got := ParseSelftest([]byte("没有沙箱: 打开探针令牌\n"))
	if len(got) != 1 || got[0].Status != FAIL || got[0].Item != 0 || !strings.Contains(got[0].Evidence, "没有沙箱") {
		t.Fatalf("%+v", got)
	}
}

func TestBuildAggregatesAndFillsMissingItems(t *testing.T) {
	checks := []Check{
		{Item: 5, ID: "5.a", Status: PASS},
		{Item: 5, ID: "5.b", Status: FAIL, Evidence: "10060"},
		{Item: 13, ID: "13.scan", Status: MANUAL},
		{Item: 18, ID: "18.len", Status: PASS},
	}
	r := Build(checks, "pc-xx", time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC))
	if len(r.Items) != 19 {
		t.Fatal(len(r.Items))
	}
	if r.Items[5].Status != FAIL || r.Items[13].Status != MANUAL || r.Items[18].Status != PASS || r.Items[1].Status != SKIP {
		t.Fatalf("%+v", r.Items)
	}
	if r.Overall != FAIL || r.Counts[FAIL] != 1 || r.Counts[PASS] != 1 || r.Counts[MANUAL] != 1 || r.Counts[SKIP] != 15 {
		t.Fatalf("%s %v", r.Overall, r.Counts)
	}
	if !strings.Contains(r.Items[1].Checks[0].Evidence, "没跑到") {
		t.Fatalf("没有结果的项要说明: %+v", r.Items[1])
	}
	b, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil || back.Overall != FAIL || len(back.Items) != 19 {
		t.Fatalf("%v %+v", err, back)
	}
	txt := r.Text()
	for _, want := range []string{"总体: FAIL", "[FAIL]  5.", "5.b", "10060", "docs/jobs-sandbox.md", "pc-xx"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("文本报告缺 %q:\n%s", want, txt)
		}
	}
	// FAIL 的项排在前面，方便先看
	if strings.Index(txt, "[FAIL]  5.") > strings.Index(txt, "[PASS]  18.") {
		t.Fatalf("FAIL 要排在前面:\n%s", txt)
	}
}

func TestOverallIgnoresOnlyPassAndCleanup(t *testing.T) {
	var cs []Check
	for i := 1; i <= 18; i++ {
		cs = append(cs, Check{Item: i, ID: "x", Status: PASS})
	}
	if r := Build(cs, "", time.Now()); r.Overall != PASS {
		t.Fatal(r.Overall)
	}
	cs = append(cs, Check{Item: 0, ID: "0.cleanup", Status: FAIL})
	if r := Build(cs, "", time.Now()); r.Overall != FAIL {
		t.Fatal("清理失败也要让人看见:", r.Overall)
	}
}

func TestResultWriterAppendsJSONLines(t *testing.T) {
	var file, echo bytes.Buffer
	w := &ResultWriter{f: &file, echo: &echo, source: "helper"}
	w.Add(Check{Item: 1, ID: "1.start", Status: PASS, Evidence: "退出码 0"})
	w.Add(Check{ID: "11.wake", Status: MANUAL})
	got := ReadJSONL(&file, "")
	if len(got) != 2 || got[0].Source != "helper" || got[1].Item != 11 {
		t.Fatalf("%+v", got)
	}
	// 控制台只打英文（PowerShell 5.1 读中文会乱码）
	if strings.ContainsAny(echo.String(), "退出码") || !strings.Contains(echo.String(), "PASS 1.start") {
		t.Fatalf("%q", echo.String())
	}
}

func TestReportReadsWorkDirAndWritesBothFiles(t *testing.T) {
	work := t.TempDir()
	os.WriteFile(filepath.Join(work, "ps.jsonl"), []byte(`{"item":12,"id":"12.account","status":"PASS","source":"ps"}`+"\n"), 0o644)
	os.WriteFile(filepath.Join(work, "limited.jsonl"), []byte(`{"item":18,"id":"18.cmdline_len","status":"PASS"}`+"\n"), 0o644)
	os.WriteFile(filepath.Join(work, "sandbox-selftest.txt"), []byte(sampleSelftest), 0o644)
	os.WriteFile(filepath.Join(work, "inventory.txt"), []byte("KEY x\n"), 0o644) // 别的文件不读
	out := filepath.Join(t.TempDir(), "sandbox-check-x")
	if rc := report(work, out); rc != 1 {
		t.Fatalf("自检里有 FAIL，退出码要 1: %d", rc)
	}
	txt, err := os.ReadFile(out + ".txt")
	if err != nil || !bytes.HasPrefix(txt, []byte("\xef\xbb\xbf")) || !bytes.Contains(txt, []byte("selftest.connect_controller")) {
		t.Fatalf("%v\n%s", err, txt)
	}
	var r Report
	b, _ := os.ReadFile(out + ".json")
	if err := json.Unmarshal(b, &r); err != nil || r.Items[12].Checks[0].Source != "ps" || r.Items[18].Checks[0].Source != "limited" {
		t.Fatalf("%v %+v", err, r.Items[12])
	}
}
