package main

// 结果、汇总和报告：纯 Go，Mac 上测（report_test.go）。真机上的检查在 limited_windows.go，
// PowerShell 一侧（tools/sandbox-check/run.ps1）写同样格式的 JSON 行。

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 状态。MANUAL = 证据收齐了，要人看一眼才能下结论（盘点、叫不醒管道之类）。
const (
	PASS   = "PASS"
	FAIL   = "FAIL"
	SKIP   = "SKIP"
	MANUAL = "MANUAL"
)

// Check 是一条检查结果（JSON 一行）。Item 是 docs/jobs-sandbox.md 第 7 节的条目号，0 = 运行与清理。
type Check struct {
	Item     int    `json:"item"`
	ID       string `json:"id"`
	Status   string `json:"status"`
	Evidence string `json:"evidence,omitempty"`
	Source   string `json:"source,omitempty"` // ps（run.ps1）/ helper / job（任务侧脚本）/ selftest
}

// ItemInfo 是一项的标题和 FAIL 时该看的地方。
type ItemInfo struct {
	N     int    `json:"item"`
	Title string `json:"title"`
	Doc   string `json:"doc"`
}

const doc = "docs/jobs-sandbox.md "

// Items 和 docs/jobs-sandbox.md 第 7 节的 18 条一一对应。
var Items = []ItemInfo{
	{0, "运行与清理（前置检查、自检退出码、收尾）", "tools/sandbox-check/README.md"},
	{1, "CreateProcessWithLogonW 挂起、重定向输出、放进作业对象", doc + "第 2 节「启动」"},
	{2, "非提升建窗口站和桌面；Low IL 下 user32 初始化", doc + "第 2 节「独立桌面」"},
	{3, "Low IL：sitecustomize 降级、torch/CUDA/DataLoader、审计管道连接", doc + "第 2 节「Low IL 和特权」、第 5 节 sitecustomize"},
	{4, "拒执行 0x20：CreateProcess/LoadLibrary 失败，makedirs/rmtree/walk 正常", doc + "第 3 节"},
	{5, "按 SID 的防火墙：拦截返回 10013、不依赖 IPsec、回环不受影响", doc + "第 4 节"},
	{6, "sitecustomize 先于脚本目录加载；出错退出 97", doc + "第 5 节 sitecustomize"},
	{7, "multiprocessing spawn 的命令行形状；钩子和管道", doc + "第 5 节「策略」"},
	{8, "DPAPI（LocalMachine）解密；C: 还原后的表现", doc + "第 2 节「账户」第 5 条"},
	{9, "seclogon 可用；secedit 合并用户权限", doc + "第 2 节「账户」第 3–4 条"},
	{10, "非管理员枚举、结束任务账户的进程；任务结束后清场宽限", doc + "第 6 节、jobbox/platform_windows.go 清场"},
	{11, "审计管道：DisconnectNamedPipe/CancelIoEx 叫醒 ReadFile，Close 叫醒 ConnectNamedPipe", doc + "第 7 节第 11 条、jobbox/box.go serveAudit"},
	{12, "install.ps1 第 4/8 步落地的状态（账户、组、ACL、数据卷）", doc + "第 2 节「账户」、第 3 节「上级目录」「数据卷」"},
	{13, "回环监听盘点（钩子之外任务账户连得上的端口）", doc + "第 4 节第 4 条、第 8 节"},
	{14, "C: 上 Users 可读内容盘点（ProgramData、Users\\Public）", doc + "第 3 节「数据卷」"},
	{15, "TreeResetNamedSecurityInfoW 遇到排除探针的子项；mkdir(0o700)", doc + "第 3 节「结束后收回」、第 8 节"},
	{16, "删特权后 torch/CUDA；窗口站/桌面权限；CWF_CREATE_ONLY 重建", doc + "第 2 节「独立桌面」「Low IL 和特权」"},
	{17, "系统金丝雀新增项（hardlink、chdir_tmp、exec_artifact_root、read_data_disk、privileges_dropped）", doc + "第 5 节「金丝雀」"},
	{18, "命令行长度在 1024 字符以内", doc + "第 2 节「启动」"},
}

var rank = map[string]int{PASS: 0, SKIP: 1, MANUAL: 2, FAIL: 3}

// Worst 是一组状态的汇总：有 FAIL 就 FAIL；有 MANUAL 就 MANUAL；有没验证到的（SKIP）就 SKIP；全 PASS 才 PASS。没有结果算 SKIP。
func Worst(ss []string) string {
	if len(ss) == 0 {
		return SKIP
	}
	w := PASS
	for _, s := range ss {
		if rank[s] > rank[w] {
			w = s
		}
	}
	return w
}

var idItem = regexp.MustCompile(`^(\d+)\.`)

// itemOf 从 id 的前缀取项号（"12.account" → 12），取不到是 0。
func itemOf(id string) int {
	if m := idItem.FindStringSubmatch(id); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// normalize：状态大写、不认识的算 FAIL；项号缺了按 id 前缀，超出范围归第 0 项。
func normalize(c Check) Check {
	c.Status = strings.ToUpper(strings.TrimSpace(c.Status))
	if _, ok := rank[c.Status]; !ok {
		c.Evidence = strings.TrimSpace(fmt.Sprintf("状态 %q 不认识 %s", c.Status, c.Evidence))
		c.Status = FAIL
	}
	if c.Item == 0 {
		c.Item = itemOf(c.ID)
	}
	if c.Item < 0 || c.Item >= len(Items) {
		c.Item = 0
	}
	return c
}

// ReadJSONL 读一行一个 JSON 的结果；坏行记成第 0 项的 FAIL（不丢）。source 非空时补上来源。
func ReadJSONL(r io.Reader, source string) []Check {
	var out []Check
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" {
			continue
		}
		var c Check
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			out = append(out, Check{ID: "0.bad_result_line", Status: FAIL, Evidence: trunc(line, 300), Source: source})
			continue
		}
		if c.Source == "" {
			c.Source = source
		}
		out = append(out, normalize(c))
	}
	return out
}

// selftestItems：-sandbox-selftest 的每一行算哪几项的证据（docs/jobs-sandbox.md 第 5、7 节）。
var selftestItems = map[string][]int{
	"health": {2, 8, 12}, "grant": {4}, "start": {1, 10},
	"integrity_low": {3}, "privileges_dropped": {16, 17}, "desktop": {2, 16},
	"read_probe_json": {12}, "read_secrets": {12}, "read_data_disk": {12, 17}, "exec_artifact_root": {4, 17},
	"hardlink_probe_json": {17}, "chdir_tmp": {17},
	"write_code": {4}, "write_params": {4}, "delete_params": {4}, "write_job_root": {4},
	"write_sitecustomize": {12}, "write_env": {12},
	"write_tmp": {4}, "write_output": {4}, "exec_tmp": {4}, "load_tmp_dll": {4}, "set_dacl_own_file": {4},
	"write_programdata": {3}, "write_windows_temp": {3}, "write_users_public": {3},
	"connect_controller": {5}, "socketpair": {5},
	"hook_installed": {6}, "ready_in_layer": {6}, "ready_main": {3},
	"subprocess_blocked": {7}, "spawn_flags_blocked": {7}, "connect_blocked": {7}, "dns_blocked": {7},
	"unc_blocked": {7}, "unc_paths_blocked": {7}, "env_tamper_blocked": {7}, "tmp_py_blocked": {7},
	"rename_py_blocked": {7}, "dlopen_tmp_blocked": {7}, "mp_child": {7}, "ready_child": {7},
	"loopback_blocked": {13}, "socketpair_ok": {13},
	"sweep": {10}, "revoke": {15},
}

// ParseSelftest 解析 sandbox-selftest.txt（jobbox.SelfTest 的表："OK    名字 说明" / "FAIL  名字 说明"，"== 段落"）。
// 同名的行（start 在两段里都可能有）加上 @段落。一行都没有算第 0 项的 FAIL（自检根本没起来，原文当证据）。
func ParseSelftest(txt []byte) []Check {
	var out []Check
	section := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimPrefix(string(txt), "\ufeff"), "\n") {
		line = strings.TrimRight(line, "\r")
		if s, ok := strings.CutPrefix(line, "== "); ok {
			section, _, _ = strings.Cut(s, "（")
			section = strings.TrimSpace(section)
			continue
		}
		st := ""
		switch {
		case strings.HasPrefix(line, "OK  "):
			st, line = PASS, line[4:]
		case strings.HasPrefix(line, "FAIL"):
			st, line = FAIL, line[4:]
		default:
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := f[0]
		ev := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), name))
		id := "selftest." + name
		if name == "start" || seen[id] {
			id += "@" + section
		}
		seen[id] = true
		items := selftestItems[name]
		if len(items) == 0 {
			items = []int{0}
		}
		for _, it := range items {
			out = append(out, Check{Item: it, ID: id, Status: st, Evidence: ev, Source: "selftest"})
		}
	}
	if len(out) == 0 {
		out = append(out, Check{ID: "0.selftest_output", Status: FAIL, Evidence: "自检没有输出任何一行结果: " + trunc(string(txt), 500), Source: "selftest"})
	}
	return out
}

// ItemResult 是一项的汇总。
type ItemResult struct {
	ItemInfo
	Status string  `json:"status"`
	Checks []Check `json:"checks"`
}

// Report 是最后的报告（JSON 和文本两份）。
type Report struct {
	Version   int            `json:"version"`
	Generated string         `json:"generated"`
	Host      string         `json:"host,omitempty"`
	Overall   string         `json:"overall"`
	Counts    map[string]int `json:"counts"` // 第 1–18 项各状态的个数
	Items     []ItemResult   `json:"items"`
}

// Build 按项汇总。没有任何结果的项补一条 SKIP（没跑到）。总体 = 第 1–18 项加上第 0 项的 FAIL。
func Build(checks []Check, host string, now time.Time) Report {
	r := Report{Version: 1, Generated: now.Format(time.RFC3339), Host: host, Counts: map[string]int{}}
	by := make([][]Check, len(Items))
	for _, c := range checks {
		c = normalize(c)
		by[c.Item] = append(by[c.Item], c)
	}
	var all []string
	for i, info := range Items {
		cs := by[i]
		if len(cs) == 0 && i > 0 {
			cs = []Check{{Item: i, ID: fmt.Sprintf("%d.not_run", i), Status: SKIP, Evidence: "没跑到（前面的步骤失败、超时，或者缺环境层）"}}
		}
		var ss []string
		for _, c := range cs {
			ss = append(ss, c.Status)
		}
		st := Worst(ss)
		if i == 0 {
			if st == FAIL {
				all = append(all, FAIL)
			}
			if len(cs) == 0 {
				st = PASS
			}
		} else {
			r.Counts[st]++
			all = append(all, st)
		}
		r.Items = append(r.Items, ItemResult{ItemInfo: info, Status: st, Checks: cs})
	}
	r.Overall = Worst(all)
	return r
}

// JSON 是报告的 JSON。
func (r Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Text 是给人看的报告：FAIL 的项排最前，然后 MANUAL、SKIP、PASS；每项列出全部检查和证据。
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Epsilon 批任务沙箱真机验证（docs/jobs-sandbox.md 第 7 节）\n生成 %s  主机 %s\n", r.Generated, r.Host)
	fmt.Fprintf(&b, "总体: %s    PASS %d  FAIL %d  MANUAL %d  SKIP %d（第 1–18 项）\n", r.Overall, r.Counts[PASS], r.Counts[FAIL], r.Counts[MANUAL], r.Counts[SKIP])
	b.WriteString("FAIL = 不符合设计，按该项后面写的文档章节查；MANUAL = 证据收齐了，要人判断；SKIP = 没验证到（缺环境层、缺 GPU 或前面失败）。\n\n")
	items := append([]ItemResult(nil), r.Items...)
	sort.SliceStable(items, func(i, j int) bool { return rank[items[i].Status] > rank[items[j].Status] })
	for _, it := range items {
		fmt.Fprintf(&b, "[%s]  %d. %s\n        出错看: %s\n", it.Status, it.N, it.Title, it.Doc)
		for _, c := range it.Checks {
			fmt.Fprintf(&b, "    %-6s %-40s %s\n", c.Status, c.ID, trunc(oneLine(c.Evidence), 600))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ResultWriter 把结果追加成 JSON 行；控制台只回显状态和 id（英文：PowerShell 5.1 读中文输出会乱码）。
type ResultWriter struct {
	mu     sync.Mutex
	f      io.Writer
	echo   io.Writer
	source string
}

// OpenResults 打开（追加）结果文件。
func OpenResults(path, source string) (*ResultWriter, func() error, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return &ResultWriter{f: f, echo: os.Stdout, source: source}, f.Close, nil
}

// Add 写一条。
func (w *ResultWriter) Add(c Check) {
	if c.Source == "" {
		c.Source = w.source
	}
	c = normalize(c)
	b, _ := json.Marshal(c)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.f.Write(append(b, '\n'))
	if w.echo != nil {
		fmt.Fprintf(w.echo, "%s %s\n", c.Status, c.ID)
	}
}

// AddAll 写多条。
func (w *ResultWriter) AddAll(cs []Check) {
	for _, c := range cs {
		w.Add(c)
	}
}

// readAll 读工作目录里的结果：*.jsonl 和 sandbox-selftest.txt（有的话）。
func readAll(work string) ([]Check, error) {
	ents, err := os.ReadDir(work)
	if err != nil {
		return nil, err
	}
	var out []Check
	for _, e := range ents {
		name := e.Name()
		p := work + string(os.PathSeparator) + name
		switch {
		case strings.HasSuffix(name, ".jsonl"):
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			out = append(out, ReadJSONL(bytes.NewReader(b), strings.TrimSuffix(name, ".jsonl"))...)
		case name == "sandbox-selftest.txt":
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			out = append(out, ParseSelftest(b)...)
		}
	}
	return out, nil
}
