package main

// 判定：纯函数，Mac 上测（judge_test.go）。limited_windows.go 量出数，交给这里判。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"epsilon/jobbox"
)

// ParseCheckLines 解析任务侧脚本（py/job_check.py）的输出："CHECK <id> <状态> [证据]"，别的行跳过。
func ParseCheckLines(out []byte, source string) []Check {
	var cs []Check
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.SplitN(strings.TrimRight(line, "\r"), " ", 4)
		if len(f) < 3 || f[0] != "CHECK" || f[1] == "" {
			continue
		}
		c := Check{ID: f[1], Status: f[2], Source: source}
		if len(f) == 4 {
			c.Evidence = strings.TrimSpace(f[3])
		}
		cs = append(cs, normalize(c))
	}
	return cs
}

// ParseInventory 取盘点清单（"INV <标记> <路径>" 行，去掉 "INV "）。
func ParseInventory(out []byte) []string {
	var ls []string
	for _, line := range strings.Split(string(out), "\n") {
		if s, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "INV "); ok {
			ls = append(ls, s)
		}
	}
	return ls
}

// ExpectChecks 补上该报而没报的 id（脚本中途崩了之类），记 FAIL 并附上原因。
func ExpectChecks(got []Check, want []string, why string) []Check {
	seen := map[string]bool{}
	for _, c := range got {
		seen[c.ID] = true
	}
	out := append([]Check(nil), got...)
	for _, id := range want {
		if !seen[id] {
			out = append(out, normalize(Check{ID: id, Status: FAIL, Evidence: "没报: " + why}))
		}
	}
	return out
}

// JudgeCmdLines（第 18 项）：每条命令行（UTF-16 字符数）都不超过 max。
func JudgeCmdLines(lens map[string]int, max int) Check {
	names := make([]string, 0, len(lens))
	for n := range lens {
		names = append(names, n)
	}
	sort.Strings(names)
	st := PASS
	var ev []string
	for _, n := range names {
		ev = append(ev, fmt.Sprintf("%s=%d", n, lens[n]))
		if lens[n] > max {
			st = FAIL
		}
	}
	return Check{Item: 18, ID: "18.cmdline_len", Status: st, Evidence: fmt.Sprintf("上限 %d: %s", max, strings.Join(ev, " "))}
}

// JudgeSweepTimes（第 10 项）：进程退出、作业关掉以后，任务账户的进程多久从 WTSEnumerateProcessesExW 里消失。
// 超过探针的宽限（jobbox.Config.SweepGrace，默认 3 秒）的话，每个普通任务结束都会被判成"逃出作业"、停接到重启。
func JudgeSweepTimes(id string, ds []time.Duration, grace time.Duration, err error) Check {
	c := Check{ID: id}
	if err != nil {
		c.Status, c.Evidence = FAIL, err.Error()
		return normalize(c)
	}
	if len(ds) == 0 {
		c.Status, c.Evidence = SKIP, "没有量到"
		return normalize(c)
	}
	var mx time.Duration
	var parts []string
	for _, d := range ds {
		mx = max(mx, d)
		parts = append(parts, d.Round(time.Millisecond).String())
	}
	c.Status = PASS
	if mx > grace {
		c.Status = FAIL
	}
	c.Evidence = fmt.Sprintf("max %s（宽限 %s）: %s", mx.Round(time.Millisecond), grace, strings.Join(parts, " "))
	return normalize(c)
}

// JudgeWake（第 11 项）：叫醒挂着的管道调用要多久。叫不醒或者比探针等的久都不会卡住探针（只是少收尾几秒），记 MANUAL 给人看。
func JudgeWake(id string, woke bool, d, limit time.Duration) Check {
	c := Check{ID: id, Status: PASS, Evidence: fmt.Sprintf("%s 内醒了（探针等 %s）", d.Round(time.Millisecond), limit)}
	switch {
	case !woke:
		c.Status, c.Evidence = MANUAL, fmt.Sprintf("等了 %s 没醒：探针在这一步会等满 %s 再放弃（文档第 7 节第 11 条）", d.Round(time.Millisecond), limit)
	case d > limit:
		c.Status = MANUAL
		c.Evidence = fmt.Sprintf("%s 才醒，比探针等的 %s 长", d.Round(time.Millisecond), limit)
	}
	return normalize(c)
}

// JudgeCreateOnly（第 16 项）：窗口站已经被本进程建好时，第二个实例必须因为 CWF_CREATE_ONLY 建不出来。
func JudgeCreateOnly(err error) Check {
	c := Check{Item: 16, ID: "16.create_only"}
	switch {
	case err == nil:
		c.Status, c.Evidence = FAIL, "同名窗口站已经存在时第二个实例照样建出来了（CWF_CREATE_ONLY 没生效）"
	case strings.Contains(err.Error(), "建窗口站"):
		c.Status, c.Evidence = PASS, err.Error()
	default:
		c.Status, c.Evidence = FAIL, "第二个实例因为别的原因失败，判断不了: "+err.Error()
	}
	return c
}

// JudgeExit97（第 6 项）：审计管道不在时，sitecustomize 必须 os._exit(97)，一行用户代码都不跑。
func JudgeExit97(code int, err error) Check {
	c := Check{Item: 6, ID: "6.exit97_without_pipe"}
	switch {
	case err != nil:
		c.Status, c.Evidence = FAIL, err.Error()
	case code == 97:
		c.Status, c.Evidence = PASS, "退出码 97"
	default:
		c.Status, c.Evidence = FAIL, fmt.Sprintf("退出码 %d（要 97：连不上审计管道就该退出）", code)
	}
	return c
}

// JudgeTreeReset（第 15 项）：任务在 output\ 下建了只给自己（OW）的受保护目录，探针收回权限时
// TreeResetNamedSecurityInfoW 是报错中止（Box 改名隔离，出错即拒，符合设计），还是跳过（报"成功"却没收回，要加抽查）。
// quarantined 是 Box.Run 返回的 Result.Dir；lockedErr 是收回以后探针列那个目录的错误；runErr 是 Box.Run 的错误。
func JudgeTreeReset(quarantined string, lockedErr, runErr error) Check {
	c := Check{Item: 15, ID: "15.treereset_locked_child"}
	switch {
	case runErr != nil:
		c.Status, c.Evidence = FAIL, "任务没跑成: "+runErr.Error()
	case quarantined != "":
		c.Status, c.Evidence = PASS, "TreeReset 报错中止，目录已改名隔离: "+quarantined
	case lockedErr != nil:
		c.Status, c.Evidence = FAIL, "收回报成功，但锁住的子目录探针还是读不了（TreeReset 跳过了它，要加抽查）: "+lockedErr.Error()
	default:
		c.Status, c.Evidence = MANUAL, "收回成功、子目录也读得了：锁目录可能没建成，看任务侧 15.lockdir 那一行"
	}
	return c
}

// JudgeMkdir700（第 15 项）：任务 os.mkdir(..., 0o700) 之后收回权限。Python 3.12.4+ 在 Windows 上给它建受保护 DACL，
// 文档预计收回会失败、改名隔离；成真的话要人决定钩子是不是改成拦。收回报成功的话要回读：readErr 是收回以后探针列 m700 的错误
// （和 lockdir 一样；TreeReset 跳过了它，下一个任务——同一个账户、就是所有者——照样读得到）。
func JudgeMkdir700(pyver, quarantined string, readErr, runErr error) Check {
	c := Check{Item: 15, ID: "15.mkdir700"}
	switch {
	case runErr != nil:
		c.Status, c.Evidence = FAIL, "任务没跑成: "+runErr.Error()
	case quarantined != "":
		c.Status, c.Evidence = MANUAL, fmt.Sprintf("Python %s：mkdir(0o700) 让收回失败，目录改名隔离了 %s；要不要在钩子里拦 mkdir(0o700)（第 8 节）", pyver, quarantined)
	case readErr != nil:
		c.Status, c.Evidence = FAIL, fmt.Sprintf("Python %s：收回报成功，但探针读不了 output\\m700（TreeReset 跳过了它，要加抽查）: %v", pyver, readErr)
	default:
		c.Status, c.Evidence = PASS, fmt.Sprintf("Python %s：收回成功，探针读得了 output\\m700", pyver)
	}
	return c
}

// JudgeIdentity（第 0 项）：helper 要和探针一样是非提升的身份。关了 UAC 的管理员登录时 RunLevel Limited 拿到的是完整令牌，
// 后面 10.terminate、2.winsta_limited、15.* 这些项会在比生产高的权限下通过，报告却看不出来。
func JudgeIdentity(user string, elevated bool, err error) Check {
	c := Check{ID: "0.helper_identity", Status: PASS, Evidence: fmt.Sprintf("helper 以 %s 运行，提升=false（和探针一样）", user)}
	switch {
	case err != nil:
		c.Status, c.Evidence = FAIL, "查不了自己的令牌: "+err.Error()
	case elevated:
		c.Status = FAIL
		c.Evidence = fmt.Sprintf("helper 以 %s 运行，但令牌是提升的（关了 UAC 的管理员？）：后面的项都在比探针高的权限下测，结果不算数", user)
	}
	return c
}

// JudgeAfterRestore（第 8 项，-AfterRestore）：C: 还原以后健康检查过不了也是对的（出错即拒、心跳 jobs:false）；
// 过了说明主密钥和账户都还在。只要没崩、没卡住都算 PASS，证据写明是哪一种。
func JudgeAfterRestore(err error) Check {
	c := Check{Item: 8, ID: "8.after_restore", Status: PASS}
	if err != nil {
		c.Evidence = "健康检查不过（出错即拒，心跳会报 jobs:false；重跑 install.ps1 恢复）: " + err.Error()
	} else {
		c.Evidence = "还原后密码文件还能解、账户也在：健康检查照常通过"
	}
	return c
}

// JudgeRun 判一次 Box.Run（经过两次金丝雀、钩子、清场、收回的完整流程）。被拒就只有一条 FAIL。
func JudgeRun(item int, name string, res jobbox.Result, err error) []Check {
	pre := fmt.Sprintf("%d.%s", item, name)
	if err != nil {
		return []Check{normalize(Check{ID: pre + ".run", Status: FAIL, Evidence: err.Error()})}
	}
	var cs []Check
	run := Check{ID: pre + ".run", Status: PASS, Evidence: fmt.Sprintf("退出码 %d，%.1f 秒", res.ExitCode, res.Seconds)}
	if res.Killed != "" {
		run.Status, run.Evidence = FAIL, fmt.Sprintf("被杀（%s），%.1f 秒", res.Killed, res.Seconds)
	}
	cs = append(cs, run)
	var ils []string
	var blocks []string
	for _, line := range bytes.Split(res.AuditLog, []byte("\n")) {
		var r jobbox.Record
		if json.Unmarshal(line, &r) != nil {
			continue
		}
		switch {
		case r.Ev == "ready":
			ils = append(ils, fmt.Sprintf("pid %d il=%s", r.Pid, r.IL))
		case r.Act == "block":
			blocks = append(blocks, r.Ev+" "+trunc(r.Args, 120))
		}
	}
	ready := Check{ID: fmt.Sprintf("3.%s.ready", name), Status: PASS, Evidence: strings.Join(ils, "; ")}
	if !res.Audit.Ready {
		ready.Status = FAIL
		ready.Evidence = "主进程没有就绪记录 " + ready.Evidence
	}
	cs = append(cs, ready)
	bl := Check{ID: fmt.Sprintf("7.%s.blocks", name), Status: PASS, Evidence: fmt.Sprintf("拦截 %d 次", res.Audit.Blocked)}
	if res.Audit.Blocked > 0 || len(blocks) > 0 {
		// 测试任务自己不做被拦的事：有拦截多半是库（torch、platform 之类）内部的调用。不自动判失败（22.6.1：拦截交给人复查），
		// 但要人看是不是误拦了正常任务一定会用到的东西
		bl.Status = MANUAL
		bl.Evidence = fmt.Sprintf("测试任务不做被拦的事，却拦了 %d 次（库内部的调用？会不会误拦正常任务？）: %s", res.Audit.Blocked, strings.Join(blocks, "; "))
	}
	cs = append(cs, bl)
	esc := Check{ID: fmt.Sprintf("10.%s.no_escape", name), Status: PASS, Evidence: "结束后宽限内任务账户的进程都消失了"}
	for _, n := range res.Notes {
		if strings.Contains(n, "逃出") || strings.Contains(n, "还有任务账户的进程") {
			esc.Status, esc.Evidence = FAIL, n
		}
	}
	cs = append(cs, esc)
	for i := range cs {
		cs[i] = normalize(cs[i])
	}
	return cs
}

// Listener 是 run.ps1 用 Get-NetTCPConnection -State Listen 盘点的一个监听（第 13 项）。
type Listener struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
	Pid  int    `json:"pid"`
	Proc string `json:"proc"`
}

// ScanTargets 把盘点出的监听换成任务账户要试着连的地址：通配地址换成回环（0.0.0.0 → 127.0.0.1，:: → ::1），
// 跳过链路本地，按地址和端口去重排序。PowerShell 5.1 的 ConvertTo-Json 只有一个元素时输出对象，也认。
func ScanTargets(b []byte) ([]Listener, error) {
	b = bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
	var ls []Listener
	if bytes.HasPrefix(b, []byte("{")) {
		var one Listener
		if err := json.Unmarshal(b, &one); err != nil {
			return nil, err
		}
		ls = []Listener{one}
	} else if err := json.Unmarshal(b, &ls); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Listener
	for _, l := range ls {
		switch {
		case l.Addr == "0.0.0.0":
			l.Addr = "127.0.0.1"
		case l.Addr == "::":
			l.Addr = "::1"
		case strings.HasPrefix(strings.ToLower(l.Addr), "fe80"):
			continue
		}
		k := fmt.Sprintf("%s|%d", l.Addr, l.Port)
		if l.Port <= 0 || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}
