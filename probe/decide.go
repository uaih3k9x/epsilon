// Package probe 是学生机上的探针：只上报、只执行期望状态，不做调度决策。
package probe

import (
	"fmt"
	"strings"
	"time"

	"epsilon/proto"
)

// Observed 是本机此刻的情况。
type Observed struct {
	Now           time.Time
	IdleSeconds   int // -1 = 拿不到
	ForeignGPU    []string
	ForeignVRAMMB int  // 别人比模型刚加载好时多占的显存；-1 = 不知道（没在跑）
	VRAMShort     bool // 之前因显存被占卸载过，现在空闲显存还不够装回模型
	ControllerOK  bool // 主控失联没超过 MaxOfflineMins
}

// Mode 是分档让位的结果。
type Mode int

const (
	Stop Mode = iota // 不跑：进程停掉、显存放出来
	Warm             // 模型留在显存里，但不接新请求（有人在用电脑）
	Run              // 正常接请求
)

// Decide 判断此刻该跑到哪一档；不是 Run 时给出原因（上报用）。
func Decide(d proto.DesiredState, o Observed) (Mode, string) {
	switch {
	case d.Workload == "":
		return Stop, "no_workload"
	case !o.ControllerOK:
		return Stop, "controller_lost"
	case !InWindow(d.Windows, o.Now):
		return Stop, "outside_window"
	case d.ForeignVRAMMB > 0 && o.ForeignVRAMMB >= d.ForeignVRAMMB:
		return Stop, "foreign_vram"
	case o.VRAMShort:
		return Stop, "vram_short"
	case d.YieldOnForeign && len(o.ForeignGPU) > 0:
		return Stop, "foreign_gpu"
	case d.YieldOnInput && o.IdleSeconds >= 0 && o.IdleSeconds < d.InputIdleSeconds:
		if d.KeepWarm {
			return Warm, "user_active"
		}
		return Stop, "user_active"
	}
	return Run, ""
}

// InWindow: 时段写成 "HH:MM-HH:MM"，结束早于开始表示跨午夜；没有时段 = 全天。写错的时段不匹配。
func InWindow(windows []string, now time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	m := now.Hour()*60 + now.Minute()
	for _, w := range windows {
		from, to, ok := parseWindow(w)
		if !ok {
			continue
		}
		if from <= to && m >= from && m < to || from > to && (m >= from || m < to) {
			return true
		}
	}
	return false
}

func parseWindow(w string) (int, int, bool) {
	a, b, ok := strings.Cut(w, "-")
	if !ok {
		return 0, 0, false
	}
	from, ok1 := hhmm(a)
	to, ok2 := hhmm(b)
	return from, to, ok1 && ok2
}

func hhmm(s string) (int, bool) {
	var h, m int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d:%d", &h, &m); err != nil || h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}
