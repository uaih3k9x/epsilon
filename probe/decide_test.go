package probe

import (
	"testing"
	"time"

	"epsilon/proto"
)

func at(hhmm string) time.Time {
	t, _ := time.Parse("15:04", hhmm)
	return time.Date(2026, 10, 24, t.Hour(), t.Minute(), 0, 0, time.Local)
}

func TestDecideRunsWhenNothingStopsIt(t *testing.T) {
	d := proto.DesiredState{Workload: "qwen"}.Defaults()
	run, why := Decide(d, Observed{Now: at("12:00"), IdleSeconds: 9999, ControllerOK: true})
	if run != Run || why != "" {
		t.Fatalf("want run, got %v %q", run, why)
	}
}

func TestDecideStopReasons(t *testing.T) {
	base := proto.DesiredState{Workload: "qwen", YieldOnInput: true, InputIdleSeconds: 300,
		YieldOnForeign: true, Windows: []string{"22:00-07:00"}}.Defaults()
	night := Observed{Now: at("23:00"), IdleSeconds: 9999, ControllerOK: true}

	cases := []struct {
		name string
		d    proto.DesiredState
		o    Observed
		why  string
	}{
		{"no workload", proto.DesiredState{}.Defaults(), night, "no_workload"},
		{"outside window", base, Observed{Now: at("12:00"), IdleSeconds: 9999, ControllerOK: true}, "outside_window"},
		{"user active", base, Observed{Now: at("23:00"), IdleSeconds: 30, ControllerOK: true}, "user_active"},
		{"foreign gpu", base, Observed{Now: at("23:00"), IdleSeconds: 9999, ForeignGPU: []string{"game.exe"}, ControllerOK: true}, "foreign_gpu"},
		{"controller lost", base, Observed{Now: at("23:00"), IdleSeconds: 9999, ControllerOK: false}, "controller_lost"},
	}
	for _, c := range cases {
		run, why := Decide(c.d, c.o)
		if run != Stop || why != c.why {
			t.Errorf("%s: want stop %q, got run=%v %q", c.name, c.why, run, why)
		}
	}
	// 拿不到键鼠空闲时间(-1)时不因输入让位，免得服务模式下永远跑不起来
	if run, _ := Decide(base, Observed{Now: at("23:00"), IdleSeconds: -1, ControllerOK: true}); run != Run {
		t.Error("idle unknown should not block")
	}
	// 关掉开关就不管
	off := base
	off.YieldOnInput, off.YieldOnForeign = false, false
	if run, _ := Decide(off, Observed{Now: at("23:00"), IdleSeconds: 1, ForeignGPU: []string{"x"}, ControllerOK: true}); run != Run {
		t.Error("yield switches off should run")
	}
}

func TestDecideKeepWarmAndVRAM(t *testing.T) {
	d := proto.DesiredState{Workload: "qwen", YieldOnInput: true, InputIdleSeconds: 60,
		KeepWarm: true, ForeignVRAMMB: 1500}.Defaults()
	night := func(idle, foreignMB int, short bool) Observed {
		return Observed{Now: at("23:00"), IdleSeconds: idle, ForeignVRAMMB: foreignMB, VRAMShort: short, ControllerOK: true}
	}
	cases := []struct {
		o    Observed
		mode Mode
		why  string
	}{
		{night(9999, 0, false), Run, ""},
		{night(5, 0, false), Warm, "user_active"},     // 有人在看网页：模型留着
		{night(5, 2000, false), Stop, "foreign_vram"}, // 有人开游戏吃显存：卸载
		{night(9999, 1499, false), Run, ""},           // 没到阈值
		{night(9999, -1, true), Stop, "vram_short"},   // 卸载后显存还没空出来
		{night(5, -1, false), Warm, "user_active"},    // 没在跑也按 Warm（会把模型拉起来但不接活）
	}
	for i, c := range cases {
		if m, why := Decide(d, c.o); m != c.mode || why != c.why {
			t.Errorf("case %d: want %v %q, got %v %q", i, c.mode, c.why, m, why)
		}
	}
	off := d
	off.KeepWarm = false
	if m, _ := Decide(off, night(5, 0, false)); m != Stop {
		t.Error("keep_warm off should stop on user input")
	}
}

func TestInWindow(t *testing.T) {
	cases := []struct {
		w    []string
		now  string
		want bool
	}{
		{nil, "12:00", true},
		{[]string{"22:00-07:00"}, "23:30", true},
		{[]string{"22:00-07:00"}, "06:59", true},
		{[]string{"22:00-07:00"}, "07:00", false},
		{[]string{"12:00-13:30", "18:00-19:00"}, "13:00", true},
		{[]string{"12:00-13:30", "18:00-19:00"}, "15:00", false},
		{[]string{"bad"}, "15:00", false},
	}
	for _, c := range cases {
		if got := InWindow(c.w, at(c.now)); got != c.want {
			t.Errorf("%v at %s: want %v", c.w, c.now, c.want)
		}
	}
}
