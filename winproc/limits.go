package winproc

// Limits 是批任务作业对象在 KILL_ON_JOB_CLOSE 之外的限制（docs/jobs-sandbox.md 第 2 节）。
// 不设 BREAKAWAY_OK：任务的子进程逃不出作业。
type Limits struct {
	ActiveProcesses uint32 // 0 = 不限
	DieOnUnhandled  bool   // 未处理异常直接死，不弹出错报告对话框
	RestrictUI      bool   // JOBOBJECT_BASIC_UI_RESTRICTIONS 全开：剪贴板、全局原子、桌面切换、显示设置、注销关机……
}

// SandboxLimits 是 jobbox 起任务时用的。
var SandboxLimits = Limits{ActiveProcesses: 64, DieOnUnhandled: true, RestrictUI: true}

const (
	jobKillOnJobClose = 0x2000
	jobDieOnUnhandled = 0x0400
	jobActiveProcess  = 0x0008
	jobBreakawayOK    = 0x0800
	uiRestrictAll     = 0xff // HANDLES|READCLIPBOARD|WRITECLIPBOARD|SYSTEMPARAMETERS|DISPLAYSETTINGS|GLOBALATOMS|DESKTOP|EXITWINDOWS
)

func (l Limits) flags() (ext, ui uint32) {
	ext = jobKillOnJobClose
	if l.DieOnUnhandled {
		ext |= jobDieOnUnhandled
	}
	if l.ActiveProcesses > 0 {
		ext |= jobActiveProcess
	}
	if l.RestrictUI {
		ui = uiRestrictAll
	}
	return ext, ui
}
