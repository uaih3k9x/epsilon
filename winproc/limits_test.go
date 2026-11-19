package winproc

import "testing"

func TestLimitFlags(t *testing.T) {
	ext, ui := Limits{}.flags()
	if ext != jobKillOnJobClose || ui != 0 {
		t.Fatalf("什么都不加也要 KILL_ON_JOB_CLOSE: 0x%x 0x%x", ext, ui)
	}
	ext, ui = SandboxLimits.flags()
	// KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION | ACTIVE_PROCESS
	if ext != 0x2000|0x400|0x8 {
		t.Fatalf("ext = 0x%x", ext)
	}
	// HANDLES READ/WRITECLIPBOARD SYSTEMPARAMETERS DISPLAYSETTINGS GLOBALATOMS DESKTOP EXITWINDOWS
	if ui != 0xff {
		t.Fatalf("ui = 0x%x", ui)
	}
	if SandboxLimits.ActiveProcesses != 64 {
		t.Fatal(SandboxLimits.ActiveProcesses)
	}
	if ext&0x1800 != 0 { // BREAKAWAY_OK | SILENT_BREAKAWAY_OK
		t.Fatal("不能让任务的子进程逃出作业")
	}
}
