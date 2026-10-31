package probe

import (
	"context"
	"os/exec"
	"time"

	"epsilon/proto"
	"epsilon/winproc"
)

// RealSystem 是真机观测：显卡走 nvidia-smi，键鼠和内存按平台实现（sys_windows.go）。
type RealSystem struct{}

func (RealSystem) GPUs() []proto.GPU {
	return ParseGPUs(nvidiaSmi("--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits"))
}

func (RealSystem) ComputeApps() string {
	return nvidiaSmi("--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader,nounits")
}

func (RealSystem) IdleSeconds() int                       { return idleSeconds() }
func (RealSystem) MemFreeMB() int                         { return memFreeMB() }
func (RealSystem) DiskMB(path string) (total, free int64) { return diskMB(path) }

func nvidiaSmi(args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nvidia-smi", args...)
	winproc.Hide(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}
