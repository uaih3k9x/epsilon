package probe

// 日志轮转（设计书 21.4）：超上限就复制成 <文件>.1（覆盖旧的）再把原文件截断到 0。
// 不改名：Windows 上改名正在被写的文件会失败，截断不会；追加写的一方接着从 0 写。复制和截断之间写进来的几行会丢。

import (
	"io"
	"os"
	"time"
)

const (
	ProbeLogMax    = 10 << 20 // probe.log
	WorkloadLogMax = 20 << 20 // 每个工作负载的日志
)

// rotateLogs 每分钟查一次探针日志和正在跑的工作负载日志。只在 Step 里调。
func (a *Agent) rotateLogs(now time.Time) {
	if now.Sub(a.rotatedAt) < time.Minute {
		return
	}
	a.rotatedAt = now
	if a.LogPath != "" {
		RotateLog(a.LogPath, a.logMax)
	}
	if w, ok := a.cfg.Workloads[a.sup.Status().Name]; ok && w.Log != "" {
		RotateLog(w.Log, a.workloadLogMax)
	}
}

// RotateLog 超过 max 字节就轮转，返回是否轮转了。出错就当没轮转，下次再试。
func RotateLog(path string, max int64) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() <= max {
		return false
	}
	src, err := os.Open(path)
	if err != nil {
		return false
	}
	defer src.Close()
	dst, err := os.Create(path + ".1")
	if err != nil {
		return false
	}
	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false
	}
	return os.Truncate(path, 0) == nil
}
