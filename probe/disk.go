package probe

// 磁盘上报（设计书 21.3）：盘总量 / 剩余每次心跳现取，D:\epsilon 分项占用后台每 10 分钟遍历一次。

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"epsilon/proto"
)

var errBudget = errors.New("统计超时")

// diskUsage 按顶层分类统计 root 下普通文件的大小（MB），块目录不在 root 里也单独算进 chunks。
// 符号链接、junction 不跟也不算。超过 budget 就停，complete=false。
func diskUsage(root, chunkDir string, budget time.Duration) (usage map[string]int64, complete bool) {
	deadline := time.Now().Add(budget)
	bytes := map[string]int64{}
	chunkDir = filepath.Clean(chunkDir)
	walk := func(dir string, class func(path string) string) error {
		return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if !time.Now().Before(deadline) {
				return errBudget
			}
			if err != nil || !d.Type().IsRegular() {
				return nil // 读不了的跳过；目录本身、链接都不计
			}
			if info, err := d.Info(); err == nil {
				bytes[class(path)] += info.Size()
			}
			return nil
		})
	}
	err := walk(root, func(path string) string {
		if chunkDir != "." && (path == chunkDir || strings.HasPrefix(path, chunkDir+string(filepath.Separator))) {
			return "chunks"
		}
		rel, _ := filepath.Rel(root, path)
		top, _, nested := strings.Cut(rel, string(filepath.Separator))
		switch {
		case nested && top == "models":
			return "models"
		case nested && (top == "A" || top == "B" || top == "R"):
			return "slots"
		case !nested && strings.Contains(top, ".log"):
			return "logs"
		}
		return "other"
	})
	if err == nil && chunkDir != "." {
		if rel, rerr := filepath.Rel(root, chunkDir); rerr != nil || strings.HasPrefix(rel, "..") {
			err = walk(chunkDir, func(string) string { return "chunks" })
		}
	}
	usage = map[string]int64{}
	for k, v := range bytes {
		usage[k] = v >> 20
	}
	return usage, err == nil
}

// startUsage 到点就在后台重算分项。只在 Step 里调。
func (a *Agent) startUsage(now time.Time) {
	if a.cfg.ArtifactRoot == "" || now.Sub(a.usageStarted) < a.usageEvery || !a.usageBusy.CompareAndSwap(false, true) {
		return
	}
	a.usageStarted = now
	go func() {
		defer a.usageBusy.Store(false)
		u, complete := diskUsage(a.cfg.ArtifactRoot, a.cfg.ChunkDir, 30*time.Second)
		a.umu.Lock()
		a.usage, a.usageAt, a.usageComplete = u, time.Now(), complete
		a.umu.Unlock()
	}()
}

// disk 给心跳用；没配 artifact_root 就不报。
func (a *Agent) disk() *proto.Disk {
	if a.cfg.ArtifactRoot == "" {
		return nil
	}
	total, free := a.sys.DiskMB(a.cfg.ArtifactRoot)
	d := &proto.Disk{TotalMB: total, FreeMB: free}
	a.umu.Lock()
	defer a.umu.Unlock()
	if a.usage != nil {
		d.UsageMB, d.UsageAgeSec, d.Complete = a.usage, int(time.Since(a.usageAt).Seconds()), a.usageComplete
	}
	return d
}
