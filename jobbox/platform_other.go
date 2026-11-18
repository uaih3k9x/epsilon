//go:build !windows

package jobbox

import "errors"

// 非 Windows 构建没有真实现：探针一个任务都不跑（Mac 上的测试注入假的 Platform 或 Sandbox）。
func newPlatform(Config) (Platform, error) {
	return nil, errors.New("这个系统上没有批任务沙箱（只支持 Windows）")
}
