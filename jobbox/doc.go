// Package jobbox 是批任务的沙箱（issue #1 第 4 步，docs/jobs-sandbox.md）：
// 专用低权限账户 epsilon-job、任务目录 ACL 和完整性标签、独立桌面、作业对象、审计管道、金丝雀、出错即拒。
//
// 策略（SDDL、环境块、金丝雀对照、审计记录、编排和出错即拒）都是纯函数或走 Platform 接口，在 macOS 上测；
// Windows 系统调用在 *_windows.go。非 Windows 构建没有真实现，New 返回"不支持"，探针一个任务都不跑。
package jobbox
