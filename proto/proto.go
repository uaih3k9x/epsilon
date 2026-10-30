// Package proto 是探针和主控之间的协议 v1。规矩：只增不改，双方都忽略不认识的字段。
package proto

const Version = 1

// Register 是探针开机后的第一次登记。
type Register struct {
	Node     string   `json:"node"`
	Version  string   `json:"version"`        // 探针版本
	Boot     string   `json:"boot,omitempty"` // 引导器版本/槽位，如 "1/A"；直接跑本体时为空
	Hostname string   `json:"hostname"`
	GPUs     []GPU    `json:"gpus,omitempty"`
	MemoryMB int      `json:"memory_mb,omitempty"`
	Workload []string `json:"workloads"` // 本机配置里允许跑的工作负载名
}

// Heartbeat 是周期上报；主控的回复是 DesiredState。
type Heartbeat struct {
	Node        string   `json:"node"`
	Version     string   `json:"version"`
	Boot        string   `json:"boot,omitempty"`
	IdleSeconds int      `json:"idle_seconds"` // 键鼠多久没动；-1 = 拿不到
	ForeignGPU  []string `json:"foreign_gpu"`  // 别的程序在用显卡（进程名）
	GPUs        []GPU    `json:"gpus,omitempty"`
	MemFreeMB   int      `json:"mem_free_mb,omitempty"`
	Running     string   `json:"running"` // 正在跑的工作负载名，空 = 没跑
	Serving     *Serving `json:"serving,omitempty"`
	Reason      string   `json:"reason"` // 为什么是现在这个状态（让位原因等）
}

// Serving 表示工作负载起来了、健康检查通过，可以接请求。
type Serving struct {
	Model string `json:"model"`
	Port  int    `json:"port"`
}

type GPU struct {
	Name     string `json:"name"`
	Util     int    `json:"util"` // %
	MemUsed  int    `json:"mem_used_mb"`
	MemTotal int    `json:"mem_total_mb"`
	TempC    int    `json:"temp_c"`
	PowerW   int    `json:"power_w"`
}

// DesiredState 是声明式的：主控说"应该怎样"，探针自己想办法做到。
type DesiredState struct {
	Workload         string   `json:"workload"`          // 本机配置里的名字；空 = 什么都不跑
	Windows          []string `json:"windows,omitempty"` // 可运行时段 "22:00-07:00"；空 = 全天
	YieldOnInput     bool     `json:"yield_on_input"`    // 有人动键鼠就让位
	InputIdleSeconds int      `json:"input_idle_seconds"`
	YieldOnForeign   bool     `json:"yield_on_foreign_gpu"` // 别的程序用显卡就让位（Windows 下进程表含桌面进程，慎用）
	KeepWarm         bool     `json:"keep_warm"`            // 有人用电脑时模型留在显存里，只停接新请求
	ForeignVRAMMB    int      `json:"foreign_vram_mb"`      // 别人比模型刚加载好时多占这么多显存就卸载；0 = 不看
	HeartbeatSeconds int      `json:"heartbeat_seconds"`
	MaxOfflineMins   int      `json:"max_offline_minutes"` // 主控失联多久后停掉工作负载
}

// Event 是让位、崩溃这类值得记一笔的事。
type Event struct {
	Node   string `json:"node"`
	Kind   string `json:"kind"` // yield / resume / crash / start_failed / health_failed
	Detail string `json:"detail"`
}

// Defaults 填上没给的字段，探针和主控用同一套默认值。
func (d DesiredState) Defaults() DesiredState {
	if d.InputIdleSeconds <= 0 {
		d.InputIdleSeconds = 300
	}
	if d.HeartbeatSeconds <= 0 {
		d.HeartbeatSeconds = 10
	}
	if d.MaxOfflineMins <= 0 {
		d.MaxOfflineMins = 30
	}
	return d
}
