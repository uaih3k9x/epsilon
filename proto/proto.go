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
	Workload []string `json:"workloads"`          // 本机配置里允许跑的工作负载名
	P2PPort  int      `json:"p2p_port,omitempty"` // 本机分块服务端口；0 = 不提供
	Chunks   []string `json:"chunks,omitempty"`   // 登记时本地已有的全部块（之后用 /v1/have 增量报）
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
	MaxOfflineMins   int      `json:"max_offline_minutes"`       // 主控失联多久后停掉工作负载
	Artifacts        []string `json:"artifacts,omitempty"`       // 当前工作负载要用的制品（manifest ID）；没备齐前不起工作负载
	Preload          []string `json:"preload,omitempty"`         // 预热：后台拉进本地缓存但不拼文件、不影响工作负载；排在 Artifacts 之后拉
	LogRequest       int64    `json:"log_request,omitempty"`     // 非 0 且和上次处理过的不同：把日志末尾经 POST /v1/logs 传上来
	P2PUploadMbps    int      `json:"p2p_upload_mbps,omitempty"` // 分块服务上传限速；0 = 不限
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

// ---- 第 2 阶段：教室内 P2P 分块分发（契约见 docs/p2p.md）----

// Manifest 描述一个制品（比如一个模型）：由哪些文件组成、每个文件切成哪些块。块 ID = 块内容的 sha256（小写十六进制）。
type Manifest struct {
	ID        string         `json:"id"`         // 如 "qwen3.5-4b-q4km"
	ChunkSize int64          `json:"chunk_size"` // 字节；最后一块可以更小
	Files     []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Path   string   `json:"path"` // 相对路径，正斜杠，不许 .. 和绝对路径；落到探针的 artifact_root 下
	Size   int64    `json:"size"`
	SHA256 string   `json:"sha256"` // 整个文件
	Chunks []string `json:"chunks"` // 按顺序
}

// Have 是探针增量报告本地块缓存的变化（每存好一块就报，淘汰了也报）。
type Have struct {
	Node string   `json:"node"`
	Add  []string `json:"add,omitempty"`
	Del  []string `json:"del,omitempty"`
}

// Peers 是 GET /v1/peers?manifest=&node= 的回复：每个块去哪拿，按优先级排好（同交换机 > 同教室 > 其他 > 主控）。
// 来源是 "http://ip:port" 形式的邻居地址；空字符串 "" 表示主控自己（走 GET /v1/chunks/{hash}）。
// 某块的列表为空 = 现在没人能给你，过 RetryAfterSeconds 再问（种子还在拉）。
type Peers struct {
	Sources           map[string][]string `json:"sources"`
	RetryAfterSeconds int                 `json:"retry_after_seconds,omitempty"`
}

// Logs 是探针应主控要求（DesiredState.LogRequest）传上来的日志末尾：文件名 → 末尾若干字节。
type Logs struct {
	Node    string            `json:"node"`
	Request int64             `json:"request"`
	Files   map[string]string `json:"files"`
}
