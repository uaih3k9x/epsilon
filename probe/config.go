package probe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"epsilon/proto"
)

// Workload 只在本机配置里定义：主控只能挑名字，不能指定程序和参数。
type Workload struct {
	Exe             string   `json:"exe"`
	Args            []string `json:"args"`
	Dir             string   `json:"dir"`
	Port            int      `json:"port"`
	Model           string   `json:"model"`  // 对外报的模型名，路由按它分流
	Health          string   `json:"health"` // 健康检查路径；"tcp" = 端口能连上就算健康；"none" = 进程活着就算（rpc-server 只服务一个客户端，连它会添乱）
	StartTimeoutSec int      `json:"start_timeout_sec"`
	Log             string   `json:"log"` // 工作负载的输出存这里；默认放在 probe.json 旁边的 <名字>.log
	env             []string // 额外环境变量，测试用
}

type Config struct {
	Node       string              `json:"node"`
	Controller string              `json:"controller"`
	Token      string              `json:"token"`
	Workloads  map[string]Workload `json:"workloads"`
	GPUIgnore  []string            `json:"gpu_ignore"` // 追加到内置的显卡进程忽略名单

	// 第 2 阶段 P2P 分发（docs/p2p.md）。相对路径按 probe.json 所在目录算。
	ArtifactRoot string `json:"artifact_root"`  // 制品拼好后落到这里；默认 probe.json 所在目录
	ChunkDir     string `json:"chunk_dir"`      // 块缓存；默认 <artifact_root>/chunks，相对路径按 artifact_root 算
	ChunkQuotaGB int64  `json:"chunk_quota_gb"` // 块缓存配额；默认 100
	P2PPort      int    `json:"p2p_port"`       // 分块服务端口；没写 = 47100，写 0 = 不开
}

// LoadConfig 读本机配置；extra 是引导器槽里随本体发布的工作负载表，同名的覆盖本机配置，文件不存在就跳过。
func LoadConfig(path string, extra ...string) (Config, error) {
	c := Config{P2PPort: 47100} // 先填默认值：JSON 里没写的字段保持不动，写了 0 才是 0
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Workloads == nil {
		c.Workloads = map[string]Workload{}
	}
	for _, p := range extra {
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		var more map[string]Workload
		if err == nil {
			err = json.Unmarshal(b, &more)
		}
		if err != nil {
			return c, fmt.Errorf("%s: %w", p, err)
		}
		for name, w := range more {
			c.Workloads[name] = w
		}
	}
	c.Controller = strings.TrimRight(c.Controller, "/")
	if c.Controller == "" {
		return c, fmt.Errorf("%s: 没写 controller", path)
	}
	if c.Node == "" {
		c.Node, _ = os.Hostname()
	}
	c.ArtifactRoot = under(filepath.Dir(path), c.ArtifactRoot)
	if c.ChunkDir == "" {
		c.ChunkDir = "chunks"
	}
	c.ChunkDir = under(c.ArtifactRoot, c.ChunkDir)
	if c.ChunkQuotaGB <= 0 {
		c.ChunkQuotaGB = 100
	}
	for name, w := range c.Workloads {
		if w.Exe == "" || w.Port == 0 {
			return c, fmt.Errorf("%s: 工作负载 %s 缺 exe 或 port", path, name)
		}
		if w.Health == "" {
			w.Health = "/health"
		}
		if w.StartTimeoutSec <= 0 {
			w.StartTimeoutSec = 300 // 大模型从机械盘加载可能要几分钟
		}
		if w.Log == "" {
			w.Log = filepath.Join(filepath.Dir(path), name+".log")
		}
		if w.Model == "" {
			w.Model = name
		}
		c.Workloads[name] = w
	}
	return c, nil
}

// under: 空 = base；相对路径接在 base 下面（开机自启时工作目录不可靠）。
func under(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// ParseGPUs 解析 nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw --format=csv,noheader,nounits
func ParseGPUs(out string) []proto.GPU {
	var gpus []proto.GPU
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := splitCSV(line)
		if len(f) != 6 {
			continue
		}
		gpus = append(gpus, proto.GPU{Name: f[0], Util: num(f[1]), MemUsed: num(f[2]),
			MemTotal: num(f[3]), TempC: num(f[4]), PowerW: num(f[5])})
	}
	return gpus
}

// gpuIgnore 是判断"别的程序在用显卡"时不算数的进程（文件名，比较时不区分大小写）。
// Windows WDDM 下 nvidia-smi 会把桌面进程（C+G）也列出来，不滤掉就一直让位。
var gpuIgnore = []string{
	"explorer.exe",                // 资源管理器/桌面
	"dwm.exe",                     // 桌面窗口管理器
	"csrss.exe",                   // 系统进程
	"SearchHost.exe",              // 搜索（Win11）
	"SearchApp.exe",               // 搜索（Win10）
	"SearchUI.exe",                // 搜索/小娜（旧版 Win10）
	"StartMenuExperienceHost.exe", // 开始菜单
	"ShellExperienceHost.exe",     // 任务栏/通知中心
	"ShellHost.exe",               // 快速设置（Win11）
	"TextInputHost.exe",           // 触摸键盘/输入面板
	"ctfmon.exe",                  // 输入法
	"ChsIME.exe",                  // 微软拼音
	"LockApp.exe",                 // 锁屏
	"LogonUI.exe",                 // 登录界面
	"Widgets.exe",                 // 小组件
	"WidgetService.exe",           // 小组件
	"ApplicationFrameHost.exe",    // UWP 窗口框架
	"SystemSettings.exe",          // 设置
	"PhoneExperienceHost.exe",     // 手机连接
	"GameBar.exe",                 // Xbox Game Bar
	"GameBarFTServer.exe",         // Xbox Game Bar
	"GameBarPresenceWriter.exe",   // Xbox Game Bar
	"XboxGameBarWidgets.exe",      // Xbox Game Bar
	"NVIDIA Overlay.exe",          // NVIDIA 叠加层
	"NVIDIA Share.exe",            // NVIDIA 叠加层（旧名）
	"NVIDIA Web Helper.exe",       // NVIDIA 应用
	"NVIDIA app.exe",              // NVIDIA 应用
	"nvcontainer.exe",             // NVIDIA 容器
	"NVDisplay.Container.exe",     // NVIDIA 显示容器
	"nvsphelper64.exe",            // NVIDIA 叠加层
	// 浏览器算轻度使用，由分级让位的"降档"去管，不在这里触发让位。
	"msedge.exe",         // Edge
	"msedgewebview2.exe", // WebView2（很多应用内嵌）
	"chrome.exe",         // Chrome
	"firefox.exe",        // Firefox
	"360se.exe",          // 360 安全浏览器
	"360chrome.exe",      // 360 极速浏览器
	"QQBrowser.exe",      // QQ 浏览器
	"SogouExplorer.exe",  // 搜狗浏览器
	"opera.exe",          // Opera
	"brave.exe",          // Brave
}

// ForeignApps 解析 nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits，
// 去掉自己的工作负载、内置忽略名单和 ignore 里的进程，返回其他在用显卡的进程名。显存是 [N/A] 也照算。
func ForeignApps(out string, ownPID int, ignore ...string) []string {
	skip := map[string]bool{}
	for _, n := range append(gpuIgnore, ignore...) {
		skip[strings.ToLower(n)] = true
	}
	var apps []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := splitCSV(line)
		if len(f) != 3 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid == ownPID {
			continue
		}
		name := f[1]
		if i := strings.LastIndexAny(name, `\/`); i >= 0 {
			name = name[i+1:]
		}
		if skip[strings.ToLower(name)] {
			continue
		}
		apps = append(apps, name)
	}
	return apps
}

func splitCSV(line string) []string {
	f := strings.Split(line, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

func num(s string) int {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int(v)
}
