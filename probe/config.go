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
}

// LoadConfig 读本机配置；extra 是引导器槽里随本体发布的工作负载表，同名的覆盖本机配置，文件不存在就跳过。
func LoadConfig(path string, extra ...string) (Config, error) {
	var c Config
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

// ForeignApps 解析 nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits，
// 去掉自己的工作负载，返回其他在用显卡的进程名。Windows WDDM 下可能全是 [N/A]，那就当没有。
func ForeignApps(out string, ownPID int) []string {
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
