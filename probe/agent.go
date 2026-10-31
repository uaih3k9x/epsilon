package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"epsilon/proto"
)

// System 是对本机的观测，测试里换成假的。
type System interface {
	IdleSeconds() int    // 键鼠空闲秒数；-1 = 拿不到
	GPUs() []proto.GPU   // nvidia-smi
	ComputeApps() string // nvidia-smi --query-compute-apps 原始输出
	MemFreeMB() int
	DiskMB(path string) (total, free int64) // path 所在盘；拿不到就 0, 0
}

type Agent struct {
	cfg     Config
	sys     System
	sup     *Supervisor
	client  *http.Client
	version string

	desired    proto.DesiredState
	registered atomic.Bool // 拉取的 goroutine 收到 have 409 也会置 false
	lastOK     time.Time   // 最近一次心跳成功
	reason     string      // 上一轮不跑的原因，变化时记事件

	gpus    []proto.GPU
	foreign []string
	mode    Mode

	// 显存账：模型起来前后各记一次，算出"模型占多少"和"别人多占了多少"
	vram      vramBook
	gpuAt     time.Time
	gpuEvery  time.Duration // 显卡多久查一次（nvidia-smi 不便宜）
	lastBeat  time.Time
	beatEvery time.Duration // 0 = 按期望状态里的 HeartbeatSeconds

	maxOfflineUnit time.Duration // MaxOfflineMins 的单位，测试里缩短

	// 离线确认（docs/boot.md）：跑起来后持续 offlineAfter，联系主控的失败全是网络层的，也算这个版本能用
	offlineAfter time.Duration
	startedAt    time.Time
	netFailed    bool // 登记/心跳出现过网络层失败
	httpFailed   bool // 主控明确回过错误：这次启动只认心跳成功

	Boot     string // 引导器版本/槽位，原样上报
	OnOnline func() // 第一次心跳成功（或离线确认）时调一次：告诉引导器"这个版本能用"
	LogPath  string // 探针自己的日志；主控要日志时一起传

	logMax, workloadLogMax int64     // 日志轮转上限（logrotate.go）
	rotatedAt              time.Time // 上次查日志大小

	usageEvery    time.Duration // 分项占用多久算一次（disk.go）
	usageStarted  time.Time
	usageBusy     atomic.Bool
	umu           sync.Mutex // 以下和后台统计共享
	usage         map[string]int64
	usageAt       time.Time
	usageComplete bool

	logDone atomic.Int64 // 已经传过的日志请求号
	logBusy atomic.Bool  // 正在传，别重复开

	// P2P 分发（docs/p2p.md）。块缓存和拼装在 chunk 包里，由 main 注入；Chunks 为 nil 时期望状态里的 artifacts 永远备不齐。
	Chunks   ChunkStore
	Assemble func(m proto.Manifest, root string) error // 块齐了按清单拼成文件落到 root 下
	Ready    func(m proto.Manifest, root string) bool  // 拼好的文件还在、和清单一致（只看 stat 和校验戳）

	upload    *limiter // 分块服务上传限速，跟着期望状态走
	p2pSrv    *http.Server
	p2pPort   int          // 分块服务实际端口；0 = 没开
	p2pClient *http.Client // 取块用：块有 64 MiB，不能套 10 秒总超时，靠 sourceTimeout

	fetchParallel int           // 并发取块数
	sourceTimeout time.Duration // 单个来源多久没给完一块就换下一个
	retryUnit     time.Duration // retry_after_seconds 的单位，测试里缩短
	fetchRetry    time.Duration // 一次拉取失败后多久再来

	// 以下只在 Step 里碰
	wantArts []string             // 上次看到的期望 artifacts，变了才重新核对
	wantPre  []string             // 上次看到的期望预热
	ready    map[string]bool      // 已备齐的制品（缓存：只在期望变化、拉取结束时更新）
	jobs     map[string]*fetchJob // 正在后台拉的
	failedAt map[string]time.Time // 上次拉失败的时间，过 fetchRetry 再来
	lastErr  map[string]string    // 上次失败的原因，一样就不再发事件

	fetchCtx  context.Context // Shutdown 时取消全部后台拉取
	stopFetch context.CancelFunc

	fmu       sync.Mutex // 以下和后台拉取共享
	wanted    []string
	manifests map[string]proto.Manifest
	results   []fetchResult

	hmu              sync.Mutex // /v1/have 一次一个，没报出去的攒着
	haveAdd, haveDel []string
}

func NewAgent(cfg Config, sys System, version string) *Agent {
	a := &Agent{cfg: cfg, sys: sys, sup: NewSupervisor(), version: version,
		client: &http.Client{Timeout: 10 * time.Second}, desired: proto.DesiredState{}.Defaults(),
		lastOK: time.Now(), maxOfflineUnit: time.Minute, offlineAfter: time.Minute, gpuEvery: 5 * time.Second,
		vram: vramBook{grace: 30 * time.Second}, upload: newLimiter(), p2pClient: &http.Client{},
		fetchParallel: 4, sourceTimeout: 30 * time.Second, retryUnit: time.Second, fetchRetry: time.Minute, logMax: ProbeLogMax, workloadLogMax: WorkloadLogMax, usageEvery: 10 * time.Minute,
		ready: map[string]bool{}, jobs: map[string]*fetchJob{}, failedAt: map[string]time.Time{}, lastErr: map[string]string{},
		manifests: map[string]proto.Manifest{}}
	a.fetchCtx, a.stopFetch = context.WithCancel(context.Background())
	return a
}

// Run 每 step 看一次要不要让位（便宜：只读键鼠空闲），显卡每 5 秒查一次，心跳按间隔发。
func (a *Agent) Run(stop <-chan struct{}, step time.Duration) {
	t := time.NewTicker(step)
	defer t.Stop()
	for {
		a.Step(time.Now())
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

func (a *Agent) Step(now time.Time) {
	if a.startedAt.IsZero() {
		a.startedAt = now
	}
	if !a.registered.Load() {
		a.register()
	}
	if now.Sub(a.gpuAt) >= a.gpuEvery {
		a.gpus = a.sys.GPUs()
		a.foreign = ForeignApps(a.sys.ComputeApps(), a.sup.Status().PID, a.cfg.GPUIgnore...)
		a.gpuAt = now
	}
	st := a.sup.Status()
	if st.Healthy && a.vram.loaded == 0 { // 刚健康：手上的显卡读数可能是加载前的，马上重读
		a.gpus, a.gpuAt = a.sys.GPUs(), now
	}
	a.vram.observe(st, a.gpus, now)
	obs := Observed{Now: now, IdleSeconds: a.sys.IdleSeconds(), ForeignGPU: a.foreign,
		ForeignVRAMMB: a.vram.foreign(st, a.gpus, now), VRAMShort: a.vram.short(a.gpus, a.desired.ForeignVRAMMB),
		ControllerOK: now.Sub(a.lastOK) < time.Duration(a.desired.MaxOfflineMins)*a.maxOfflineUnit}
	mode, why := Decide(a.desired, obs)
	w, known := a.cfg.Workloads[a.desired.Workload]
	if mode != Stop && !known {
		mode, why = Stop, "unknown_workload"
	}
	if !a.artifactsReady(now) && mode != Stop { // 不跑的时候也要拉：趁没人用、在时段外先备好
		mode, why = Stop, "fetching"
	}
	if why == "foreign_vram" {
		a.vram.waiting = true // 卸载之后要等显存空出来才装回去
	}
	if why != a.reason {
		a.transition(a.reason, why)
		a.reason = why
	}
	a.mode = mode
	a.sup.Ensure(a.desired.Workload, w, mode != Stop)

	every := a.beatEvery
	if every == 0 {
		every = time.Duration(a.desired.HeartbeatSeconds) * time.Second
	}
	if now.Sub(a.lastBeat) >= every {
		a.lastBeat = now
		if !a.heartbeat(obs) && every > 2*time.Second {
			a.lastBeat = now.Add(2*time.Second - every) // 失败了 2 秒后再试，不用等满一个间隔
		}
		for _, e := range a.sup.DrainEvents() {
			a.sendEvent(e)
		}
	}
	a.rotateLogs(now)
	a.startUsage(now)
	// 走到这里说明主循环在正常跑
	if a.OnOnline != nil && a.netFailed && !a.httpFailed && now.Sub(a.startedAt) >= a.offlineAfter {
		log.Printf("主控连不上，按网络故障离线确认")
		a.online()
	}
}

// online 告诉引导器这个版本能用，只调一次。
func (a *Agent) online() {
	if a.OnOnline != nil {
		a.OnOnline()
		a.OnOnline = nil
	}
}

// contactFailed 给登记/心跳的失败归类，供离线确认用。409 不算失败。
func (a *Agent) contactFailed(err error) {
	switch {
	case err == errUnknownNode:
	case isNetErr(err):
		a.netFailed = true
	case !a.httpFailed:
		a.httpFailed = true
		if a.OnOnline != nil {
			log.Printf("主控回了错误，这次启动只认心跳成功、不走离线确认: %v", err)
		}
	}
}

// isNetErr：没拿到主控的 HTTP 回答——连不上、拒绝连接、DNS 失败、超时、连上就断。
// 主控回了状态码（401/404/5xx 等）、回包解析不了都不算。
func isNetErr(err error) bool {
	var op *net.OpError
	var dns *net.DNSError
	var ne net.Error
	switch {
	case err == nil:
		return false
	case errors.As(err, &op), errors.As(err, &dns):
		return true
	case errors.As(err, &ne) && ne.Timeout(): // *url.Error 也是 net.Error，只认超时
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

var yieldReason = map[string]bool{"user_active": true, "foreign_gpu": true, "foreign_vram": true,
	"vram_short": true, "controller_lost": true}

// vramBook 记显存账。都按第一张卡算（学生机只有一张）。
type vramBook struct {
	pid     int // 记账时的工作负载进程
	before  int // 起模型之前已用显存（桌面等）
	base    int // 上一次装模型时的桌面基线，卸载后用它判断"别人还占着没"
	loaded  int // 模型健康后的已用显存（稳定期内取最大值）
	model   int // 模型自己占多少 = loaded - before
	waiting bool

	healthyAt time.Time
	grace     time.Duration // 健康后这段时间显存还在涨（KV 缓存等），只记账不判"别人占"
}

func usedMB(g []proto.GPU) (used, total int) {
	if len(g) == 0 {
		return 0, 0
	}
	return g[0].MemUsed, g[0].MemTotal
}

func (v *vramBook) observe(st WorkloadStatus, g []proto.GPU, now time.Time) {
	used, _ := usedMB(g)
	switch {
	case st.PID == 0: // 没在跑：持续刷新"起模型之前"的读数（等显存时不刷，免得把游戏算进基线）
		v.pid, v.loaded = 0, 0
		if !v.waiting {
			v.before = used
		}
	case st.PID != v.pid: // 新进程
		v.pid, v.loaded = st.PID, 0
	case st.Healthy && v.loaded == 0 && used > 0: // 刚健康，记下模型占用
		v.loaded, v.base, v.healthyAt = used, v.before, now
	case v.loaded > 0 && now.Sub(v.healthyAt) < v.grace && used > v.loaded: // 稳定期：只涨不跌
		v.loaded = used
	}
	if v.loaded > v.before {
		v.model = v.loaded - v.before
	}
}

// foreign: 别人比模型刚加载好时多占的显存；没在跑或还没记账 = -1。
func (v *vramBook) foreign(st WorkloadStatus, g []proto.GPU, now time.Time) int {
	used, _ := usedMB(g)
	if st.PID == 0 || v.loaded == 0 || used == 0 || now.Sub(v.healthyAt) < v.grace {
		return -1
	}
	return used - v.loaded
}

// short: 因显存被占卸载过，要等别人放掉（比装模型时的桌面基线多占的降到阈值以下）、
// 且空闲显存装得下模型（留 512 MB 余量）才解除；不然卸了马上又装回来，白卸还来回抖。
func (v *vramBook) short(g []proto.GPU, threshold int) bool {
	if !v.waiting {
		return false
	}
	used, total := usedMB(g)
	if total > 0 && used-v.base < threshold && total-used >= v.model+512 {
		v.waiting = false
	}
	return v.waiting
}

// transition 记让位 / 恢复事件；"没有工作负载"之类的平常状态不记。
func (a *Agent) transition(from, to string) {
	switch {
	case yieldReason[to]:
		a.sendEvent(proto.Event{Kind: "yield", Detail: to})
	case to == "" && yieldReason[from]:
		a.sendEvent(proto.Event{Kind: "resume", Detail: "from " + from})
	case to == "":
		a.sendEvent(proto.Event{Kind: "start", Detail: a.desired.Workload})
	}
}

func (a *Agent) register() {
	host, _ := os.Hostname()
	names := make([]string, 0, len(a.cfg.Workloads))
	for n := range a.cfg.Workloads {
		names = append(names, n)
	}
	req := proto.Register{Node: a.cfg.Node, Version: a.version, Boot: a.Boot, Hostname: host,
		GPUs: a.sys.GPUs(), MemoryMB: a.sys.MemFreeMB(), Workload: names, P2PPort: a.p2pPort}
	if a.Chunks != nil {
		req.Chunks = a.Chunks.List() // 主控以此重置这台的块表，之后靠 /v1/have 增量
	}
	if err := a.post("/v1/register", req, nil); err != nil {
		log.Printf("登记失败: %v", err)
		a.contactFailed(err)
		return
	}
	a.registered.Store(true)
}

func (a *Agent) heartbeat(obs Observed) bool {
	st := a.sup.Status()
	hb := proto.Heartbeat{Node: a.cfg.Node, Version: a.version, Boot: a.Boot, IdleSeconds: obs.IdleSeconds,
		ForeignGPU: obs.ForeignGPU, GPUs: a.gpus, MemFreeMB: a.sys.MemFreeMB(),
		Running: st.Name, Reason: a.reason, Disk: a.disk()}
	if st.Healthy && a.mode == Run { // 保温档：模型在显存里，但不接新请求
		hb.Serving = &proto.Serving{Model: st.Model, Port: st.Port}
	}
	var d proto.DesiredState
	if err := a.post("/v1/heartbeat", hb, &d); err != nil {
		log.Printf("心跳失败: %v", err)
		a.contactFailed(err)
		if err == errUnknownNode {
			a.registered.Store(false)
		}
		return false
	}
	a.desired = d.Defaults()
	a.upload.setMbps(d.P2PUploadMbps)
	if d.LogRequest != 0 && d.LogRequest != a.logDone.Load() && a.logBusy.CompareAndSwap(false, true) {
		go a.uploadLogs(d.LogRequest)
	}
	a.lastOK = time.Now()
	a.online()
	return true
}

func (a *Agent) sendEvent(e proto.Event) {
	e.Node = a.cfg.Node
	if err := a.post("/v1/events", e, nil); err != nil {
		log.Printf("事件没发出去 %s %s: %v", e.Kind, e.Detail, err)
	}
}

var errUnknownNode = fmt.Errorf("主控不认识这台机器（重启过？）")

func (a *Agent) post(path string, body, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, a.cfg.Controller+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
	r, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode == http.StatusConflict {
		return errUnknownNode
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, r.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(r.Body).Decode(out); err != nil {
			return fmt.Errorf("%s: 回包解析: %v", path, err) // %v：不让 io.EOF 被当成网络错误
		}
	}
	return nil
}

// Shutdown 退出前停掉工作负载、后台拉取和分块服务。
func (a *Agent) Shutdown() {
	a.stopFetch()
	if a.p2pSrv != nil {
		a.p2pSrv.Close()
	}
	a.sup.Stop()
}

// uploadLogs 把探针日志和各工作负载日志的末尾（每个最多 64 KB）传给主控。传成功才算处理过，失败了下次心跳再传。
func (a *Agent) uploadLogs(req int64) {
	defer a.logBusy.Store(false)
	files := map[string]string{}
	add := func(path string) {
		if t := tailFile(path, 64<<10); t != "" {
			files[filepath.Base(path)] = t
		}
	}
	add(a.LogPath)
	for _, w := range a.cfg.Workloads {
		add(w.Log)
	}
	if err := a.post("/v1/logs", proto.Logs{Node: a.cfg.Node, Request: req, Files: files}, nil); err != nil {
		log.Printf("日志没传上去（下次心跳再传）: %v", err)
		return
	}
	a.logDone.Store(req)
}
