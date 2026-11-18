package jobbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// AuditPipe 是审计管道（探针建、sitecustomize 连）。只有一个任务在跑，所以名字固定；
// 探针建第一个实例时带 FILE_FLAG_FIRST_PIPE_INSTANCE，被人抢注就建不出来、不跑。
const AuditPipe = `\\.\pipe\epsilon-audit`

// AuditMax 是回传的 audit.log 上限；超了只计数、标 truncated。
const AuditMax = 8 << 20

// maxRecord 是一条记录的上限。钩子的 args 截到 512 字节，正常一条远小于它；超了就是有人往管道里乱写。
const maxRecord = 4096

// 中止原因（jobrun.Result.Killed）。
const (
	AbortNoReady = "no-ready" // 主进程恢复运行后这么久没发就绪：钩子没装上，一行用户代码都没跑
	AbortAudit   = "audit"    // 主进程的审计连接在进程退出前断了、或者记录格式不对：视为篡改
)

// Record 是审计管道里的一行（sitecustomize 写，一行一个 JSON）。
type Record struct {
	T     float64 `json:"t"`
	Pid   int     `json:"pid"`
	PPid  int     `json:"ppid,omitempty"`
	Ev    string  `json:"ev"`
	Act   string  `json:"act,omitempty"` // block / log / count；就绪记录没有
	N     int     `json:"n,omitempty"`   // count 类：这个进程里累计多少次
	Args  string  `json:"args,omitempty"`
	IL    string  `json:"il,omitempty"`      // 就绪：完整性级别
	Dir   string  `json:"job_dir,omitempty"` // 就绪：这个进程拿到的 EPSILON_JOB_DIR
	File  string  `json:"file,omitempty"`    // 就绪：sitecustomize 的路径
	Layer string  `json:"layer,omitempty"`   // 就绪：环境层（sys.prefix）
}

// Summary 写进 summary.json 的 audit（能力 35）。
type Summary struct {
	Ready     bool           `json:"ready"`
	Blocked   int            `json:"blocked"`
	Logged    int            `json:"logged"`
	ByEvent   map[string]int `json:"by_event"`
	Truncated bool           `json:"truncated"`
}

// Log 收一个任务所有进程的审计记录：原文留到上限，计数一直记。多个连接并发写。
type Log struct {
	mu        sync.Mutex
	max       int
	buf       bytes.Buffer
	truncated bool
	ready     map[int]Record
	blocked   map[string]int
	logged    map[string]int
	counts    map[string]map[int]int // 事件 → pid → 最大累计次数
	nBlocked  int
	onBlock   func(total int) // 每拦一次调一次（锁外）；nil = 不报
}

func NewLog(max int) *Log {
	return &Log{max: max, ready: map[int]Record{}, blocked: map[string]int{}, logged: map[string]int{}, counts: map[string]map[int]int{}}
}

func parseRecord(line []byte) (Record, error) {
	if len(line) > maxRecord {
		return Record{}, fmt.Errorf("审计记录超过 %d 字节", maxRecord)
	}
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		return Record{}, fmt.Errorf("审计记录不是 JSON 对象: %v", err)
	}
	if r.Ev == "" || r.Pid <= 0 {
		return Record{}, errors.New("审计记录缺 ev 或 pid")
	}
	switch {
	case r.Ev == "ready" && r.Act == "":
	case r.Act == "block" || r.Act == "log" || r.Act == "count":
	default:
		return Record{}, fmt.Errorf("审计记录的 act %q 不认识", r.Act)
	}
	return r, nil
}

// Add 解析一行并记下来；格式不对返回错误（调用方当篡改处理）。
func (l *Log) Add(line []byte) (Record, error) {
	r, err := parseRecord(line)
	if err != nil {
		return r, err
	}
	l.mu.Lock()
	total, cb := l.add(line, r), l.onBlock
	l.mu.Unlock()
	if r.Act == "block" && cb != nil {
		cb(total)
	}
	return r, nil
}

// add 在锁里记一条，返回累计拦截次数。
func (l *Log) add(line []byte, r Record) int {
	if !l.truncated && l.buf.Len()+len(line)+1 <= l.max {
		l.buf.Write(line)
		l.buf.WriteByte('\n')
	} else {
		l.truncated = true
	}
	switch r.Act {
	case "":
		l.ready[r.Pid] = r
	case "block":
		l.blocked[r.Ev]++
		l.nBlocked++
	case "log":
		l.logged[r.Ev]++
	case "count":
		m := l.counts[r.Ev]
		if m == nil {
			m = map[int]int{}
			l.counts[r.Ev] = m
		}
		m[r.Pid] = max(m[r.Pid], r.N)
	}
	return l.nBlocked
}

// Summary 按主进程 pid 汇总。
func (l *Log) Summary(mainPid int) Summary {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Summary{ByEvent: map[string]int{}, Truncated: l.truncated}
	_, s.Ready = l.ready[mainPid]
	for ev, n := range l.blocked {
		s.Blocked += n
		s.ByEvent[ev] += n
	}
	for ev, n := range l.logged {
		s.Logged += n
		s.ByEvent[ev] += n
	}
	for ev, m := range l.counts {
		for _, n := range m {
			s.Logged += n
			s.ByEvent[ev] += n
		}
	}
	return s
}

// ReadyOf 返回某个进程的就绪记录。
func (l *Log) ReadyOf(pid int) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.ready[pid]
	return r, ok
}

// ChildReady 判断主进程起的子进程（ppid = 主进程）有没有发就绪（金丝雀查 multiprocessing）。
func (l *Log) ChildReady(mainPid int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for pid, r := range l.ready {
		if pid != mainPid && r.PPid == mainPid {
			return true
		}
	}
	return false
}

// Bytes 是要回传的 audit.log 原文。
func (l *Log) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}

// watcher 盯着一次运行的审计连接：
//   - 主进程恢复运行后 readyTimeout 内没收到它的就绪 → AbortNoReady；
//   - 主进程的连接断了、grace 内 Stop 没来（进程还在跑）→ AbortAudit；
//   - 任何连接上记录格式不对、第一条不是就绪、pid 和就绪的对不上 → AbortAudit；
//   - 就绪记录的 job_dir 不是这个任务的目录 → AbortAudit（子进程的环境块被换了，它的钩子按别的目录判）。
type watcher struct {
	log          *Log
	jobDir       string
	readyTimeout time.Duration
	grace        time.Duration
	pid          chan int
	ev           chan auditEvent
	abort        chan string
	stopped      chan struct{}
	once         sync.Once
}

type auditEvent struct {
	kind int
	pid  int
}

const (
	evReady = iota
	evClosed
	evBad
)

func newWatcher(l *Log, readyTimeout, grace time.Duration, jobDir string) *watcher {
	w := &watcher{log: l, jobDir: jobDir, readyTimeout: readyTimeout, grace: grace, pid: make(chan int, 1),
		ev: make(chan auditEvent), abort: make(chan string, 1), stopped: make(chan struct{})}
	go w.run()
	return w
}

// Abort 是给 jobrun.Spec.Abort 的：最多出一个原因。
func (w *watcher) Abort() <-chan string { return w.abort }

// Start 在进程起来（已恢复运行）后调。
func (w *watcher) Start(mainPid int) { w.pid <- mainPid }

// Stop 在进程树结束后调。可以重复调。
func (w *watcher) Stop() { w.once.Do(func() { close(w.stopped) }) }

func (w *watcher) send(e auditEvent) bool {
	select {
	case w.ev <- e:
		return true
	case <-w.stopped:
		return false
	}
}

func (w *watcher) fire(reason string) {
	select {
	case w.abort <- reason:
	default:
	}
}

// Serve 读一个连接直到 EOF。每个连接一个 goroutine。
func (w *watcher) Serve(r io.Reader) {
	br := bufio.NewReaderSize(r, maxRecord+1)
	pid := 0
	for {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			w.send(auditEvent{kind: evBad})
			return
		}
		if err != nil { // EOF（不完整的最后一行是进程被杀时写了一半，丢掉）
			if pid != 0 {
				w.send(auditEvent{kind: evClosed, pid: pid})
			}
			return
		}
		rec, perr := w.log.Add(bytes.TrimRight(line, "\r\n"))
		switch {
		case perr != nil, pid == 0 && (rec.Ev != "ready" || !sameDir(rec.Dir, w.jobDir)), pid != 0 && rec.Pid != pid:
			w.send(auditEvent{kind: evBad})
			return
		case pid == 0:
			pid = rec.Pid
			w.send(auditEvent{kind: evReady, pid: pid}) // watcher 停了也接着读，记录照样进 Log
		}
	}
}

func (w *watcher) run() {
	var main int
	select {
	case main = <-w.pid:
	case <-w.stopped:
		return
	}
	deadline := time.NewTimer(w.readyTimeout)
	defer deadline.Stop()
	var grace <-chan time.Time
	for {
		select {
		case e := <-w.ev:
			switch {
			case e.kind == evBad:
				w.fire(AbortAudit)
			case e.kind == evReady && e.pid == main:
				deadline.Stop()
			case e.kind == evClosed && e.pid == main:
				grace = time.After(w.grace)
			}
		case <-deadline.C:
			if _, ok := w.log.ReadyOf(main); !ok {
				w.fire(AbortNoReady)
			}
		case <-grace:
			w.fire(AbortAudit)
		case <-w.stopped:
			return
		}
	}
}
