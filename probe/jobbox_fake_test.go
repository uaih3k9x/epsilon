package probe

import (
	"context"
	"sync"

	"epsilon/jobbox"
	"epsilon/jobrun"
)

// passBox 是 Mac 上测试用的假沙箱：照常用 jobrun.Plain 跑（不换账户），审计结果和停接原因由测试指定。
type passBox struct {
	mu       sync.Mutex
	halt     string
	checks   int
	reject   string
	audit    jobbox.Summary
	auditLog []byte
	notes    []string
	killed   string // 非空：假装被沙箱按这个原因杀了
	ran      int
	retry    bool          // reject 是本机的问题
	rejectN  int           // 只拒前几次（0 = 一直拒）
	blocked  int           // 非 0：运行中先报这么多次拦截
	hold     chan struct{} // 非 nil：报完拦截等它关了再跑
}

func (b *passBox) Check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checks++
	return nil
}

func (b *passBox) Halted() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.halt
}

func (b *passBox) set(f func(b *passBox)) { b.mu.Lock(); f(b); b.mu.Unlock() }

func (b *passBox) Run(ctx context.Context, j jobbox.Job) (jobbox.Result, error) {
	b.mu.Lock()
	reject, audit, auditLog, notes, killed := b.reject, b.audit, b.auditLog, b.notes, b.killed
	b.ran++
	if b.rejectN > 0 && b.ran > b.rejectN {
		reject = ""
	}
	retry, blocked, hold := b.retry, b.blocked, b.hold
	b.mu.Unlock()
	if reject != "" {
		return jobbox.Result{}, &jobbox.RejectError{Msg: reject, Retry: retry}
	}
	if blocked > 0 && j.OnBlocked != nil {
		j.OnBlocked(blocked)
	}
	if hold != nil {
		<-hold
	}
	r, err := jobrun.Run(ctx, jobrun.Spec{Dir: j.Dir, Interp: j.Interp, Entry: j.Entry, Timeout: j.Timeout,
		DiskMaxMB: j.DiskMaxMB, Env: j.Env, CheckEvery: j.CheckEvery})
	if killed != "" && err == nil {
		r.Killed, r.ExitCode = killed, -1
	}
	return jobbox.Result{Result: r, Audit: audit, AuditLog: auditLog, Notes: notes}, err
}
