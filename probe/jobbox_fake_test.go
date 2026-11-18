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
	b.mu.Unlock()
	if reject != "" {
		return jobbox.Result{}, &jobbox.RejectError{Msg: reject}
	}
	r, err := jobrun.Run(ctx, jobrun.Spec{Dir: j.Dir, Interp: j.Interp, Entry: j.Entry, Timeout: j.Timeout,
		DiskMaxMB: j.DiskMaxMB, Env: j.Env, CheckEvery: j.CheckEvery})
	if killed != "" && err == nil {
		r.Killed, r.ExitCode = killed, -1
	}
	return jobbox.Result{Result: r, Audit: audit, AuditLog: auditLog, Notes: notes}, err
}
