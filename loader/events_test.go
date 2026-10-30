package loader

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"epsilon/boot"
)

func line(kind, detail string) string {
	b, _ := json.Marshal(boot.Event{Time: "2026-10-30T08:00:00Z", Kind: kind, Detail: detail})
	return string(b) + "\n"
}

func (e *env) appendEvents(s string) {
	f, err := os.OpenFile(filepath.Join(e.l.Root, boot.EventsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		e.t.Fatal(err)
	}
	f.WriteString(s)
	f.Close()
}

func (e *env) sent() int64 {
	b, err := os.ReadFile(filepath.Join(e.l.Root, SentFile))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (e *env) kinds() []string {
	e.ctl.mu.Lock()
	defer e.ctl.mu.Unlock()
	var k []string
	for _, ev := range e.ctl.events {
		if ev.Node != "pc-test" {
			e.t.Fatalf("事件 node = %q", ev.Node)
		}
		k = append(k, ev.Kind)
	}
	return k
}

func (e *env) forward() error { return e.l.ForwardEvents(context.Background()) }

func TestForwardNoFile(t *testing.T) {
	e := newEnv(t)
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if len(e.kinds()) != 0 {
		t.Fatal("没文件也发了事件")
	}
}

// 只转发完整的行；半行等 boot 写完再发。
func TestForwardCompleteLines(t *testing.T) {
	e := newEnv(t)
	a, b := line("boot_rollback", "回到 A"), line("boot_slot_bad", "槽 B 坏了")
	e.appendEvents(a + b[:10])
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 1 || k[0] != "boot_rollback" {
		t.Fatalf("发了 %v", k)
	}
	if e.sent() != int64(len(a)) {
		t.Fatalf("偏移 %d，应为 %d", e.sent(), len(a))
	}
	e.appendEvents(b[10:])
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 2 || k[1] != "boot_slot_bad" {
		t.Fatalf("发了 %v", k)
	}
	if e.sent() != int64(len(a+b)) {
		t.Fatalf("偏移 %d", e.sent())
	}
	// 再来一次不重发
	if err := e.forward(); err != nil || len(e.kinds()) != 2 {
		t.Fatalf("重发了: %v %v", err, e.kinds())
	}
	e.ctl.mu.Lock()
	d := e.ctl.events[0].Detail
	e.ctl.mu.Unlock()
	if !strings.Contains(d, "回到 A") || !strings.Contains(d, "2026-10-30T08:00:00Z") {
		t.Fatalf("detail = %q，要带原文和 boot 记的时间", d)
	}
}

func TestForwardFailureKeepsOffset(t *testing.T) {
	e := newEnv(t)
	e.appendEvents(line("boot_rollback", "x") + line("boot_staged", "y"))
	e.ctl.evFail = true
	if err := e.forward(); err == nil {
		t.Fatal("主控 500 应该报错")
	}
	if e.sent() != 0 {
		t.Fatalf("失败了还推进偏移到 %d", e.sent())
	}
	e.ctl.mu.Lock()
	e.ctl.evFail = false
	e.ctl.mu.Unlock()
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 2 {
		t.Fatalf("发了 %v", k)
	}
}

// 发到一半失败：已发的那条算数，后面的下次再发。
func TestForwardPartialFailure(t *testing.T) {
	e := newEnv(t)
	a := line("one", "1")
	e.appendEvents(a + line("two", "2"))
	e.ctl.evFailKind = "two"
	if err := e.forward(); err == nil {
		t.Fatal("应该报错")
	}
	if e.sent() != int64(len(a)) {
		t.Fatalf("偏移 %d，应为 %d", e.sent(), len(a))
	}
	e.ctl.mu.Lock()
	e.ctl.evFailKind = ""
	e.ctl.mu.Unlock()
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 2 || k[0] != "one" || k[1] != "two" {
		t.Fatalf("发了 %v", k)
	}
}

// 文件比偏移短 = 被轮转了，从 0 开始。
func TestForwardRotated(t *testing.T) {
	e := newEnv(t)
	e.appendEvents(line("old1", "x") + line("old2", "y") + line("old3", "z"))
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	os.Rename(filepath.Join(e.l.Root, boot.EventsFile), filepath.Join(e.l.Root, boot.EventsFile+".1"))
	nl := line("new", "n")
	e.appendEvents(nl)
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 4 || k[3] != "new" {
		t.Fatalf("发了 %v", k)
	}
	if e.sent() != int64(len(nl)) {
		t.Fatalf("偏移 %d", e.sent())
	}
}

// 坏行跳过，不然会永远卡在那。
func TestForwardSkipsGarbage(t *testing.T) {
	e := newEnv(t)
	all := "不是 json\n" + line("ok", "x")
	e.appendEvents(all)
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 1 || k[0] != "ok" {
		t.Fatalf("发了 %v", k)
	}
	if e.sent() != int64(len(all)) {
		t.Fatalf("偏移 %d", e.sent())
	}
}

// Run 一轮里既备版本又转事件，ctx 取消就返回。
func TestRun(t *testing.T) {
	e := newEnv(t)
	e.appendEvents(line("boot_rollback", "x"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.l.Run(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := e.staged(); ok && len(e.kinds()) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run 第一轮没备好版本或没转事件")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("取消后 Run 没返回")
	}
}

// 轮转后新文件在 loader 回来之前就长过了旧偏移：偏移前一个字节不是换行，说明不是同一个文件，从 0 读。
func TestForwardRotatedAndRegrown(t *testing.T) {
	e := newEnv(t)
	e.appendEvents(line("old", "x"))
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	old := e.sent()
	os.Rename(filepath.Join(e.l.Root, boot.EventsFile), filepath.Join(e.l.Root, boot.EventsFile+".1"))
	e.appendEvents(line("new1", strings.Repeat("长", 20)) + line("new2", "y")) // 比旧偏移长，且旧偏移落在行中间
	if b, _ := os.ReadFile(filepath.Join(e.l.Root, boot.EventsFile)); b[old-1] == '\n' {
		t.Fatal("测试数据没造好：旧偏移前一个字节恰好是换行")
	}
	if err := e.forward(); err != nil {
		t.Fatal(err)
	}
	if k := e.kinds(); len(k) != 3 || k[1] != "new1" || k[2] != "new2" {
		t.Fatalf("应从头发 new1 new2，发了 %v", k)
	}
}
