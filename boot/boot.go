package boot

// 断电安全的总原则（每个写盘点的注释都按这三条论证）：
//  1. 每次写盘是单个原子动作：state 用"临时文件 → 刷盘 → 改名"，删文件、改名本身原子；
//  2. 多步操作排成"任意一步之后断电，重启后从磁盘状态重来，结果一样"；
//  3. 拿不准就不动：state 读不出或写不进去时不改东西、不启动本体，等下一轮。

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// MaxTries 是新版本最多试启动几次，到了就回退（有退路时）。
const MaxTries = 3

const eventsMax = 1 << 20 // boot-events.jsonl 超过它就轮转成 .1

// Proc 是跑起来的本体。
type Proc interface {
	Exited() <-chan struct{}
	Kill()
}

// State 存在 <Root>\boot-state.json，只有 boot 写（docs/boot.md）。
type State struct {
	Current  string            `json:"current"`  // 已确认能用的槽
	Pending  string            `json:"pending"`  // 待试的槽
	Tries    int               `json:"tries"`    // 待试槽已经试了几次（先记再启动，防断电）
	Good     string            `json:"good"`     // 上一个好槽
	Bad      string            `json:"bad"`      // 试过不行的版本
	Versions map[string]string `json:"versions"` // 槽 -> boot 认定的版本
}

// Boot 只做本地事：消费 staged.json、选槽、验签、试启动、看护、转正、回退。不联网。
type Boot struct {
	Root  string
	Keys  []ed25519.PublicKey
	Start func(slotDir, confirmFile string) (Proc, error)

	ConfirmWithin time.Duration // 新版本多久内要确认
	Backoff       time.Duration // 本体退出、启动失败、没槽可跑时等多久再来
	Poll          time.Duration // 看护时多久看一次确认文件和 staged.json

	// Rescue 运行救援槽 R 里的本体（-seed：跑一轮 loader 就退出，docs/boot.md "救援槽 R"）。
	// 返回的 Proc 有 ExitCode() int 方法时，事件里记退出码。
	Rescue       func(slotDir string) (Proc, error)
	RescueWithin time.Duration // 救援最多跑多久，到了杀掉
	RescueGap    time.Duration // 两次救援至少隔多久

	lastRescue time.Time // 上次救援的时间，只记在内存里：boot 重启后可以立刻再救一次
}

func (b *Boot) path(name string) string { return filepath.Join(b.Root, name) }

func (b *Boot) state() (State, error) {
	st, err := ReadState(b.Root)
	if err != nil {
		log.Printf("读 %s: %v", StateFile, err)
	}
	return st, err
}

func (b *Boot) save(st State) error {
	raw, _ := json.MarshalIndent(st, "", "  ")
	err := writeAtomic(b.path(StateFile), raw)
	if err != nil {
		log.Printf("写 %s: %v", StateFile, err)
	}
	return err
}

// writeAtomic: 临时文件 → 刷盘 → 改名。断电后看到的要么是旧文件、要么是新文件。
// Windows 上 loader 正开着目标文件读时改名会失败，所以改名重试一会儿。
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	for i := 0; ; i++ {
		if err = os.Rename(tmp, path); err == nil || i == 9 {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// event 记 boot.log，并往 boot-events.jsonl 追加一行留给 loader 转发。写不进去只记日志，不影响引导。
func (b *Boot) event(kind, format string, a ...any) {
	detail := fmt.Sprintf(format, a...)
	log.Printf("%s: %s", kind, detail)
	line, _ := json.Marshal(Event{Time: time.Now().UTC().Format(time.RFC3339), Kind: kind, Detail: detail})
	if err := appendLine(b.path(EventsFile), line); err != nil {
		log.Printf("写 %s: %v", EventsFile, err)
	}
}

// appendLine 往文件末尾追加一行（一次 Write），超过 eventsMax 先改名为 .1（覆盖旧的）。
// 断电可能留下半行：追加前发现末尾不是换行就先补一个，坏的只有那半行。
func appendLine(path string, line []byte) error {
	if fi, err := os.Stat(path); err == nil && fi.Size() > eventsMax {
		if err := os.Rename(path, path+".1"); err != nil {
			log.Printf("轮转 %s: %v", path, err) // loader 正开着就下次再轮转，这次照常追加
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		last := []byte{0}
		if _, err := f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func sumFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

// check 验槽（签名、min_boot、文件哈希），并核对清单版本 == state 记的版本。
// 版本对不上说明 loader 往里写过新东西，不能当已确认的版本跑（docs/boot.md "回退时核对版本"）。
func (b *Boot) check(st State, slot string) error {
	m, err := VerifySlot(b.path(slot), b.Keys)
	if err == nil && m.Version != st.Versions[slot] {
		err = fmt.Errorf("槽里是 %s，记的是 %q", m.Version, st.Versions[slot])
	}
	return err
}

// consumeStaged 按 docs/boot.md 第 1–4 步处理 loader 留下的 staged.json。
// 返回 true 表示 pending 现在指向它，调用方要（停掉本体）重新选槽。
//
// 断电安全：先写 state，再删 staged.json。
//   - 写 state 前断电：staged.json 还在、state 是旧的，重启后整个重来；
//   - 写完 state、删 staged.json 前断电：重启后看到 pending==slot 且版本一致，只删 staged.json，
//     不重置 tries（否则每次试启动都断电就能无限试下去）；
//   - 拒绝只有"删 staged.json"一步，删前断电就重判一遍，结论一样（事件可能多一条）。
func (b *Boot) consumeStaged() bool {
	path := b.path(StagedFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		log.Printf("读 %s: %v", StagedFile, err) // 可能 loader 正在改名，下个周期再看
		return false
	}
	st, err := b.state()
	if err != nil {
		return false
	}
	var sg Staged
	var m Manifest
	err = json.Unmarshal(raw, &sg)
	switch {
	case err != nil:
	case sg.Slot != "A" && sg.Slot != "B":
		err = fmt.Errorf("槽 %q 不是 A/B", sg.Slot)
	case sg.Slot == st.Current:
		err = fmt.Errorf("槽 %s 是当前槽", sg.Slot)
	default:
		// 版本以槽里验过的清单为准，不信 staged.json
		if m, err = VerifySlot(b.path(sg.Slot), b.Keys); err == nil && m.Version == st.Bad {
			err = fmt.Errorf("版本 %s 试过不行", m.Version)
		}
	}
	if err != nil {
		b.event("boot_staged_rejected", "%.200s: %v", raw, err)
		os.Remove(path)
		return false
	}
	if st.Pending != sg.Slot || st.Versions[sg.Slot] != m.Version {
		st.Pending, st.Tries = sg.Slot, 0
		st.Versions[sg.Slot] = m.Version
		if st.Good == sg.Slot {
			st.Good = "" // 被覆盖了，不能再当退路
		}
		if b.save(st) != nil {
			return false // staged.json 留着，下个周期再来
		}
		b.event("boot_staged", "版本 %s（槽 %s）待试", m.Version, sg.Slot)
	}
	if err := os.Remove(path); err != nil {
		log.Printf("删 %s: %v", StagedFile, err) // 下次走上面的幂等分支再删
	}
	return true
}

// Pick 决定这次启动哪个槽；trial 表示在试新版本。返回空表示现在没东西能跑，等 Backoff 再来。
//
// 断电安全：每条路径最多写一次 state，写成功才启动。试启动先把 tries+1 写盘再启动：
// 断电也算一次，宁可早回退，也不会无限试一个起不来的版本。
func (b *Boot) Pick() (slot string, trial bool) {
	st, err := b.state()
	if err != nil {
		return "", false
	}
	if p := st.Pending; p != "" {
		if err := b.check(st, p); err != nil {
			// 文件坏了多半是本机的事（断电、杀毒），不算版本坏；丢掉待试槽，loader 会重下
			b.event("boot_slot_bad", "待试槽 %s: %v", p, err)
			st.Pending, st.Tries = "", 0
		} else if st.Tries >= MaxTries && b.hasFallback(st) {
			b.event("boot_rollback", "版本 %s（槽 %s）试了 %d 次没确认，回到 %q", st.Versions[p], p, st.Tries, st.Current)
			st.Bad, st.Pending, st.Tries = st.Versions[p], "", 0
		} else {
			if st.Tries >= MaxTries {
				st.Tries = 0 // 没有退路（首次安装、current 也坏了）：判 bad 也没别的可跑，一直试
			}
			st.Tries++
			if b.save(st) != nil {
				return "", false
			}
			return p, true
		}
		if b.save(st) != nil {
			return "", false
		}
	}
	for _, s := range []string{st.Current, st.Good} {
		if s == "" {
			continue
		}
		if err := b.check(st, s); err != nil {
			b.event("boot_slot_bad", "槽 %s: %v", s, err)
			continue
		}
		if s != st.Current {
			b.event("boot_fallback", "槽 %s 用不了，改跑上一个好版本 %s（槽 %s）", st.Current, st.Versions[s], s)
			st.Current, st.Good = s, ""
			if b.save(st) != nil {
				return "", false
			}
		}
		return s, false
	}
	return "", false
}

func (b *Boot) hasFallback(st State) bool {
	for _, s := range []string{st.Current, st.Good} {
		if s != "" && b.check(st, s) == nil {
			return true
		}
	}
	return false
}

// promote: 试启动的槽确认了，转正，原来的 current 留作 good。返回 false 表示没写成，下个周期再试。
// 断电安全：一次写 state；写之前断电，重启后再试启动一次（多记一次 tries）。
func (b *Boot) promote(slot string) bool {
	st, err := b.state()
	if err != nil {
		return false
	}
	if st.Pending != slot {
		return true // 不该发生；不是待试槽了就按普通运行看护
	}
	st.Good, st.Current = st.Current, slot
	st.Pending, st.Tries = "", 0
	if b.save(st) != nil {
		return false
	}
	b.event("boot_promoted", "版本 %s（槽 %s）转正", st.Versions[slot], slot)
	return true
}

// rescueWhy 判断该不该跑救援槽，返回原因；空表示不该（docs/boot.md "救援槽 R" 的两种情况）。
// 只读不写，state 读不出时不救（拿不准就不动）。
func (b *Boot) rescueWhy() string {
	st, err := b.state()
	switch {
	case err != nil || b.hasFallback(st):
		return ""
	case st.Pending == "" || b.check(st, st.Pending) != nil:
		return fmt.Sprintf("没有能跑的槽（current %q，good %q，pending %q）", st.Current, st.Good, st.Pending)
	case st.Current == "" && st.Tries >= MaxTries:
		return fmt.Sprintf("首次安装的版本 %s（槽 %s）试了 %d 次没确认", st.Versions[st.Pending], st.Pending, st.Tries)
	}
	return ""
}

// rescue 验 R、运行它、等它退出（最多 RescueWithin，超时杀掉）。返回 false 表示收到 stop。
//
// 断电/崩溃安全：救援这边只追加事件，不写 state、不写确认文件、不碰 R，所以
//   - 救援中断电、boot 被杀：boot 的磁盘状态和救援前一模一样，重启后重新判断（限频在内存里，会立刻再救一次）；
//     Windows 上救援进程在作业对象里，随 boot 一起走，不会和新起的 boot 同时跑；
//   - 超时或 stop 时杀掉救援进程：loader 写到一半的槽还没有 staged.json，boot 不会用它（loader 的写法保证
//     staged.json 最后原子写）；它写的目标槽永远不是 current，正在用的退路不会被它写坏。
func (b *Boot) rescue(stop <-chan struct{}, why string) bool {
	b.lastRescue = time.Now() // R 验不过也算一次，免得每轮都记 boot_rescue_bad
	dir := b.path(RescueSlot)
	m, err := VerifySlot(dir, b.Keys)
	if err != nil {
		b.event("boot_rescue_bad", "%s；救援槽验不过: %v", why, err)
		return true
	}
	b.event("boot_rescue", "%s；运行救援版本 %s", why, m.Version)
	p, err := b.Rescue(dir)
	if err != nil {
		b.event("boot_rescue_done", "起不来: %v", err)
		return true
	}
	timeout := time.NewTimer(b.RescueWithin)
	defer timeout.Stop()
	select {
	case <-stop:
		kill(p)
		return false
	case <-timeout.C:
		kill(p)
		b.event("boot_rescue_done", "超时（%s），杀掉", b.RescueWithin)
	case <-p.Exited():
		code := -1
		if c, ok := p.(interface{ ExitCode() int }); ok {
			code = c.ExitCode()
		}
		b.event("boot_rescue_done", "退出码 %d", code)
	}
	return true
}

func (b *Boot) sleep(stop <-chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return false
	case <-time.After(d):
		return true
	}
}

// kill 杀掉本体并等它真的退出，免得新旧两个本体同时跑。
func kill(p Proc) {
	p.Kill()
	<-p.Exited()
}

// Run 一直跑到 stop：消费 staged.json、选槽、启动本体、看护。
func (b *Boot) Run(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		b.consumeStaged()
		if !b.runOnce(stop) {
			return
		}
	}
}

// runOnce 选一个槽跑一次直到它该换掉（没槽可跑时先看要不要救援）；返回 false 表示收到 stop。
func (b *Boot) runOnce(stop <-chan struct{}) bool {
	if time.Since(b.lastRescue) >= b.RescueGap { // 先看限频，省得每轮都给槽算哈希
		if why := b.rescueWhy(); why != "" {
			return b.rescue(stop, why) // 跑完回 Run 的循环：先消费它留下的 staged.json 再选槽
		}
	}
	slot, trial := b.Pick()
	if slot == "" {
		return b.sleep(stop, b.Backoff)
	}
	// 先删旧确认文件再启动：上次留下的文件不能让这次没确认的版本转正。删不掉就不启动。
	confirm := b.path("confirm-" + slot)
	if err := os.Remove(confirm); err != nil && !os.IsNotExist(err) {
		log.Printf("删 %s: %v", confirm, err)
		return b.sleep(stop, b.Backoff)
	}
	p, err := b.Start(b.path(slot), confirm)
	if err != nil {
		b.event("boot_start_failed", "槽 %s: %v", slot, err)
		return b.sleep(stop, b.Backoff)
	}
	started := time.Now()
	tick := time.NewTicker(b.Poll)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			kill(p)
			return false
		case <-p.Exited():
			// 试启动的次数在 Pick 里已经记过；歇一下再来，免得起不来的版本把 CPU 和磁盘打满
			b.event("boot_probe_exited", "槽 %s 的本体退出，%s 后再起", slot, b.Backoff)
			return b.sleep(stop, b.Backoff)
		case <-tick.C:
		}
		if trial {
			// 试启动期间不看 staged.json（loader 在 pending 时不该写；就算写了也等这次试完再说）
			if _, err := os.Stat(confirm); err == nil {
				trial = !b.promote(slot)
			} else if time.Since(started) > b.ConfirmWithin {
				b.event("boot_unconfirmed", "槽 %s %s 内没确认，停掉重试", slot, b.ConfirmWithin)
				kill(p)
				return true
			}
			continue
		}
		if b.consumeStaged() {
			log.Printf("有新版本待试，停掉槽 %s 的本体", slot)
			kill(p)
			return true
		}
	}
}
