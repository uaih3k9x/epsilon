package boot

// 状态机穷举（设计书 11.12 "状态机穷举"）：不走 Run 和真实时间，直接驱动 consumeStaged、rescueWhy、
// Pick、promote，外加模拟的事件（崩溃/卡死不确认、确认、槽被篡改导致验签失败）。
//
// 状态 = boot-state.json（current/pending/good ∈ {"",A,B}，tries，bad，versions）
//      × A、B、R 三个槽的内容 ∈ {好, 另一个版本（签名合法但版本对不上）, 被篡改, 缺失}
//      × staged.json ∈ {无, A, B, 垃圾}。
// 从所有初始状态做 BFS（深度不超过 smDepth），每一步对照一个独立的模型（不调被测代码）检查：
// 不 panic；不启动验不过或版本对不上的槽；I3（有退路时 tries 每次启动 +1 且不超过 MaxTries）；
// I7；没有事件时 Pick 是不动点；有能跑的槽时这一轮一定启动点什么；没东西跑时一定要救援；
// 救援不写 state、不跑验不过的 R。
//
// 初始状态的约简：current/pending/good 只取互不相同的组合（I7 本身就是要检查的不变量，
// 违反它的初始状态 boot 自己写不出来）；pending 为空时 tries 不参与任何判断，只取 0。
// -short 只从 R 完好、bad 为空的初始状态出发，跑它们可达的状态。

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

type smContent uint8

const (
	cGood     smContent = iota // 签名合法，版本 1.<槽>
	cOther                     // 签名合法，版本 2.<槽>（loader 写进了别的版本）
	cTampered                  // 1.<槽> 的清单，本体文件被改
	cMissing                   // 没有这个槽目录
)

var smContentName = [...]string{"好", "另一版本", "被篡改", "缺失"}

func (c smContent) String() string { return smContentName[c] }

const smDepth = 3 * (MaxTries + 2)

type smKey struct {
	Cur, Pend, Good string
	Tries           int
	Bad             string
	VA, VB          string // versions[A]、versions[B]
	A, B, R         smContent
	Staged          string // "" / "A" / "B" / "junk"
}

func (k smKey) String() string {
	return fmt.Sprintf("{cur=%q pend=%q tries=%d good=%q bad=%q ver=%s/%s 槽A=%v B=%v R=%v staged=%q}",
		k.Cur, k.Pend, k.Tries, k.Good, k.Bad, k.VA, k.VB, k.A, k.B, k.R, k.Staged)
}

// ---- 模型（不调被测代码）----

func (k smKey) content(slot string) smContent {
	switch slot {
	case "A":
		return k.A
	case "B":
		return k.B
	case RescueSlot:
		return k.R
	}
	return cMissing
}

func (k smKey) version(slot string) string {
	switch slot {
	case "A":
		return k.VA
	case "B":
		return k.VB
	}
	return ""
}

// signedVersion 是槽里验得过的清单版本；验不过返回空。
func signedVersion(slot string, c smContent) string {
	switch c {
	case cGood:
		return "1." + slot
	case cOther:
		return "2." + slot
	}
	return ""
}

func (k smKey) runnable(slot string) bool {
	v := signedVersion(slot, k.content(slot))
	return slot != "" && v != "" && v == k.version(slot)
}

func (k smKey) hasFallback() bool { return k.runnable(k.Cur) || k.runnable(k.Good) }

func (k smKey) withContent(slot string, c smContent) smKey {
	switch slot {
	case "A":
		k.A = c
	case "B":
		k.B = c
	}
	return k
}

func smKeyOf(st State, from smKey) (smKey, error) {
	for s := range st.Versions {
		if s != "A" && s != "B" {
			return smKey{}, fmt.Errorf("versions 里出现了槽 %q", s)
		}
	}
	return smKey{Cur: st.Current, Pend: st.Pending, Tries: st.Tries, Good: st.Good, Bad: st.Bad,
		VA: st.Versions["A"], VB: st.Versions["B"], A: from.A, B: from.B, R: from.R}, nil
}

func smDistinct(k smKey) bool {
	return distinctSlots(State{Current: k.Cur, Pending: k.Pend, Good: k.Good})
}

// ---- 磁盘现场 ----

type smWorker struct {
	tmpl    string // 每种槽内容一份模板：<tmpl>/<槽>-<内容>
	keys    []ed25519.PublicKey
	base    string
	boots   map[[3]smContent]*Boot
	rescued bool
}

func smTemplates(t *testing.T) (string, []ed25519.PublicKey) {
	t.Helper()
	_, priv := keys(t)
	dir := t.TempDir()
	for _, slot := range []string{"A", "B", RescueSlot} {
		for _, c := range []smContent{cGood, cOther, cTampered} {
			d := filepath.Join(dir, fmt.Sprintf("%s-%d", slot, c))
			v := signedVersion(slot, c)
			if c == cTampered {
				v = signedVersion(slot, cGood)
			}
			if err := makeSlot(d, priv, v, 1); err != nil {
				t.Fatal(err)
			}
			if c == cTampered {
				write(t, filepath.Join(d, "epsilon-probe.exe"), "evil")
			}
		}
	}
	return dir, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}
}

func (w *smWorker) boot(k smKey) *Boot {
	combo := [3]smContent{k.A, k.B, k.R}
	if b := w.boots[combo]; b != nil {
		return b
	}
	root := filepath.Join(w.base, fmt.Sprintf("%d%d%d", k.A, k.B, k.R))
	if err := os.MkdirAll(root, 0o755); err != nil {
		panic(err)
	}
	for i, slot := range []string{"A", "B", RescueSlot} {
		if combo[i] == cMissing {
			continue
		}
		src := filepath.Join(w.tmpl, fmt.Sprintf("%s-%d", slot, combo[i]))
		os.MkdirAll(filepath.Join(root, slot), 0o755)
		for _, f := range []string{"epsilon-probe.exe", ReleaseFile} {
			raw, err := os.ReadFile(filepath.Join(src, f))
			if err == nil {
				err = os.WriteFile(filepath.Join(root, slot, f), raw, 0o644)
			}
			if err != nil {
				panic(err)
			}
		}
	}
	b := &Boot{Root: root, Keys: w.keys, RescueWithin: time.Minute,
		Rescue: func(string) (Proc, error) {
			w.rescued = true
			p := &fakeProc{exited: make(chan struct{})}
			p.Kill()
			return p, nil
		}}
	w.boots[combo] = b
	return b
}

func (w *smWorker) put(k smKey) *Boot {
	b := w.boot(k)
	vers := map[string]string{}
	if k.VA != "" {
		vers["A"] = k.VA
	}
	if k.VB != "" {
		vers["B"] = k.VB
	}
	if err := writeState(b.Root, State{Current: k.Cur, Pending: k.Pend, Tries: k.Tries, Good: k.Good, Bad: k.Bad, Versions: vers}); err != nil {
		panic(err)
	}
	staged := filepath.Join(b.Root, StagedFile)
	switch k.Staged {
	case "":
		os.Remove(staged)
	case "junk":
		os.WriteFile(staged, []byte(`{"slot":"C"`), 0o644)
	default:
		os.WriteFile(staged, []byte(`{"slot":"`+k.Staged+`","version":"9.9.9"}`), 0o644)
	}
	return b
}

func (w *smWorker) read(b *Boot, from smKey) (smKey, []byte) {
	raw, err := os.ReadFile(filepath.Join(b.Root, StateFile))
	if err != nil {
		panic(err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		panic(fmt.Sprintf("state 写坏了: %v %q", err, raw))
	}
	k, err := smKeyOf(st, from)
	if err != nil {
		panic(err)
	}
	return k, raw
}

// step 从 k 出发走一轮 Run 的循环体，返回所有后继状态和发现的问题。
func (w *smWorker) step(k smKey) (succ []smKey, errs []string) {
	fail := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	defer func() {
		if r := recover(); r != nil {
			fail("panic: %v", r)
		}
	}()
	b := w.put(k)

	// 1. 消费 staged.json
	accepted := b.consumeStaged()
	k1, _ := w.read(b, k)
	want := false
	if s := k.Staged; s == "A" || s == "B" {
		v := signedVersion(s, k.content(s))
		want = s != k.Cur && v != "" && v != k.Bad
		if accepted && (k1.Pend != s || k1.version(s) != v) {
			fail("接受了 staged %s 但 state 没指向它: %v", s, k1)
		}
	}
	if accepted != want {
		fail("consumeStaged 返回 %v，模型认为 %v", accepted, want)
	}
	if _, err := os.Stat(filepath.Join(b.Root, StagedFile)); err == nil {
		fail("I5: staged.json 没被消费")
	}
	if !smDistinct(k1) {
		fail("I7: 消费 staged 后 %v", k1)
	}

	// 2. 救援（限频期间不救，直接走 3，所以两条路都是后继）
	why := b.rescueWhy()
	wantRescue := !k1.hasFallback() && (k1.Pend == "" || !k1.runnable(k1.Pend) || k1.Tries >= MaxTries)
	if (why != "") != wantRescue {
		fail("rescueWhy=%q，模型认为该救援=%v（%v）", why, wantRescue, k1)
	}
	if why != "" {
		_, before := w.read(b, k)
		w.rescued = false
		b.rescue(nil, why)
		if _, after := w.read(b, k); string(after) != string(before) {
			fail("救援写了 state")
		}
		if ok := signedVersion(RescueSlot, k.R) != ""; w.rescued != ok {
			fail("R 是 %v，救援跑了=%v", k.R, w.rescued)
		}
		succ = append(succ, k1)
	}

	// 3. 选槽
	slot, trial := b.Pick()
	k2, raw2 := w.read(b, k)
	if !smDistinct(k2) {
		fail("I7: Pick 后 %v", k2)
	}
	if slot == "" {
		if why == "" {
			fail("没东西可跑却不救援")
		}
		if k1.hasFallback() || k1.runnable(k1.Pend) {
			fail("有能跑的槽却什么也没启动（%v）", k1)
		}
	} else {
		if v := signedVersion(slot, k2.content(slot)); v == "" || v != k2.version(slot) {
			fail("I2: 启动了槽 %s（内容 %v，记的版本 %q）", slot, k2.content(slot), k2.version(slot))
		}
		switch {
		case trial && slot != k2.Pend:
			fail("试启动的 %s 不是 pending（%v）", slot, k2)
		case !trial && slot != k2.Cur:
			fail("非试启动的 %s 不是 current（%v）", slot, k2)
		case trial && k1.hasFallback() && (k2.Tries != k1.Tries+1 || k2.Tries > MaxTries):
			fail("I3: 有退路，tries %d -> %d（上限 %d）", k1.Tries, k2.Tries, MaxTries)
		case trial && k1.Pend == slot && k2.Tries <= k1.Tries && k1.Tries < MaxTries:
			fail("I3: 试启动没有先记次数：tries %d -> %d", k1.Tries, k2.Tries)
		}
	}
	// 没有事件时 Pick 是不动点（试启动每次都 +1，那是"又起了一次"，不算）
	if !trial {
		s2, t2 := b.Pick()
		if _, raw3 := w.read(b, k); s2 != slot || t2 || string(raw3) != string(raw2) {
			fail("没有事件时 Pick 不是不动点：%q -> %q，state %s -> %s", slot, s2, raw2, raw3)
		}
	}

	// 4. 事件
	succ = append(succ, k2) // 崩溃 / 卡死不确认 / 没东西跑时时间流逝：state 不变
	if slot == "" {
		return succ, errs
	}
	succ = append(succ, k2.withContent(slot, cTampered)) // 跑着的槽被篡改（下次验签失败）
	if trial {
		if !b.promote(slot) {
			fail("promote 失败")
		}
		k3, _ := w.read(b, k)
		if k3.Cur != slot || k3.Pend != "" || k3.Tries != 0 || k3.Good != k2.Cur {
			fail("确认后转正不对: %v -> %v", k2, k3)
		}
		if !smDistinct(k3) {
			fail("I7: 转正后 %v", k3)
		}
		succ = append(succ, k3)
	}
	return succ, errs
}

func smInitial(short bool) []smKey {
	slots := []string{"", "A", "B"}
	var out []smKey
	for _, cur := range slots {
		for _, pend := range slots {
			for _, good := range slots {
				for tries := 0; tries <= MaxTries+1; tries++ {
					if pend == "" && tries > 0 {
						continue
					}
					for _, bad := range []string{"", "1.A", "1.B"} {
						for a := cGood; a <= cMissing; a++ {
							for b := cGood; b <= cMissing; b++ {
								for r := cGood; r <= cMissing; r++ {
									for _, staged := range []string{"", "A", "B", "junk"} {
										k := smKey{Cur: cur, Pend: pend, Good: good, Tries: tries, Bad: bad,
											VA: "1.A", VB: "1.B", A: a, B: b, R: r, Staged: staged}
										if !smDistinct(k) || (short && (r != cGood || bad != "")) {
											continue
										}
										out = append(out, k)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

func TestStateMachine(t *testing.T) {
	// 每一步都记好几条日志，穷举时几十万行，只会拖慢；不并行的测试里换掉再换回来是安全的
	defer log.SetOutput(log.Writer())
	log.SetOutput(io.Discard)
	tmpl, pub := smTemplates(t)
	nw := min(runtime.GOMAXPROCS(0), 4) // 再多 APFS 上反而更慢（元数据锁竞争）
	workers := make([]*smWorker, nw)
	for i := range workers {
		w := &smWorker{tmpl: tmpl, keys: pub, base: t.TempDir(), boots: map[[3]smContent]*Boot{}}
		onFault(t, w.base, func(op, path string) error {
			if op == "sync" {
				return errSkip // 只模拟逻辑，不需要真刷盘
			}
			return nil
		})
		workers[i] = w
	}

	frontier := smInitial(testing.Short())
	initial := len(frontier)
	visited := make(map[smKey]bool, 4*initial)
	for _, k := range frontier {
		visited[k] = true
	}
	problems := map[string]smKey{} // 问题 -> 第一个暴露它的状态
	depth := 0
	for ; depth < smDepth && len(frontier) > 0; depth++ {
		succs := make([][]smKey, len(frontier))
		errs := make([][]string, len(frontier))
		var wg sync.WaitGroup
		next := make(chan int)
		for _, w := range workers {
			wg.Add(1)
			go func(w *smWorker) {
				defer wg.Done()
				for i := range next {
					succs[i], errs[i] = w.step(frontier[i])
				}
			}(w)
		}
		for i := range frontier {
			next <- i
		}
		close(next)
		wg.Wait()

		var nf []smKey
		for i, k := range frontier {
			for _, e := range errs[i] {
				if _, ok := problems[e]; !ok {
					problems[e] = k
				}
			}
			for _, s := range succs[i] {
				if !visited[s] {
					visited[s] = true
					nf = append(nf, s)
				}
			}
		}
		frontier = nf
	}
	if len(frontier) > 0 {
		t.Errorf("深度 %d 还没收敛，剩 %d 个新状态", smDepth, len(frontier))
	}
	var msgs []string
	for e, k := range problems {
		msgs = append(msgs, fmt.Sprintf("%s\n    从 %v", e, k))
	}
	sort.Strings(msgs)
	for i, m := range msgs {
		if i == 20 {
			t.Errorf("……还有 %d 个", len(msgs)-20)
			break
		}
		t.Error(m)
	}
	t.Logf("初始 %d 个状态，可达共 %d 个，%d 层收敛", initial, len(visited), depth)
}
