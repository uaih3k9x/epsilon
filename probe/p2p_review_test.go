package probe

// 第二轮审查发现的问题的复现测试。

import (
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// 迟到的 add（块已经又被淘汰）不能把还没报出去的 del 吞掉：主控会一直以为这台有这块。
func TestReportHaveLateAddDoesNotSwallowDel(t *testing.T) {
	e := newFetchEnv(t, 1)
	a := e.a
	a.registered.Store(true)
	h := e.hashes()[0]
	e.fc.haveCode = http.StatusInternalServerError
	a.reportHave(nil, []string{h}) // 淘汰了，del 没报出去
	e.fc.mu.Lock()
	e.fc.haveCode = 0
	e.fc.mu.Unlock()
	a.reportHave([]string{h}, nil) // 又 Put 又被淘汰后迟到的 add：块不在缓存
	if !slices.Contains(e.haveDels(), h) {
		t.Fatalf("del 被迟到的 add 吞掉了: %+v", e.fc.haves)
	}
	if slices.Contains(e.haveAdds(), h) {
		t.Fatal("不在缓存的块不该报 add")
	}
}

// del 是在 hmu 外算的：发出去时块已经重新放回缓存（并发的拉取又 Put 了、add 也先报了）就不报 del。
func TestReportHaveSkipsDelForChunkBackInCache(t *testing.T) {
	e := newFetchEnv(t, 1)
	a := e.a
	a.registered.Store(true)
	h := e.hashes()[0]
	e.store.data[h] = e.data[h]
	a.reportHave(nil, []string{h})
	if slices.Contains(e.haveDels(), h) {
		t.Fatal("块已经回到缓存还报 del，主控会漏记这台有它")
	}
}

// 被拿下的主控把 chunk_size 写成 MaxInt64：不能让 capReader 溢出 panic、打崩探针。
func TestCapReaderHugeLimitNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	n, err := io.Copy(io.Discard, &capReader{r: strings.NewReader("abc"), left: math.MaxInt64})
	if n != 3 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestCheckManifestRejectsBadChunkSize(t *testing.T) {
	e := newFetchEnv(t, 1)
	for _, cs := range []int64{-1, maxChunkSize + 1, math.MaxInt64} {
		m := e.m
		m.ChunkSize = cs
		if err := checkManifest(m, m.ID); err == nil {
			t.Errorf("chunk_size=%d 应该拒收", cs)
		}
	}
	for _, cs := range []int64{0, 1 << 20, maxChunkSize} {
		m := e.m
		m.ChunkSize = cs
		if err := checkManifest(m, m.ID); err != nil {
			t.Errorf("chunk_size=%d: %v", cs, err)
		}
	}
}
