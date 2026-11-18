package chunk

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// forgetForBench 把块从缓存里拿掉（文件也删），好让下一轮重新 Put。
func forgetForBench(s *Store, h string) {
	s.mu.Lock()
	if it := s.items[h]; it != nil {
		s.total -= it.size
		delete(s.items, h)
	}
	s.mu.Unlock()
	os.Remove(chunkPath(s.dir, h))
}

func BenchmarkStorePut(b *testing.B) {
	data := make([]byte, 8<<20)
	rand.Read(data)
	h := sum(data)
	s, _ := NewStore(b.TempDir(), 0)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Put(h, bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		forgetForBench(s, h)
		b.StartTimer()
	}
}

// BenchmarkAssemble: 64 MiB 文件、8 MiB 一块，每轮拼到新的位置。
func BenchmarkAssemble(b *testing.B) {
	src, out := b.TempDir(), b.TempDir()
	data := make([]byte, 64<<20)
	rand.Read(data)
	os.WriteFile(filepath.Join(src, "m.bin"), data, 0o644)
	m, err := Build("bm", src, []string{"m.bin"}, 8<<20, out)
	if err != nil {
		b.Fatal(err)
	}
	s, _ := NewStore(out, 0)
	root := b.TempDir()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		os.Remove(filepath.Join(root, "m.bin") + StampSuffix) // stamp 没了就会重拼
		if err := Assemble(m, s, root); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStoreEvict: 1 万块，每次超配额一块，测一次 Evict（排序 + 删一块）。
func BenchmarkStoreEvict(b *testing.B) {
	dir := b.TempDir()
	blobs := map[string][]byte{}
	for i := 0; i < 10000; i++ { // 直接写文件再让 NewStore 扫：一万次 Put 每次都刷盘太慢
		blk := []byte{byte(i), byte(i >> 8), 'x', 'y'}
		h := sum(blk)
		blobs[h] = blk
		os.MkdirAll(filepath.Join(dir, h[:2]), 0o755)
		os.WriteFile(chunkPath(dir, h), blk, 0o644)
	}
	s, _ := NewStore(dir, 0)
	s.quota = s.total - 1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gone := s.Evict(nil)
		if len(gone) != 1 {
			b.Fatalf("删了 %d 块", len(gone))
		}
		b.StopTimer()
		s.Put(gone[0], bytes.NewReader(blobs[gone[0]]))
		b.StartTimer()
	}
}
