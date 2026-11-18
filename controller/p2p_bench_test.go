package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"epsilon/proto"
)

// BenchmarkPeers: 60 台节点、每台持有 300 块清单里的全部块，问一次 peers。
func BenchmarkPeers(b *testing.B) {
	dir := b.TempDir()
	var hs []string
	for i := 0; i < 300; i++ {
		s := sha256.Sum256([]byte(fmt.Sprint(i)))
		hs = append(hs, hex.EncodeToString(s[:]))
	}
	m := proto.Manifest{ID: "big", ChunkSize: 64 << 20, Files: []proto.ManifestFile{{Path: "m.gguf", Size: 300 * 64 << 20, Chunks: hs}}}
	raw, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, "big.json"), raw, 0o644)
	topo := map[string]Place{}
	for i := 0; i < 60; i++ {
		topo[fmt.Sprintf("pc-%02d", i)] = Place{Room: fmt.Sprintf("R%d", i/30+1), Switch: fmt.Sprintf("S%d", i/10)}
	}
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	r := newP2PRig(b, Config{Topology: topo, Default: proto.DesiredState{Artifacts: []string{"big"}}})
	r.c.cfg.ChunksDir = dir
	for i := 0; i < 60; i++ {
		r.join(fmt.Sprintf("pc-%02d", i), fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), 47100, hs...)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := r.do("GET", "/v1/peers?manifest=big&node=pc-07", "10.0.0.8", "tok", nil)
		if w.Code != 200 {
			b.Fatal(w.Code)
		}
	}
}
