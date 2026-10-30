// epsilon-chunk: 在 Mac 上把模型切块、出清单（契约见 docs/p2p.md）。
// 用法: epsilon-chunk build -id qwen3.5-4b-q4km -root models -out dist/chunks Qwen3.5-4B-Q4_K_M.gguf
// 把 -out 目录整个传到主控的 chunks_dir；已有的块不会重写，可以反复往同一个目录里 build。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"epsilon/chunk"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 || os.Args[1] != "build" {
		log.Fatal("用法: epsilon-chunk build -id <id> [-chunk 字节数] -root <目录> -out <块目录> <相对路径>...")
	}
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	id := fs.String("id", "", "制品 ID，清单写成 <out>/<id>.json")
	size := fs.Int64("chunk", chunk.DefaultChunkSize, "块大小（字节）")
	root := fs.String("root", ".", "文件所在目录；路径相对它")
	out := fs.String("out", "", "块目录（输出）")
	fs.Parse(os.Args[2:])
	if *id == "" || *out == "" || fs.NArg() == 0 {
		log.Fatal("要 -id、-out 和至少一个相对路径")
	}
	m, err := chunk.Build(*id, *root, fs.Args(), *size, *out)
	if err != nil {
		log.Fatal(err)
	}
	var total int64
	n, uniq := 0, map[string]bool{}
	for _, f := range m.Files {
		total += f.Size
		n += len(f.Chunks)
		for _, h := range f.Chunks {
			uniq[h] = true
		}
		fmt.Printf("  %s  %d 字节  %d 块\n", f.Path, f.Size, len(f.Chunks))
	}
	fmt.Printf("%s: %d 个文件，%d 块（去重后 %d），共 %d 字节（%.2f GiB），块大小 %d\n",
		m.ID, len(m.Files), n, len(uniq), total, float64(total)/(1<<30), m.ChunkSize)
}
