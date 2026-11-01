// epsilon-env: 在机器上手工安装环境层（探针接上之前用来实测，契约见 docs/jobs.md）。
// 用法: epsilon-env install -name py311-torch2.5-cu124@1 -digest <钥匙环里的摘要> -manifest <清单.json> -chunks <块目录> -root D:\epsilon
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"epsilon/chunk"
	"epsilon/envlayer"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 || os.Args[1] != "install" {
		log.Fatal("用法: epsilon-env install -name <名字@版本> -digest <sha256> -manifest <清单> -chunks <块目录> -root <目录>")
	}
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	name := fs.String("name", "", "环境层 名字@版本")
	digest := fs.String("digest", "", "清单的 SHA-256（来自钥匙环）")
	manifest := fs.String("manifest", "", "清单文件")
	chunks := fs.String("chunks", "", "块目录")
	root := fs.String("root", "", "落到 <root>/envs/<名字@版本>")
	fs.Parse(os.Args[2:])
	if *name == "" || *digest == "" || *manifest == "" || *chunks == "" || *root == "" {
		log.Fatal("-name、-digest、-manifest、-chunks、-root 都要")
	}
	raw, err := os.ReadFile(*manifest)
	if err != nil {
		log.Fatal(err)
	}
	s, err := chunk.NewStore(*chunks, 0)
	if err != nil {
		log.Fatal(err)
	}
	start := time.Now()
	res, err := envlayer.Install(raw, *name, *digest, s, *root)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"dir": res.Dir, "files": res.Files, "seconds": time.Since(start).Seconds(),
	})
}
