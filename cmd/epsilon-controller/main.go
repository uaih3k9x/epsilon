// epsilon-controller: 主控（节点管理 + 期望状态 + OpenAI 兼容路由）。用法: epsilon-controller [-config controller.json]
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"

	"epsilon/controller"
)

func main() {
	path := flag.String("config", "controller.json", "主控配置")
	flag.Parse()
	b, err := os.ReadFile(*path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg controller.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("%s: %v", *path, err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8090"
	}
	if cfg.ProbeToken == "" {
		log.Print("警告: 没设 probe_token，谁都能冒充探针登记")
	}
	log.Printf("epsilon-controller 监听 %s", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, controller.New(cfg).Handler()))
}
