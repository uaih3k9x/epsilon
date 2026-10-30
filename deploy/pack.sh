#!/bin/sh
# 组装试点 U 盘包到 dist/deploy/epsilon/：程序 + 脚本 + llama.cpp(CUDA 12.4 / Vulkan) + 模型 + 配置
# 用法: deploy/pack.sh   （先下好 dist/deploy/dl/ 里的 zip 和 gguf，密钥在 dist/deploy/secrets.env）
set -e
cd "$(dirname "$0")/.."
DL=dist/deploy/dl
OUT=dist/deploy/epsilon
B=b11849
. dist/deploy/secrets.env   # 密钥和部署地址，不进仓库
: "${EPS_CONTROLLER:?}"
rm -rf "$OUT" && mkdir -p "$OUT/llama" "$OUT/llama-vulkan" "$OUT/models"
cp dist/epsilon-probe.exe dist/epsilon-controller.exe "$OUT/"
for f in deploy/*.bat; do sed "s/@CONTROLLER@/$EPS_CONTROLLER/g" "$f" > "$OUT/$(basename "$f")"; done
cp dist/deploy/files/vc_redist.x64.exe "$OUT/"
unzip -q -o "$DL/llama-$B-bin-win-cuda-12.4-x64.zip" -d "$OUT/llama"
unzip -q -o "$DL/cudart-llama-bin-win-cuda-12.4-x64.zip" -d "$OUT/llama"
unzip -q -o "$DL/llama-$B-bin-win-vulkan-x64.zip" -d "$OUT/llama-vulkan"
if [ -f "$DL/Qwen3.5-4B-Q4_K_M.gguf" ]; then cp "$DL/Qwen3.5-4B-Q4_K_M.gguf" "$OUT/models/"; else echo "警告: 模型还没下完，models/ 先空着"; fi
printf '%s' "$EPS_CONTROLLER" > "$OUT/controller-ip.txt"
printf '%s' "$API_KEY" > "$OUT/api_key.txt"
python3 - "$OUT" "$PROBE_TOKEN" "$API_KEY" "$EPS_CONTROLLER" <<'PY'
import json, sys
out, token, key, ctl_ip = sys.argv[1:]
base = [r"-m", r"D:\epsilon\models\Qwen3.5-4B-Q4_K_M.gguf", "--alias", "qwen3.5-4b",
        "--host", "0.0.0.0", "--port", "8080", "-ngl", "99"]
# 并发档位：主控只能挑名字。p4 起用统一 KV（-kvu）：所有槽共用一个上下文池，短请求多就多并发，长请求能占大块
presets = {"qwen3.5-4b": ["-c", "16384", "-np", "2"],          # 老名字 = p2，兼容已下发的主控配置
           "q4b-p2": ["-c", "16384", "-np", "2"],
           "q4b-p4": ["-c", "32768", "-np", "4", "-kvu"],
           "q4b-p8": ["-c", "32768", "-np", "8", "-kvu"],
           "q4b-p16": ["-c", "65536", "-np", "16", "-kvu"]}
wl = {name: {"exe": r"D:\epsilon\llama\llama-server.exe", "args": base + extra, "dir": r"D:\epsilon\llama",
             "port": 8080, "model": "qwen3.5-4b"} for name, extra in presets.items()}
wl["qwen3.5-4b-vulkan"] = {"exe": r"D:\epsilon\llama-vulkan\llama-server.exe", "args": base + presets["qwen3.5-4b"],
                           "dir": r"D:\epsilon\llama-vulkan", "port": 8080, "model": "qwen3.5-4b"}
probe = {"controller": f"http://{ctl_ip}:8090", "token": token, "workloads": wl}
json.dump(probe, open(f"{out}/probe.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
# 学生机兜底当主控时用的配置，和 221 上那份一致
ctl = {"listen": ":8090", "probe_token": token, "api_keys": [key], "stale_seconds": 30,
       "default": {"workload": "qwen3.5-4b", "yield_on_input": True, "input_idle_seconds": 60,
                   "yield_on_foreign_gpu": False, "keep_warm": True, "foreign_vram_mb": 1500,
                   "heartbeat_seconds": 10, "max_offline_minutes": 30}, "nodes": {}}
json.dump(ctl, open(f"{out}/controller.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
PY
sed "s/@CONTROLLER@/$EPS_CONTROLLER/g" deploy/先看我.txt > "$OUT/先看我.txt"
du -sh "$OUT"; ls "$OUT"
