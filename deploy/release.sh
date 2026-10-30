#!/bin/sh
# 出一版本体：编译 -> 生成工作负载表 -> 用 dist/keys 里的私钥签名 -> dist/release/
# 再把 dist/release/ 传到 221 的 /opt/epsilon/files/release/（灰度先传 release-canary/）。
# 用法: deploy/release.sh 0.2.0
# 同时生成哦易下发用的引导器和裸机安装脚本到 dist/deploy/upgrade/（传到 221 files/upgrade/），一整行命令在 dist/deploy/哦易远程命令.txt
set -e
cd "$(dirname "$0")/.."
V=${1:?版本号}
. dist/deploy/secrets.env   # 密钥和部署地址，不进仓库
: "${EPS_CONTROLLER:?}" "${EPS_POOL_HEADS:?}" "${EPS_POOL_RANGE:?}" "${EPS_RPC_PEERS:?}"
go test ./...
mkdir -p dist/build
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w -X main.version=$V" -o dist/build/epsilon-probe.exe ./cmd/epsilon-probe
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" -o dist/build/epsilon-boot.exe ./cmd/epsilon-boot
go build -o dist/build/epsilon-release ./cmd/epsilon-release
python3 - dist/build/workloads.json "$EPS_RPC_PEERS" <<'PY'
import json, sys
L = r"D:\epsilon\llama"
base = ["-m", r"D:\epsilon\models\Qwen3.5-4B-Q4_K_M.gguf", "--alias", "qwen3.5-4b",
        "--host", "0.0.0.0", "--port", "8080", "-ngl", "99"]
# 并发档位：主控只能挑名字。p4 起用统一 KV（-kvu）
presets = {"qwen3.5-4b": ["-c", "16384", "-np", "2"],
           "q4b-p2": ["-c", "16384", "-np", "2"],
           "q4b-p4": ["-c", "32768", "-np", "4", "-kvu"],
           "q4b-p8": ["-c", "32768", "-np", "8", "-kvu"],
           "q4b-p16": ["-c", "65536", "-np", "16", "-kvu"]}
wl = {n: {"exe": L + r"\llama-server.exe", "args": base + x, "dir": L, "port": 8080, "model": "qwen3.5-4b"}
      for n, x in presets.items()}
# 拼机 v1：固定 4 台，1 台当主节点，3 台跑 rpc-server（地址在 secrets.env 的 EPS_RPC_PEERS）
wl["q27-rpc"] = {"exe": L + r"\ggml-rpc-server.exe", "args": ["-H", "0.0.0.0", "-p", "50052", "-c"],
                 "dir": L, "port": 50052, "health": "none", "model": "q27-rpc"}
peers = sys.argv[2]
wl["q27-head"] = {"exe": L + r"\llama-server.exe", "dir": L, "port": 8080, "model": "qwen3.8-27b",
                  "start_timeout_sec": 1200,
                  "args": ["-m", r"D:\epsilon\models\Qwen3.8-27B-Q4_K_M.gguf", "--alias", "qwen3.8-27b",
                           "--rpc", peers, "-ngl", "99", "-c", "16384", "-np", "4", "-kvu",
                           "--host", "0.0.0.0", "--port", "8080"]}
# 并发档位：主控换名字就能扫 -np
for np_ in (1, 8):
    w = json.loads(json.dumps(wl["q27-head"]))
    w["args"][w["args"].index("-np") + 1] = str(np_)
    wl[f"q27-head-np{np_}"] = w
json.dump(wl, open(sys.argv[1], "w"), indent=2)
PY
dist/build/epsilon-release -key dist/keys/release-main.key -version "$V" -out dist/release \
  dist/build/epsilon-probe.exe dist/build/workloads.json
mkdir -p dist/deploy/upgrade
cp dist/build/epsilon-boot.exe dist/deploy/upgrade/
cp dist/build/epsilon-probe.exe dist/deploy/upgrade/epsilon-probe-seed.exe   # 装机时跑一次 -seed，放进第一个版本
SHA=$(shasum -a 256 dist/build/epsilon-boot.exe | cut -d' ' -f1)
SEED=$(shasum -a 256 dist/build/epsilon-probe.exe | cut -d' ' -f1)
sed -e "s/@BOOT_SHA256@/$SHA/" -e "s/@SEED_SHA256@/$SEED/" -e "s/@CONTROLLER@/$EPS_CONTROLLER/" \
    -e "s/@POOL_HEADS@/$EPS_POOL_HEADS/" -e "s/@POOL_RANGE@/$EPS_POOL_RANGE/" deploy/install.ps1 > dist/deploy/upgrade/install.ps1
rm -f dist/deploy/upgrade/upgrade.ps1
umask 077   # 哦易一整行命令，含 api key
printf '%s\r\n' "powershell -NoProfile -ExecutionPolicy Bypass -Command \"\$env:EPS_KEY='$API_KEY'; iex (iwr http://$EPS_CONTROLLER:8090/dl/upgrade/install.ps1 -Headers @{Authorization='Bearer '+\$env:EPS_KEY} -UseBasicParsing).Content\"" > dist/deploy/哦易远程命令.txt
ls -la dist/release dist/deploy/upgrade
