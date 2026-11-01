#!/bin/sh
# 构建: 探针是 Windows 无窗口程序(-H windowsgui，不弹黑框)，主控给 221 用 linux/amd64
set -e
cd "$(dirname "$0")"
go test ./...
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" -o dist/epsilon-probe.exe ./cmd/epsilon-probe
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/epsilon-controller ./cmd/epsilon-controller
# 环境层手工安装（探针接上之前用来实测）
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/epsilon-env.exe ./cmd/epsilon-env
# 兜底：学生机临时当主控（连不上 221 时）
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/epsilon-controller.exe ./cmd/epsilon-controller
ls -la dist
