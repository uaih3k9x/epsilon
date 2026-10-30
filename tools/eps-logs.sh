#!/bin/sh
# 远程看学生机：最近事件，或者点名要日志（不用跑到机器跟前）。
# 用法:
#   EPS=http://<controller>:8090 EPS_KEY=<api key> tools/eps-logs.sh events [节点] [类型]   # 最近事件，新的在前
#   EPS=... EPS_KEY=... tools/eps-logs.sh logs <节点>                                     # 要日志，等它下次心跳传上来再打印
set -eu
: "${EPS:?设 EPS=http://<controller>:8090}" "${EPS_KEY:?设 EPS_KEY=<api key>}"
api() { curl -sS --noproxy '*' -H "Authorization: Bearer $EPS_KEY" "$@"; }
case "${1:-}" in
events)
	api "$EPS/v1/events?node=${2:-}&kind=${3:-}&limit=30" | python3 -c '
import json, sys
for e in json.load(sys.stdin):
    print("%s  %-10s %-14s %s" % (e["time"][:19], e["node"], e["kind"], e["detail"]))'
	;;
logs)
	n=${2:?节点名}
	req=$(api -X POST "$EPS/v1/nodes/$n/logs" | python3 -c 'import json,sys;print(json.load(sys.stdin)["request"])')
	echo "已点名 ${n}（请求 ${req}），等它下次心跳传上来…" >&2
	for _ in $(seq 1 30); do
		out=$(api "$EPS/v1/nodes/$n/logs" 2>/dev/null || true)
		if printf '%s' "$out" | python3 -c "import json,sys;sys.exit(0 if json.load(sys.stdin).get('request')==$req else 1)" 2>/dev/null; then
			printf '%s' "$out" | python3 -c '
import json, sys
for name, text in sorted(json.load(sys.stdin)["files"].items()):
    print("\n===== %s =====\n%s" % (name, text))'
			exit 0
		fi
		sleep 2
	done
	echo "60 秒没等到：${n} 可能离线，或者探针版本太老（0.3.1 起才支持）" >&2
	exit 1
	;;
*)
	sed -n '2,5p' "$0" >&2
	exit 2
	;;
esac
