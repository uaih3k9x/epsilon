# epsilon

ProjectEpsilon 的探针和主控，v0.1。设计书在 CiderLLM `ProjectEpsilon/设计书.md`，这里是第 0–1 阶段能用的最小实现：

- `epsilon-probe.exe`：学生机上跑。按主控的期望状态起停 `llama-server`；有人用电脑就让位；每 10 秒心跳。
- `epsilon-controller`：主控（221）。管节点、下发期望状态；同时是 OpenAI 兼容路由，按模型分给手上活最少的节点，连不上就换一台。

只用 Go 标准库。`./build.sh` 跑测试并产出 `dist/epsilon-probe.exe`（Windows，无窗口）和 `dist/epsilon-controller`（linux/amd64）。

## 安全模型

主控只能说"跑哪个**名字**的工作负载"；名字对应哪个 exe、什么参数，写死在每台机器自己的 `probe.json` 里。主控被冒充也只能在本机允许的几个程序里挑，不能执行任意命令。

本体发布由 `epsilon-boot.exe`（引导器）按 A/B 槽管理：ed25519 验签、试启动失败自动回退、`canary_nodes` 灰度（设计书 11.9）。还没有 HTTPS：探针和主控之间靠 `probe_token`，路由靠 `api_keys`，只在机房内网用。

## 部署配置（不进仓库）

密钥和部署地址都放在 `dist/pilot/secrets.env`（`dist/` 已被忽略），`pilot/release.sh`、`pilot/pack.sh` 从这里读，并把 `pilot/` 里的 `@CONTROLLER@` 这类占位符填上：

```sh
PROBE_TOKEN=...          # 探针 ↔ 主控
API_KEY=...              # 路由与 /dl/
EPS_CONTROLLER=...       # 主控 IP
EPS_POOL_HEADS=...       # 拼机主节点机器名，逗号分隔
EPS_POOL_RANGE=...       # 拼机网段，如 a.b.c.70-a.b.c.77
EPS_RPC_PEERS=...        # rpc-server 地址，如 a.b.c.71:50052,...
```

签名私钥在 `dist/keys/`，同样不进仓库。

## 学生机（每台一次）

数据盘（D:，哦易"场景数据盘"，不还原）上放：

```
D:\epsilon\
  epsilon-probe.exe
  probe.json            照 examples/probe.json 改主控地址和 token
  llama\llama-server.exe 及其 DLL（llama.cpp Windows CUDA 版）
  models\Qwen3.5-4B-Q4_K_M.gguf
```

开机自启：在 `shell:startup`（启动文件夹）里放一个指向 `D:\epsilon\epsilon-probe.exe` 的快捷方式。探针要和学生在同一个登录会话里才能读到键鼠空闲时间，所以 v0.1 用启动文件夹，不用 Windows 服务。启动文件夹在 C 盘、会被还原的话，就得把这个快捷方式做进镜像，或者每次手动双击。

日志在 `D:\epsilon\probe.log`。

## 主控（221）

```bash
scp dist/epsilon-controller 221:/opt/epsilon/
# controller.json 照 examples/controller.json 改 token、api_keys
/opt/epsilon/epsilon-controller -config /opt/epsilon/controller.json
```

看节点：`curl -H 'Authorization: Bearer <api_key>' http://221:8090/v1/nodes`

用模型：任何 OpenAI 兼容客户端，`base_url = http://221:8090/v1`，`model = qwen3.5-4b`。响应头 `X-Epsilon-Node` 是实际干活的机器。

## 期望状态

`controller.json` 的 `default` 给所有节点，`nodes` 里按机器名整个覆盖（写 `{}` = 这台什么都不跑）。

| 字段 | 含义 |
|---|---|
| `workload` | 跑哪个工作负载（`probe.json` 里的名字），空 = 不跑 |
| `windows` | 可运行时段，如 `["22:00-07:00"]`，空 = 全天 |
| `yield_on_input` / `input_idle_seconds` | 键鼠在这么多秒内动过就让位（默认 300） |
| `yield_on_foreign_gpu` | 别的程序用显卡就让位（Windows WDDM 下 nvidia-smi 可能拿不到进程表，那时这项不起作用） |
| `heartbeat_seconds` | 心跳间隔（默认 10） |
| `max_offline_minutes` | 主控失联多久后停掉工作负载（默认 30） |

让位检查每秒一次，与心跳无关。

## 已知限制

- 一台机器一次只跑一个工作负载；
- 主控把节点表放内存，重启后探针会被要求重新登记（自动）；
- 路由在已经开始回数据后不换节点：学生机中途让位，那个请求会断。
