# epsilon

ProjectEpsilon 的探针和主控，v0.1。设计书在内部仓库（未公开），这里是第 0–1 阶段能用的最小实现：

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

### 模型分发（第 2 阶段，契约见 `docs/p2p.md`）

主控在期望状态里写 `artifacts` 后，探针自己拉模型：先问主控每块去哪拿（同交换机的邻居优先），校验 sha256 存进本地块缓存，齐了拼成文件。没备齐前不起工作负载（心跳原因 `fetching`，不算让位）；开始、备齐、失败各记一条 `fetch` 事件。同时每台探针也开分块服务给邻居供块。`probe.json` 里相关的字段都可以不写：

| 字段 | 默认 | 含义 |
|---|---|---|
| `artifact_root` | `probe.json` 所在目录 | 拼好的文件落到 `<artifact_root>\<清单里的 path>`，旁边写 `<文件>.epsilon-ok` 校验戳 |
| `chunk_dir` | `<artifact_root>\chunks` | 块缓存；相对路径按 `artifact_root` 算 |
| `chunk_quota_gb` | 100 | 块缓存超过这么多就按最近使用淘汰（不动当前要用的块） |
| `p2p_port` | 47100 | 分块服务端口；写 `0` = 不开（只从别人那拿，不给别人） |

`artifact_root`、`chunk_dir` 写相对路径时按 `probe.json` 所在目录算。分块服务要在 Windows 防火墙放行入站 TCP `p2p_port`，不然邻居连不上，只能都从主控拿。上传限速由主控的 `p2p_upload_mbps` 统一管。

## 主控（221）

```bash
scp dist/epsilon-controller 221:/opt/epsilon/
# controller.json 照 examples/controller.json 改 token、api_keys
/opt/epsilon/epsilon-controller -config /opt/epsilon/controller.json
```

看节点：`curl -H 'Authorization: Bearer <api_key>' http://221:8090/v1/nodes`

用模型：任何 OpenAI 兼容客户端，`base_url = http://221:8090/v1`，`model = qwen3.5-4b`。响应头 `X-Epsilon-Node` 是实际干活的机器。

P2P 分块分发（第 2 阶段，契约见 `docs/p2p.md`）在 `controller.json` 里配：

- `chunks_dir`：`epsilon-chunk build` 产出的目录（`<id>.json` 清单 + `<hash[:2]>/<hash>` 块）；不写就不开 P2P 接口。
- `topology`：节点在哪间教室、哪台交换机，决定邻居来源的先后（同交换机 > 同教室 > 其他）。从座位 → 交换机端口表生成：
  `python3 pilot/ports2topology.py ports.json > topology.json`，再贴进 `topology`。不在表里的节点直接从主控拉。
- `seeds_per_room`：每间教室几台种子（期望状态 `artifacts` 含该制品的在线节点按名字排序取前几台）可以从主控拉块，其余等邻居；默认 2。

`/v1/nodes` 的 `chunks` 是每台节点持有的块数。

缓存管理（开了 `chunks_dir` 才有，走 `api_keys`）：

```bash
K='Authorization: Bearer <api_key>'
# 看缓存：每个清单的块数/字节数、完整/部分持有的节点数（按教室分）；每台在线节点的块数、字节数、各清单完成百分比；预热规则
curl -H "$K" http://<controller>:8090/v1/cache
# 预热：只把块拉进学生机本地缓存，不拼文件、不影响正在跑的工作负载。nodes / room / all 三选一，同一 manifest 再发就覆盖
curl -H "$K" -d '{"manifest":"qwen3.5-9b-q4km","room":"R1"}' http://<controller>:8090/v1/cache/preload
curl -H "$K" -d '{"manifest":"qwen3.5-9b-q4km","nodes":["pc-01","pc-02"]}' http://<controller>:8090/v1/cache/preload
curl -H "$K" -d '{"manifest":"qwen3.5-9b-q4km","all":true}' http://<controller>:8090/v1/cache/preload
# 撤掉预热（已缓存的块不删，按 LRU 自然淘汰）
curl -H "$K" -X DELETE 'http://<controller>:8090/v1/cache/preload?manifest=qwen3.5-9b-q4km'
```

预热规则存在 `<chunks_dir>/preload.json`，主控重启后还在；心跳回复的期望状态里 `preload` 就是匹配这台的规则（已在 `artifacts` 里的不重复放）。预热这个清单的节点和要用它的一样可以当种子。

## 期望状态

`controller.json` 的 `default` 给所有节点，`nodes` 里按机器名整个覆盖（写 `{}` = 这台什么都不跑）。

| 字段 | 含义 |
|---|---|
| `workload` | 跑哪个工作负载（`probe.json` 里的名字），空 = 不跑 |
| `windows` | 可运行时段，如 `["22:00-07:00"]`，空 = 全天 |
| `yield_on_input` / `input_idle_seconds` | 键鼠在这么多秒内动过就让位（默认 300） |
| `yield_on_foreign_gpu` | 别的程序用显卡就让位。桌面/外壳/输入法类进程和常见浏览器内置忽略（浏览器算轻度使用，归降档管）；本机 `probe.json` 可用 `gpu_ignore` 追加忽略的进程名（不区分大小写） |
| `heartbeat_seconds` | 心跳间隔（默认 10） |
| `max_offline_minutes` | 主控失联多久后停掉工作负载（默认 30） |

让位检查每秒一次，与心跳无关。

## 已知限制

- 一台机器一次只跑一个工作负载；
- 主控把节点表放内存，重启后探针会被要求重新登记（自动）；
- 路由在已经开始回数据后不换节点：学生机中途让位，那个请求会断。
