# 第 2 阶段：教室内 P2P 分块分发（实现契约）

设计依据：内部设计书 4.5、11.5、14 节。本文件是各模块之间的约定，改动要同步改这里。
类型都在 `proto/proto.go`（Manifest / ManifestFile / Have / Peers，Register.P2PPort / Register.Chunks，DesiredState.Artifacts / P2PUploadMbps）。

## 流程

1. Mac 上 `epsilon-chunk build` 把模型切成 64 MiB 的块，产出 `<chunks_dir>/<id>.json`（Manifest）和 `<chunks_dir>/<hash[:2]>/<hash>`（块文件），传到 221。
2. 主控配置里给节点的期望状态写 `artifacts: ["<id>"]`。
3. 探针看到 artifacts 里有没备齐的 → 不起工作负载（原因 `fetching`），开始拉：
   `GET /v1/manifests/{id}` → `GET /v1/peers?manifest={id}&node={node}` → 按来源顺序取块 → 校验 sha256 存进本地块缓存 → `POST /v1/have` 报新块 → 某块没来源就过 `retry_after_seconds` 再问 peers。
4. 所有块齐了 → 按 Manifest 拼成文件（写临时文件、校验整文件 sha256、改名）落到 `artifact_root/<path>` → 工作负载照常启动。
5. 每台探针同时开分块服务（端口 `p2p_port`，默认 47100），给邻居提供 `GET /v1/chunks/{hash}`。

## 接口

| 接口 | 谁提供 | 认证 | 说明 |
|---|---|---|---|
| `GET /v1/manifests/{id}` | 主控 | probe token | 读 `<chunks_dir>/<id>.json` |
| `GET /v1/chunks/{hash}` | 主控、每台探针 | probe token | 块内容；hash 必须是 64 位小写十六进制，否则 404 |
| `GET /v1/peers?manifest=&node=` | 主控 | probe token | 回 `proto.Peers` |
| `POST /v1/have` | 主控 | probe token | 收 `proto.Have`；节点没登记过回 409（和心跳一样，探针重新登记） |

登记（`/v1/register`）带 `p2p_port` 和本地全部块 `chunks`，主控以此重置该节点的块表。

## 主控的来源排序（peers）

- 拓扑：主控配置 `topology: {"<节点名>": {"room": "R1", "switch": "R1U12"}}`，由 `tools/ports2topology.py` 从座位 → 交换机端口表 `ports.json` 生成。不在表里的节点 room/switch 当空串（彼此不算同交换机、同教室）。
- 每个块的来源 = 心跳没过期、`p2p_port>0`、持有这个块的其他节点，地址 `http://<心跳来源 IP>:<p2p_port>`；顺序：同交换机 > 同教室 > 其他；同一层内随机打乱（分散压力）。
- **种子**：每间教室里，期望状态含该 manifest 的在线节点按名字排序取前 `seeds_per_room`（默认 2）台为种子。主控 `""` 只出现在：请求者是种子；或者请求者所在教室没有在线种子（不在拓扑里的节点也算这种）。非种子拿到空列表就等种子和邻居先拉到。
- `retry_after_seconds`：有块来源为空时给 3。

## 探针侧

- 本机配置 `probe.json` 新增：`artifact_root`（默认 probe.json 所在目录）、`chunk_dir`（默认 `<artifact_root>\chunks`）、`chunk_quota_gb`（默认 100）、`p2p_port`（默认 47100，0 = 不开）。
- 块缓存超配额按最近使用淘汰（不淘汰当前期望 artifacts 用到的块），淘汰的块经 `/v1/have` 的 `del` 报。
- 已经拼好的文件：同目录写 `<文件>.epsilon-ok`（内容是整文件 sha256 + 大小 + 修改时间），开机核对一致就不重算哈希。
- 并发取块默认 4 个；单个来源 30 秒没完成就换下一个来源；同一来源连续 3 次校验失败拉黑到本轮结束。
- 上传限速按期望状态 `p2p_upload_mbps`。

## 不在这一版

制品清单签名（现在靠 token + 块哈希；块哈希保证邻居给不了假数据，清单本身信主控）、热度回报、纠删码、HTTPS。

## 缓存管理（预热、查看）

主控统一管：哪台缓存了什么、要预热什么。

- **预热**：`DesiredState.Preload` 是要预热的 manifest ID。探针在 Artifacts 都备齐（或没有）之后，用同一个拉取器把这些块拉进本地块缓存，**只缓存块、不拼成文件、不影响工作负载**。以后换成这个模型时只差拼文件这一步（几 GB 本地拷贝，不走网络）。选种子时，Preload 里有这个 manifest 的节点和 Artifacts 里有的一样算候选。
- 淘汰时 keep = Artifacts ∪ Preload 用到的块。
- 主控接口（都走 api key，给人和脚本用）：

| 接口 | 说明 |
|---|---|
| `GET /v1/cache` | 每个 manifest：块数、字节数、完整持有 / 部分持有的节点数，按教室分组；每台节点：持有块数、字节数、各 manifest 完成百分比；当前预热规则 |
| `POST /v1/cache/preload` | body `{"manifest":"<id>","nodes":["pc-01"]}`、`{"manifest":"<id>","room":"R1"}` 或 `{"manifest":"<id>","all":true}`；同一 manifest 再发一次就覆盖。manifest 不存在 404 |
| `DELETE /v1/cache/preload?manifest=<id>` | 撤掉这个 manifest 的预热规则（已缓存的块不主动删，按 LRU 自然淘汰） |

- 预热规则存 `<chunks_dir>/preload.json`（原子写），主控重启后还在。`desiredFor` 把匹配本节点的规则并进 `Preload`（去重，已在 Artifacts 里的不重复放）。
- 块字节数：第 i 块大小 = min(ChunkSize, 文件大小 − i×ChunkSize)。节点字节数只算能在某个清单里查到大小的块。

## 补充约定（实现中定下的）

- **manifest ID 不可变**：内容变了就换 ID（带版本，如 `qwen3.5-4b-q4km-v1`）。探针会缓存"已备齐"，不会发现同 ID 换了内容。
- **`preload` 是保留名**：预热规则存在 `<chunks_dir>/preload.json`，不能当 manifest ID。
- 拉黑：同一来源连续 3 次失败（校验不过、超时、连不上、非 200 都算）本次拉取内拉黑，成功一次清零；连续 3 轮"有来源却一块没取到"算这次拉取失败，1 分钟后整个重来。只是在等种子（来源为空）的轮次不算。
- `retry_after_seconds` 为 0 时探针按 3 秒；`chunk_quota_gb` 写 0 当默认 100（没有"不限"）。
- 拉取（含预热）**不让位**（2026-10-30 定）：有人用电脑时也照样拉。分块是教室内网流量，学生上网走的是上联，基本不冲突；真有人嫌卡，用期望状态的 `p2p_upload_mbps` 限上传。
- 预热在当前 artifacts 都备齐之后才开始；`/v1/have` 的 `del` 只报真正删掉的块（`Evict` 淘汰的，或拼装时校验不过删掉的坏块；Windows 上正被读的块删不掉，下次再试）。`add` 发出前再看一眼缓存，已经被淘汰的块不报。
- 拓扑表要全：不在表里的节点会直接从主控拉，绕过种子限流。

## 坏块自愈、回包上限（加固时补的行为说明）

接口形状和 `proto/` 都没变，只是下面这些行为写清楚：

- **块先刷盘再改名**：`Store.Put` 写临时文件、校验、`Sync`，然后才改成正式文件名。断电后正式文件名下不会是半截块。
- **开机清理**：`NewStore` 只删放了 1 小时以上没动的 `.tmp-*`（同一块目录上可能同时开着别的 Store，比如探针和 `epsilon-env`，不能删人家正在写的）；0 字节、又不是空内容哈希的块直接删掉（断电的典型残留）。别的大小、内容不对的块开机看不出来（不知道应有多大，100 GB 缓存开机重算哈希太慢），拼装时再处理。
- **坏块自愈**：`chunk.Assemble` 整文件哈希或大小对不上时逐块重算，内容和块名对不上的块从缓存里删掉，错误里带块名（包着 `ErrHashMismatch`）。探针的拉取看到拼装失败后有块不见了，就经 `/v1/have` 的 `del` 报给主控（别再把这台排成这块的来源），在同一次拉取里重取、再拼一次；还不行才按失败处理，过 1 分钟整个重来。一次拼装会把清单里所有文件的坏块都找出来（不是只看第一个出错的文件），所以一次重取就能补齐。整文件对不上但每块都没问题（清单本身写错），不删任何块，错误里说明是清单的问题。
- **回包上限**：从邻居或主控取一块时，回包最多 `chunk_size` 字节（清单没写按 64 MiB）。`Content-Length` 超了直接不收；没写或写少了就边读边数，超了就断。这一块算这个来源失败一次（计入拉黑）。
- **同一路径拼装排队**：同一进程里两次拼装落到同一个目标路径时排队执行（路径按小写比较：Windows 和 macOS 默认不分大小写）；stamp 记的大小和修改时间取自改名前、句柄已关掉的临时文件，不会配上别人刚改名过来的文件。
- **报 have 不拖住取块**：取到的块交给一个后台 goroutine 报；上一次 `/v1/have` 还没回来时取到的块攒着，下一次一起报。主控慢或卡住时并发取块照常进行（以前每个 worker 都排队等同一次 HTTP，退化成一块一块取）。

已知限制：

- 开机不核对块的大小和内容，只预热、没拼装的坏块会一直报给主控；邻居来取时校验不过，记那台失败一次。
- 清单本身写错（整文件哈希或大小不对）时，每次重试都会把这个文件的块整个重读一遍核对，按 `fetchRetry` 每分钟一次，直到主控换掉清单。
- 探针和 `epsilon-env` 共用块目录时，一边核对坏块、另一边恰好把同一块的好副本改名过来，好副本可能被删掉。内容仍按哈希校验，最坏多取一次。
- 拼装排队只管本进程；跨进程同时拼同一路径，靠 stamp 取自改名前的临时文件兜底，最坏是 Ready 为假、再拼一次。
