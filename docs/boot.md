# boot 与 loader（实现契约）

设计依据：内部设计书 11.9–11.12。**boot 要冻结进母镜像，冻结后不再改**；本文件里标"冻结"的约定一旦冻结就只能加不能改。

## 分工

| | boot（`boot/` + `cmd/epsilon-boot`，冻结） | loader（`loader/`，随本体发布） |
|---|---|---|
| 做什么 | 挑槽、验签、试启动计数、启动并看护本体、确认后转正、失败回退 | 问主控有没有新版本、下载到空闲槽、验签、写"已备好"标记、转发 boot 的事件 |
| 依赖 | 本地磁盘 + 编进程序的公钥。**不联网、不读 probe.json** | 主控接口、网络、probe.json |
| 谁调用 | 计划任务 / 服务 | 本体（epsilon-probe）里的后台 goroutine；安装时 `epsilon-probe -seed` 跑一次就退出 |

## 目录（冻结）

```
<root>\                     例如 D:\epsilon
  A\  B\                    槽：本体文件 + release.json（签名清单原文）
  boot-state.json           只有 boot 写
  staged.json               只有 loader 创建；只有 boot 删除
  boot-events.jsonl         只有 boot 追加写；loader 只读
  boot-events.sent          只有 loader 写：已转发到的字节偏移
  confirm-A / confirm-B     本体第一次心跳成功后创建；boot 读到就转正
```

**每个文件只有一个写入方**（staged.json 是"loader 创建、boot 消费删除"的交接）。写文件一律"临时文件 → 刷盘 → 改名"。

## boot-state.json（冻结，只有 boot 写）

```json
{"current":"A","pending":"","tries":0,"good":"B","bad":"0.3.0","versions":{"A":"0.4.0","B":"0.3.1"}}
```

- `current`：已确认能用的槽；`pending`：正在试的槽；`tries`：pending 已试次数（先写盘再启动，防断电）；`good`：上一个好槽；`bad`：试过不行的版本；`versions`：boot 认定的每个槽的版本。
- loader **只读**它：`pending != ""`（正在试新版本）时不下载；目标版本等于 `bad` 时不下载。

## staged.json（冻结，loader → boot 的交接）

```json
{"slot":"B","version":"0.4.0"}
```

loader 的步骤：
1. 只在 `pending == ""` 时动手；目标槽 = `current` 以外的那个（`current` 为空时是 A）。**绝不写 current 槽**。
2. 清空目标槽 → 逐个下载文件（`.part` → 校验大小和 sha256 → 改名）→ 最后写 `release.json`。
3. 对整个槽按 boot 同样的规则验一遍（签名 + 每个文件哈希 + `min_boot` ≤ boot 版本）。
4. 原子写 `staged.json`。它出现就表示"槽已备好、可以切"。

boot 的处理（启动选槽前，以及看护非试启动的本体时每个 Poll 周期检查一次）：
1. 读 `staged.json`；`slot` 不是 A/B、等于 `current`，或者槽验不过、版本等于 `bad`、`min_boot` 太大 → 记事件，删掉 `staged.json`，不切。
2. 版本**以槽里 release.json 验过的为准**，不信 staged.json 里写的。
3. 写 state：`pending = slot`、`tries = 0`、`versions[slot] = 验过的版本`；若 `good == slot` 则 `good = ""`（它被覆盖了，不能再当退路）。**先写 state，再删 staged.json**（断电后重来是幂等的：发现 `pending == slot` 且版本一致，直接删 staged.json）。
4. 如果本体正在跑（非试启动），停掉它，按新 state 重新选槽启动。

## 回退时核对版本（冻结）

boot 启动 `current` 或回退到 `good` 前，除了验签和哈希，还要核对**槽里清单的版本 == `versions[槽]`**。对不上说明 loader 已经往里写了新东西，这个槽不能当"已确认的好版本"来跑，跳过。

## 事件（冻结格式）

boot 不联网，事件追加写到 `boot-events.jsonl`，一行一个：

```json
{"time":"2026-10-30T08:00:00Z","kind":"boot_rollback","detail":"版本 0.4.0（槽 B）试了 3 次没确认，回到 \"A\""}
```

文件超过 1 MB 时 boot 把它改名为 `boot-events.jsonl.1`（覆盖旧的）再新开。loader 按 `boot-events.sent` 记的偏移读新行，经 `POST /v1/events` 转发（`node` 用本机名），转发成功才推进偏移；发现文件比偏移短（被轮转了）就从 0 开始。

## 首次安装（槽为空）

boot 不下载，所以安装脚本负责放进第一个版本：
1. 从主控 `/dl/` 下载 `epsilon-probe.exe` 到临时目录；
2. 运行 `epsilon-probe.exe -seed -config <root>\probe.json -root <root>`：loader 跑一轮（按上面的步骤写槽和 `staged.json`）就退出；
3. 启动 boot。boot 消费 `staged.json`，按试启动流程跑第一个版本（`current` 为空时没有退路，试启动失败就一直重试，不判 bad）。

## boot 的命令行（冻结）

`epsilon-boot [-root <dir>]`：启动本体为
`<slot>\epsilon-probe.exe -config <root>\probe.json -log <root>\probe.log -workloads <slot>\workloads.json -confirm <root>\confirm-<slot> -boot <boot版本>/<slot> -root <root>`

不再传 `-controller`（本体自己读 probe.json）。单实例锁：占本机 127.0.0.1:47199。

## 无盘模式

不支持（设计书 11.11）。前提：真机验证数据盘重启后不还原。

## 补充约定（2026-10-30，boot 改造评审后定）

- **boot 版本 2 = 不联网的 boot**。loader 只在 `-boot` 传来的版本 ≥ 2 时工作（`loader.OfflineBoot`）；在旧引导器（1）下面不插手，避免和它抢同一个空闲槽。
- loader 判断 `min_boot` 用**机器上实际在跑的 boot 版本**（`-boot` 参数），验槽用 `boot.VerifySlotFor`；不是编进本体的 boot 包版本。
- 发布的 `min_boot` 由发版时显式给（`epsilon-release -min-boot`，默认 2），只在本体真的依赖新引导器时调高。
- loader 下载完、写 staged.json 前**再读一次 state**：期间 boot 换了 current（目标槽成了 current）或开始试启动，就不交接。
- **本体命令行是冻结约定**：本体以后每个版本都必须接受 boot 传的这一整套参数（`-config -log -workloads -confirm -boot -root`），只能加不能删；Go 的 flag 遇到不认识的参数会直接退出。
- 已知、待定（见设计书 11.11 后的评审记录）：A/B 都跑不起来时没有自愈；首次装的版本是坏的没法远程修；试启动期间主控不在线会把好版本判坏；事件轮转判断不够稳。

