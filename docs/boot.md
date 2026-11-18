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
- 下面三节（救援槽、离线确认、事件转发加固）是 2026-10-30 定的，解决：A/B 都跑不起来时没有自愈；首次装的版本是坏的没法远程修；试启动期间主控不在线会把好版本判坏；事件轮转判断不够稳。

## 救援槽 R（冻结，2026-10-30 定）

loader 住在本体里，本体跑不起来就没人下载修复版。所以加一个**只读的救援槽** `<root>\R`：

- 内容：`epsilon-probe.exe` + 签了名的 `release.json`（+ `workloads.json`），和 A/B 一样能用 `VerifySlot` 验。
- **只有安装脚本写 R**；boot 和 loader 都不写、不删。R 不进 `boot-state.json` 的 `versions`，不当 current / good / pending。
- **什么时候用**：boot 选槽时"没有能跑的"——
  1. current 和 good 都验不过（或版本对不上），且没有能试的 pending；或者
  2. **没有退路**（current 为空即首次安装，或 current/good 都验不过），pending 已经连续试了 ≥ `MaxTries` 次都没确认。
- **怎么用**：先 `VerifySlot(R)`，验不过记事件、不跑。验过就运行
  `R\epsilon-probe.exe -seed -config <root>\probe.json -root <root> -log <root>\rescue.log -boot <boot版本>/R`（`-log` 必须给，否则日志默认写进 R），
  等它退出（最多 30 分钟，超时杀掉）。它是一次性的：跑一轮 loader 就退出，不是常驻本体，不写确认文件。
  之后 boot 照常回到选槽循环（有了 staged.json 就按正常流程消费）。
- **限频**：两次救援之间至少隔 10 分钟（记在内存里即可；boot 重启后可以立刻再救一次）。
- 事件：`boot_rescue`（开始，带原因）、`boot_rescue_done`（退出码）、`boot_rescue_bad`（R 验不过）。

### 救援时 loader 选哪个槽

`-seed` 模式（安装、救援都是它）下 loader 的目标槽规则放宽：

- `pending == ""`：照旧，目标 = current 以外的那个（current 空则 A）。
- `pending != ""` 且 `current == ""`（首次安装那个版本坏了）：目标 = **pending 以外的那个槽**。boot 在两次试启动之间看到 staged.json（slot ≠ current）会接受它，改试新槽，`tries` 从 0 开始。
- `pending != ""`、`current != ""` 且 `tries ≥ MaxTries`：救援只在没有退路时才跑，说明 current 也跑不起来 → 目标 = **pending 槽**（覆盖那个试满的坏版本；不碰 current，它若只是暂时坏，仍是唯一可能的退路）。
- `pending != ""`、`current != ""` 且没试满：什么都不做（安装脚本重跑时也不打断正在进行的试启动）。
- 常驻模式（被 boot 拉起的本体里的 loader）不变：`pending != ""` 时不动。
- `-seed` 带 `-boot` 参数时，按它的版本判断 `min_boot`；没带（安装脚本）时用编进本体的 `boot.Version`。
- 主控发的版本**就是 pending 槽里那个**（首次安装的坏版本还在发）：不放进另一个槽，等主控发新版本。否则同一个坏版本会每 10 分钟换个槽再试 3 次，来回空转。

## 离线确认（本体侧，不冻结）

"确认能用"原来只认第一次心跳成功。试启动期间断网或主控宕机，好版本会连续 3 次确认不了被判 bad。改为：

- 心跳成功 → 确认（不变）；
- 或者：本体启动后**持续 60 秒**，每次联系主控（登记、心跳）失败都是**网络层错误**（连不上、拒绝连接、超时、DNS），并且本体自己的主循环在正常跑 → 也确认，记一条日志"主控连不上，按网络故障离线确认"。
- 主控**明确回了**错误（HTTP 状态码 401/404/5xx 等）不算网络故障，不确认——这多半是新版本和主控对不上，正是该回退的情况。409（主控不认识这台）按现有逻辑重新登记，不算失败也不算网络故障。
- 60 秒要小于 boot 的 `ConfirmWithin`（3 分钟）。
- 算网络层错误的：拒绝连接、超时、DNS、连上就断（EOF）。走代理时代理回的 502 会被当成主控回了错误（不确认）；学生机不走代理，不处理。只统计登记和心跳的失败。

## 事件转发加固（loader 侧，不冻结）

- 偏移 > 0 时，先检查文件里偏移前一个字节是不是换行；不是，说明文件已经轮转并重新长过了旧偏移，从 0 开始读。
- 读到不能解析的行（半行、NUL）跳过（已经是这样）。
- 读完立刻关文件（boot 改名轮转时不要被占着）。

### R 里的 loader 也近似冻结

R 只在重装时更新，所以"救援时选哪个槽"的规则以**装进 R 的那个本体**为准，这台机器重装前都改不了。改这些规则时要想到：已经装出去的 R 还是旧规则。


## 冻结前折磨测试（设计书 11.12，2026-11-18）

生产代码只改了一处：`boot/fault.go` 加了一道断电注入的缝（`faultHook`，生产里是 nil），`boot.go` 里的写盘点
（`writeAtomic` 的 Create/Write/Sync/Rename、`appendLine` 的轮转 Rename/OpenFile/Write/Sync、删 staged.json 的两处、
删确认文件的一处）换成了同名小包装，逻辑没动。测试都在 `boot/` 下：

- 开发时的快速回归：`go test -race -short ./boot`（约 13 秒）。状态机只从一小部分初始状态出发，断电只断每第 5 个写盘点；
- 冻结、合并前跑全量：`go test -race ./boot`（约 45 秒，大头是状态机穷举）。

| 11.12 的手段 | 做了没有 | 在哪 |
|---|---|---|
| 断电模拟 | ✅ 8 个场景，共 155 个写盘点，每个点都断一次（不抽样）；write 断在一半（撕裂写） | `powercut_test.go`（`-v` 打印每个场景"N 个写盘点全试过"） |
| 模糊测试 | ✅ 4 个目标，本地各跑 5 分钟无失败；种子语料在 `testdata/fuzz/` | `fuzz_test.go` |
| 状态机穷举 | ✅ 2.8 万个初始状态 BFS，可达约 4.8 万个，12 层收敛 | `statemachine_test.go`（`-short` 只跑一小部分初始状态） |
| 对抗用例 | ✅ 签名攻击、版本回滚、槽文件不完整 | `adversarial_test.go` |
| Windows 专项 | ⬜ 没做：exe 被替换、杀毒隔离、磁盘满、只读、中文路径、两个 boot 同时启动，要在真机上测 | |
| 对抗评审 | ⬜ 没做：要另派一个不知道设计思路的人 | |
| 真机长跑 | ⬜ 没做：牺牲机 + 试点机 | |

**断电模拟**的场景：消费 staged.json（接受 / 拒绝）、试启动后确认转正、试满 MaxTries 回退、current 坏了改跑 good、
首次安装、救援之后消费 staged.json、事件文件轮转。每个点断电后，在同一目录上新起一个 Boot 跑到稳定，检查：

- I1 boot-state.json 总能解析；
- I2 启动的槽一定验得过，非试启动时清单版本等于 `versions[槽]`；
- I3 有退路时，同一个待试版本跨重启的试启动总次数不超过 MaxTries；
- I4 最后在跑的是新版本或者旧的好版本；
- I5 staged.json 最终被消费；
- I6 事件文件每个完整的行都能解析，一次断电最多留下一行半截的；
- I7 current、pending、good 非空时互不相同。

断电模型的前提：改名、删除一旦返回就算落盘（见下面 F4）。断电那一下之后，Run 再走到写盘点就直接结束（`runtime.Goexit`），
和真断电一样后面的代码不再跑。每次只断一次电，恢复途中再断一次没有测。

**状态机穷举**的状态：current/pending/good × tries（0..MaxTries+1）× bad × A/B/R 槽内容（好 / 签名合法但版本不同 /
被篡改 / 缺失）× staged.json（无 / A / B / 垃圾），事件是崩溃或卡死不确认、确认、跑着的槽被篡改，以及 loader 往非 current
的槽写进另一个签名版本、放 staged.json（所以 2.x 版本、bad=2.x 的状态也会遇到交接）。每一步对照一个不调被测代码的
模型检查：消费 staged.json 后整个 state 和模型逐字段一致（含 tries：新槽或新版本清零，同槽同版本的重放不清零）、
不 panic、不启动验不过的槽、I3、I7、没有事件时 Pick 是不动点、有能跑的槽就一定启动、没东西跑就一定救援、救援不写
state 也不跑验不过的 R。用几个故意改坏的 boot.go（不核对版本、不记次数、不拒 bad、转正不留 good、多试一次、
被覆盖的 good 不清、交接新版本时不清零 tries、同槽同版本重放也清零 tries）验证过，每一个都会被抓出来。

模糊测试的签名私钥由固定种子生成（种子语料要跨次运行有效），等于是公开的；`TestFuzzKeyNotInReleaseKeys` 保证它的
公钥不会进 `loader.PublicKeys`（`cmd/epsilon-boot` 的那份由 `loader/keys_test.go` 保证一致）。

## 冻结前暴露的问题

折磨测试**没有找到 boot 逻辑的 bug**，所以 boot.go 除了换包装没有别的改动。下面几条要动冻结契约，或者要在真机上
确认，只记下来待定，没有改。F1–F3 各有一条 `TestKnownIssue*` 用例记录现状，定了怎么改再把断言反过来。

- **F1 清单不要求有本体**。`VerifySlot` 只校验清单里列出的文件，不要求列出 `epsilon-probe.exe`；而 boot 启动的就是
  `<slot>\epsilon-probe.exe`。签名清单如果漏了它，槽里随便放一个 exe 都会被当成验过的本体启动。`epsilon-release` 签的是
  命令行给的那些文件，也不检查有没有 exe，发版时漏传一个参数就会出这样的清单。可能的改法：`VerifySlot` 要求 `Files` 里有 `epsilon-probe.exe`
  （loader 也用它，一起生效）。救援槽 R 走的是同一个 `VerifySlot`，R 的清单漏了本体时 R 里的 exe 也会被运行；
  这个改法对 R 一起生效（`TestKnownIssueF1RescueSlot`）。
- **F2 bad 只记一个版本**。两个坏版本交替下发（比如管理员在两个版本之间来回调），每个都会重新试满 MaxTries 次，
  来回空转。可能的改法：bad 改成最近几个版本的列表（State 加字段，动契约），或者在主控 / loader 侧挡住。
- **F3 槽里多余的文件不拦**。只有清单里的文件受保护。本体或它拉起的程序如果按名字加载同目录的 DLL，多出来的
  文件就是没验过签的代码。要不要改取决于对 Windows DLL 搜索顺序的评估（Windows 专项里一起看）。
- **F4 改名不一定马上落盘**。`writeAtomic` 刷了临时文件，但 Windows 上 `os.Rename` 不带 `MOVEFILE_WRITE_THROUGH`，
  改名本身可能在断电后被日志回滚成旧文件（I1 仍然成立，旧文件是完整的）。后果是"先记 tries 再启动"在断电时
  不一定生效：如果新版本一起来就让整机断电或蓝屏，tries 可能一直记不上，就不会回退。断电模拟假设改名一返回就
  落盘，覆盖不到这一条，要在真机上拔电验证；要改的话是 Windows 专用代码。
- **F5 state 被别人改坏时的容忍度**（只记录）。boot 只自己写 state，正常写不出这些值；但如果 state 被别的程序改了：
  负的 tries 会让试启动次数超过 MaxTries；pending/current 可以指向 A/B 以外的目录（仍然要验签和版本，所以只能跑
  签过名的本体）。模糊测试确认这些情况下都不会 panic，也不会启动验不过的槽。
