# 批任务签名契约（钥匙环 + 任务包）

对应 issue #1 第 1–2 步。代码在 `jobsign/`（格式和校验）、`cmd/epsilon-release/jobcmd.go`（签名命令）、
`controller/jobs.go`（主控队列）、`probe/jobs.go` + `jobrun/`（探针执行）。格式一旦发布只增不改。

## 信任链

```
根钥匙（发布钥匙 release-main / release-backup，离线）
   │ 签
   ▼
任务钥匙环 job-keyring.json  —— 列出能签任务包的钥匙、过期时间、权限上限、吊销的任务包
   │ 其中某把钥匙签
   ▼
任务包 job.signed.json  —— job.json 原文 + 签名 + 钥匙名
```

- 主控只分发这两个文件，**不能**加钥匙、改任务包；主控被拿下最坏是重复跑签过名的任务包。
- 和本体发布签名一样：签名针对**原文字节**，验签不重新序列化。`sign-job` 直接签 `job.json` 文件原文（审核人读到什么就签什么，未知字段也保留），文件要是无 BOM 的 UTF-8。签名后的文件一个字节都不要改，重新排版也算改。
- 根公钥沿用 `loader.PublicKeys`（一主一备，任意一把验过即可）。

## 钥匙环

签名前的明文（人手写这份，交给 `epsilon-release keyring`）：

```json
{
  "version": 1,
  "issued": "2026-11-01T00:00:00Z",
  "keys": [
    {
      "name": "reviewer-a",
      "pub": "<base64 ed25519 公钥>",
      "expires": "2027-02-01T00:00:00Z",
      "limits": {"max_hours": 4, "max_nodes": 20, "rooms": ["R1", "R2"], "network": false}
    }
  ],
  "revoked_jobs": ["<任务包摘要>"],
  "env_layers": {"py311-torch2.5-cu124@1": "<环境层清单的 SHA-256>"}
}
```

| 字段 | 规则 |
|---|---|
| `version` | ≥ 1，**单调递增**。探针记住见过的最高版本，拒收更旧的（防回滚到吊销前） |
| `issued` | RFC3339。比本机时钟超前 24 小时以上就拒（时钟坏了或伪造）；`keyring` 命令没写会自动填当前时间 |
| `keys[].name` | 小写字母、数字、连字符，3–32 位，不重复 |
| `keys[].pub` | base64 的 32 字节 ed25519 公钥 |
| `keys[].expires` | RFC3339；过期后这把钥匙签的任务包一律不跑 |
| `keys[].limits.max_hours` | > 0；任务包的 `max_hours` 不能超过它（探针核对） |
| `keys[].limits.max_nodes` / `rooms` | 主控派活时执行：这把钥匙签的任务同时最多占几台（**0 = 不限制**，负数钥匙环验不过）；`rooms` 空 = 不限。`keyring` 命令要求源文件里每把钥匙**显式写出** `max_nodes`（漏写或键名写错会被当成 0 = 不限制，所以直接拒签），写 0 会打 warning。**含义变更**：本 PR 之前的草稿里 0 是"一台都不派"，手头钥匙环要是按旧含义用 0 停用某把钥匙，先改成删掉这把钥匙（或写具体数字）再升版本重签 |
| `keys[].limits.network` | false 时，要联网的任务包（`network: true`）一律不跑 |
| `revoked_jobs` | 任务包摘要（`job.signed.json` 里 `job` 字段原文的 SHA-256，小写十六进制） |
| `env_layers` | `名字@版本` → 环境层清单原文的 SHA-256。探针只用表里的环境层，拉到清单后核对摘要；主控换不了环境层 |

- **吊销钥匙** = 发一份不含它的新版本钥匙环。
- **吊销任务包** = 把它的摘要写进 `revoked_jobs`，发新版本。
- 未知字段忽略（以后加字段，旧探针照常工作）。

## 任务包

`job.signed.json`：

```json
{"job": "<job.json 原文>", "sig": "<base64 签名>", "key": "reviewer-a"}
```

`job` 的字段见提交手册第 5.2 节。探针核对的硬规则（`jobsign.VerifyJob`）：

1. `key` 在钥匙环里、没过期，签名对得上这把钥匙；
2. 摘要不在 `revoked_jobs` 里；
3. 必填字段（`schema` `name` `version` `owner` `entry` `env` `gpu_mem_mb` `max_hours` `disk_max_mb` `output_max_mb` `code_sha256`）都有，不许写 `null`；
   `schema` = 1；`name`、`version`（x.y.z）、`env` / `data`（`名字@版本`）、`code_sha256`（64 位小写十六进制）格式合法；`owner` 非空；`disk_max_mb` / `output_max_mb` ≥ 1；`env` 在钥匙环的 `env_layers` 里；
4. `entry` = `[解释器, 脚本, 参数…]`：解释器只能是 `python` / `python3`，后面可以有 `-B` / `-u`（不影响执行什么代码；其他解释器参数不行），然后必须是脚本，脚本是 `code\` 下的相对 `.py` 路径、不含 `..`，后面不许出现 `-c` / `-m`；
5. `gpu_mem_mb` 在 0–7168，`max_hours` > 0；`gpu` 不写按 `true` 算（读 `Job.NeedsGPU()`），GPU 任务的 `gpu_mem_mb` 不能是 0，纯 CPU 任务要明确写 `"gpu": false`；
6. `max_hours` ≤ 钥匙的 `max_hours`；要联网的，钥匙必须有 `network` 权限；
7. `params` 每一项的声明（`jobsign.CheckParamDecls`，签名时就查，免得签出来每次提交都 400）：
   - 简写：`"int"` / `"number"` / `"string"` / `"bool"`；
   - 对象：`{"type": 上面四种之一, "min": 数, "max": 数, "enum": [值...], "default": 值, "description": "给人看"}`，除 `type` 都可省；
   - **别的键一律拒**（写错成 `minimum` 不能悄悄失效）；`min` / `max` 只许用在 `int` / `number`，`min` ≤ `max`；`enum` 不能是空数组，每一项都要符合类型和范围；`default` 要符合类型、范围，有 `enum` 时要在里面；
   - 值的规则（`FillParams`，主控提交时、探针拿到时各查一次）：类型对、在范围和 `enum` 里，`int` 不许带小数，数字不许写成字符串；没声明的参数直接拒。

不影响安全和调度的问题只报 warning（`jobsign.JobWarnings`）：`description` 没写或超过 200 字、`owner` 格式不规范。`sign-job` 打印出来并写进 `job.signed.json` 的 `warnings` 留痕；这个字段不受签名保护，探针不看。

`code_sha256` 和实际 `code.zip` 是否一致，签名时由 `sign-job` 核对；探针拉到代码包以后**再核一次**（见下面"探针执行"）。

## 命令

```sh
# 给审核人发钥匙（审核人自己在自己机器上跑，私钥不离手；把打印出来的公钥给根钥匙持有人）
epsilon-release keygen -out dist/keys/reviewer-a.key

# 根钥匙持有人签钥匙环（out 已存在时，新版本号必须更大）
epsilon-release keyring -key dist/keys/release-main.key -in keyring-src.json -out job-keyring.json

# 审核人签任务包（核对 code.zip 哈希、私钥与钥匙环里同名钥匙一致，签完按探针规则自验；
# 顺手在 -chunks 下出代码包清单 code-<sha>.json 和块，已有清单只核对不覆盖，已有块重算哈希）
epsilon-release sign-job -key dist/keys/reviewer-a.key -name reviewer-a \
    -keyring job-keyring.json -job job.json -code code.zip -chunks dist/chunks -out job.signed.json
```

不带子命令时 `epsilon-release` 照旧做本体发布签名，用法不变。

## 环境层

代码在 `envlayer/`，配置在 `deploy/envs/<名字>/`，构建脚本 `tools/build-env-layer.py`。

- **一层就是一个 zip**：清单（`proto.Manifest`）只有一个文件 `envs/<名字@版本>.zip`，走现有分块分发（`docs/p2p.md`），几万个小文件不进清单。
- **信任**：钥匙环 `env_layers` 写清单原文的 SHA-256。探针先核对摘要，再拼 zip、解压到 `<root>/envs/<名字@版本>/`。解压先进临时目录，写好 stamp 再改名；路径穿越、链接、大小写冲突、缺 `python.exe` 都拒。
- **不改旧层**：要加包就发新版本（`@2`）。构建是确定性的（文件排序、固定时间），embeddable Python 核 SHA-256，wheel 按 `requirements.lock` 的哈希装。

构建和手工安装：

```sh
python3 tools/build-env-layer.py deploy/envs/py311-torch2.5-cu124 --out dist/envs   # 打印要写进钥匙环的摘要
epsilon-env install -name py311-torch2.5-cu124@1 -digest <摘要> -manifest <清单> -chunks <块目录> -root D:\epsilon
```

两个容易踩的点，执行器必须照做：

1. **层里没有 `._pth`，执行时固定加 `-E -s -B`（`envlayer.Flags`）。** embeddable 自带的 `._pth` 会打开 `safe_path`（CPython `getpath.py`），脚本目录不进 `sys.path`，多文件任务一 `import` 就失败。没有 `._pth` 就是普通的 `site.py`，所以：`-E` 不读 `PYTHON*` 环境变量；**`-s` 不加用户 site-packages**（`%APPDATA%\Python\Python3xx\site-packages`）——`-E` 管不到它，那里的 `.pth` 每次启动都会执行，一个任务埋下的代码会跑进以后每个任务，签名和环境层摘要都管不到，而且比环境层的审计钩子（`sitecustomize`）还先跑。不能用 `-I`：它连脚本目录也从 `sys.path` 拿掉。
2. **层内 pyc 是预编译的（`unchecked-hash`）。** 任务不写字节码，解压也不保留修改时间；不预编译的话，每次启动都要重新编译 torch。

真机验证：`<层目录>\python.exe -E -s -B deploy\envs\smoke\smoke.py`。

## 任务输出回传

代码在 `joboutput/`（探针侧）和 `controller/joboutput.go`（主控侧），命令行 `epsilon-env upload`。主控配 `jobs_dir` 才开；单任务上限 `job_output_max_mb`（默认 2048）。

| 接口 | 认证 | 说明 |
|---|---|---|
| `HEAD /v1/jobs/{id}/chunks/{hash}` | probe token | 主控有没有这块；已完成的任务按清单回答 |
| `PUT /v1/jobs/{id}/chunks/{hash}` | probe token | 传一块，内容和哈希对不上回 400，超上限回 413 |
| `PUT /v1/jobs/{id}/output` | probe token | 传清单（`proto.Manifest`）。缺块回 409；校验整文件后才算完成 |
| `GET /v1/jobs/{id}/output` | api key | 取清单，没完成回 404 |
| `GET /v1/jobs/{id}/files/{路径}` | api key | 下载；只发清单里列的文件 |

- **续传**：重新运行一遍就行，主控已有的块不再传。
- **完成后冻结**：`manifest.json` 写好后内容不可改，同样内容再传直接成功，不同内容回 409。完成后删掉块目录，不留两份。
- 队列里的任务（`/v1/jobs` 派出去的）只收**当前派到的节点、当前这一次**的回传（请求头 `X-Epsilon-Node`、`X-Epsilon-Attempt`，对不上回 403）；不在队列里的任务号（`epsilon-env upload` 手工传）照旧。token 还是所有探针共用，所以这只防错（失联后又回来的旧一次），不防冒充。

## 显存实测

`tools/job-runner.py` 每秒采一次 `nvidia-smi`，结果写进任务摘要（`output/_runner/summary.json`，随输出回传，不计入任务自己的输出）：

| 字段 | 含义 |
|---|---|
| `vram_baseline_mb` / `vram_peak_mb` / `vram_delta_mb` | 运行前整卡占用、运行中整卡峰值、两者之差 |
| `vram_job_process_mb` | `nvidia-smi` 报的任务进程显存。Windows WDDM 下实测全是 `[N/A]`，这时为 `null`，不能靠它 |
| `vram_allocator_peak_mb` | 任务 `RESULT.json` 自报的 `gpu_peak_allocated_mb`，不含 CUDA 上下文和驱动开销 |
| `vram_reliable` / `vram_notes` | 基线缺失、采样失败、拿不到进程列表、运行中有别的 GPU 进程出现或退出时为 `false`，原因写在 notes |

真机标定（RTX 4060，C445B-40）：任务分配 1024 MB 时差值两次都是 1129 MB，即 CUDA 上下文和驱动约多占 105 MB；中途另一进程分配 512 MB 时差值变成 1745 MB 并被标记。

审核人按 `vram_delta_mb` 校对 `gpu_mem_mb`。`vram_reliable` 为 `false` 的数据不要用，换台机器重测。任务自己开的 GPU 子进程也会被标记，因为现在只认主进程的 pid。

## 主控队列（第 2 步）

`controller.json`：

| 字段 | 说明 |
|---|---|
| `jobs_dir` | 已有：任务输出落这里；队列存 `<jobs_dir>/queue.json`（原子写，主控重启不丢） |
| `job_keyring` | 根钥匙签的 `job-keyring.json`。原样发给探针；主控也拿它核任务包（每次现读，换文件不用重启） |
| `job_packages_dir` | 签好的任务包，文件名 `<名字>@<版本>.json`（就是 `job.signed.json`） |
| `job_max_retries` | 节点失联或重启后重派几次，没写 = 2 |
| `chunks_dir` | 已有：环境层和代码包从这里发 |

`jobs_dir` 和 `job_keyring` 都配了才开下面这些接口：

| 接口 | 认证 | 说明 |
|---|---|---|
| `GET /v1/job-keyring` | probe token | 钥匙环原文 |
| `POST /v1/jobs` | api key | `{"package":"名字@x.y.z","params":{...},"count":N,"nodes":[...],"rooms":[...]}`，回 `{"jobs":[任务号...]}`。不认识的字段、不认识的参数直接 400 |
| `GET /v1/jobs` | api key | 全部任务（按提交时间） |
| `GET /v1/jobs/{id}` | api key | 一个任务：状态、节点、第几次、失联过的节点、退出码、签名者、摘要、输出传完没有（`output`） |
| `DELETE /v1/jobs/{id}` | api key | 撤销：排队的不再派；派出去的从期望状态里去掉，探针看不到了就整树杀。已结束的回 409 |

- **主控只能挑、填、选**：提交时用 `jobsign.VerifyJob` 核任务包（验签、过期、吊销、字段），`jobsign.FillParams` 按包里的 `params` 声明校验参数（类型、`min`/`max`、`enum`）并补 `default`。下发的是任务包原文，探针自己再验。
- **提交时就拒**：任务包不存在 404；签名/钥匙/字段不过、带 `data`（数据集还没做）、`rooms` 超出钥匙权限、`chunks_dir` 里没有代码包或环境层的清单都是 400。
- **`queue.json` 读坏了**：批任务停用，`POST` / `DELETE /v1/jobs` 回 503，主控**不再写** `queue.json`（坏文件里是旧任务和序号，等人修好或挪走再重启）。
- **代码包约定**：清单 ID `code-<code_sha256>`，里面只有一个文件 `jobcode/<code_sha256>.zip`。`sign-job` 签名时顺手生成（`-chunks` 目录，默认 `dist/chunks`，整个传到主控 `chunks_dir`）；那里已有 `code-<sha>.json` 的，按它的块大小重切 `code.zip` 比对，对不上就报错、不覆盖、不写块、不出签名文件，对得上原样不动。块目录里已有的块文件也逐个重算哈希，坏了（rsync 中断、拷贝出错）报错并指出是哪个块，删掉它重签即可。手工做也行：把 `code.zip` 改名放到 `<目录>/jobcode/<sha>.zip`，`epsilon-chunk build -id code-<sha> -root <目录> -out <chunks_dir> jobcode/<sha>.zip`。
- 任务号 `<任务名>-<序号>`，序号存在 `queue.json` 里接着往下排，不和 `jobs_dir` 里已有的目录撞。`count` 份就是 `count` 个任务号，各自回传输出。
- **派活**（每次心跳和每 5 秒）：按提交顺序，给每个排队的任务挑一台节点（按名字排）：
  - 节点开了能力 32（心跳 `jobs: true`）、心跳没过期、手上没有没结束的任务（正在杀的旧任务也算占着）；
  - 在提交的 `nodes` / `rooms` 里；钥匙限了 `rooms` 的，节点必须在拓扑表里且在这些教室；
  - GPU 任务：心跳里第一张卡的显存总量 ≥ `gpu_mem_mb`；
  - 这把钥匙现在占着的节点数 < `max_nodes`（**`max_nodes` 为 0 = 不限制**）。"占着"除了主控派出去没结束的，还算探针还报着没结束的：撤销了正在杀的、失联了可能还在跑的（失联的最多算到它最后一次心跳后 `max_hours`，探针自己到时也会杀）；
  - 派之前用当前钥匙环复核一次：已吊销、钥匙过期的任务直接 `rejected`。复核只在真要派的时候做（有空节点、钥匙有名额、挑得出节点），排队再多，每次心跳也只验要派出去的那几份。
- **派了任务的节点先停推理**：心跳回包里 `job` 有值时 `workload` 置空；探针这边也会自己停（双保险）。
- **失联从头重跑**：派到的节点心跳超过 `stale_seconds`，或探针重新登记时手上没有这次任务（重启过），任务放回队列，`attempt` 加一，丢掉上次没传完的输出块。重派先避开失联过的节点，实在没别的再用。超过 `job_max_retries` 次算 `failed`。退出码非 0、超时、超磁盘都是最终结果，**不重试**。
- **输出已经传完的不重跑**：探针传完输出（`manifest.json` 冻结）到下一次心跳报结束状态之间重启或失联的，按回传的 `_runner/summary.json` 记结束状态（退出码 0 → `succeeded`，非 0 → `failed`，超时/超磁盘 → `killed`），`detail` 里注明"输出已传完，结束状态没报上来"。重跑的话新一次的摘要不同，回传必然 409。
- **状态随心跳对账**：探针在登记和每次心跳里带 `job`（`proto.JobStatus`），主控只认当前派到的节点、当前这一次（`attempt`）。回包丢了（探针下一次心跳没报这个任务）就再发一次，不算失联。

任务状态：`queued` → `assigned`（发出去了，探针还没报）→ `fetching` → `running` → `uploading` → `succeeded` / `failed`（退出码非 0、输出超限、回传失败、拉取超时、重试用完）/ `killed`（超时、超磁盘、撤销）/ `rejected`（探针或主控复核没过，一行代码都没跑）/ `cancelled`（撤销）。

## 探针执行（第 2 步）

`probe.json`：

| 字段 | 默认 | 能力 | 说明 |
|---|---|---|---|
| `jobs` | `false` | 32 | 执行签名任务包。**上线前必须先做下面"上线前必须做"** |
| `job_keyring` | `true` | 33 | 每 10 分钟拉一次钥匙环、记住最高版本号；关了就一个任务都验不了。主控没配批任务（404）只记一次日志 |

一次任务（`probe/jobs.go`）：

1. **钥匙环**：`GET /v1/job-keyring`，用根公钥（和本体发布同一套 `loader.PublicKeys`）验签；版本比 `<artifact_root>/job-keyring.version` 记的旧就拒；验过后更高的版本号原子写回（临时文件 + Sync + 改名）。版本文件坏了就全拒，不当 0。
2. **任务包**：`jobsign.VerifyJob` 自己验（签名、钥匙过期、吊销、字段、`max_hours` 和联网不超钥匙权限）；参数再过一遍 `FillParams`，主控塞进去没声明的参数直接拒。
3. **时钟**：判断过期用的"现在"取 本机时间、主控回包的 `Date`、钥匙环 `issued` 里**最晚**的。主控可以骗探针提早判过期，骗不了它放过过期的钥匙。
4. **环境层**：钥匙环 `env_layers` 的摘要核对清单 → 分块/P2P 拉 → 拼 zip → 解压（`envlayer`）。已经装好就直接用。
5. **代码包**：取清单 `code-<code_sha256>`，只许一个文件 `jobcode/<sha>.zip`、整文件哈希等于 `code_sha256`；拉块、拼好后**整个文件重算 SHA-256**（二次核对，不信清单也不信 `.epsilon-ok` 校验戳），不符就删掉、拒跑。
6. 第 1、4、5 步主控一时出错（连不上、超时、5xx）就退避重试（5 秒起翻倍，最多 2 分钟一次）；钥匙环、环境层和代码包 2 小时内没拉齐算失败，放出机器。验签、摘要、哈希不对直接 `rejected`，不重试。
7. **展开**到 `<artifact_root>/jobs/<id>/`（`jobrun.Prepare`）：旧目录整个删掉从头来；`code/`（zip 解压前整包查一遍，有一条不过就拒：路径穿越、链接、大小写冲突、Windows 保留名 `CON` `NUL` `COM1` `LPT9` 等（带扩展名也算）、段尾的点和空格、展开后路径超过 259 字符、解压后合计超过 256 MB）、`data/`（空）、`params.json`（核过的参数）、`output/`、`tmp/`、`job.log`。
8. **执行**（`jobrun.Run`）：`<环境层>\python.exe -E -s -B <entry[1:]...>`，工作目录 `code\`，**不经 shell**；`TMP`/`TEMP` 指到 `tmp\`。Windows 上挂起启动 → 放进新建的作业对象 → 再恢复，任务起的子进程逃不出这棵树；超时（`max_hours`）、写盘超过 `disk_max_mb`（`output/` + `tmp/` + `job.log`，每 10 秒查）、撤销时整棵树一起杀；主进程正常退出后树里剩下的也杀掉。探针自己死了作业对象句柄关闭，Windows 也会杀整棵。
9. **回传**：写 `output/_runner/summary.json`（任务号、第几次、节点、任务包、签名者、摘要、参数、退出码、被杀原因、秒数）和 `output/_runner/job.log`（`job.log` 末尾 1 MB），再用 `joboutput` 回传（失败隔 30 秒续传，最多 5 轮）。成功、失败、超时、超磁盘都回传；撤销的不回传；`output/` 超过 `output_max_mb` 的算失败、不回传。**`output/_runner/` 只许平台写**：任务结束（整棵树已杀）后里面有任何东西，就是任务自己写的（伪造摘要、绕过 `output_max_mb`），算失败、不回传；摘要写不进去也算失败、不回传。
10. 开始发一条 `job` 事件（任务号、第几次、任务包、签名者、摘要前 12 位、参数）；结束发一条（任务号、第几次、结束状态、签名者、摘要前 12 位、原因；验签之前就被拒的没有签名者，写明"没验过签"）。钥匙环升版本发 `keyring` 事件。

## 上线前必须做（issue #1 第 4 步，这一版没有）

- **专用低权限账户**：任务进程现在以探针的账户运行，教室机自动登录的是 `Administrator`，等于签过名的代码拿到管理员。必须改成 `epsilon-job`（`CreateProcessWithLogonW` 或指定账户的计划任务，每台密码由安装脚本生成存数据盘）。
- **写执行分离**：`code\` 只读，`output\`、`tmp\` 可写但拒绝 `FILE_EXECUTE`（NTFS ACL）；环境层审计钩子（设计书 22.6.1）。
- **出站防火墙**：只许连主控和同教室；钥匙 `network: true` 才放开。现在声明了 `network` 的任务只记一条日志。

`probe.json` 默认 `jobs: false`，这三条做完之前不要在教室机上打开。

## 还没做（按 issue #1）

- 上面"上线前必须做"三条（第 4 步）；
- 网页"任务"页（第 5 步），现在只有 API；
- 数据集（`data`）：清单还没被根钥匙钉住，带 `data` 的任务包主控和探针都拒；
- 让位、检查点、多机并行、允许时段（`windows`）：第一版不做；
- 磁盘空间管理：任务目录本地保留和 24 小时回收（设计书 22.4）还没做，现在留着不删；
- 任务显存实测：`tools/job-runner.py` 有，执行器还没接（心跳和运行摘要里都没有）；`EPSILON-PROGRESS` 进度行不解析；
- 一次提交只能"一组参数 × N 份"，不支持参数列表；
- `sign-job` 签名前强制跑静态审核工具（另一个分支在写）。
