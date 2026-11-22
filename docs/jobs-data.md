# 批任务数据包 / 代码包拆分（设计稿，未实现）

状态：**只有设计，没有代码**。方向 9x 已同意；等 #13（主控队列）合并、#17（沙箱）定型后按第 10 节分步实现。
现状：任务包的 `data` 字段主控（`controller/jobs.go` `handleJobSubmit`，"数据集还没做"）和探针（`probe/jobs.go` `runJob`）都直接拒；
`jobrun.Prepare` 建的 `data\` 是空目录。

## 0. 已定方向（不再讨论）

- 数据包**单独签名**、按**内容哈希**寻址、复用 `chunk/` + P2P 分发（`docs/p2p.md`，#15 加固）。
- 代码包只放代码，按哈希引用一个或多个数据包。
- 探针本地缓存数据块（LRU），校验哈希后**只读**进任务目录。
- `epsilon-review` 只审代码包；数据包只查格式和大小。

## 1. 信任链

```
根钥匙 ──签──▶ 钥匙环（新增：data_keys 列表、revoked_data）
                 │
     ┌───────────┴────────────┐
 keys[] 里的钥匙签          data_keys[] 里的钥匙签
 任务包 job.signed.json      数据包 data.signed.json
   └─ data[].sha256 ──引用──▶ 数据包摘要 ──▶ manifest_sha256 ──▶ 清单原文 ──▶ 文件哈希 / 块哈希
```

- 任务包签名里写死数据包摘要，**完整性**由任务包签名传递下来（换一个字节就对不上），主控换不了数据。
- 数据包自己的签名管的是**授权**：谁担保这份数据格式合规、大小合规、密级标对了；可以单独吊销。
- 两道签名都过、摘要都对才跑。
- 数据包摘要只看原文、不含签名和钥匙名：同一份 `data.json` 换一把数据钥匙重签，摘要不变，引用它的任务包不用重签。

## 2. 包格式与签名

### 2.1 数据包 `data.json`（签名原文，规则同任务包：签原文字节，不重新序列化，无 BOM UTF-8）

```json
{
  "schema": 1,
  "name": "cifar10-train",
  "version": "1.0.0",
  "owner": "zhang3",
  "description": "CIFAR-10 训练集，5 个 tar 分片",
  "manifest": "data-cifar10-train-1.0.0",
  "manifest_sha256": "<清单原文的 SHA-256>",
  "bytes": 186000000,
  "sensitivity": "public"
}
```

| 字段 | 规则 |
|---|---|
| `name` / `version` | 同任务包（`jobName`、x.y.z） |
| `manifest` | 清单 ID，固定为 `data-<name>-<version>`（`sign-data` 填）。**不能用 `data-<manifest_sha256>`**：`proto.Manifest` 里自带 `id`，ID 里含清单自己的哈希是死循环，算不出来 |
| `manifest_sha256` | 清单原文 SHA-256。信任只认它；ID 只是主控 `chunks_dir` 里的文件名。两份不同内容撞了同一个 `name@version`，后来的那份在 `sign-data`（已有清单只核对不覆盖）和主控提交（清单哈希对不上）两处被拒，换版本号就行 |
| `bytes` | 清单里所有文件大小之和（探针核对）；≤ 签名钥匙的 `data_max_gb` |
| `sensitivity` | `public` / `campus` / `restricted`，含义和处理见第 6 节 |

签名后：`data.signed.json` = `{"data": "<原文>", "sig": "...", "key": "data-a"}`，形状同 `SignedJob`。
**数据包摘要** = `data` 字段原文的 SHA-256（同 `JobDigest`）。主控按 `<job_data_dir>/<摘要>.json` 存。

### 2.2 钥匙环（只加字段，旧探针忽略）

```json
{
  "...": "...",
  "data_keys": [
    {"name": "data-a", "pub": "<base64>", "expires": "2027-02-01T00:00:00Z",
     "limits": {"data_max_gb": 20, "rooms": ["R1", "R2"]}}
  ],
  "revoked_data": ["<数据包摘要>"]
}
```

| 新字段 | 规则 |
|---|---|
| `data_keys[]` | 只能签数据包的钥匙。`name` / `pub` / `expires` 规则同 `keys[]`；**名字不能和 `keys[]` 里的任何一把重复** |
| `data_keys[].limits.data_max_gb` | 单个数据包上限，必填、> 0 |
| `data_keys[].limits.rooms` | 用了这把钥匙签的数据包的任务只能派到这些教室（主控执行，和任务钥匙的 `rooms` 取交集）；空 = 不限 |
| `revoked_data` | 数据包摘要列表 |

**为什么单独一个列表，不在 `keys[]` 上加 `roles`**：老探针、老主控不认识 `roles`，`keys[]` 里一把只该签数据的钥匙，
在它们眼里就是一把普通任务钥匙，能签 `schema: 1` 的任务包拿去跑代码。A/B 槽回滚、主控回滚都是支持的操作，
这条提权路必须结构上堵死：`data_keys` 老版本根本看不到，`keys[]` 原样不动。
顺带：数据钥匙不用填 `max_hours` / `max_nodes` 这些对它没意义的字段，`VerifyKeyring` 对 `keys[]` 的校验也不用改。
一个人既审代码又担保数据，就发两把钥匙。

### 2.3 任务包引用数据（`schema: 2`）

```json
{"schema": 2, "...": "...", "data": [{"sha256": "<数据包摘要>", "as": "cifar"}]}
```

- **`schema: 2` ⇔ 带非空的 `data`**。`schema: 1` 带 `data`、`schema: 2` 不带都拒。老探针 `VerifyJob` 只认 `schema = 1`，拿到新包直接 `rejected`，不会无数据硬跑。
- `as` 是 `data\` 下的目录名：小写字母数字连字符，1–32 位，同一个任务包里不重复；同一个摘要也不许引用两次。任务代码读 `data\<as>\...`。
- Go 侧 `Job.Data` 从 `[]string` 改成 `[]DataRef{SHA256, As}`。`[]string` 形式从没被接受过，不算破坏已发布格式。
- 数量上限：一个任务最多 8 个数据包（先拍个数，见第 11 节）。

### 2.4 数据清单：复用 `proto.Manifest`

- ID 见 2.1；文件路径就是数据目录里的**相对路径**，不加前缀（拼的时候根目录是 `jobs\<id>\data\<as>\`，见 5.3）。
- **不拆 zip、不解压**：文件原样列在清单里。好处是探针侧没有解压这一层攻击面。
- 清单受现有 16 MB 读取上限约束，再加硬限制：文件数 ≤ 4096。几万张小图请打成 tar / parquet / webdataset 分片（数据包作者负责）。
- 路径过 `chunk.SafePath` + `chunk.WindowsSafe`，大小写不冲突；相对路径 ≤ 160 字符（`sign-data` 不知道探针的 `artifact_root` 和任务号，留出前缀的余量；
  探针拼之前按真实路径再查 259）。

## 3. 签名命令

```sh
epsilon-release sign-data -key dist/keys/data-a.key -name data-a -keyring job-keyring.json \
    -in data.json -root ./cifar10 -chunks dist/chunks -out dist/data
```

1. 遍历 `-root`，过格式检查（下面），`chunk.Build` 出清单 `data-<name>-<version>` 和块，回填 `manifest` `manifest_sha256` `bytes`；
2. 打印完整 `data.json` 让签名人过目（密级是人填的，工具不猜），确认后签名，写 `dist/data/<摘要>.json`；
3. 按探针规则自验一遍（同 `sign-job`）；已有清单只核对不覆盖、已有块重算哈希（同 `sign-job`）。

**格式检查（只查格式和大小，不审内容）**：

- 拒：符号链接、硬链接、空文件名、路径规则不过、大小写冲突、文件数 / 总量超限、文件名以 `.epsilon-ok` 结尾（块缓存的校验戳后缀，免得以后有人又拿 `chunk.Assemble` 拼）；
- 拒（按扩展名，不区分大小写）：`.py` `.pyc` `.pyw` `.pth` `.pyd` `.dll` `.exe` `.so` `.bat` `.cmd` `.ps1`——数据目录里不该有代码，报错直接说是哪个文件。
  不做按文件头识别可执行格式：真正的边界是 `data\` 没有 FILE_EXECUTE（继承 `jobs\<id>\` 的只读）、审计钩子拦 `code\` 以外的 `.py`/`.pth` 读写和 `sys.path` 外的导入、
  `ctypes.dlopen` 只许环境层和 System32。这里只是早报错；
- 不拒 pickle / `.pt`：代码那边 `epsilon-review` 的 `pickle-use`、`unsafe-load` 已经拒签加载它们的写法（torch 2.5 的 `torch.load` 默认不是 `weights_only`）。数据里有 pickle 只打 warning。

`sign-job` 增加：任务包带 `data` 时，`-data dist/data` 里必须找到每个摘要对应的数据包，并且按当前钥匙环验得过（免得签出来提交就 400）。

## 4. 主控变化

| 项 | 变化 |
|---|---|
| `controller.json` | 新增 `job_data_dir`：放 `<摘要>.json`（`data.signed.json`）。没配就照旧拒带 `data` 的任务包 |
| `POST /v1/jobs` | 带 `data` 的：每个摘要文件存在、`jobsign.VerifyData` 过（签名、`data_keys`、没过期、没吊销、`bytes` ≤ 钥匙上限）、不是 `restricted`、`chunks_dir` 里有清单且**原文 SHA-256 = `manifest_sha256`**、清单文件大小之和 = `bytes`。任一不过 400 |
| 派活 | 只派给心跳报 `job_data: true` 的探针；数据钥匙限了 `rooms` 的，和任务钥匙的 `rooms` 一样执行；心跳 `disk.free_mb` ≥ 2 × 数据总量 + `disk_max_mb` + 1 GB（块缓存一份 + 拼进任务目录一份；主控不算哪些块已在缓存，宁可保守）；派之前复核数据包（吊销、钥匙过期，和复核任务包同一处），不过就 `rejected` |
| 下发 | `proto.JobAssign` 加 `data []string`：派活时从 `job_data_dir` 现读的各数据包 `data.signed.json` 原文，顺序同任务包 `data[]`。不另开接口（省一个端点和一套重试）；探针按摘要逐个核对，多了少了都拒 |
| 种子 | `mayUseMaster` 的候选除了期望状态 Artifacts / Preload，再加"手上有没结束的任务、任务引用了这个清单"的节点（数据、代码、环境层都算）。现在任务拉的清单不在任何期望状态里，每间教室都没有种子，`count` 份任务同时开拉就是每台都直连主控；数据集一大就扛不住 |
| `GET /v1/jobs/{id}` | 多一列数据包摘要和名字 |
| 预热 | `POST /v1/cache/preload` 对 `data-…` 清单：只有 `job_data_dir` 里有引用它、而且是 `public` 的数据包才允许，否则 400（`campus` 预热就等于铺满全教室，和"用完删块"矛盾） |

主控仍然只能挑、填、选：不能造数据包，也不能把任务包指向别的数据。被拿下的主控能做的：不发、发错（探针拒）、
无视 `rooms` 和预热限制把块铺到别的机器——但它本来就持有全部块的明文，这不是新的泄漏面。

## 5. 探针侧

### 5.1 一次任务多出来的步骤

拉取阶段（和环境层、代码包同一个 `fctx`，算进 2 小时时限），插在现在第 5 步"代码包"之后：

1. 核对 `JobAssign.data`：条数和任务包 `data[]` 一样，第 i 条原文的摘要 = 第 i 个 `sha256`；`jobsign.VerifyData`（同一份钥匙环、同一个"现在"）；`restricted` 拒（**探针自己也拒**，不靠主控）；
2. 取清单 `<manifest>`，核原文 SHA-256 = `manifest_sha256`、文件大小之和 = `bytes`、文件数、路径规则；
3. **查空间**：缺的块字节数 + 数据总量（拼装那一份）+ `disk_max_mb` + 1 GB ≤ 剩余空间，不够 `rejected`（retry，换一台）；
4. `pull` 照用（P2P、限速、拉黑、同一套退避），只拉块，不拼。

展开阶段：**在 `jobrun.Prepare` 之后、`JobBox.Run`（设 ACL）之前**拼数据（见 5.3）。不能放在拉取阶段拼：`Prepare` 第一步就是整个删掉任务目录。

能力 37（心跳 `job_data: true`）：**随 `jobs_sandboxed` 打开，没有单独开关**（同沙箱的 34、35）。方案 A 不碰沙箱边界，没有需要单独关掉的新东西；
要停用数据功能，主控不配 `job_data_dir` 即可。

### 5.2 缓存

- **块**：就放现有块缓存（`chunk_dir`，`chunk_quota_gb`），不另开目录。
- **淘汰**：`keepFor` 现在只留"正在拉的这份清单 + 期望状态"，拉第二个数据包时第一个的块就可能被淘汰。改成：从开始拉到拼完，keep 一直带着**这次任务所有数据清单**的块。
  拼完以后数据已经在任务目录里，块可以照常淘汰。现在一台机器同时只跑一个任务，不需要引用计数。
- **配额**：keep 里的块不淘汰，数据大时缓存会暂时超过 `chunk_quota_gb`（`Store.Put` 不查配额）；靠第 5.1 步的空间检查兜底，
  **任务结束后**再跑一次 `evict`（keep 只剩期望状态）收回来。
- **展开出来的文件**：不做第二层缓存（见 5.3 方案 A），任务目录删掉就没了。
- 淘汰后照旧经 `/v1/have` 的 `del` 报。

### 5.3 只读进任务目录：三种做法

| | A. 每次从块拼进任务目录 | B. 共享展开目录 + 目录联接 | C. 共享展开目录 + 硬链接 |
|---|---|---|---|
| 做法 | 从块拼到 `jobs\<id>\data\<as>\` | 拼到 `jobdata\<sha>\` 一次；`data\<as>` 是 junction；开跑时给 `jobdata\<sha>\` 加 `(A;OICI;FR;;;<job>)`，结束删 | 同 B，但逐个文件硬链接进 `data\<as>\`，ACE 加在每个文件上 |
| ACL | **零新代码**：`jobs\<id>\` 已经是任务只读，结束后已有的收回逻辑一并收回 | 新增：共享目录上临时 ACE 的加/收；收回失败要删整个展开目录 | 同 B，且是逐文件（文件 DACL 被所有链接共用） |
| 任务能否改坏共享缓存 | 不能：块在 `D:\epsilon\chunks`，任务账户读都读不了；拼的时候整文件重算 SHA-256 | 不能写（只给 FR），但共享目录对任务账户的可读窗口要靠收回 ACE 关上 | 同 B；另外 `RemoveAll` 删任务目录时要保证不删到共享文件 |
| 跨任务泄漏 | 没有共享面 | 收回失败时下一个任务可读（所有任务同一个账户） | 同 B |
| 坑 | 每次任务多一次本地拷贝（读块 + 写 + 哈希），磁盘临时多一份 | Go 把 junction 报成 `ModeIrregular`；`RemoveAll` 遇 junction 的行为要钉测试；真机未验 | 只能同卷；逐文件改 DACL 慢 |

**建议 v1 用 A**。几 GB 的数据集本地拷贝是几十秒，换来的是不加任何新 ACL 代码、不碰沙箱边界。B 作为后续优化：等真机测出拼装时间确实碍事再做（第 10 节第 6 步）。C 不做。

A 的细节：

- **不能直接用 `chunk.Assemble`**：它在每个文件旁边写 `<文件>.epsilon-ok` 校验戳，任务 `glob("*")` 会看到多出来的文件；
  数据里要是恰好有 `x` 和 `x.epsilon-ok` 两个文件，后写的会把先写的盖掉，而且盖掉之后没有任何哈希再核。
  加一个不写戳、不跳过的 `chunk.AssembleTo(m, store, root)`（任务目录每次都是新建的，没有可复用的）：每个文件写临时文件、整文件哈希、改名；
  动手前查齐块（同 `Assemble`）；大小写冲突、展开后超过 259 字符先拒。
- 任务目录 ACL 由沙箱在**拼完之后**设（`Prepare` → 拼数据 → `JobBox.Run` 设 ACL），`data\` 继承 `jobs\<id>\` 的只读、无执行；不用新 ACE。
  拼之前 `jobs\<id>\` 还是继承 `D:\epsilon` 根上对任务账户的拒绝，没有可读窗口。
- `disk_max_mb` 照旧只算 `output\` `tmp\` `job.log`，数据不计。
- 系统金丝雀加一项 `write_data`（在 `data\` 下建文件必须错误 5）。不加 `exec_data`：`data\` 下的文件和 `code\`、`params.json` 继承同一条 ACE，
  没数据的任务也没有文件可测，现有的项已经覆盖。

## 6. 隐私

数据集可能含学校数据，先把现实摆出来：

1. **教室机自动登录的是 `Administrator`，和探针同一个 SID**。坐在机器前的人能读 `D:\epsilon\chunks`、任务目录、`probe.json`。ACL 挡的是任务账户，挡不住本机管理员。
2. **probe token 所有探针共用**，就在 `probe.json` 里。拿到 token、知道块哈希，就能从主控或任何一台探针的 P2P 端口 `GET /v1/chunks/{hash}`；清单 ID 是 `data-<名字>-<版本>`，猜得到就能取清单。哈希和 ID 都不是秘密，不能当口令。
3. 所以：**数据一旦放进教室 P2P，就等于对能坐到任何一台教室机前的人公开**。加密块、按节点发令牌都能缓解，但不是这一期的量。

因此按 `sensitivity` 分三档：

| 档 | 例子 | 处理 |
|---|---|---|
| `public` | 公开数据集 | 正常缓存、P2P、预热、LRU |
| `campus` | 课程数据、去标识化的统计表 | 同上，但不许预热；任务结束后这些块从缓存里删掉、报 `del`（不留给下一个任务和坐在机器前的人；期望状态 / 预热也用到的块跳过） |
| `restricted` | 含个人信息的原始数据 | **v1 不支持**：主控提交时 400，探针拿到也拒。要做先拍板（加密块 + 按任务发密钥，或者只派到不对学生开放的机器） |

`campus` 删块要扛得住探针中途重启：开始拉 `campus` 数据之前，先把它的块哈希原子写进 `<artifact_root>/campus-pending.json`；
任务结束和探针启动时删掉里面的块（不在 keep 里的），全删掉了才清空文件；Windows 上正被 P2P 读着删不掉的，留在文件里下次再删。

其他：

- 任务账户：只能在跑的时候读自己任务目录里的 `data\`；块缓存、别的任务目录、`jobdata\`（B 方案才有）都读不了（沙箱第 3 节的根上拒绝 ACE）。
- 任务结束：任务目录收回 ACL 后按现有规则保留 24 小时（设计书 22.4，还没做）。**带 `campus` 数据的任务目录里的 `data\` 结束就删**，只留 `output\`。
- 输出回传：任务可以把数据原样抄进 `output\` 回传。这是代码审核的事（`epsilon-review` 只能提示，挡不住），送审手册要写明；`output_max_mb` 是唯一的硬上限。
- 密级标错（把个人数据标成 `public`）只能靠数据钥匙持有人；吊销数据包挡得住以后的任务，挡不住已经铺出去的块——发现了要配合 `DELETE /v1/cache/preload` 和清缓存。

## 7. 失败与回滚

| 情况 | 结果 |
|---|---|
| 清单取不到、主控 5xx、块来源一直为空 | 退避重试，算进现有 2 小时拉取时限；超时 `failed`（拉取超时），放出机器 |
| `JobAssign.data` 缺条、多条、摘要对不上；验签不过、不是 `data_keys` 里的钥匙、吊销、过期、`restricted`、清单哈希或 `bytes` 不符 | `rejected`，不重试 |
| 剩余空间不够（拉之前查） | `rejected`（retry），主控换一台 |
| 拼装时磁盘满（查过之后又被别的写满，比如预热同时在拉） | 删掉任务目录，`rejected`（retry）；不能像现在 `fetchManifest` 那样把拼装错误一律当 `rejected` 不重试 |
| 拼装时整文件哈希不对 | 走 #15 的坏块自愈（报 `del`、重取、再拼）；仍不对 `rejected` |
| 拼装中途探针重启 | 任务目录本来就整个删掉重来（`Prepare`），没有半成品状态；`campus` 块按 `campus-pending.json` 补删 |
| 任务跑着时数据包被吊销 | 不杀（同任务包被吊销：派之前复核，跑起来的不追）；需要立刻停就 `DELETE /v1/jobs/{id}` |
| 老主控派来带数据的任务（`JobAssign` 没有 `data`） | 缺条，`rejected` |

功能回滚：

- 主控不配 `job_data_dir`：带数据的任务包提交就 400，不派。
- A/B 槽回滚到老探针：老探针不报 `job_data`，主控不派；就算派了，`schema: 2` 被 `VerifyJob` 拒。
- 主控回滚到老版本：老主控拒带 `data` 的任务包（现状），`queue.json` 里已有的带数据任务——老主控读得进（多出来的字段忽略），派出去最多 `rejected`。上线前清空队列里带数据的任务更干净。
- 钥匙环加的 `data_keys` / `revoked_data` 老版本看不到；数据钥匙在老探针、老主控眼里不存在，签不了任何东西。现有钥匙环原样可用。

## 8. 兼容旧任务包

- `schema: 1`、不带 `data` 的任务包：行为完全不变（代码路径、ACL、回传）。
- `schema: 1` 带 `data`：继续拒，错误信息改成"带数据请用 schema 2"。
- 旧钥匙环：没有 `data_keys` 就签不了数据包，带 `data` 的任务包提交时 400。
- 代码包格式不变（`code-<sha>`，一个 zip）。

## 9. `epsilon-review` 边界

- 只审代码包（现状不变）。数据包的格式 / 大小检查在 `sign-data` 里，不进 `epsilon-review`。
- 送审手册补一节：数据怎么读（`data\<as>\`，只读）、别在数据里放代码、`campus` 数据别原样写进输出。
- （可选，不阻塞）`job.json` 交集检查加一条：`schema: 2` 的 `data[].as` 和代码里常量路径 `data/<名字>` 对得上（对不上只提示）。

## 10. 分步实现（每步可单独合并）

每步都过 `go test ./...`、`go test -race ./...`、`go vet ./...`、`GOOS=windows go build ./...`；动到 Python 的过 `pytest tools/`。测试只写临时目录。

1. **`jobsign`：数据包格式和钥匙环字段**（纯函数，不接线）
   - `Data` / `SignedData` / `VerifyData` / `DataDigest`；`Keyring.DataKeys`、`RevokedData`；`Job.Data` 改 `[]DataRef`。
   - 测试：`data_keys` 的钥匙签的任务包拒、`keys[]` 的钥匙签的数据包拒；两个列表重名拒；`data_max_gb` 缺或 ≤ 0 拒；过期、吊销、超上限；
     `manifest` 不是 `data-<name>-<version>` 拒；`schema: 1` 带 data、`schema: 2` 不带都拒；`as` 重名、非法名、超过 32 位、同一摘要引用两次、超过 8 个；
     原文改一个字节验签失败；同一原文换钥匙重签摘要不变；旧钥匙环原样验过；**旧版 `Keyring` 结构解析新钥匙环看不到任何数据钥匙**。
2. **`epsilon-release sign-data` + `sign-job -data`**
   - 测试：链接、硬链接、黑名单扩展名、`.epsilon-ok` 后缀、大小写冲突、相对路径超过 160 字符拒；文件数和总量上限；已有清单不覆盖、坏块报出；签完自验；
     `sign-job` 找不到数据包或验不过时不出签名文件。
3. **主控：`job_data_dir`、提交校验、`JobAssign.data`、派活条件、种子候选、预热限制**
   - 测试：没配目录照旧拒；缺数据包、缺清单、清单哈希不符、`bytes` 不符、吊销、`restricted` 400；只派给 `job_data: true`、空间够、在数据钥匙 `rooms` 里的节点；
     派前复核吊销 → `rejected`；老探针（不报能力）永远不派；`JobAssign.data` 顺序和任务包一致；有任务引用这个清单的节点算种子；`campus` 数据清单预热 400。
4. **探针：核对数据包、拉块、`AssembleTo` 拼进任务目录（方案 A）、keep、`campus` 删块**
   - 测试（假主控 + 假块缓存，同 `jobs_e2e_test.go`）：正常跑通，任务读得到 `data\<as>\`，目录里没有 `.epsilon-ok`；主控换数据包 / 换清单 / 少给一条 → `rejected`；
     `restricted` 探针自己拒；坏块自愈；空间不够 `rejected`（retry）；拼装时磁盘写失败 `rejected`（retry）；拉第二个数据包时第一个的块不被淘汰；
     任务结束后缓存回到配额内；`campus` 结束后块被删并报 `del`，期望状态用到的块不删；`campus-pending.json` 里的块在重启后被删；没开 `jobs_sandboxed` 时不报能力。
5. **沙箱金丝雀 `write_data` + 文档（`docs/jobs.md`、手册）+ 真机验证**
   - 真机：数据读取速度、拼装耗时（1 GB / 5 GB）、任务在 Low IL 下读 `data\`、DataLoader 多进程读 `data\`、4096 个文件时设 ACL 和收回的耗时。
6. **（可选）方案 B：共享展开目录 + junction**——只在第 5 步测出拼装时间不可接受时做。先单独钉 `os.RemoveAll` 遇 junction 不跟进去、收回失败删展开目录。

## 11. 已拍板（2026-11-21，9x）

1. 只读进任务目录：**方案 A**（每次从块缓存拷贝），junction 方案 B 留作以后优化。
2. 数据钥匙放钥匙环 **`data_keys`**。加钥匙要根钥匙签一次钥匙环，发数据包不用动根钥匙。
3. **钥匙过期和手动吊销两种机制同时保留**：
   - 自动：数据钥匙过期以后，它签过的数据包不能再用（和任务包一致）。换钥匙重签摘要不变，任务包不用跟着重签。
   - 手动：钥匙环 `revoked_data` 里列摘要，可以单独吊销某一份数据，不用等钥匙过期。
   - 两种都只挡住以后派的活：跑着的任务不追（第 7 节），已经铺出去的块要配合 `DELETE /v1/cache/preload` 和清缓存（第 6 节）。
4. 敏感度**先宽松**：学校数据 v1 默认按 **`public`** 处理（正常缓存、P2P、预热、LRU）。`campus` 和 `restricted` 两档和第 6 节的处理照常实现、保留，以后要收紧时直接把数据换档，不改代码。`restricted` v1 仍然不支持。
5. 上限按建议：每个任务最多 8 个数据包；`data_max_gb` 由钥匙定，默认 20 GB；清单文件数上限 4096。
6. 数据里出现 pickle / `.pt`：**只警告**，不拒签（代码侧已经拒签加载写法）。
7. 主控 v1 **不做**按缓存优先派活，第 4 步之后看数据再说。
8. 任务结束后 `public` 数据的块**不删**，走 LRU。
9. 2 小时拉取时限 v1 **不改**，大的 `public` 数据集先预热再提交；不够再改成按 `bytes` 算。
10. 同意：种子候选加上"有任务引用这个清单的节点"，可以先于数据功能单独做。
