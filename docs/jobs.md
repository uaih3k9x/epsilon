# 批任务签名契约（钥匙环 + 任务包）

对应 issue #1 第 1 步。代码在 `jobsign/`（格式和校验）和 `cmd/epsilon-release/jobcmd.go`（签名命令）。
探针执行、主控队列还没做；这里先把**格式和规则**定下来，格式一旦发布只增不改。

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
- 和本体发布签名一样：签名针对**原文字节**，验签不重新序列化。签名后的文件一个字节都不要改，重新排版也算改。
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
  "revoked_jobs": ["<任务包摘要>"]
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
| `keys[].limits.max_nodes` / `rooms` | 主控派活时执行（`rooms` 空 = 不限） |
| `keys[].limits.network` | false 时，要联网的任务包（`network: true`）一律不跑 |
| `revoked_jobs` | 任务包摘要（`job.signed.json` 里 `job` 字段原文的 SHA-256，小写十六进制） |

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
3. `schema` = 1；`name`、`version`（x.y.z）、`env` / `data`（`名字@版本`）、`code_sha256`（64 位小写十六进制）格式合法；
4. `entry` = `[解释器, 脚本, 参数…]`：解释器只能是 `python` / `python3`，脚本是 `code\` 下的相对 `.py` 路径、不含 `..`，后面不许出现 `-c` / `-m`；
5. `gpu_mem_mb` 在 0–7168，`max_hours` > 0；
6. `max_hours` ≤ 钥匙的 `max_hours`；要联网的，钥匙必须有 `network` 权限。

`code_sha256` 和实际 `code.zip` 是否一致，签名时由 `sign-job` 核对；探针拉到代码包以后**还要再核一次**（还没实现）。

## 命令

```sh
# 给审核人发钥匙（审核人自己在自己机器上跑，私钥不离手；把打印出来的公钥给根钥匙持有人）
epsilon-release keygen -out dist/keys/reviewer-a.key

# 根钥匙持有人签钥匙环（out 已存在时，新版本号必须更大）
epsilon-release keyring -key dist/keys/release-main.key -in keyring-src.json -out job-keyring.json

# 审核人签任务包（核对 code.zip 哈希、私钥与钥匙环里同名钥匙一致，签完按探针规则自验）
epsilon-release sign-job -key dist/keys/reviewer-a.key -name reviewer-a \
    -keyring job-keyring.json -job job.json -code code.zip -out job.signed.json
```

不带子命令时 `epsilon-release` 照旧做本体发布签名，用法不变。

## 还没做（按 issue #1）

- 探针：拉钥匙环、持久化最高版本号（`job-keyring.version`，原子写）、拉任务包和代码包、二次核对哈希、执行；
- 主控：分发钥匙环、`/v1/jobs` 队列、按 `max_nodes` / `rooms` 派活；
- `sign-job` 签名前强制跑静态审核工具（另一个分支在写）；
- 时钟：过期判断依赖本机时间。学生机时间来自 Windows 自动对时；没对上时宁可误拒，不要误放。
