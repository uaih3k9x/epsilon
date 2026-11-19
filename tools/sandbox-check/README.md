# 批任务沙箱真机验证套件

把 `docs/jobs-sandbox.md` 第 7 节那 21 项"必须在真 Windows 上验证"的单子，变成在一台牺牲机上**一条命令跑完、拿回一份报告**。
能自动判的自动判（PASS / FAIL），证据收齐了要人拿主意的标 MANUAL，没条件测的（缺环境层、缺 GPU）标 SKIP。
**第 19–21 项（攻击任务包、跑到一半杀探针、量开销）和第 3 项里"和沙箱前对比"套件不做**，报告里各有一条 MANUAL（4.2）：
所以报告的总体最好也只是 MANUAL，不会是 PASS。

套件只读状态、起测试进程、建测试任务目录，**不改 install.ps1 装好的任何配置**，结束时把自己弄出来的东西清掉。
但它会以任务账户真的去试那些"应该被拦下"的操作：要是哪一项没拦住，机器上就真的留下了痕迹。所以只在牺牲机上跑。

## 1. 在哪台机器跑

- **牺牲机**：一台可以随便折腾、坏了能整盘恢复的学生机或测试机（下文叫 pc-xx）。**不要在教室里正在用的机器上跑，不要铺教室。**
- 机器要求：Windows 10/11 64 位、有 D: 数据盘（NTFS）、按 `deploy/install.ps1` 装过探针，并且**开过沙箱**
  （`$env:EPS_JOB_SANDBOX='1'` 跑过一次 install.ps1，`D:\epsilon\job-sandbox.enabled` 在）。
- 想测 GPU 那几项（第 3、4、16 项的 CUDA / cuDNN）：机器要有 NVIDIA 显卡和驱动，`D:\epsilon\envs\` 下要有带钩子的环境层
  （`@2` 及以后，`Lib\site-packages\sitecustomize.py` 在，比如 `py311-torch2.5-cu124@2`）。没有环境层的话 python 相关的项都是 SKIP。
- 跑的时候要有人以平时的账户**登录在桌面上**（探针的计划任务是登录用户身份、Limited 令牌；套件用同样的身份跑）。

### 先做整盘镜像备份

参照设计书 16.15 的做法：动手之前先给牺牲机做一份**整盘镜像**（C: 和 D: 都要），确认镜像能恢复，再开始。
套件本身会清理，但验证的就是"系统控制挡不挡得住"，挡不住的时候清理不一定干净；有镜像，最坏的情况就是整盘还原。

如果牺牲机装了 C: 还原（哦易），C: 每次重启都会回到母镜像：第 8 项（C: 还原后的 DPAPI）正好要用它，见 4.3。

## 2. 准备和拷过去

在开发机上（Mac 也行）构建，产物都是 Windows 64 位：

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -o dist/sandbox-check/epsilon-sandbox-check.exe ./cmd/epsilon-sandbox-check
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-H=windowsgui -s -w" -o dist/sandbox-check/epsilon-probe.exe ./cmd/epsilon-probe
cp tools/sandbox-check/run.ps1 tools/sandbox-check/README.md dist/sandbox-check/
```

`epsilon-probe.exe` 要用**这个分支**构建的（它带 `-sandbox-selftest`）；不放的话套件照跑，自检那部分记 SKIP。

拿 U 盘把整个 `dist/sandbox-check` 目录拷到牺牲机的 **`D:\epsilon\sandbox-check\`**（必须在 `D:\epsilon` 下面：
那里根上有拒绝任务账户的 ACE，任务账户读不到套件；登录用户可写，结果才写得进去）。

然后在牺牲机上，以管理员打开 PowerShell：

```powershell
Stop-ScheduledTask epsilon-probe
Get-Process epsilon-boot, epsilon-probe -ErrorAction SilentlyContinue | Stop-Process -Force
Set-Content D:\epsilon\sandbox-check.optin 'sacrificial machine, disk image taken'
```

`sandbox-check.optin` 是你确认"这是牺牲机、镜像做好了"的标记，没有它脚本一步都不走。

## 3. 怎么跑

管理员 PowerShell（或者管理员 cmd）里一条命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File D:\epsilon\sandbox-check\run.ps1
```

可选参数：

| 参数 | 说明 |
|---|---|
| `-EnvDir D:\epsilon\envs\<名字>@2` | 指定环境层；不写就挑 `envs\` 下最新的、带 `sitecustomize.py` 的那个 |
| `-TimeoutMinutes 60` | 受限阶段最多等多久（默认 60 分钟；第一次导入 torch 可能很慢） |
| `-AfterRestore` | 重启（C: 还原）以后再跑一次，只测第 8 项，见 4.3 |

前置检查（任何一条不过就退出码 2，**什么都不改**）：管理员、`job-sandbox.enabled`、`sandbox-check.optin`、套件在 `D:\epsilon` 下、
探针和引导器都停了、没有 `epsilon-job` 的进程、上一次没留下计划任务 `epsilon-sandbox-check`。

跑的过程：

1. 管理员身份查 install.ps1 第 4/8 步落地的状态（账户、组、登录界面隐藏、`secrets\` / `D:\epsilon` / `envs\` / 数据卷根的 ACL、
   secedit 用户权限、seclogon、两条防火墙规则）、盘点本机 TCP 监听（`listeners.json`、`netstat.txt`）。
2. 注册临时计划任务 `epsilon-sandbox-check`（和探针一样：`BUILTIN\Users`、`RunLevel Limited`），里面跑 `epsilon-sandbox-check.exe limited`，
   会弹一个黑色控制台窗口显示进度。它依次：
   - 跑 `epsilon-probe.exe -sandbox-selftest <环境层>`（健康检查 + 两次金丝雀，结果 `D:\epsilon\sandbox-selftest.txt`）；
   - 用探针自己的沙箱代码（`jobbox`）逐项实测：健康检查、`CWF_CREATE_ONLY`、命令行长度、挂起起进程、进程可见/可结束、清场宽限、
     无管道退出 97、审计管道叫醒、防火墙 10013 和回环、绕过钩子连本机监听、C: 可读内容盘点；
   - 用 `Box.Run` 完整跑三个测试任务（两次金丝雀、钩子、清场、收回都和真任务一样）：Low IL 下 user32 / 文件操作 / multiprocessing /
     torch / CUDA / cuDNN / DataLoader(`num_workers=2`)、建排除探针的锁目录看收回、`mkdir(0o700)` 看收回。
3. 清理（不管前面成没成都做）：删临时计划任务、结束测试进程和 `epsilon-job` 的残留进程、删 `jobs\_check-*` 和改名隔离的测试目录
   （锁住的先 takeown 再删）、删散落在 `C:\ProgramData` 等处的金丝雀文件。**不删 `epsilon-job` 账户**（套件没建它）。
4. 汇总出报告。

整个过程一般 10–30 分钟（看 torch 导入和盘点的文件数）。结束后探针还是停着的：`Start-ScheduledTask epsilon-probe` 或重启拉回来。

## 4. 结果怎么看

- `D:\epsilon\sandbox-check-<时间>.txt`：**先看这个**。顶上一行总体结论和计数，下面按项列出，FAIL 排最前；每项后面写了"出错看"哪一节文档，
  再下面是每一条检查的状态、id、证据。
- `D:\epsilon\sandbox-check-<时间>.json`：同样内容，给程序读（`items[].checks[]`）。
- `D:\epsilon\sandbox-check\run-<时间>\`：原始证据——`ps.jsonl`（管理员阶段）、`limited.jsonl`（受限阶段）、`cleanup.jsonl`、
  `sandbox-selftest.txt`、`task-job.log` / `task-audit.log`（测试任务的输出和审计记录）、`inventory.txt`（C: 盘点清单）、`listeners.json`、`netstat.txt`。

**`uninstall.ps1` 会删掉整个 `D:\epsilon`：回滚之前先把报告和 `run-<时间>\` 拷走。**

状态：

| 状态 | 含义 |
|---|---|
| PASS | 实测符合设计 |
| FAIL | 不符合设计；按"出错看"那一节查，证据里有错误码和原文 |
| MANUAL | 证据收齐了，要人判断（盘点清单、叫不醒的管道、嵌套作业……） |
| SKIP | 没验证到：缺环境层 / torch / GPU、没放 `epsilon-probe.exe`，或者前面一步失败了 |

id 的前缀就是第 7 节的条目号；`selftest.*` 是 `-sandbox-selftest` 的原行，`0.*` 是运行和清理本身。
`0.helper_identity` 是 FAIL 的话（helper 拿到的是提升的令牌，比如登录的是关了 UAC 的管理员），后面的结果都是在比探针高的权限下测的，不算数。

### 4.1 能自动判的

| 项 | 怎么判 |
|---|---|
| 1 | `CreateProcessWithLogonW` 挂起起 `cmd /c echo`，输出进了文件、退出码 0（`1.start_stdout`）；任务进程在作业里（`1.in_job`）；seclogon 起的挂起进程事先在不在别的作业里（`1.prior_job`，在的话 MANUAL） |
| 2 | 非提升身份建窗口站和桌面（`2.winsta_limited`、自检 `health`）；Low IL 下 `CreateWindowExW`（`2.user32_window`）；自检 `desktop`；反向：任务打不开交互窗口站 `WinSta0`（自检 `winsta0_denied`，必须错误 5）、令牌里没有 Users 以外的本机组（自检 `token_groups`，证据里有登录 SID） |
| 3 | 就绪记录 il=low（`3.*.ready`）、令牌 Low（`3.low_il`）、torch 导入耗时、CUDA matmul、DataLoader 两个 worker；自检 `integrity_low`、`ready_main`、往 ProgramData / Windows\Temp / Users\Public 写不进 |
| 4 | 自检 `exec_tmp`、`load_tmp_dll`、`set_dacl_own_file`、任务目录各处写不进；Low IL 下 makedirs / walk / rmtree（`4.fs_ops`）；cuDNN 卷积（`4.cudnn`） |
| 5 | 两条规则在、按 SID、不要 IPsec（`5.fw_rules`）；任务账户连主控和 192.0.2.1 必须 10013；回环必须连得上、探针这边收得到；对照：探针自己连不是 10013 |
| 6 | 任务的 `sitecustomize` 来自环境层，`code\sitecustomize.py` 没被执行（`6.sitecustomize_first`）；没有审计管道时退出码 97、用户代码一行没跑（`6.exit97_without_pipe`）；自检 `hook_installed`、`ready_in_layer` |
| 7 | `multiprocessing` spawn 的 Pool 和 DataLoader worker 跑得起来；测试任务被拦过的话 `7.*.blocks` 记 MANUAL、列出事件；自检钩子那一段全部 |
| 8 | 探针身份解得开 SYSTEM 写的密码文件（`8.dpapi_limited`、自检 `health`） |
| 9 | seclogon 没被禁用；secedit 四条拒绝里有任务账户、拒绝本地登录里没有 |
| 10 | 非管理员列得出任务账户的进程（`10.visible`，附带查不到 SID 的进程数）、结束得了（`10.terminate`，作业内的进程；作业外的、WMI 起的没测，见第 19 项）；普通进程退出后多久从枚举里消失，超过 3 秒宽限算 FAIL（`10.sweep_after_exit_*`）；测试任务结束后没有判成逃出（`10.*.no_escape`） |
| 11 | 关连接时挂着的 `ReadFile` 2 秒内醒、`Close` 时挂着的 `ConnectNamedPipe` 3 秒内醒（醒不了记 MANUAL：探针不会卡住，只是多等） |
| 12 | 账户属性、只在 Users、登录界面隐藏、`secrets\` 受保护且拒绝任务账户、`D:\epsilon` 根上两条拒绝、`envs\` 读+执行、每个数据卷根拒读、install.log 里是 "job sandbox ready" |
| 15 | 任务建只给自己的锁目录后，收回是报错中止（改名隔离，PASS）还是报成功却跳过了（FAIL，要加抽查）；`mkdir(0o700)` 之后收回成不成 |
| 16 | 删特权后只剩 SeChangeNotify（`16.privileges`）、CUDA 照常；同名窗口站已经在时第二个实例建不出（`16.create_only`）；上一个进程退出后新进程重建得出（`16.winsta_rebuild`） |
| 17 | 自检 `hardlink_probe_json`、`chdir_tmp`、`exec_artifact_root`、`read_data_disk`、`privileges_dropped` |
| 18 | 真机路径下两次金丝雀、测试任务，以及 64 个字符的任务目录名下的金丝雀，命令行都不超过 1023 |

### 4.2 要人看的（MANUAL）

- **5 入站**：入站规则在不在自动查了，但"别的机器连不进任务开的端口"要第二台机器，没测。
- **12 安装耗时和中途失败**：没自动化。要测的话，在牺牲机上 `Measure-Command { ... install.ps1 ... }` 量第 4/8 步
  （第一次 `/reset`、数据卷根上拒读的传播）；再拷一份 install.ps1，在第 4/8 步 `try {` 里 secedit 之前临时插一行 `throw 'test'`，
  确认后面照常装、`secrets\epsilon-job.json` 被删、心跳报 `jobs:false`。做完用原版 install.ps1 重跑一次恢复。
- **13 回环监听**：`13.listeners` 是全部监听，`13.port_*` 是任务账户**绕过钩子**也连得上的。逐个确认要认证
  （教室管理软件、llama-server :8080、ggml-rpc-server :50052 尤其要看）。
- **14 C: 可读内容**：`inventory.txt` 里 `KEY` 是内容像口令/密钥，`NAME` 是文件名可疑，`EXT` 是配置类。看有没有管理软件的配置、口令。
- **1 嵌套作业**、**11 叫不醒**、**15 mkdir(0o700)** 出现 MANUAL 时，证据里写了影响和该拍板的事。
- **3 和沙箱前对比**（`3.baseline_compare`）：同一台机器上不开沙箱跑一次 smoke 和 torch GPU + DataLoader，对比显存和耗时。
- **19 攻击任务包**（`19.attack_pack`，第 7 节步骤 4）：用测试钥匙环签一个攻击包，逐条试 `docs/jobs-sandbox.md` 第 7 节第 19 条列的操作，
  每一条都要被拦下并在 `audit.log` 里留记录；**逃出作业的进程**（WMI `Win32_Process.Create`、schtasks）要让本机停接
  （事件里有"逃出"），再看它是不是真被结束了（`Sweep` 以探针身份可能结束不了，文档第 8 节）。套件里"逃出作业"这条路一次都没真走过。
- **20 跑到一半杀探针**（`20.kill_probe_midway`）：任务跑着时结束 `epsilon-probe.exe`，整棵进程树要一起死（作业对象 KILL_ON_JOB_CLOSE）。
- **21 开销**（`21.overhead`）：每次金丝雀的耗时、Low IL 下 torch 的导入时间（自检和 `3.torch_import` 有一部分）。

### 4.3 C: 还原后（第 8 项）

1. 第一次跑完以后重启牺牲机（装了还原的话 C: 回到母镜像，`epsilon-job` 账户和防火墙规则都没了，D: 不变）。
2. 登录，停探针，`powershell -NoProfile -ExecutionPolicy Bypass -File D:\epsilon\sandbox-check\run.ps1 -AfterRestore`。
3. 报告里 `8.after_restore`：健康检查不过（找不到账户 / 解不开）= 出错即拒，心跳会报 `jobs:false`，符合设计；过了说明主密钥和账户都还在。
   别的项这次都是 SKIP，正常。
4. 重跑 install.ps1 恢复。

## 5. FAIL 了看哪里

报告里每一项都写了"出错看"，大致：

| 项 | 文档 |
|---|---|
| 1、18 | `docs/jobs-sandbox.md` 第 2 节「启动：CreateProcessWithLogonW」；代码 `jobbox/platform_windows.go` `Start`、`winproc.AdoptSuspended` |
| 2、16 | 第 2 节「独立桌面」「Low IL 和特权」；`jobbox/platform_windows.go` `ensureDesktop`、`jobbox/secret.go` `WinstaSD` / `DesktopSD` |
| 3、6、7 | 第 2 节「Low IL 和特权」、第 5 节 sitecustomize 和「策略」；`jobbox/py/sitecustomize.py` |
| 4、15 | 第 3 节（任务目录 ACL、结束后收回）、第 8 节剩余风险；`jobbox/sddl.go` |
| 5、13 | 第 4 节（出站防火墙、管不到的出口）；install.ps1 第 4/8 步 h) |
| 8、9、12、14 | 第 2 节「账户」、第 3 节「上级目录」「数据卷」；install.ps1 第 4/8 步 |
| 10、11 | 第 6 节（出错就拒的表）；`jobbox/box.go` `leftover` / `mustSee` / `serveAudit` |
| 17 | 第 5 节「金丝雀」；`jobbox/py/canary_sys.py` |
| `0.*` | 本文件；受限阶段没起来多半是没人登录桌面 |

没有 FAIL、每一条 MANUAL 都看过并拍了板，**并且第 19–21 项和 `3.baseline_compare` 都按 4.2 手工做完**之后，
才把 `docs/jobs.md` 的"上线前必须做"改成"已做"，`probe.json` 的 `jobs_sandboxed` 才能打开。只看报告全 PASS 是不够的（也不会出现）。

## 6. 回滚

- 只想撤掉这次验证：套件结束时已经清理了。确认 `Get-ScheduledTask epsilon-sandbox-check` 不存在、`D:\epsilon\jobs\` 下没有 `_check-*`。
  删掉标记：`Remove-Item D:\epsilon\sandbox-check.optin`，套件目录可以留着下次用，也可以 `Remove-Item -Recurse D:\epsilon\sandbox-check`。
- 撤掉沙箱（账户、规则、数据卷根上的拒绝）：以管理员跑 `deploy\uninstall.ps1`。**它会删掉整个 `D:\epsilon`，先把报告拷走。**
  只想关沙箱、保留探针：`$env:EPS_JOB_SANDBOX='0'` 再跑一次 install.ps1（删掉 `job-sandbox.enabled`；账户和规则随下一次 C: 还原消失）。
- 最坏的情况：用第 1 节做的整盘镜像还原。
