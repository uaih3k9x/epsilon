# 批任务沙箱（issue #1 第 4 步）

代码在 `jobbox/`（策略、编排、Windows 实现）、`jobbox/py/`（审计钩子和两份金丝雀）、`jobrun/`（`Starter` 接口）、
`winproc/`（`AdoptSuspended`）、`probe/jobs.go`（接线）、`deploy/install.ps1` 第 4/8 步（账户、密码文件、ACL、防火墙）。
对应设计书 22.2、22.4、22.6、22.6.1、22.8（能力 34–36）和《任务包编写与送审手册》1.3、5.3、6.1、6.5。

**状态：代码写完、Mac 上的测试全过；Windows 一侧只保证能编译，一次都没在真机上跑过。** 第 7 节的单子过完之前，
`probe.json` 的 `jobs` 保持 `false`。

## 0. 前提

1. **探针的身份**：`install.ps1` 注册的计划任务以 `GroupId S-1-5-32-545`、`RunLevel Limited` 跑在自动登录的
   `Administrator` 会话里。内置 Administrator（RID 500）默认可能拿到完整令牌，但沙箱不依赖探针有任何特权。
2. **C: 每次重启都被哦易还原**：本地账户、防火墙规则、本机策略都在 C:，重启后全没了。`install.ps1` 负责补回来（SYSTEM 身份）。D: 不还原。
3. **老版本 `install.ps1` 的 `icacls ... /T`**：在 `D:\epsilon` 下每个文件上写了一条显式 Users 修改权。显式允许排在继承来的拒绝前面，
   所以只在根上加拒绝不够。现在去掉了 `/T`，开沙箱时一次性 `/reset` 换回继承的（Users 实际权限不变）。
4. **目录联接不回传**：Go 1.25 把 junction 报成 `ModeIrregular`，`joboutput.Upload` 遇到非普通文件整个拒掉（有测试钉住）。

## 1. 两层

| 层 | 作用 | 性质 |
|---|---|---|
| 系统控制：专用账户、Low IL、NTFS ACL 和标签、作业对象、独立桌面、按账户 SID 的防火墙 | **边界** | 全部生效才跑 |
| 环境层里的审计钩子（PEP 578，`sitecustomize.py`） | **绊线和取证** | 没装上也算失败 |

每个任务真正起来之前，先用任务账户跑两次**金丝雀**实测（第 5 节）。任何一项不符就拒跑。

## 2. 账户和进程

### 账户（`install.ps1` 第 4/8 步，显式开启）

`$env:EPS_JOB_SANDBOX='1'` 跑一次安装，会留下 `D:\epsilon\job-sandbox.enabled`，以后的重跑（修复、C: 还原后）都照做；`'0'` 删掉标记。每次：

1. 建或重设 `epsilon-job`：32 字节随机数 base64、前面加 `Aa1-`（复杂度策略）；PasswordNeverExpires、不能改密码、不过期；
   只在 Users，移出 Administrators。不用 `net user`（超过 14 位的密码会弹交互提示）。
2. `SpecialAccounts\UserList` 里 `epsilon-job=0`，登录界面不显示。
3. secedit：拒绝网络、远程桌面、批处理、服务登录。**不拒本地交互登录**：seclogon 走的就是它。
4. seclogon 被禁用就改成手动。
5. 密码只放 D:：`secrets\epsilon-job.json` = `{"version":1,"user":"epsilon-job","sid":"S-1-5-21-…","password_dpapi":"<base64>"}`，
   DPAPI **LocalMachine** 作用域（脚本是 SYSTEM、探针是登录用户，用户作用域两边解不通），附加熵 `epsilon-job/v1`。
   `secrets\` 是受保护 DACL `D:P(D;OICI;FA;;;<job>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)`。先写临时文件再改名；密码不打印。
6. **不要把 `epsilon-job` 做进哦易母镜像**：每台密码就一样了，还和 D: 上的文件对不上。

DPAPI 能防什么：LocalMachine 下本机任何进程都能解密，挡任务进程的是 `secrets\` 上那条拒绝 ACE；DPAPI 防的是把 D: 拷走去读。
C: 还原后主密钥可能变了、解不开，账户也同时没了，结果一样：心跳报 `jobs:false`，重跑 `install.ps1` 恢复。
坐在机器前的人本来就是 Administrator；每台不同的密码加上拒绝网络登录，防的是拿它横向登录别的机器。

### 启动：`CreateProcessWithLogonW`

| 方式 | 要的特权 | 本场景 |
|---|---|---|
| `LogonUser` + `CreateProcessAsUser`（Go 的 `SysProcAttr.Token`） | SeAssignPrimaryTokenPrivilege | 探针没有，报 1314，不行 |
| `LogonUser` + `CreateProcessWithTokenW` | SeImpersonatePrivilege | 探针是 Limited，不能指望 |
| 计划任务指定账户 | 注册要管理员；拿不到作业对象和 stdout | 不行 |
| **`CreateProcessWithLogonW`** | **不需要**（走 seclogon） | 唯一不依赖探针特权的；代价是要明文密码 |

参数：`dwLogonFlags=0`（先不加载配置文件）、`CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT`、`STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW(SW_HIDE)`、
stdout/stderr 接日志句柄（复制一份可继承的）、`lpDesktop = epsilon-job\Default`。拿到挂起的进程后 `winproc.AdoptSuspended`：
新建作业对象（KILL_ON_JOB_CLOSE、DIE_ON_UNHANDLED_EXCEPTION、ActiveProcessLimit 64、`JOBOBJECT_BASIC_UI_RESTRICTIONS` 全开，
不设 BREAKAWAY_OK）→ 指派 → `ResumeThread`。任何一步失败都结束这个进程，它一行都还没跑。

**独立桌面**：不指定的话 seclogon 把任务账户加进 `WinSta0\Default`，任务就能截学生的屏、读剪贴板、轮询按键。探针第一次健康检查时建窗口站
`epsilon-job` 和桌面 `Default`（DACL 给任务 SID，标签 `S:(ML;;NW;;;LW)`，否则 Low IL 进程初始化 user32 会失败），句柄攥到退出。
`CreateDesktop` 要先 `SetProcessWindowStation`（整个进程生效），建完马上切回。建不出来就不接任务。

**Low IL**：`sitecustomize` 在装钩子之前用 ctypes 把自己的令牌降到 Low，子进程都继承。之后只能写标了 Low 的地方（`output\` `tmp\`），
`C:\ProgramData`、`C:\Users\Public`、`C:\Windows\Temp` 这些"人人可写可执行"的目录自动写不了。级别写在就绪记录里（用户代码还没机会运行）。
CUDA 在 Low IL 下能不能跑要真机验证；不行的备选是给已知的人人可写目录加拒绝写（单子不全），金丝雀会实测几个。

**环境块**（`jobbox.JobEnv`，从零拼，不继承探针的）：系统变量 `SystemRoot` `windir` `NUMBER_OF_PROCESSORS` `PROCESSOR_*` `OS` `PATHEXT`；
`PATH` = 环境层 + System32；`TMP` `TEMP` `TMPDIR` → `tmp\`；`USERPROFILE` `APPDATA` `LOCALAPPDATA` → `tmp\home\…`；
`CUDA_CACHE_PATH` `TORCH_HOME` `HF_HOME` `MPLCONFIGDIR` `XDG_CACHE_HOME` → `tmp\cache\…`；`HF_HUB_OFFLINE=1` `TRANSFORMERS_OFFLINE=1`；`EPSILON_JOB_DIR`。按名字排序。

**联网任务（`network: true`）这一版直接拒**（手册 1.3：机器不能访问外网，现在没有用例）。真要时再加第二个账户 `epsilon-jobnet`
（不挂出站拦截、入站照拦），由钥匙权限决定用哪个，防火墙规则保持静态。

## 3. 任务目录 ACL（能力 34）

目录是探针自己建的，作为所有者有 WRITE_DAC，不要特权。SDDL 由 `jobbox.JobDirSDs` / `RevokedSDs` 生成（纯函数），
`SetNamedSecurityInfoW` 落盘并传到子项。`<job>` 是任务账户 SID，`<probe>` 是探针令牌的用户 SID。

| 路径 | 安全描述符 | 说明 |
|---|---|---|
| `jobs\<id>\` | `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<probe>)(A;OICI;FR;;;<job>)(A;OICI;0x20000;;;OW)` | 受保护，任务只读：建不了文件、删不了 `params.json` |
| `code\` | 继承只读 | **只读、没有执行权限**（任务原文写的是读+执行，这里按 22.6.1 取更严的；.py 不要执行权限） |
| `output\` `tmp\` | 追加 `(D;OIIO;0x20;;;<job>)(A;OICI;0x13019f;;;<job>)`，标签 `S:(ML;OICI;NW;;;LW)` | `0x13019f` = 修改权去掉 FILE_EXECUTE，也没有 WRITE_DAC/WRITE_OWNER。拒绝执行**必须写成 `0x20`**：`FX` 连 SYNCHRONIZE、READ_CONTROL 一起拒，读文件就坏了。`OIIO` 只作用在文件上 |
| `job.log` `canary.out` | 继承只读 | 任务进程经探针给的句柄写 |

- **OWNER RIGHTS（`OW`）不能省**：任务在 `output\` 里新建的文件所有者是任务账户，所有者天生有 WRITE_DAC，能删掉拒绝执行；有了 OW，所有者只剩 READ_CONTROL。
- **结束后收回**：根换成没有 `<job>` 的版本；`output\` `tmp\` 用 `TreeResetNamedSecurityInfoW` 整棵重置成只继承（任务建文件时可以自带 DACL，
  见第 8 节剩余风险）。所有任务共用一个账户，不收回下一个任务就能读这一份输出（本地保留 24 小时）。第一次健康检查时把 `jobs\*` 都收回一遍。收回失败停接任务。
- **上级目录**（`install.ps1`）：`D:\epsilon` 根上 `(D;OICI;0xd0157;;;<job>)`（读/列目录、写、追加、写 EA、删子项、写属性、删除、WRITE_DAC、WRITE_OWNER；不拒遍历和 READ_CONTROL），
  `envs\` 上 `(A;OICI;0x1200a9;;;<job>)`（读+执行）。任务账户读不到 `probe.json`、`secrets\`、日志、别的任务，写不了槽位、钥匙环版本文件和环境层（含 `sitecustomize.py`）。
  环境层在 `envs\` 下解压再改名，ACL 跟着 `envs\` 走。哪一处漂了，金丝雀都测得出来。

## 4. 出站防火墙

1. `install.ps1` 建两条静态规则：`epsilon-job-out`（出站）和 `epsilon-job-in`（入站），`-Action Block -Protocol Any -Profile Any -LocalUser "O:LSD:(A;;CC;;;<job SID>)"`。
   入站也要拦：`epsilon-p2p` 给**任何程序**放行了 47100–47119，不拦的话任务能抢在探针前面占端口。
2. **按账户 SID，不按程序路径**：环境层路径随版本变、安装时不知道；按路径管不住层里别的 exe 和 System32；按 SID 连逃出作业对象的进程也管。
3. **不放行主控和同教室**（比设计书 22.6 和手册更严，待拍板）：任务不需要，拉取回传都是探针做；拦截优先于允许，要放行只能把补集写成 RemoteAddress 区间。
4. **管不到的出口**（剩余风险）：DNS 由 dnscache 服务发出；UNC 由内核 SMB/WebDAV 重定向器发出。这两条靠审计钩子拦，根治是独立 VLAN（16.7）。
5. 探针不读防火墙配置，金丝雀以任务账户连主控，必须得到 **WSAEACCES（10013）**；连上、超时、被拒绝都算失败。

## 5. 审计钩子（能力 35）和金丝雀

能力 34 = 第 3 节，35 = 本节，36（吊销表）已由钥匙环的 `revoked_jobs` 实现。设计书 22.6.1 设想"审核人钥匙也能签吊销表"，现在**只有根钥匙能签**。
账户和防火墙不另编号；Windows 上 34、35 随 32 强制打开，没有单独开关。

### sitecustomize

- 在环境层 `Lib\site-packages\sitecustomize.py`，由 `tools/build-env-layer.py` 放进去，所以要新版本 `@2`（`deploy/envs/py311-torch2.5-cu124` 已升）。
  `@1` 没有钩子，金丝雀按"钩子没装上"拒掉。依赖包自带 `sitecustomize`/`usercustomize` 的构建时就拒。
- 执行参数 `-E -s -B` 不含 `-S`，site 照常导入它；CPython 先导入 site 再把脚本目录加进 `sys.path`，`code\` 里同名文件抢不到。
  `jobrun.checkZip` 另外拒收代码包里任何位置的 `sitecustomize.py` / `usercustomize.py`。
- 只在任务进程里装：令牌用户是 `epsilon-job`，或者有 `EPSILON_JOB_DIR`。人手工跑层里的 python 不受影响。
- **顺序，任何一步出错就 `os._exit(97)`**（site.py 只会打印一句然后接着跑）：用 `CreateFileW(FILE_WRITE_DATA)` 连 `\\.\pipe\epsilon-audit`
  （管道 DACL 不给任务账户 FILE_CREATE_PIPE_INSTANCE，普通 `open` 要的 GENERIC_WRITE 会被拒；不用 stderr，multiprocessing 的子进程不继承句柄）
  → 降到 Low IL → `sys.addaudithook` → 写就绪记录 `{"ev":"ready","pid","ppid","il","file","layer"}`。
- 探针一侧：主进程恢复后 30 秒内收不到它的就绪，整树杀、`rejected`；主进程的连接在进程退出前断开（宽限 5 秒），或者任何连接上记录格式不对，视为篡改：整树杀、`failed`、照常回传。
- 记录一行一个 JSON：`{"t","pid","ev","act":"block|log|count","args"}`，args 截到 512 字节，一次 `os.write` 写完。

### 策略（`jobbox/py/sitecustomize.py` 的 `decide`，纯函数）

| 事件 | 处理 |
|---|---|
| `subprocess.Popen` `os.system` `os.startfile` `os.spawn` `os.exec` `os.posix_spawn` `webbrowser.open` | 拦 |
| `_winapi.CreateProcess` | 只放行程序是本层 `python.exe`、命令行一字不差是 multiprocessing spawn 的那种（`-B -E -s -c "from multiprocessing.spawn import spawn_main; spawn_main(...)" --multiprocessing-fork`）。多出 `-S` `-I` 就能起没有钩子的子进程 |
| `socket.connect` `sendto` `sendmsg` `bind` | 目标不是 127.0.0.1 / ::1 / localhost 就拦（回环要放行：`socketpair`、asyncio） |
| `socket.getaddrinfo` `gethostbyname*` `gethostbyaddr` `getnameinfo` | 不是 localhost 就拦（DNS 隐蔽通道） |
| `open` `os.listdir` `os.scandir` | 拦 UNC、`\\?\UNC\`、`\\.\` 设备路径（`\\.\pipe\` 和 `\\?\X:\` 除外）；`code\` 和环境层以外的 `.py` `.pyc` `.pyw` `.pth` 读写都拦 |
| `import` | `sys.path` 里有 `code\` 和环境层以外的条目就拦 |
| `ctypes.dlopen` | 全记；带路径的在环境层和 System32 之外就拦 |
| `ctypes.call_function` `pickle.find_class` `marshal.loads` | 只计数（每种原样记前 50 条，之后每 1000 次一条累计）；multiprocessing、torch 内部也会触发 |
| `compile` `exec` | 文件名在 `code\`、环境层（含层内 pyc 的相对路径）、冻结模块的算导入，只计数；`<string>` 之类算动态执行，逐条记 |
| `winreg` 写操作 | 拦 |
| 改 `EPSILON_*` 环境变量 | **拦**（设计稿写的是记录；改了 `EPSILON_JOB_DIR` 再起 multiprocessing 子进程，子进程的钩子就按别的目录判了） |
| `sys.addaudithook` `cpython.run_*` | 记 |

拦截是抛 `PermissionError`，任务可以接住接着跑，但已经计数。有拦截不自动判失败，按 22.6.1 交给人复查、吊销。

### 回传

- `output\_runner\audit.log`（上限 8 MB，超了只计数、标 `truncated`）；`summary.json` 加 `audit`：`{ready, blocked, logged, by_event, truncated}`。
- `proto.JobStatus` 加 `audit_blocked,omitempty`（只增不改）；结束事件里写"有拦截 N 次"。

### 金丝雀（每个任务都跑，两次；源码打包在探针里）

在任务目录 ACL 设好之后、任务起来之前，以任务账户、同样的桌面和作业对象跑，输出写 `canary.out`，由 `jobbox.CheckCanary` 对照（每一项恰好报一次且 ok，任何 fail 都拒）。之后清空 `tmp\` `output\`。

1. **系统控制**（`python -I -S -c`，不加载钩子；先用和 sitecustomize 一模一样的代码降到 Low，测试核对两份相同）：
   `integrity_low` `desktop` `read_probe_json` `read_secrets` `write_code` `write_params` `delete_params` `write_job_root` `write_sitecustomize` `write_env`
   `write_tmp` `write_output` `exec_tmp`（复制 python.exe 进 tmp 再起，必须错误 5）`load_tmp_dll` `set_dacl_own_file`（改自己文件的 DACL 必须错误 5，验 OW）
   `write_programdata` `write_windows_temp` `write_users_public` `connect_controller`（必须 10013）`socketpair`。
2. **钩子**（`python -E -s -B -c`）：`hook_installed` `subprocess_blocked` `spawn_flags_blocked` `connect_blocked` `dns_blocked` `unc_blocked`
   `env_tamper_blocked` `tmp_py_blocked` `dlopen_tmp_blocked` `mp_child`；探针另从审计管道核对 `ready_main` `ready_in_layer` `ready_child`。

## 6. 出错就拒

健康检查（探针启动时、之后每 10 分钟）：密码文件能解密、`LookupAccountName` 的 SID 和文件一致、不在 Administrators（按 SID 比）、窗口站建好了。
不过就心跳报 `jobs:false`（主控以最近一次心跳为准，不再派），原因变了才记一次日志、发 `jobbox` 事件。

| 环节失败 | 结果 | 本机停接任务？ |
|---|---|---|
| 健康检查不过（典型：C: 被还原） | 派来的任务 `rejected` | 是，直到下一次检查通过 |
| 设 ACL 或标签失败 | `rejected`，删掉任务目录 | 否 |
| `CreateProcessWithLogonW` 报 1326 / 1385 / 1058 / 1327 / 1330 / 1331 / 1907 / 1909 | `rejected` | 是，直到下一次健康检查通过 |
| 其他启动错误；指派作业对象或恢复失败 | 结束挂起的进程，`rejected` | 否 |
| 系统控制金丝雀不符（配置漂移，不是任务的问题） | `rejected` | 是，直到下一次健康检查通过 |
| 钩子金丝雀不符（层没有钩子、钩子不对） | `rejected`，写明是哪个环境层 | 否 |
| 30 秒内没收到就绪；没发就绪就退出 | 整树杀，`rejected` | 否 |
| 运行中审计管道断开、记录被篡改 | 整树杀，`failed`，照常回传 | 否 |
| 结束后还有这个 SID 的进程（`WTSEnumerateProcessesExW`，查到就 TerminateProcess） | 有进程逃出了作业对象，发事件 | 是，直到重启（C: 还原自然清场） |
| 收回 ACL 失败 | 照常回传，发事件 | 是，直到重启 |

编译期：Windows 构建里探针只有真沙箱（`jobbox.New`），没有不受限的路径；非 Windows 构建的 `New` 返回 `Unavailable`。
Mac 上的测试注入假的 `Platform`（`jobbox/box_test.go`）或假的 `Sandbox`（`probe/jobbox_fake_test.go`）。`jobrun.Plain` 只给测试用。

## 7. 真机验证（这一轮全部没做）

Mac 上测了：SDDL 字面量、环境块、金丝雀解析和对照（每一项不符都拒）、两份金丝雀真跑一遍名字对得上、审计记录解析和监视（就绪超时、主进程断开、篡改、截断、计数）、
编排顺序和每一步失败的出错即拒、心跳 `jobs` 跟着沙箱、`network:true` 拒、`sitecustomize.py` 拒收、链接不回传、钩子策略（pytest，subprocess/socket/环境变量在真解释器里端到端）、
`install.ps1` 静态检查；`GOOS=windows go build/vet ./...`。

**必须在真 Windows 上验证**（牺牲机或测试机，不铺教室）：

1. `CreateProcessWithLogonW` 在 `CREATE_SUSPENDED` 下重定向 stdout/stderr 是否可用；返回的进程句柄能不能 AssignProcessToJobObject；进程会不会已经被 seclogon 放进别的作业。
2. 非提升用户能不能建窗口站和桌面；CUDA 在这个桌面下能不能用；Low 标签对 user32 初始化够不够；非交互窗口站的桌面堆够不够。
3. sitecustomize 降低自身完整性级别能否成功；torch、CUDA、DataLoader 在 Low IL 下是否正常；命名管道的 Low 标签和 `CreateFileW(FILE_WRITE_DATA)` 连接。
4. 拒绝 `0x20` 之后 CreateProcess 和 LoadLibrary 是否都失败；Python 的 makedirs、rmtree、walk，cuDNN、CUDA 缓存是否正常；`TreeResetNamedSecurityInfoW` 的行为。
5. 按 `LocalUser` 写的防火墙规则不依赖 IPsec 能否生效；拦截返回码是不是 10013；回环不受影响。
6. sitecustomize 是否先于脚本目录加载；出错时是否真的退出 97。
7. multiprocessing spawn 的子进程命令行是否就是放行的那种形状；钩子和管道是否都正常。
8. DPAPI 在 C: 还原后的表现。
9. 教室机上 seclogon 是否可用；secedit 合并用户权限是否正确。
10. `WTSEnumerateProcessesExW` 能否查到别的账户的进程，终止权限够不够。
11. 服务端关管道连接时，挂着的同步 `ReadFile` 能不能被 `DisconnectNamedPipe` / `CancelIoEx` 叫醒（叫不醒的话探针只是少收尾 2 秒，不会卡住）。
12. `install.ps1` 第 4/8 步整段：`Add/Remove-LocalGroupMember -SID`、`Set-LocalUser` 参数、一次性 `/reset` 的耗时。

步骤：

1. `EPS_JOB_SANDBOX=1` 跑 `install.ps1`；查账户不在管理员组、登录界面看不到、两条规则都在、`secrets\` 的 ACL、`D:\epsilon` 根上的拒绝 ACE。
2. `epsilon-probe -sandbox-selftest D:\epsilon\envs\<层@2>`：只跑健康检查和两次金丝雀，逐项打印并写 `D:\epsilon\sandbox-selftest.txt`（方便截屏、OCR）。
3. 跑 `smoke` 和 torch GPU + DataLoader（`num_workers=2`）的任务，核对子进程的就绪记录、显存、耗时和沙箱前一致。
4. 攻击任务包（测试钥匙环）：往 `tmp\` 写 exe 并运行、ctypes 加载 `tmp\` 的 dll、写 `C:\ProgramData`、读 `probe.json`、连主控、DNS、UNC、subprocess、
   WMI `Win32_Process.Create`、schtasks、`output\` 里 `mklink /J`、改自己文件的 ACL、ctypes `CreateFileW` 自带 DACL 建文件、留后台进程不退、两个任务先后跑第二个读第一个的输出。每一条都要被拦下并留记录。
5. 跑到一半杀探针，整棵进程树一起死。
6. 重启（C: 还原）后心跳报 `jobs:false`；重跑 `install.ps1` 恢复。
7. 量开销：每次金丝雀的耗时、torch 在 Low IL 下的导入时间。

全过之后才把 `docs/jobs.md` 的"上线前必须做"改成"已做"。

## 8. 待拍板和剩余风险

待拍板（代码按建议做了）：

1. 联网任务 v1 直接拒；有用例再加 `epsilon-jobnet`。
2. 任务账户出站全拦，不放行主控和同教室（比设计书和手册严，手册要跟着改）。
3. 采用 Low IL（前提是 CUDA 实测能跑）。
4. 独立桌面建不出来就不接任务（学生隐私）。
5. `code\` 只读、不给执行。
6. `install.ps1` 一次性 `/reset` `D:\epsilon` 的 ACL。

剩余风险：

- 防火墙按 SID 拦不住 DNS 和 SMB/WebDAV 出口，靠钩子拦和留痕，根治靠 VLAN。
- 钩子可以被绕过（ctypes 直接调系统 API 只计数），系统控制兜着。
- **建文件时自带 DACL**：任务用 ctypes `CreateFileW` 传安全描述符，可以给自己新建的文件加上执行权限，绕过写执行分离（OW 只管事后改 DACL）。
  仍在 Low IL、作业对象、防火墙、独立桌面之内；结束后 `TreeResetNamedSecurityInfoW` 把 `output\` `tmp\` 重置成只继承，防的是留给下一个任务读。
  任务要是把探针也排除在 DACL 外，探针读不了、重置不了：回传失败或收回失败，后者停接任务。
- 内存里生成机器码的 JIT（numba 等）绕得过写执行分离，环境层默认不装。
- 任务账户能运行 System32 下的程序：钩子挡着；绕过钩子也还在作业对象、Low IL 和防火墙之内；逃出作业对象的由结束后的清扫兜底。
- 审计管道只认第一条就绪记录里的 pid（没用 `GetNamedPipeClientProcessId` 核对）；任务可以伪造自己子进程的记录，只影响取证，不影响边界。
