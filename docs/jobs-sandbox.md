# 批任务沙箱（issue #1 第 4 步）

代码在 `jobbox/`（策略、编排、Windows 实现）、`jobbox/py/`（审计钩子和两份金丝雀）、`jobrun/`（`Starter` 接口）、
`winproc/`（`AdoptSuspended`）、`probe/jobs.go`（接线）、`deploy/install.ps1` 第 4/8 步（账户、密码文件、ACL、防火墙）。
对应设计书 22.2、22.4、22.6、22.6.1、22.8（能力 34–36）和《任务包编写与送审手册》1.3、5.3、6.1、6.5。

**状态：代码写完、Mac 上的测试全过；Windows 一侧只保证能编译，一次都没在真机上跑过。** 第 7 节的单子过完之前，
`probe.json` 的 `jobs_sandboxed` 保持 `false`。

开关故意不叫 `jobs`：A/B 槽回滚到这一版之前的探针读的是 `jobs`，会以登录用户不受限地跑任务。`jobs: true` 还留着时本机不接任务；
心跳和登记带 `jobs_sandboxed`，主控只派给报了它的探针（老探针不报）。

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

`$env:EPS_JOB_SANDBOX='1'` 跑一次安装，会留下 `D:\epsilon\job-sandbox.enabled`，以后的重跑（修复、C: 还原后）都照做；`'0'` 删掉标记。
整段包在 try/catch 里：出错就删掉密码文件（健康检查不过、心跳报 `jobs:false`），接着往下装计划任务，不会让整台掉线。每次：

1. 建 `epsilon-job`：32 字节随机数 base64、前面加 `Aa1-`（复杂度策略）；PasswordNeverExpires、不能改密码、不过期；
   只在 Users，移出 Administrators。不用 `net user`（超过 14 位的密码会弹交互提示）。
   **账户在、密码文件解得开、SID 对得上就不换密码**（每次都换的话，改密码和写文件之间任何一步出错两边就对不上，报 1326）。
   要换时先写 `epsilon-job.json.tmp`、再改密码、马上改名；密码文件紧跟着账户写，中间不夹别的步骤。
2. `SpecialAccounts\UserList` 里 `epsilon-job=0`，登录界面不显示。
3. secedit：拒绝网络、远程桌面、批处理、服务登录。**不拒本地交互登录**：seclogon 走的就是它。
4. seclogon 被禁用就改成手动。
5. 密码只放 D:：`secrets\epsilon-job.json` = `{"version":1,"user":"epsilon-job","sid":"S-1-5-21-…","password_dpapi":"<base64>"}`，
   DPAPI **LocalMachine** 作用域（脚本是 SYSTEM、探针是登录用户，用户作用域两边解不通），附加熵 `epsilon-job/v1`。
   `secrets\` 是受保护 DACL `D:P(D;OICI;FA;;;<job>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)`。先写临时文件再改名；密码不打印。
6. **不要把 `epsilon-job` 做进哦易母镜像**：每台密码就一样了，还和 D: 上的文件对不上。

DPAPI 能防什么：LocalMachine 下本机任何进程都能解密，挡任务进程的是 `secrets\` 上那条拒绝 ACE；DPAPI 防的是把 D: 拷走去读。
**本机任何本地用户都被当作和探针同等可信**：`secrets\` 给 BU 读（探针是 Limited 令牌，BA 只是仅拒绝），熵是公开的，
所以本机用户能解出密码、以 `epsilon-job` 登录本地会话，读写正在跑的任务的目录。教室机上坐在机器前的人本来就是 Administrator，不另设防。
C: 还原后主密钥可能变了、解不开，账户也同时没了，结果一样：心跳报 `jobs:false`，重跑 `install.ps1` 恢复。
坐在机器前的人本来就是 Administrator；每台不同的密码加上拒绝网络登录，防的是拿它横向登录别的机器。

### 启动：`CreateProcessWithLogonW`

| 方式 | 要的特权 | 本场景 |
|---|---|---|
| `LogonUser` + `CreateProcessAsUser`（Go 的 `SysProcAttr.Token`） | SeAssignPrimaryTokenPrivilege | 探针没有，报 1314，不行 |
| `LogonUser` + `CreateProcessWithTokenW` | SeImpersonatePrivilege | 探针是 Limited，不能指望 |
| 计划任务指定账户 | 注册要管理员；拿不到作业对象和 stdout | 不行 |
| **`CreateProcessWithLogonW`** | **不需要**（走 seclogon） | 唯一不依赖探针特权的；代价是要明文密码 |

`lpCommandLine` **最多 1024 个字符**：金丝雀源码（几 KB）不放命令行，探针写进任务目录的 `canary\`（任务只读），命令行是一段短引导
（`jobbox.canaryBoot`，先去掉 `sys.path` 里的 `''`，`code\` 里的同名模块抢不到标准库）。起任何进程之前查长度（`jobbox.CmdLine`，纯函数），超了按任务的问题拒。

参数：`dwLogonFlags=0`（先不加载配置文件）、`CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT`、`STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW(SW_HIDE)`、
stdout/stderr 接日志句柄（复制一份可继承的）、`lpDesktop = epsilon-job\Default`。拿到挂起的进程后 `winproc.AdoptSuspended`：
新建作业对象（KILL_ON_JOB_CLOSE、DIE_ON_UNHANDLED_EXCEPTION、ActiveProcessLimit 64、`JOBOBJECT_BASIC_UI_RESTRICTIONS` 全开，
不设 BREAKAWAY_OK）→ 指派 → `ResumeThread`。任何一步失败都结束这个进程，它一行都还没跑。

**独立桌面**：不指定的话 seclogon 把任务账户加进 `WinSta0\Default`，任务就能截学生的屏、读剪贴板、轮询按键。探针第一次健康检查时建窗口站
`epsilon-job`（`CWF_CREATE_ONLY`：同名的已经存在就失败，不用别人的）和桌面 `Default`，标签 `S:(ML;;NW;;;LW)`（否则 Low IL 进程初始化 user32 会失败），句柄攥到退出。
任务账户在窗口站上是 `0x2037f`、桌面上是 `0x201ff`（全部具体权限 + READ_CONTROL），**没有 WRITE_DAC、WRITE_OWNER、DELETE**，改不了它们的 DACL。
第一次健康检查之前先清场：上一个探针的残留进程攥着窗口站时建不出新的。
`CreateDesktop` 要先 `SetProcessWindowStation`（整个进程生效），建完马上切回。建不出来就不接任务。
**`lpDesktop` 只决定进程起在哪个桌面，不挡它主动打开别的**（审查 #17 第 3 条，待真机确认）：MSDN 说 LocalSystem 不能调
`CreateProcessWithLogonW`，理由是"它要用调用者令牌里的登录 SID"，也就是任务令牌里很可能带着探针（学生登录会话）的 `S-1-5-5-x-y`，
而 `WinSta0`、`WinSta0\Default` 的 DACL 正是按这个登录 SID 授权的。那样任务（Low IL 也一样，读不受 NW 标签限制）可以
`OpenWindowStationW("WinSta0", WINSTA_READSCREEN|WINSTA_ENUMERATE)` → `SetProcessWindowStation` → `OpenDesktopW("Default")` → 截屏、轮询按键。
系统金丝雀 `winsta0_denied` 反向实测（必须错误 5），`token_groups` 把令牌里的登录 SID 写进证据：成立的话每个任务都会因为系统金丝雀不符被拒、
本机停接（fail-closed），要换方案（sitecustomize 用把登录 SID 设成仅拒绝的受限令牌重新起自己，`CreateProcessAsUser` 用自己令牌的受限版本不要特权），
或者拍板写进剩余风险。

**Low IL 和特权**：`sitecustomize` 在装钩子之前用 ctypes 把自己的令牌降到 Low，再用 `SE_PRIVILEGE_REMOVED` 删掉除 SeChangeNotifyPrivilege 以外的全部特权
（工作站上 Users 有 SeShutdownPrivilege，不删的话任务能 `InitiateShutdownW` 重启教室机；作业对象的 UILIMIT_EXITWINDOWS 只管 ExitWindowsEx），子进程都继承。之后只能写标了 Low 的地方（`output\` `tmp\`），
`C:\ProgramData`、`C:\Users\Public`、`C:\Windows\Temp` 这些"人人可写可执行"的目录自动写不了。级别写在就绪记录里（用户代码还没机会运行）。
CUDA 在 Low IL 下能不能跑要真机验证；不行的备选是给已知的人人可写目录加拒绝写（单子不全），金丝雀会实测几个。
**放弃 Low IL 之前**：硬链接这条路现在靠 Low IL 挡着（沙箱令牌建硬链接要目标的 FILE_WRITE_ATTRIBUTES）。`joboutput` 已经按句柄查链接数、
金丝雀 `hardlink_probe_json` 实测，两条都在；换成备选方案时这项金丝雀必须照样过。

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
| `jobs\<id>\` | `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<probe>)(A;OICI;FR;;;<job>)(A;CI;0x20;;;<job>)(A;OICI;0x20000;;;OW)` | 受保护，任务只读：建不了文件、删不了 `params.json`。`(A;CI;0x20)` 是目录上的 FILE_TRAVERSE（只给目录，文件拿不到 FILE_EXECUTE）：`SetCurrentDirectory`（`lpCurrentDirectory`、`os.chdir`）以它打开目标目录本身，SeChangeNotify 只免中间各级 |
| `code\` | 继承只读 | **只读、没有执行权限**（任务原文写的是读+执行，这里按 22.6.1 取更严的；.py 不要执行权限） |
| `output\` `tmp\` | 追加 `(D;OIIO;0x20;;;<job>)(A;OICI;0x13019f;;;<job>)`，标签 `S:(ML;OICI;NW;;;LW)` | `0x13019f` = 修改权去掉 FILE_EXECUTE，也没有 WRITE_DAC/WRITE_OWNER。拒绝执行**必须写成 `0x20`**：`FX` 连 SYNCHRONIZE、READ_CONTROL 一起拒，读文件就坏了。`OIIO` 只作用在文件上 |
| `job.log` `canary.out` | 继承只读 | 任务进程经探针给的句柄写 |
| `canary\` | 继承只读 | 探针每次写两份金丝雀源码（`sys.txt` `hook.txt`，不叫 `.py`）和配置 `cfg.json` |

- **OWNER RIGHTS（`OW`）不能省**：任务在 `output\` 里新建的文件所有者是任务账户，所有者天生有 WRITE_DAC，能删掉拒绝执行；有了 OW，所有者只剩 READ_CONTROL。
- **结束后收回**：根换成没有 `<job>` 的版本；`output\` `tmp\` 用 `TreeResetNamedSecurityInfoW` 整棵重置成只继承（任务建文件时可以自带 DACL，
  见第 8 节剩余风险）。所有任务共用一个账户，不收回下一个任务就能读这一份输出（本地保留 24 小时）。第一次健康检查时（先于建桌面）把 `jobs\*` 都收回一遍。
  **收回失败**：把目录改名成 `jobs\.q-<32 位随机十六进制>`（`jobs\` 对任务账户不可列，下一个任务按路径找不到它），发事件、不停接；
  改名也失败才停接到重启。启动时也一样（以前是每次重启都再失败一次、永久停接）。设 ACL 失败时也先收回再删目录。
- **硬链接不回传**：`joboutput` 每个文件在同一个句柄上查链接数（必须是 1）再读，Windows 上以 `FILE_FLAG_OPEN_REPARSE_POINT` 打开、重解析点也拒。
- **上级目录**（`install.ps1`）：`D:\epsilon` 根上 `(D;OICI;0xd0157;;;<job>)`（读/列目录、写、追加、写 EA、删子项、写属性、删除、WRITE_DAC、WRITE_OWNER；不拒遍历和 READ_CONTROL）
  和 `(D;OIIO;0x20;;;<job>)`（文件上拒执行：探针、引导器、llama-server、ggml-rpc-server 都不能执行，也不能按映像映射进来读），
  `envs\` 上 `(A;OICI;0x1200a9;;;<job>)`（读+执行，显式的排在继承来的拒绝前面）。任务账户读不到 `probe.json`、`secrets\`、日志、别的任务，写不了槽位、钥匙环版本文件和环境层（含 `sitecustomize.py`）。
- **数据卷**（`install.ps1`）：非系统盘根上默认 Users 可读，D: 又不被还原（学生、老师的文件，别的软件的配置）。每个固定 NTFS 数据卷的根上
  `(D;OICI;0x1;;;<job>)`（拒读/列目录；已经有就不重做，加一次要传播整个卷）。`jobs\<id>\`、`secrets\` 是受保护 DACL 不受影响，`envs\` 的显式允许照常。
  C: 上 Users 可读的（`C:\ProgramData` 里管理软件的配置）只能在真机上盘点（第 7 节）。
  环境层在 `envs\` 下解压再改名，ACL 跟着 `envs\` 走。哪一处漂了，金丝雀都测得出来。

## 4. 出站防火墙

1. `install.ps1` 建两条静态规则：`epsilon-job-out`（出站）和 `epsilon-job-in`（入站），`-Action Block -Protocol Any -Profile Any -LocalUser "O:LSD:(A;;CC;;;<job SID>)"`。
   入站也要拦：`epsilon-p2p` 给**任何程序**放行了 47100–47119，不拦的话任务能抢在探针前面占端口。
2. **按账户 SID，不按程序路径**：环境层路径随版本变、安装时不知道；按路径管不住层里别的 exe 和 System32；按 SID 连逃出作业对象的进程也管。
3. **不放行主控和同教室**（比设计书 22.6 和手册更严，待拍板）：任务不需要，拉取回传都是探针做；拦截优先于允许，要放行只能把补集写成 RemoteAddress 区间。
4. **管不到的出口**（剩余风险）：
   - DNS 由 dnscache 服务发出（LLMNR、NetBIOS 也一样）。
   - UNC：名字解析走 dnscache，SMB 连接由内核以 System 身份发出，**还会带上 `epsilon-job` 的 NTLM 认证**。`os.path.exists(r"\\<数据>.attacker\x")`
     这种纯 Python 就够，不需要 ctypes。钩子在所有带路径的审计事件上拦 UNC，但 **`os.stat` / `os.path.exists` 没有审计事件，拦不住、也不留记录**。
     系统层的办法（整机拦出站 TCP 139/445、禁用 WebClient 服务）会影响本机所有用户，待拍板（第 8 节）；根治是独立 VLAN（16.7）或受限的解析器。
   - **回环不过 Windows 防火墙**（连本机自己的地址也按回环处理）：本机 `epsilon-boot`、p2p（有令牌）、停推理那一小段时间的 llama-server :8080
     和 ggml-rpc-server :50052（没有认证）、以 SYSTEM 运行的教室管理代理都在听。钩子只许连本进程自己 bind 的回环端口；探针开始跑任务前
     等推理、rpc 进程真的退出。**钩子挡不住的连接只能靠盘点本机监听、逐个确认要认证（第 7 节第 13 条），这一条是硬要求**：
     绕过钩子不止 ctypes 一条路（静态审核拒签），纯 Python 用 gc 枚举、取钩子帧也能改钩子的状态（会留记录，第 5 节、第 8 节）。
     以前这里写的"绕过要 ctypes"不成立（审查 #17 第 1 条）：那时任务一句 `sys.modules['sitecustomize'].decide = ...` 就关掉了钩子，不留记录。
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
  → 降到 Low IL → 删特权 → `sys.addaudithook` → 写就绪记录 `{"ev":"ready","pid","ppid","il","privs","job_dir","file","layer"}`。
- **钩子运行时不查任何任务改得了的东西**（审查 #17 第 1 条）。任务用纯 Python 改模块全局、标准库函数（`ntpath.normpath`、`os.write`、`json.dumps`）、
  类属性（`socket.socket.getsockname`）和内建（`builtins.isinstance`）都不触发审计事件，所以钩子路径上的函数把用到的一切在 import 时（用户代码之前）
  绑成**位置默认参数**：没有全局和内建查找、没有闭包（`cell_contents` 能改）、不用 `__kwdefaults__`（能改的字典），默认参数只放不可变的东西；
  改这些函数的 `__code__`/`__defaults__` 有 `object.__setattr__` 事件，钩子认得自己的函数，拦下。
  参数按类型读底层数据（str 子类、元组子类、int 子类和 C 读到的一样），**不调任务的任何代码**（`__fspath__`、`__repr__`、`__eq__`、重写的方法）。
  钩子运行中跑到的任务代码（GC 在钩子里触发的 `__del__`）照样判，不再跳过；钩子自己不触发审计事件，不会递归。
  `tools/test_sandbox_hook.py` 逐个函数核对这几条，并在真解释器里把能改的都改一遍（`test_tampering_with_globals_does_not_switch_the_hook_off`）。
  还剩的路要先拿到钩子的对象：`gc.get_objects/get_referrers/get_referents`、`sys._current_frames` 逐条记；从拦截异常的 `tb_frame` 拿到的钩子帧里只有不可变的东西和计数。
- 探针一侧：主进程恢复后 30 秒内收不到它的就绪，整树杀、`rejected`；主进程的连接在进程退出前断开（宽限 5 秒）、任何连接上记录格式不对、
  就绪记录的 `job_dir` 不是这个任务的目录、**`il` 不是 `low` 或 `privs` 不是恰好 `["SeChangeNotifyPrivilege"]`**（审查 #17 第 2 条：
  降级和删特权全在层里的 sitecustomize 里做，它写错了系统控制金丝雀测不出来），视为篡改：整树杀、`failed`、照常回传。拦截次数运行中就写进心跳。
- 记录一行一个 JSON：`{"t","pid","ev","act":"block|log|count","args"}`，args 截到 512 字节，一次 `os.write` 写完。

### 策略（`jobbox/py/sitecustomize.py` 的 `decide`，纯函数）

| 事件 | 处理 |
|---|---|
| `subprocess.Popen` `os.system` `os.startfile` `os.spawn` `os.exec` `os.posix_spawn` `webbrowser.open` | 拦 |
| `_winapi.CreateProcess` | 只放行程序是本层 `python.exe`、命令行一字不差是 multiprocessing spawn 的那种（`-B -E -s -c "from multiprocessing.spawn import spawn_main; spawn_main(...)" --multiprocessing-fork`）、不指定工作目录。多出 `-S` `-I` 就能起没有钩子的子进程。审计参数不含环境块，子进程拿到的 `EPSILON_JOB_DIR` 由探针核对就绪记录 |
| `socket.bind` | 不是 127.0.0.1 / ::1 / localhost 就拦 |
| `socket.connect` `sendto` `sendmsg` | 不是回环就拦；回环只放行本进程自己 bind 的端口（`socketpair`、asyncio 的自连），别的回环端口也拦 |
| `socket.getaddrinfo` `gethostbyname*` `gethostbyaddr` `getnameinfo` | 不是 localhost 就拦（DNS 隐蔽通道） |
| 所有带路径的事件（`open` `os.listdir` `os.scandir` `os.mkdir` `os.rename`（含 `os.replace`）`os.remove` `os.rmdir` `os.chdir` `os.chmod` `os.utime` `os.link` `os.symlink` `os.truncate` `os.add_dll_directory` `shutil.*` `tempfile.mk*` `glob.glob`，见 `PATH_ARGS`） | 拦 UNC、`\\?\UNC\`、`\\.\` 设备路径（`\\.\pipe\` 和 `\\?\X:\` 除外）。`os.stat` 没有审计事件。路径参数不是 str/bytes（`pathlib`、`os.DirEntry`、任务自己的类）只计数 `path.opaque`：钩子不调它的 `__fspath__`（第二次调可以返回和系统调用用的不一样的路径）；`open()` 不受影响（C 先转换成 str 再发事件） |
| `open` | `code\` 和环境层以外的 `.py` `.pyc` `.pyw` `.pth` 读写都拦（按 Windows 规则：`x.py.`、`x.py `、`x.py::$DATA` 都是 `x.py`） |
| `os.rename` `os.link` `os.symlink` `shutil.copyfile` `shutil.move` | 目标是 `code\` 和环境层以外的 `.py` 之类就拦（先写 `x.txt` 再改名） |
| `os.mkdir(mode=0o700)` | 计数（Python 3.12.4+ 在 Windows 上给它建受保护 DACL，所有者完全控制，收回权限会失败） |
| `import` | `sys.path` 里有 `code\` 和环境层以外的条目、或者不是字符串的条目就拦 |
| `ctypes.dlopen` | 全记；带路径的在环境层和 System32 之外就拦 |
| `ctypes.call_function` `pickle.find_class` `marshal.loads` | 只计数（每种原样记前 50 条，之后每 1000 次一条累计）；multiprocessing、torch 内部也会触发 |
| `compile` `exec` | 文件名在 `code\`、环境层（含层内 pyc 的相对路径）、冻结模块的算导入，只计数；`<string>` 之类算动态执行，逐条记 |
| `winreg` 写操作 | 拦 |
| 改 `EPSILON_*` 环境变量 | **拦**（设计稿写的是记录）。只拦得住 `os.putenv`：`_winapi.CreateProcess` 可以自带环境块，所以就绪记录里带 `job_dir`，探针核对，和任务目录不一致按篡改整树杀 |
| `sys.addaudithook` `cpython.run_*` | 记 |
| `gc.get_objects` `gc.get_referrers` `gc.get_referents` `sys._current_frames` `sys._current_exceptions` `sys.settrace` `sys.setprofile` | 记（能摸到钩子的对象和正在跑的钩子帧） |
| `object.__setattr__` 改钩子自己的函数（`__code__` `__defaults__`） | 拦 |

拦截是抛 `PermissionError`，任务可以接住接着跑，但已经计数。有拦截不自动判失败，按 22.6.1 交给人复查、吊销。

### 回传

- `output\_runner\audit.log`（上限 8 MB，超了只计数、标 `truncated`）；`summary.json` 加 `audit`：`{ready, blocked, logged, by_event, truncated}`。
- `proto.JobStatus` 加 `audit_blocked,omitempty`（只增不改）；结束事件里写"有拦截 N 次"。

### 金丝雀（每个任务都跑，两次；源码打包在探针里）

在任务目录 ACL 设好之后、任务起来之前，以任务账户、同样的桌面和作业对象跑，输出写 `canary.out`，由 `jobbox.CheckCanary` 对照（每一项恰好报一次且 ok，任何 fail 都拒）。之后清空 `tmp\` `output\`。

1. **系统控制**（`python -I -S -c <引导> canary\sys.txt canary\cfg.json`，不加载钩子；先用和 sitecustomize 一模一样的代码降到 Low、删特权，测试核对两份相同）：
   `integrity_low` `privileges_dropped`（只剩 SeChangeNotify）`desktop` `winsta0_denied`（打开交互窗口站 `WinSta0` 必须错误 5，第 2 节）
   `token_groups`（令牌里没有 Users 以外的本机组，不管直接还是嵌套；证据带登录 SID）`read_probe_json` `read_secrets` `read_data_disk`（列卷根必须错误 5）
   `exec_artifact_root`（以 FILE_EXECUTE 打开 `epsilon-boot.exe` 必须错误 5）`hardlink_probe_json`（从 `output\` 建到 `probe.json` 的硬链接必须失败）
   `chdir_tmp` `write_code` `write_params` `delete_params` `write_job_root` `write_sitecustomize` `write_env`
   `write_tmp` `write_output` `exec_tmp`（复制 python.exe 进 tmp 再起，必须错误 5）`load_tmp_dll` `set_dacl_own_file`（改自己文件的 DACL 必须错误 5，验 OW）
   `write_programdata` `write_windows_temp` `write_users_public` `connect_controller`（必须 10013）`socketpair`。
   金丝雀活着时探针核对 `WTSEnumerateProcessesExW` 列得出它（列不出 = 清场是瞎的，停接任务）。
2. **钩子**（`python -E -s -B -c <引导> canary\hook.txt canary\cfg.json`，工作目录 `code\`，和真任务一样）：`hook_installed` `subprocess_blocked` `spawn_flags_blocked` `connect_blocked` `dns_blocked` `unc_blocked`
   `unc_paths_blocked`（mkdir、rename、chdir）`env_tamper_blocked` `tmp_py_blocked` `rename_py_blocked` `dlopen_tmp_blocked` `loopback_blocked` `socketpair_ok`
   `tamper_globals_blocked`（把 sitecustomize 的模块全局、`ntpath.normpath`、`os.fspath` 换掉以后照样拦）`mp_child`；
   探针另从审计管道核对 `ready_main` `ready_in_layer` `ready_child` `ready_low_il`（主进程和子进程的就绪记录都是 il=low、只剩 SeChangeNotify）。

## 6. 出错就拒

健康检查（探针启动时、之后每 10 分钟）：密码文件能解密、`LookupAccountName` 的 SID 和文件一致、本地组恰好是 Users（按 SID 比；
Backup Operators 的 SeBackup 能绕过所有 DACL）、窗口站建好了。不过就心跳报 `jobs:false`（主控以最近一次心跳为准，不再派），原因变了才记一次日志、发 `jobbox` 事件。

**健康检查只清它自己查的那一类。** 下表"直到探针重启"的几类（登录、系统控制、看不到进程……）健康检查查不到，以前每 10 分钟清一次，
节点就回到 `jobs:true`、再烧一个任务、无限循环。现在要重跑 `install.ps1`（会停、再拉起探针）或者重启才恢复。
这几类拒绝带 `retry`：主控按失联那条放回队列、换一台（算一次重试），不算这个任务失败。

| 环节失败 | 结果 | 本机停接任务？ |
|---|---|---|
| 健康检查不过（典型：C: 被还原） | 派来的任务 `rejected`（retry） | 是，直到下一次检查通过 |
| 设 ACL 或标签失败 | 先收回再删掉任务目录，`rejected`（retry） | 否 |
| `CreateProcessWithLogonW` 报 1326 / 1385 / 1058 / 1327 / 1330 / 1331 / 1907 / 1909 | `rejected`（retry） | 是，直到探针重启 |
| 任务进程的启动错误 2 / 3 / 123 / 193 / 206 / 267（解释器、路径、工作目录不对）；命令行超过 1024 字符 | `rejected` | 否 |
| 金丝雀起不来（任何错误：程序、目录、参数都是探针生成的，审查 #17 第 7 条） | `rejected`（retry） | 是，直到探针重启 |
| 其他启动错误（5、1314……）；指派作业对象或恢复失败；建不了审计管道 | 结束挂起的进程，`rejected`（retry） | 是，直到探针重启 |
| 系统控制金丝雀不符（配置漂移，不是任务的问题） | `rejected`（retry） | 是，直到探针重启 |
| 清场列不出系统金丝雀（非管理员枚举不出别的账户进程的 SID） | `rejected`（retry） | 是，直到探针重启 |
| 推理、rpc 进程 30 秒内没退出 | `rejected`（retry） | 否 |
| 钩子金丝雀不符（层没有钩子、钩子不对） | `rejected`，写明是哪个环境层 | 否 |
| 30 秒内没收到就绪；没发就绪就退出 | 整树杀，`rejected` | 否 |
| 运行中审计管道断开、记录被篡改 | 整树杀，`failed`，照常回传 | 否 |
| 结束后 3 秒宽限内还有这个 SID 的进程（作业对象 Close 时先等 ActiveProcesses 归零；conhost、正在退出的在宽限内消失不算） | 有进程逃出了作业对象，试着 TerminateProcess（**可能结束不了**，第 8 节），发事件 | 是，直到重启（C: 还原自然清场） |
| 收回 ACL 失败 | 改名隔离（`jobs\.q-…`），照常回传，发事件 | 否；改名也失败才停到重启 |

编译期：Windows 构建里探针只有真沙箱（`jobbox.New`），没有不受限的路径；非 Windows 构建的 `New` 返回 `Unavailable`。
Mac 上的测试注入假的 `Platform`（`jobbox/box_test.go`）或假的 `Sandbox`（`probe/jobbox_fake_test.go`）。`jobrun.Plain` 只给测试用。

## 7. 真机验证（这一轮全部没做）

Mac 上测了：SDDL 字面量、环境块、金丝雀解析和对照（每一项不符都拒）、两份金丝雀真跑一遍名字对得上、审计记录解析和监视（就绪超时、主进程断开、篡改、截断、计数）、
编排顺序和每一步失败的出错即拒、心跳 `jobs` 跟着沙箱、`network:true` 拒、`sitecustomize.py` 拒收、链接不回传、钩子策略（pytest，subprocess/socket/环境变量在真解释器里端到端）、
`install.ps1` 静态检查；`GOOS=windows go build/vet ./...`。

**必须在真 Windows 上验证**（牺牲机或测试机，不铺教室）。验证套件在 `tools/sandbox-check/`：拷到牺牲机一条命令跑完下面 18 项（共 21 项），
出一份 PASS / FAIL / MANUAL / SKIP 的报告（`D:\epsilon\sandbox-check-<时间>.txt`），用法、回滚和结果怎么看见那里的 README。
第 19–21 条（下面"步骤"里的 4、5、7）套件不做，报告里各报一条 MANUAL，要手工做完（审查 #17 第 4 条）。

1. `CreateProcessWithLogonW` 在 `CREATE_SUSPENDED` 下重定向 stdout/stderr 是否可用；返回的进程句柄能不能 AssignProcessToJobObject；进程会不会已经被 seclogon 放进别的作业。
2. 非提升用户能不能建窗口站和桌面；CUDA 在这个桌面下能不能用；Low 标签对 user32 初始化够不够；非交互窗口站的桌面堆够不够。
3. sitecustomize 降低自身完整性级别能否成功；torch、CUDA、DataLoader 在 Low IL 下是否正常；命名管道的 Low 标签和 `CreateFileW(FILE_WRITE_DATA)` 连接。
4. 拒绝 `0x20` 之后 CreateProcess 和 LoadLibrary 是否都失败；Python 的 makedirs、rmtree、walk，cuDNN、CUDA 缓存是否正常；`TreeResetNamedSecurityInfoW` 的行为。
5. 按 `LocalUser` 写的防火墙规则不依赖 IPsec 能否生效；拦截返回码是不是 10013；回环不受影响。
6. sitecustomize 是否先于脚本目录加载；出错时是否真的退出 97。
7. multiprocessing spawn 的子进程命令行是否就是放行的那种形状；钩子和管道是否都正常。
8. DPAPI 在 C: 还原后的表现。
9. 教室机上 seclogon 是否可用；secedit 合并用户权限是否正确。
10. 非管理员的探针用 `WTSEnumerateProcessesExW` 能否查到别的账户的进程（`pUserSid` 是否为空；金丝雀核对会停接）、终止权限够不够
    （审查 #17 第 5 条：任务进程的 DACL 来自 LogonUser 令牌的默认 DACL——任务用户 GA、SYSTEM GA、登录 SID 只有 GR|GX——探针的用户 SID 不在里面，
    `OpenProcess(PROCESS_TERMINATE)` 很可能报 5；`10.terminate` 测得出来）；
    **普通任务结束后马上清场**会不会看到 conhost 或正在退出的进程（3 秒宽限够不够）。
11. 服务端关管道连接时，挂着的同步 `ReadFile` 能不能被 `DisconnectNamedPipe` / `CancelIoEx` 叫醒（叫不醒的话探针只是少收尾 2 秒，不会卡住）；
    `ConnectNamedPipe` 叫不醒时 stop 最多等 3 秒。`Close` 落在两次 `Accept` 之间时实例不漏（审查 #17 第 6 条；逻辑在 `jobbox/pipeserver.go`，Mac 上有单测），
    真机上连续跑两个任务，第二个照样建得出审计管道。
12. `install.ps1` 第 4/8 步整段：`Add/Remove-LocalGroupMember -SID`、`Set-LocalUser` 参数、一次性 `/reset` 的耗时、数据卷根上拒读的传播耗时；
    中途故意让一步失败（比如停掉 seclogon 之外的某个依赖），确认后面照常装、密码文件被删、心跳报 `jobs:false`。
13. 回环：`netstat -ano` 盘点 127.0.0.1 和本机地址上的监听（含教室管理软件），逐个确认要认证；钩子金丝雀 `loopback_blocked`、`socketpair_ok`。
14. `C:\ProgramData`、`C:\Users\Public` 等 C: 上 Users 可读的内容盘点：有没有管理软件的配置、口令。
15. `TreeResetNamedSecurityInfoW` 遇到把探针排除在外的子项时是中止还是跳过（跳过的话收回"成功"了却没收回，要加抽查）；Python 3.12.4+ 的 `mkdir(0o700)`。
16. 删特权以后 torch、CUDA、DataLoader 是否正常；窗口站 `0x2037f`、桌面 `0x201ff` 对 user32 初始化和 CUDA 够不够；`CWF_CREATE_ONLY` 在探针重启后能否重建。
17. 系统金丝雀新增项：`hardlink_probe_json`（Low IL 下必须失败）、`chdir_tmp`、`exec_artifact_root`、`read_data_disk`、`privileges_dropped`、
    `winsta0_denied`（第 2 节：任务令牌里有没有探针的登录 SID，`token_groups` 的证据对照探针 `whoami /groups` 的 LogonId）、`token_groups`；
    钩子金丝雀 `tamper_globals_blocked`、探针核对的 `ready_low_il`。
18. 命令行长度：两次金丝雀和真任务的命令行都在 1024 字符以内（Mac 上按同样的规则算过）。
19. **攻击任务包**（手工，下面步骤 4）。逃出作业的进程（WMI、schtasks）要让本机停接；再看它是否真被结束了（第 10 条、第 8 节）。
20. **跑到一半杀探针**（手工，步骤 5）。
21. **开销**（手工，步骤 7）。

步骤：

1. `EPS_JOB_SANDBOX=1` 跑 `install.ps1`；查账户不在管理员组、登录界面看不到、两条规则都在、`secrets\` 的 ACL、`D:\epsilon` 根上的拒绝 ACE。
2. `epsilon-probe -sandbox-selftest D:\epsilon\envs\<层@2>`：只跑健康检查和两次金丝雀，逐项打印并写 `D:\epsilon\sandbox-selftest.txt`（方便截屏、OCR）。
3. 跑 `smoke` 和 torch GPU + DataLoader（`num_workers=2`）的任务，核对子进程的就绪记录、显存、耗时和沙箱前一致。
4. 攻击任务包（测试钥匙环）：往 `tmp\` 写 exe 并运行、ctypes 加载 `tmp\` 的 dll、写 `C:\ProgramData`、读 `probe.json`、连主控、DNS、UNC、subprocess、
   WMI `Win32_Process.Create`、schtasks、`output\` 里 `mklink /J`、改自己文件的 ACL、ctypes `CreateFileW` 自带 DACL 建文件、留后台进程不退、两个任务先后跑第二个读第一个的输出。每一条都要被拦下并留记录。
5. 跑到一半杀探针，整棵进程树一起死。
6. 重启（C: 还原）后心跳报 `jobs:false`；重跑 `install.ps1` 恢复。
7. 量开销：每次金丝雀的耗时、torch 在 Low IL 下的导入时间。

报告没有 FAIL、MANUAL 都拍了板、第 19–21 条和第 3 条的"和沙箱前一致"手工做完之后，才把 `docs/jobs.md` 的"上线前必须做"改成"已做"。

## 8. 待拍板和剩余风险

待拍板（1–6 代码按建议做了；7、8 还没动）：

1. 联网任务 v1 直接拒；有用例再加 `epsilon-jobnet`。
2. 任务账户出站全拦，不放行主控和同教室（比设计书和手册严，手册要跟着改）。
3. 采用 Low IL（前提是 CUDA 实测能跑）。
4. 独立桌面建不出来就不接任务（学生隐私）。
5. `code\` 只读、不给执行。
6. `install.ps1` 一次性 `/reset` `D:\epsilon` 的 ACL。
7. **要不要整机拦出站 TCP 139/445、禁用 WebClient 服务**：堵住 UNC 经 SMB/WebDAV 出网（`os.stat` 拦不住），但影响本机所有用户（教室共享盘、打印）。
   不拦的话这条只能靠独立 VLAN 或受限的解析器。
8. **手册和运行时对 subprocess 不一致**：《任务包编写与送审手册》说 subprocess 不是红线、送审时说明理由可以批；运行时钩子一律拦（multiprocessing spawn 除外），
   没有按钥匙放开的开关。要么手册改成"不许"，要么加一个由钥匙权限决定的放行（会扩大绕过钩子的面）。

剩余风险：

- 防火墙按 SID 拦不住 DNS 和 SMB/WebDAV 出口，靠钩子拦和留痕，根治靠 VLAN。`os.stat` / `os.path.exists` 走 UNC 没有审计事件，钩子也拦不住、不留记录；
  SMB 还会带上任务账户的 NTLM（每台不同的密码、拒绝网络登录，拿到也横向不了）。
- 回环不过防火墙：钩子只放行本进程自己 bind 的端口；绕过钩子就连得上，靠本机监听都要认证（第 7 节第 13 条盘点，硬要求）。
- 钩子可以被绕过，系统控制兜着：ctypes 直接调系统 API（只计数；静态审核拒签）；纯 Python 先 `gc.get_objects()` 找到钩子的函数
  （`__closure__` / `cell_contents`、`__cantrace__` 加 `sys.settrace` 都不触发事件）——前一步逐条记录，`sys.settrace` 也记，所以**能改但留痕**。
  任务帧里拿得到的拦截异常的 `tb_frame` 只暴露钩子的默认参数（不可变）和计数字典（改了只影响 count 类记录的取证）。
  任务包静态审核（`epsilon-review`，rules_version 3，规则 `hook-tamper` / `audit-hook`，见 PR #14）在签名前再挡一道：代码包里 monkeypatch 标准库或 builtins
  （属性赋值、`del`、`setattr` / `object.__setattr__`、改模块 `__dict__`）、改函数的 `__code__` / `__defaults__` / `__kwdefaults__` / `cell_contents`、碰 `__globals__` / `__closure__`、
  访问 `sitecustomize` / `usercustomize`、`sys.settrace` / `setprofile`（含 `threading.*`、`sys.monitoring`）、`sys._current_frames`、`sys.addaudithook` / `sys.audit` 的一律拒签；
  `gc.get_objects` / `get_referrers` / `get_referents`、取帧（`sys._getframe`、`inspect.currentframe` / `stack`、`f_back` / `f_globals` / `f_locals` / `tb_frame`）列为需解释。
  运行时钩子不查可被改掉的东西、逐条记录 gc 枚举，仍是兜底；静态审核认不出模块经容器、参数传进来再改的写法。
- 路径参数不是 str/bytes 的带路径事件（`os.mkdir(Path(r"\\h\s"))`、`os.rename(p, Path("tmp/x.py"))`）只计数不拦：和 `os.stat` 一样拦不住 UNC；
  改名出来的 `.py` 也打不开、导入不了（`open` 和 `import` 两道检查都在）。
- 钩子运行中被 GC 触发的任务 `__del__` 照样受钩子管，但它和钩子在同一个线程里：要是它在 `write` 写到一半时也写记录，那一行会坏，探针按篡改整树杀（fail-closed）。
- **建文件时自带 DACL**：任务用 ctypes `CreateFileW` 传安全描述符，可以给自己新建的文件加上执行权限，绕过写执行分离（OW 只管事后改 DACL）。
  仍在 Low IL、作业对象、防火墙、独立桌面之内；结束后 `TreeResetNamedSecurityInfoW` 把 `output\` `tmp\` 重置成只继承，防的是留给下一个任务读。
  任务要是把探针也排除在 DACL 外，探针读不了、重置不了：回传失败或收回失败，后者把目录改名隔离（不停接）。
- 上面几条 ctypes 绕过，签名前先挡一道：任务包静态审核（`epsilon-review`，rules_version 2）把代码包里直接用 ctypes / cffi / `_winapi` / msvcrt / pywin32 / `os.add_dll_directory` / 可执行 mmap 的一律拒签（含 `__import__`、`importlib`、拼接、`sys.modules['ctypes']` 等写法）。运行时钩子和系统控制仍是兜底；环境层库内部的 ctypes 不受影响。
- 内存里生成机器码的 JIT（numba 等）绕得过写执行分离，环境层默认不装。
- 任务账户能运行 System32 下的程序：钩子挡着；绕过钩子也还在作业对象、Low IL 和防火墙之内。逃出作业对象的（WMI、schtasks；Low IL 下 DCOM 激活
  能不能成要真机看）结束后清扫看得见，**只保证本机停接（直到重启），不保证杀得掉**：`Sweep` 以探针身份 `OpenProcess(PROCESS_TERMINATE)`，
  任务进程的默认 DACL 里没有探针的用户 SID，多半报 5（审查 #17 第 5 条）。要真杀的话候选：再以任务账户（探针有它的密码）起一个
  `taskkill /F /PID`，同一个账户对自己的进程有 GA；或者管理员身份的计划任务。真机 `10.terminate` 失败了再选。
- 任务令牌里可能带着探针的登录 SID（第 2 节"独立桌面"）：成立的话系统金丝雀 `winsta0_denied` 不过、本机不接任务，直到换方案。
- 审计管道只认第一条就绪记录里的 pid（没用 `GetNamedPipeClientProcessId` 核对）；任务可以伪造自己子进程的记录，只影响取证，不影响边界。
- 钩子金丝雀的 multiprocessing 子进程启动时 `sys.path[0]` 是 `code\`（和真任务一样），任务包里的 `multiprocessing` 包能在那个子进程里跑起来：
  它在钩子之内，改不了父进程打出的金丝雀行（每项恰好一次、任何 fail 都拒），只是这几秒没接上整树杀。
