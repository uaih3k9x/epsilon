# 任务包静态审核 `epsilon-review`（issue #3）

签名的意义是“审核人读过这段代码”。`tools/epsilon-review.py` 在签名前把审核人可能漏看的地方按语法树列出来：二进制、会执行代码的序列化格式、动态执行和动态拼接。

它**不是沙箱，也不做最终裁决**。它只负责把可疑点一个不漏地指出来，签不签由审核人决定。运行时另有兜底：低权限账户、写执行分离、出站防火墙、审计钩子。

```sh
python3 -I tools/epsilon-review.py <任务包目录|code.zip> [--job job.json] [--json] [--strict]
```

- 需要 Python 3.9 及以上，只用标准库。被审的代码只做 `ast.parse`，**不 import、不执行**。用 `-I` 跑，免得任务包目录里的同名模块被导入。
- 输入有三种：
  - 任务包目录：里面有 `job.json`，加上 `code.zip` 或 `code/`。两个都有时扫 `code.zip`，因为签名针对的是它。
  - 单独的 `code.zip`：可以用 `--job` 带上 `job.json`。
  - 一个代码目录：没有 `job.json`，就不做 job 检查。
- 只做单文件内的局部模式匹配，不做跨文件数据流。拿不准的一律报“需解释”。

## 级别和退出码

分级以 issue #3 里 2026-11-01 的调整为准。原则是信任提交人：针对提交人的规则放宽，防主控、防钥匙泄露、防供应链的不放宽。

| 级别 | JSON 里的值 | 含义 |
|---|---|---|
| 拒签 | `reject` | 审核人读不到的代码：二进制、pickle 系、写 `.py` 再导入、审计钩子。按规矩直接退回 |
| 需解释 | `explain` | 审核人要在送审单里找到解释，当场判断 |
| 提示 | `info` | 不算违规，审核人可能想知道 |
| 工具出错 | `error` | 没扫完：zip 坏了、语法错误、解压超限等等。结果不能作为签名依据 |

| 退出码 | 条件 |
|---|---|
| 0 | 没有发现，或者只有提示 |
| 1 | 有需解释，没有拒签 |
| 2 | 有拒签；或者带了 `--strict`，且有需解释 |
| 3 | 工具出错（优先于其他结论），包括命令行参数错误 |

工具出错的优先级最高：只要没扫完，就不能说“没发现拒签”。

## 规则

规则名是稳定的，以后做豁免表就靠它们。规则或级别一有改动，`RULES_VERSION` 就加 1。

### 文件层和 zip 层

| 规则 | 级别 | 抓什么 |
|---|---|---|
| `file-type` | 拒签 | 白名单以外的扩展名。白名单是 `.py .json .yaml .yml .toml .txt .md .csv .jinja .j2` |
| `file-magic` | 拒签 | 按文件头判断真实类型，扩展名再正常也拒：<br>可执行文件和字节码：PE（`MZ`）、ELF、Mach-O（`feedface` `feedfacf` `cafebabe` 及反序）、wasm、`.pyc`；<br>压缩包：zip、gzip、bz2、xz、zstd、7z、rar、tar（偏移 257 处的 `ustar`）；<br>序列化数据：`.npy`、pickle 协议 2–5。<br>zip 里套的压缩包也由这条抓 |
| `bad-path` | 拒签 | 路径有问题：`..`、绝对路径、盘符、冒号（NTFS 备用流）、反斜杠、控制字符、零宽或双向控制符、Windows 保留名（含 `COM¹` `LPT²` 这类）、结尾是点或空格、超过 120 字符、只差大小写或 Unicode 写法（先 NFC 再 casefold 比较）；还有符号链接（包括 `code/`、`code.zip` 本身）、非普通文件、zip 里的重名条目、非 ASCII 文件名没标 UTF-8 的 zip 条目、扫描过程中被换掉的文件 |
| `zip-encrypted` | 拒签 | zip 里有加密条目 |
| `zip-too-big` / `too-big` | 工具出错 | 解压后总大小超过 256 MiB，或者条目超过 1 万个（防 zip 炸弹）。按 zip 头声明的大小先查一遍，读的时候再按实际读到的字节数查一遍 |
| `zip-corrupt` / `empty` / `no-input` | 工具出错 | zip 损坏、空包、路径不存在 |
| `internal-error` | 工具出错 | 工具自己的 bug，兜底用。出现了请报告 |
| `big-text` | 需解释 | 单个文本文件超过 1 MB |
| `encoding` | 需解释 | 文本不是 UTF-8，或者含 NUL 字节 |
| `junk` | 提示 | `__pycache__`、`.git`、`.DS_Store`、`__MACOSX` 等打包残留。只是多一条提示，**内容照常检查**：`__MACOSX` 是合法标识符，里面的 `.py` 能被 `import __MACOSX.x` 导入；残留目录里的二进制照样被 `file-type` / `file-magic` 拒 |

### 代码层（`ast` 逐个解析 `.py`）

做别名跟踪，下面这些写法都认得出：

- `import x as y`、`from builtins import eval as e`、`e = eval`、`(eval)`；
- `__builtins__.exec`、`__builtins__["exec"]`、`getattr(os, "system")`；
- `__import__("socket")`、`importlib.import_module("pickle")`；
- `nt.system`、`posix.system`，这两个都按 `os.system` 算。

别名跟踪不分流程：一个名字只要在文件里任何地方可能指向危险函数，就照危险函数算；内置函数被重新赋值也照样认。

| 规则 | 级别 | 抓什么 |
|---|---|---|
| `pickle-use` | 拒签 | 导入 `pickle` `_pickle` `cPickle` `cloudpickle` `dill` `joblib` `shelve` `marshal` `multiprocessing.reduction`；引用 `ForkingPickler`；调用 `pandas.read_pickle`、`.to_pickle()` / `.read_pickle()`。`torch.save` 只到需解释 |
| `unsafe-load` | 拒签 / 需解释 | 拒签：不带字面量 `weights_only=True` 的 `torch.load`；任何调用里的 `allow_pickle=True`（`np.load`、`np.lib.format.read_array` 等）；`Loader` 不是 Safe/Base 的 `yaml.load`；`yaml.unsafe_load`；`functools.partial` 里预先绑定了上面这些危险参数。<br>需解释：参数看不出是什么（`**kw`、变量）；`yaml.full_load`；这几个函数没被直接调用，而是赋给变量、放进容器、传给别的函数（工具查不了调用时的参数） |
| `write-then-import` | 拒签 / 需解释 | 同一个文件里，既写了 `.py` / `.pth` 文件（`open`、`io.FileIO`、`os.open`、`Path.write_text`、`shutil.copy` 等），又有动态导入（`importlib`、`runpy`、`__import__`、`imp`、`zipimport`、`pkgutil`、`pydoc.locate`）、改了 `sys.path`，或者静态 `import` 了和写出的文件同名的模块，就拒签。只写 `.py`、没看到导入的，需解释 |
| `load-source` | 拒签 / 需解释 | 按路径加载代码：`runpy.run_path`、`imp.load_source` / `load_module` / `load_compiled`、`importlib.machinery.SourceFileLoader` / `SourcelessFileLoader`、`importlib.util.spec_from_file_location`、`zipimport.zipimporter`。路径是字面量但不是 `.py`，或者加载的是字节码，拒签（工具没按代码扫过它）；其余需解释 |
| `audit-hook` | 拒签 | `sys.addaudithook`：平台用审计钩子做运行时兜底，任务代码不该碰 |
| `source-encoding` | 拒签 | 前两行声明了非 UTF-8 的源码编码（如 `# coding: utf-7`）。解释器按声明的编码解码，审核人看到的就不是同一份代码。“前两行”按解释器的规则数：直接运行时 `\r` `\n` 都算换行，`import` 时只认 `\n`，两种都查；`\x0c` `\x85` 这类字符不算换行。解析时把原始字节交给 `ast.parse`，解码方式和解释器一致 |
| `exec-call` | 需解释 | `eval` `exec` `compile` 的任何引用，`types.CodeType` / `FunctionType`，`timeit` `cProfile` `profile` `pdb` 的字符串执行，`pandas.eval`，导入 `code` / `codeop`。`model.eval()`、`re.compile` 不算 |
| `process-call` | 需解释 | 导入 `subprocess` `pty` 等；`os.system` `popen` `exec*` `spawn*` `startfile` `posix_spawn` `fork`、`asyncio.create_subprocess_*`；对动态导入的模块调 `.system` 之类；接收者认不出来（比如模块经函数参数传进来）时取 `.system` `.popen` `.Popen` `.check_output` `exec*` `spawn*` `fork` 这类属性，`getattr(m, "system")` 也算。`.run` `.call` 太常见，不算。`multiprocessing` 只到提示 |
| `native-api` | 需解释 | `ctypes` `cffi` `winreg` `win32*` `_winapi` `msvcrt` 等，`os.add_dll_directory` |
| `network` | 需解释 | `socket` `requests` `urllib`（`urllib.parse` 除外）`http.client` `ftplib` `smtplib` `paramiko` `aiohttp` `httpx` 等 |
| `reflect-nonliteral` | 需解释 | `getattr` `setattr` `delattr` `hasattr` `__import__` `importlib.import_module` `importlib.util.*` `runpy.*` `pkgutil.resolve_name` `pydoc.locate` 的名字参数不是字符串字面量；`operator.attrgetter` / `methodcaller`；从 `sys.modules` 按变量名取模块（`sys.modules[name]`、`sys.modules.get(...)`；`sys.modules["os"]` 认得出，按 `os` 算）；`logging.config.dictConfig` / `fileConfig` / `listen` 和 Hydra 的 `instantiate` / `call`，它们按配置里写的名字导入并调用对象 |
| `reflect-literal` | 提示 | 同上，但名字是字面量（能直接写就直接写）。字面量是内部属性的，另报 `dunder-access` |
| `namespace-access` | 需解释 | `globals()` `locals()` `vars()` 被下标访问、取属性或传给别的函数 |
| `dunder-access` | 需解释 | `__builtins__` `__dict__` `__code__` `__globals__` `__subclasses__` `__reduce__` `__reduce_ex__` `__getattribute__` `__mro__` `__bases__` `__base__` `__closure__`，以及定义 `__reduce__` |
| `import-machinery` | 需解释 | 改 `sys.path` `sys.modules` `sys.meta_path` `sys.path_hooks`，`site.addsitedir`，改 `PATH` `PYTHONPATH` `LD_PRELOAD` 一类环境变量（变量名看不出来的也算），改写内置函数 |
| `string-decode` | 需解释 | `base64.*decode` `binascii` `codecs.decode` `bytes.fromhex`，`zlib` `lzma` `bz2` `gzip` 解压，`.decode("rot13")` 这类编码，连续 8 个以上 `chr()` 拼接，`"".join(chr ...)`，用整数列表拼字节串 |
| `suspicious-literal` | 需解释 | 字符串长度超过 200；长度 ≥ 64 的 ASCII 串或字节串、熵 > 4.5 比特/字符；100 字符以上的十六进制 / base64 形状。docstring 不算 |
| `download` | 需解释 / 提示 | `from_pretrained` `load_dataset` `snapshot_download` `hf_hub_download` 等：看不出是本地路径就需解释，是本地路径（`DATA / "x"`、`./x`）或 `local_files_only=True` 就提示；`torch.hub.load` 会执行 `hubconf.py`，一律需解释；`download=True`、`trust_remote_code` 需解释 |
| `write-outside` | 需解释 / 提示 | 以写模式打开常量路径，而且明显在任务目录以外（`C:\`、`/`、`~`、`%TEMP%`、`AppData`）；`tempfile.*` 没给 `dir`。`expanduser` / `Path.home()` 只到提示 |
| `star-import` | 需解释 / 提示 | `from os import *` 这类：后面的名字认不出来源。从 `os` `sys` `subprocess` 等危险模块星号导入，需解释；从其他模块，提示 |
| `parse-error` | 工具出错 | 语法错误（包括 Python 2 代码）、源码不是 UTF-8、嵌套太深 |

### `job.json`（有就查，只查和代码有关的交集）

完整的 schema 校验**以 `jobsign.checkJob` 为准**（`epsilon-release sign-job` 会跑），这里不再写一份，免得两边走样。

| 规则 | 级别 | 抓什么 |
|---|---|---|
| `job-schema` | 拒签 | 解析不了、带 BOM、顶层不是对象、缺必填字段或写 `null`，`params` 不是对象 |
| `job-entry` | 拒签 | `entry[0]` 不是 `python` / `python3`；脚本不是 `code/` 下的相对 `.py`；脚本不在代码包里，或者在 `__MACOSX` 这类打包残留目录里；出现 `-c` / `-m` |
| `job-sha` | 拒签 / 提示 | `code_sha256` 和 `code.zip` 不一致就拒签；扫的是 `code/` 目录、没有 zip 可核对时，提示。库调用 `scan_files(files, job, zip_sha=...)` 时传了 `zip_sha` 就照样核对 |
| `param-unconstrained` | 需解释 | 字符串参数没有 `enum`，数值参数缺 `min` 或 `max`，或者用的是不带约束的简写 |
| `param-undeclared` | 需解释 | 代码里用字面量读了 `params` 里没声明的参数（`P["x"]`、`P.get("x")`，`P` 是 `json.load` 的结果；认得出哪个是 `params.json` 时只看那个） |

## JSON 契约（`--json`）

```json
{
  "tool_version": "0.1.0",
  "rules_version": 1,
  "package": "<命令行给的路径>",
  "name": "cifar10-hpsearch", "version": "1.0.0",
  "files": 12,
  "sha256": "<同 code_sha256>",
  "code_sha256": "<被扫的 code.zip 的 SHA-256；扫目录时为 null>",
  "verdict": "pass | info | explain | reject | error",
  "counts": {"reject": 0, "explain": 2, "info": 3, "error": 0},
  "strict": false,
  "exit_code": 1,
  "findings": [
    {"level": "explain", "rule": "reflect-nonliteral", "file": "train.py", "line": 41, "col": 5,
     "snippet": "getattr(models, cfg_name)()", "message": "...", "hint": "..."}
  ]
}
```

- `findings` 按级别从高到低排，再按文件、行排。`line` 和 `col` 从 1 开始；文件级的发现，这两个字段是 0。
- `sha256` 是 issue 里原来就有的字段，保留着，值和 `code_sha256` 相同。
- `exit_code` 和进程退出码一致，算的时候已经考虑了 `--strict`。
- 字段只增不改。

文字报告（不带 `--json`）里，文件名、代码片段、说明中的控制字符、零宽和双向控制符会转义成 `\x1b`、`\u202e` 这样的形式再输出，免得被审代码里藏的终端转义序列改写审核人看到的结论。JSON 里的字符串按 JSON 规则转义。

## sign-job 以后怎么接（只写设计，这次不实现）

1. `epsilon-release sign-job` 签名前用 `python3 -I tools/epsilon-review.py <code.zip> --job <job.json> --json` 跑一遍本工具，读 stdout 的 JSON。
2. 先核对 `report.code_sha256 == job.code_sha256`。不一致就说明扫的不是要签的那个包，拒绝签名。
3. `report.exit_code == 3`，或者 `counts.error > 0`：工具没扫完，拒绝签名。
4. 有拒签（`counts.reject > 0`）：拒绝签名。
5. 有需解释（`counts.explain > 0`）：要求审核人显式加 `-ack-review` 才签。审核人用这个参数表示“每一条都在送审单里找到了解释”。
6. 签名记录里带上 `tool_version`、`rules_version`，以及是否用了 `-ack-review`。以后规则升级了，能查出哪些包是按旧规则审过的。

## 已知限制

- 只做单文件局部匹配：数据跨文件流动（A 文件拼出名字，B 文件用）抓不到，靠审核人读代码。比如 A 文件写出 `gen.py`、B 文件 `import gen`，只在 A 报“写了 .py”需解释。
- 不知道环境层里装了哪些依赖，所以“导入了包里没有、标准库里也没有的模块”不报。
- 协议 0 / 1 的 pickle 是文本形状，没有魔数可抓。不过要加载它就得用 pickle，`pickle-use` 会拒。
- 按运行工具的那个 Python 的语法解析。用 3.9 跑工具，审 3.10 以后的语法（`match`）会报 `parse-error`，换新一点的 Python 跑就行。
- 不是沙箱：纯 Python 写的恶意逻辑（比如直接删 `output\` 以外的文件）只能靠审核人读，以及运行时的低权限账户兜底。
