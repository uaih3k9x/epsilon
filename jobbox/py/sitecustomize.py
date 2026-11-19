"""Epsilon 批任务：环境层的审计钩子（PEP 578，能力 35）。见 docs/jobs-sandbox.md 第 5 节。

定位是绊线和取证，不是边界。边界是系统控制：专用账户、Low IL、NTFS ACL、作业对象、独立桌面、防火墙。
由 tools/build-env-layer.py 放进环境层的 Lib/site-packages/（@2 起）。

只在任务进程里装：令牌用户是 epsilon-job，或者探针设了 EPSILON_JOB_DIR。人手工跑层里的 python 不受影响。
装的过程中任何一步出错就 os._exit(97)，因为 site.py 只会打印一句 "Error in sitecustomize" 然后接着跑。
顺序：连审计管道 -> 降到 Low IL -> 删掉特权 -> addaudithook -> 写就绪记录。之后才轮到用户代码。

**钩子运行时不查任何能被任务改掉的东西**（审查 #17 第 1 条）：用户代码可以随手改模块全局（sys.modules['sitecustomize'].decide = ...）、
标准库函数（ntpath.normpath、os.write、json.dumps）、类属性（socket.socket.getsockname）和内建（builtins.isinstance），
这些都不触发审计事件。所以钩子路径上的函数：
  - 用到的一切在 import 时（用户代码之前）绑成**位置默认参数**：函数体里没有全局、内建查找，没有闭包（cell_contents 能改），
    也不用 __kwdefaults__（那是一个能改的字典）。改 __defaults__ / __code__ 有审计事件，钩子认得自己的函数，拦下；
  - 默认参数只放不可变的东西（frozenset、元组、只读映射、C 函数、内建类型）；
  - 不调任务的代码：参数按类型取底层数据（str 子类用 str.__str__ 复制，元组子类用 tuple.__getitem__），不调 __fspath__、__repr__、
    __eq__，pathlib 这类路径对象只计数（第二次调 __fspath__ 可以返回和系统调用用的不一样的路径）；
  - 钩子运行中跑到的任务代码（GC 在钩子里触发的 __del__）照样判，不跳过。钩子自己不触发审计事件，不会递归。
tools/test_sandbox_hook.py 的 test_hook_path_reads_no_globals_and_holds_nothing_mutable 逐个函数核对这几条。
剩下的路：gc.get_objects / get_referrers / get_referents、sys._current_frames 能摸到钩子的对象，逐条记录（第 8 节）。

策略（decide）是纯函数，在 Mac 上用 tools/test_sandbox_hook.py 测；路径一律按 Windows 规则比较。
"""

import _json
import _socket
import json
import ntpath
import os
import re
import sys
import threading
import time
import types
import weakref

EXIT_HOOK_FAILED = 97
PIPE = "\\\\.\\pipe\\epsilon-audit"
JOB_USER = "epsilon-job"
ARGS_MAX = 512
COUNT_KEEP = 50  # count 类事件每种原样记前 50 条，之后每 1000 次记一条累计数
COUNT_EVERY = 1000
INSTALLED = False

PROC_EVENTS = frozenset({"subprocess.Popen", "os.system", "os.startfile", "os.spawn", "os.exec",
                         "os.posix_spawn", "webbrowser.open"})
NET_EVENTS = frozenset({"socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind"})
DNS_EVENTS = frozenset({"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo"})
# 带路径的事件 → 哪几个参数是路径。都要拦 UNC：mkdir、rename、chdir 也会让内核以 System 身份发 SMB（带任务账户的 NTLM），
# 防火墙按 SID 管不到。os.stat / os.path.exists 没有审计事件，拦不住（docs/jobs-sandbox.md 第 8 节）。
PATH_ARGS = types.MappingProxyType({
    "open": (0,), "os.listdir": (0,), "os.scandir": (0,), "os.mkdir": (0,), "os.rename": (0, 1), "os.remove": (0,),
    "os.rmdir": (0,), "os.chdir": (0,), "os.chmod": (0,), "os.chown": (0,), "os.utime": (0,), "os.link": (0, 1),
    "os.symlink": (0, 1), "os.truncate": (0,), "os.add_dll_directory": (0,),
    "shutil.copyfile": (0, 1), "shutil.copymode": (0, 1), "shutil.copystat": (0, 1), "shutil.copytree": (0, 1),
    "shutil.move": (0, 1), "shutil.rmtree": (0,), "shutil.unpack_archive": (0, 1), "shutil.make_archive": (0, 2, 3),
    "tempfile.mkstemp": (0,), "tempfile.mkdtemp": (0,), "glob.glob": (0,), "glob.glob/2": (0, 2),
})
# 能凭空造出 .py / .pth 的（目标是第二个参数）：先写 x.txt 再改名绕过 open 的检查
DEST_EVENTS = frozenset({"os.rename", "os.link", "os.symlink", "shutil.copyfile", "shutil.move"})
REG_WRITE_EVENTS = frozenset({"winreg.CreateKey", "winreg.DeleteKey", "winreg.DeleteValue", "winreg.SetValue",
                              "winreg.SaveKey", "winreg.LoadKey", "winreg.ConnectRegistry",
                              "winreg.DisableReflectionKey", "winreg.EnableReflectionKey"})
COUNT_EVENTS = frozenset({"ctypes.call_function", "pickle.find_class", "marshal.loads"})
# 能摸到钩子的对象或正在跑的钩子帧（gc 枚举、别的线程的帧），以及跟踪函数：正常任务很少用，逐条记
LOG_EVENTS = frozenset({"sys.addaudithook", "cpython.run_command", "cpython.run_module", "cpython.run_file",
                        "cpython.run_interactivehook", "cpython.run_startup", "cpython.run_stdin",
                        "gc.get_objects", "gc.get_referrers", "gc.get_referents", "sys._current_frames",
                        "sys._current_exceptions", "sys.settrace", "sys.setprofile",
                        "sys.monitoring.register_callback"})   # 3.12+；作用同 settrace
CODE_SUFFIXES = (".py", ".pyc", ".pyw", ".pth")
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
PRIVATE_MKDIR = 0o700  # Python 3.12.4+ 在 Windows 上给它建受保护 DACL（只有 SY、BA、所有者）
SPAWN_FLAGS = frozenset({"-B", "-E", "-s"})
SPAWN_MAIN = re.compile(r"from multiprocessing\.spawn import spawn_main; spawn_main\(parent_pid=\d+, pipe_handle=\d+\)")
QUOTED_ARGS = re.compile(r'"[^"]*"(?: "[^"]*")*')
QUOTED_TOK = re.compile(r'"([^"]*)"')

BLOCK = ("block", None)
LOG = ("log", None)
OPAQUE = ("count", "path.opaque")
CATCH = (OSError, TypeError, ValueError, AttributeError, IndexError, RuntimeError)


# ---- 钩子路径上的函数：只用参数和默认参数（见模块说明）。默认参数在这里、用户代码之前求值 ----

def as_str(x, _type=type, _str=str, _bytes=bytes, _issub=issubclass, _copy=str.__str__, _decode=bytes.decode):
    """x 底层的字符串（和 C 的路径转换读到的一样），不调 x 的任何方法。不是 str/bytes（及子类）返回 None。
    os.DirEntry 也不认：它的类属性能改（__fspath__ 换掉以后 C 转换用新的，钩子用旧的就对不上）。"""
    t = _type(x)
    if t is _str:
        return x
    if t is _bytes or _issub(t, _bytes):
        return _decode(x, "utf-8", "replace")
    if _issub(t, _str):
        return _copy(x)
    return None


def isabs(p):
    """ntpath.isabs 的规则（含它的老毛病："\\x" 也算绝对路径）。p 是 str。"""
    q = p[:3].replace("/", "\\")
    return q.startswith("\\") or q[1:3] == ":\\"


def normpath(p):
    """ntpath.normpath 的规则：合并分隔符、去掉 . 和 ..；\\\\.\\ 和 \\\\?\\ 开头的原样返回。p 是 str。"""
    p = p.replace("/", "\\")
    if p.startswith("\\\\.\\") or p.startswith("\\\\?\\"):
        return p
    if p[1:2] == ":":
        prefix, p = p[:2], p[2:]
    elif p.startswith("\\\\"):  # UNC：\\server\share 算盘符
        i = p.find("\\", 2)
        j = p.find("\\", i + 1) if i >= 0 else -1
        if i < 0:
            prefix, p = p, ""
        elif j < 0:
            prefix, p = p, ""
        else:
            prefix, p = p[:j], p[j:]
    else:
        prefix = ""
    if p.startswith("\\"):
        prefix += "\\"
        p = p.lstrip("\\")
    out = []
    for c in p.split("\\"):
        if c == "" or c == ".":
            continue
        if c == "..":
            if out and out[-1] != "..":
                out.pop()
                continue
            if prefix.endswith("\\"):
                continue
        out.append(c)
    if not prefix and not out:
        return "."
    return prefix + "\\".join(out)


def norm(p, cwd=None, _as_str=as_str, _isabs=isabs, _normpath=normpath, _len=len):
    """Windows 规则的规范化：/ 换 \\、相对路径接上 cwd、去掉 \\\\?\\X: 前缀、小写。p 不是路径返回 None。"""
    p = _as_str(p)
    if p is None:
        return None
    p = p.replace("/", "\\")
    if p[:4] == "\\\\?\\" and _len(p) > 6 and p[5] == ":":
        p = p[4:]
    if cwd is not None and not _isabs(p) and p[1:2] != ":" and p[:2] != "\\\\":
        p = cwd.rstrip("\\") + "\\" + p
    return _normpath(p).lower()


def within(p, d):
    return p == d or p.startswith(d.rstrip("\\") + "\\")


def unc_or_device(p, _as_str=as_str, _len=len):
    """UNC（\\\\host\\share、\\\\?\\UNC\\）和设备路径（\\\\.\\）。命名管道 \\\\.\\pipe\\ 和 \\\\?\\X:\\ 长路径除外。"""
    s = _as_str(p)
    if s is None:
        return False
    s = s.replace("/", "\\").lower()
    if not s.startswith("\\\\"):
        return False
    if s.startswith("\\\\.\\pipe\\"):
        return False
    if s.startswith("\\\\?\\") and _len(s) > 6 and s[5] == ":" and s[4].isalpha():
        return False
    return True


def code_file(p, _suffixes=CODE_SUFFIXES):
    """规范化后的 p 打开的是不是代码文件。Windows 去掉最后一段末尾的点和空格，"x.py::$DATA" 是 x.py 的主数据流。"""
    name = p[p.rfind("\\") + 1:]
    i = name.find(":")
    if i >= 0:
        name = name[:i]
    return name.rstrip(". ").endswith(_suffixes)


def Ctx(job_dir, env_dir, executable, system_root, getcwd=os.getcwd, _norm=norm):
    """一次任务的路径，冻结成元组：(code\\, 环境层, 解释器, System32, getcwd, 本进程 bind 过的回环 socket)。
    cwd 默认现取（任务可以 chdir）。最后一项是 {id: weakref}，只有钩子帧摸得到，往里塞东西也冒充不了端口（见 own_port）。"""
    return (_norm(job_dir.rstrip("\\/") + "\\code"), _norm(env_dir), _norm(executable),
            _norm(system_root.rstrip("\\/") + "\\System32"), getcwd, {})


def trusted(p, ctx, _within=within):
    """p（已规范化）在 code\\ 或环境层里。"""
    return _within(p, ctx[0]) or _within(p, ctx[1])


def ctx_path(p, ctx, _norm=norm):
    return _norm(p, ctx[4]())


def sockaddr(a, _type=type, _tuple=tuple, _issub=issubclass, _len=tuple.__len__, _get=tuple.__getitem__,
             _int=int, _index=int.__index__, _as_str=as_str):
    """(host 小写, port) —— 和 C 的 getsockaddrarg 读到的一样（元组子类读底层元素，int 子类读底层值）；不是 (host, port, ...) 返回 None。
    port 不是 int 的返回 (host, None)：C 会调它的 __index__，钩子不调。"""
    if not _issub(_type(a), _tuple) or _len(a) < 2:
        return None
    host = _as_str(_get(a, 0))
    if host is None:
        return None
    port = _get(a, 1)
    port = _index(port) if _issub(_type(port), _int) else None
    return host.lower(), port


def note_bound(ctx, sock, _type=type, _S1=_socket.socket, _S2=__import__("socket").socket, _ref=weakref.ref,
               _id=id, _len=len, _list=list, _catch=CATCH):
    """socket.bind 到回环：记下这个 socket（只认标准库的 socket 类型，不是任务的子类）。
    类型一律用 is 比：放进集合里查要算类型的哈希，任务的元类可以重写 __hash__。"""
    t = _type(sock)
    if t is not _S1 and t is not _S2:
        return
    bound = ctx[5]
    try:
        if _len(bound) > 1024:
            for k, r in _list(bound.items()):
                if r() is None:
                    del bound[k]
        bound[_id(sock)] = _ref(sock)
    except _catch:
        pass


def own_port(ctx, port, _list=list, _fileno=_socket.socket.fileno, _name=_socket.socket.getsockname, _catch=CATCH):
    """port 是不是本进程自己 bind 的回环端口（socketpair、asyncio 的自连）。端口用 _socket 的 C 方法现查，
    socket.socket.getsockname 被换掉也骗不了；塞进来的假对象 C 方法不认（TypeError）。"""
    if port is None:
        return False
    try:
        refs = _list(ctx[5].values())
    except _catch:
        return False
    for r in refs:
        s = r()
        if s is None:
            continue
        try:
            if _fileno(s) != -1 and _name(s)[1] == port:
                return True
        except _catch:
            pass
    return False


def loopback_lookup(event, args, _len=len, _as_str=as_str, _sockaddr=sockaddr, _loop=LOOPBACK):
    if not _len(args):
        return False
    first = args[0]
    if event == "socket.getnameinfo":
        a = _sockaddr(first)
        return a is not None and a[0] in _loop
    if first is None and event == "socket.getaddrinfo":  # 只填端口（bind 通配地址）：不查 DNS
        return True
    s = _as_str(first)
    return s is not None and s.lower() in _loop


def spawn_ok(args, ctx, _len=len, _as_str=as_str, _norm=norm, _set=set, _flags=SPAWN_FLAGS, _main=SPAWN_MAIN,
             _quoted=QUOTED_ARGS, _tok=QUOTED_TOK):
    """_winapi.CreateProcess 只放行 multiprocessing spawn 的那一种：本层 python.exe，参数一个字不差，不指定工作目录。
    多出 -S、-I 之类就能起一个没有钩子的子进程，所以别的一律拒。审计参数不含环境块：子进程的 EPSILON_JOB_DIR 由探针核对就绪记录。"""
    if _len(args) < 3 or args[2] is not None:
        return False
    app, cmd = _as_str(args[0]), _as_str(args[1])
    if app is None or cmd is None or _norm(app) != ctx[2] or _quoted.fullmatch(cmd) is None:
        return False
    toks = _tok.findall(cmd)
    if _len(toks) != 7 or _norm(toks[0]) != ctx[2]:
        return False
    return (_set(toks[1:4]) == _flags and toks[4] == "-c" and _main.fullmatch(toks[5]) is not None
            and toks[6] == "--multiprocessing-fork")


def code_origin(filename, ctx, _as_str=as_str, _isabs=isabs, _norm=norm, _trusted=trusted):
    """compile / exec 的来源：import（code\\、环境层、预编译时去掉前缀的相对路径、冻结模块）还是动态执行。"""
    filename = _as_str(filename)
    if filename is None:
        return "dynamic"
    if filename.startswith("<frozen "):
        return "import"
    if filename.startswith("<"):
        return "dynamic"
    if not _isabs(filename) and filename[1:2] != ":":
        return "import"  # 层内 pyc 用 compileall -s/-p 编译，co_filename 是 Lib/site-packages/...
    return "import" if _trusted(_norm(filename), ctx) else "dynamic"


def decide(event, args, ctx, _len=len, _type=type, _int=int, _NoneType=type(None), _bool=bool, _list=list, _tuple=tuple,
           _Code=types.CodeType, _as_str=as_str, _isabs=isabs, _norm=norm, _within=within, _unc=unc_or_device, _code_file=code_file,
           _trusted=trusted, _path=ctx_path, _sockaddr=sockaddr, _note=note_bound, _own=own_port, _lookup=loopback_lookup,
           _spawn_ok=spawn_ok, _origin=code_origin, _PROC=PROC_EVENTS, _NET=NET_EVENTS, _DNS=DNS_EVENTS,
           _PATHS=PATH_ARGS, _DEST=DEST_EVENTS, _REG=REG_WRITE_EVENTS, _COUNT=COUNT_EVENTS, _LOGS=LOG_EVENTS,
           _LOOP=LOOPBACK, _M700=PRIVATE_MKDIR, _BLOCK=BLOCK, _LOG=LOG, _OPAQUE=OPAQUE):
    """返回 None（不管）、("block", _)、("log", _) 或 ("count", 计数用的名字)。"""
    if event in _PROC:
        return _BLOCK
    if event == "_winapi.CreateProcess":
        return None if _spawn_ok(args, ctx) else _BLOCK
    if event == "socket.bind":
        a = _sockaddr(args[1]) if _len(args) > 1 else None
        if a is not None and a[0] in _LOOP:
            _note(ctx, args[0])
            return None
        return _BLOCK
    if event in _NET:
        # 回环不过防火墙（本机 epsilon-boot、p2p、推理、rpc 都在听）：只许连本进程自己 bind 的端口
        a = _sockaddr(args[1]) if _len(args) > 1 else None
        if a is not None and a[0] in _LOOP and _own(ctx, a[1]):
            return None
        return _BLOCK
    if event in _DNS:
        return None if _lookup(event, args) else _BLOCK
    idx = _PATHS.get(event)
    if idx is not None:
        opaque = False
        for i in idx:
            if i < _len(args):
                x = args[i]
                if _as_str(x) is not None:
                    if _unc(x):
                        return _BLOCK
                elif _type(x) is not _int and _type(x) is not _bool and x is not None:
                    opaque = True  # pathlib 之类：不调它的 __fspath__（fd、None 是当前目录，不管）
        if event == "open" and _len(args) and _as_str(args[0]) is not None:
            p = _path(args[0], ctx)
            if _code_file(p) and not _trusted(p, ctx):
                return _BLOCK  # 写 .py 再导入、在别处埋 .pth
        if event in _DEST and _len(args) > 1 and _as_str(args[1]) is not None:
            p = _path(args[1], ctx)
            if _code_file(p) and not _trusted(p, ctx):
                return _BLOCK
        if event == "os.mkdir" and _len(args) > 1 and _type(args[1]) is _int and args[1] == _M700:
            return ("count", "os.mkdir.0o700")
        return _OPAQUE if opaque else None
    if event == "import":
        path = args[2] if _len(args) > 2 else None
        if path:
            if _type(path) is not _list and _type(path) is not _tuple:
                return _BLOCK
            for entry in path:
                s = _as_str(entry)
                if s is None or _unc(s) or not _trusted(_path(s, ctx), ctx):
                    return _BLOCK
        fn = _as_str(args[1]) if _len(args) > 1 else None
        if fn is not None and _isabs(fn) and not _trusted(_norm(fn), ctx):
            return _BLOCK
        return None
    if event == "ctypes.dlopen":
        name = _as_str(args[0]) if _len(args) else None
        if name is not None and ("\\" in name or "/" in name):
            p = _path(name, ctx)
            if _unc(name) or not (_within(p, ctx[1]) or _within(p, ctx[3])):
                return _BLOCK
        return _LOG
    if event in _COUNT:
        return ("count", event)
    if event == "compile":
        if _origin(args[1] if _len(args) > 1 else None, ctx) == "import":
            return ("count", "compile.import")
        return _LOG
    if event == "exec":
        fn = args[0].co_filename if _len(args) and _type(args[0]) is _Code else None
        if _origin(fn, ctx) == "import":
            return ("count", "exec.import")
        return _LOG
    if event in _REG:
        return _BLOCK
    if event == "os.putenv" or event == "os.unsetenv":
        key = _as_str(args[0]) if _len(args) else None
        # 改 EPSILON_JOB_DIR 再起 multiprocessing 子进程，子进程的钩子就按别的目录判了
        if key is not None and key.upper().startswith("EPSILON_"):
            return _BLOCK
        return None
    if event in _LOGS:
        return _LOG
    return None


def one_repr(x, _type=type, _str=str, _bytes=bytes, _repr=repr, _int=int, _float=float, _bool=bool, _None=type(None),
             _as_str=as_str,
             _obj_repr=object.__repr__, _type_repr=type.__repr__, _issub=issubclass, _catch=CATCH):
    """一个参数的简短表示：内建类型原样（截断），别的只写类型和地址（不调任务的 __repr__）。"""
    t = _type(x)
    if t is _str or t is _bytes:
        return _repr(x[:200])
    if t is _int or t is _float or t is _bool or t is _None:
        try:
            return _repr(x)
        except _catch:  # 超长的 int
            return "<int>"
    s = _as_str(x)
    if s is not None:
        return _repr(s[:200])
    if _issub(t, _type):
        return _type_repr(x)  # 类：<class 'x.Y'>（C 实现，不调元类的方法）
    return _obj_repr(x)


def short_args(event, args, _len=len, _type=type, _tuple=tuple, _list=list, _bytes=bytes, _bytearray=bytearray,
               _Code=types.CodeType, _one=one_repr, _max=ARGS_MAX):
    if event == "compile":
        return _one(args[1] if _len(args) > 1 else None)
    if event == "exec":
        return _one(args[0].co_filename if _len(args) and _type(args[0]) is _Code else None)
    if event == "marshal.loads":
        t = _type(args[0]) if _len(args) else None
        return "len=%d" % (_len(args[0]) if t is _bytes or t is _bytearray else -1)
    parts = []
    for x in args[:8]:
        t = _type(x)
        if t is _tuple or t is _list:
            inner = []
            for y in x[:8]:
                inner.append(_one(y))
            parts.append(("(%s)" if t is _tuple else "[%s]") % ", ".join(inner))
        else:
            parts.append(_one(x))
    s = "(" + ", ".join(parts) + ")"
    return s.encode("ascii", "backslashreplace").decode("ascii")[:_max]


def record(event, act, args, n=None, _now=time.time, _pid=os.getpid, _enc=_json.encode_basestring_ascii, _repr=repr,
           _round=round, _short=short_args):
    """一条审计记录（一行 JSON，ASCII）。不用 json 模块：json.dumps 能被换掉。"""
    s = ('{"t":' + _repr(_round(_now(), 3)) + ',"pid":' + _repr(_pid()) + ',"ev":' + _enc(event) + ',"act":' + _enc(act)
         + ',"args":' + _enc(_short(event, args)))
    if n is not None:
        s += ',"n":' + _repr(n)
    return (s + "}\n").encode("ascii")


def ready_record(job_dir, rid, privs, now=time.time, pid=os.getpid, ppid=os.getppid):
    """就绪记录（装钩子时、用户代码之前写）。job_dir 是这个进程拿到的 EPSILON_JOB_DIR：探针核对，和任务目录不一致就当篡改（整树杀）。
    il、privs 是降级、删特权之后的令牌：探针也核对（审查 #17 第 2 条：层里的 sitecustomize 写错了，金丝雀测得出来）。"""
    r = {"t": round(now(), 3), "ev": "ready", "pid": pid(), "ppid": ppid(), "il": "low" if rid <= 0x1000 else hex(rid),
         "privs": list(privs), "job_dir": job_dir, "file": __file__, "layer": sys.prefix}
    return (json.dumps(r, ensure_ascii=True) + "\n").encode("ascii")


def _ours(roots, _FunctionType=types.FunctionType):
    """roots 和它们默认参数里（递归）的函数：钩子认得它们，改 __code__ / __defaults__ 就拦。只在装钩子时用。"""
    seen, todo = {}, list(roots)
    while todo:
        f = todo.pop()
        if type(f) is _FunctionType and id(f) not in seen:
            seen[id(f)] = f
            todo.extend(f.__defaults__ or ())
    return frozenset(seen)


def make_hook(ctx, write):
    """write(bytes) 一次写完一条；写不出去由 write 自己 os._exit。ctx 是 Ctx(...) 的元组。"""
    ours = _ours([decide, record, write])

    def hook(event, args, _ctx=ctx, _write=write, _counts={}, _decide=decide, _record=record, _ours=ours, _id=id,
             _len=len, _Err=PermissionError, _keep=COUNT_KEEP, _every=COUNT_EVERY, _BLOCK=BLOCK):
        if event == "object.__setattr__" and _len(args) and _id(args[0]) in _ours:
            verdict = _BLOCK
        else:
            verdict = _decide(event, args, _ctx)
        if verdict is None:
            return
        act, key = verdict
        if act == "count":
            n = _counts.get(key, 0) + 1
            _counts[key] = n
            if n <= _keep or n % _every == 0:
                _write(_record(key, "count", args, n))
            return
        _write(_record(event, act, args))
        if act == "block":
            raise _Err("epsilon 沙箱拦截: %s" % event)

    return hook


# ---- winsec begin（canary_sys.py 里有一份一模一样的，jobbox 的测试核对）----
def _winsec():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.GetLengthSid.restype = wintypes.DWORD
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    adv.LookupPrivilegeNameW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.c_void_p]
    return ctypes, wintypes, k32, adv


def _token_il(ctypes, wintypes, adv, token):
    need = wintypes.DWORD()
    adv.GetTokenInformation(token, 25, None, 0, ctypes.byref(need))  # TokenIntegrityLevel
    buf = ctypes.create_string_buffer(need.value)
    if not adv.GetTokenInformation(token, 25, buf, need, ctypes.byref(need)):
        raise ctypes.WinError(ctypes.get_last_error())
    sid = ctypes.c_void_p.from_buffer(buf).value  # TOKEN_MANDATORY_LABEL.Label.Sid
    n = adv.GetSidSubAuthorityCount(sid).contents.value
    return adv.GetSidSubAuthority(sid, n - 1).contents.value


def lower_integrity():
    """把自己进程令牌的完整性级别降到 Low（进程可以降低自己的；之后起的子进程都继承）。返回降完后的 RID。"""
    ctypes, wintypes, k32, adv = _winsec()
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008 | 0x0080, ctypes.byref(token)):  # QUERY | ADJUST_DEFAULT
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sid = ctypes.c_void_p()
        if not adv.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            class SidAndAttributes(ctypes.Structure):
                _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

            label = SidAndAttributes(sid.value, 0x20)  # SE_GROUP_INTEGRITY
            size = ctypes.sizeof(label) + adv.GetLengthSid(sid)
            if not adv.SetTokenInformation(token, 25, ctypes.byref(label), size):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            k32.LocalFree(sid)
        rid = _token_il(ctypes, wintypes, adv, token)
    finally:
        k32.CloseHandle(token)
    if rid > 0x1000:
        raise RuntimeError("完整性级别没降下来: 0x%x" % rid)
    return rid


KEEP_PRIVILEGE = "SeChangeNotifyPrivilege"  # 绕过遍历检查：没有它连自己的任务目录都走不进去


def drop_privileges():
    """删掉自己令牌里除 SeChangeNotifyPrivilege 以外的特权（SE_PRIVILEGE_REMOVED，删了就回不来，子进程继承）。
    工作站上 Users 有 SeShutdownPrivilege：不删的话任务能用 InitiateShutdownW 重启教室机。返回剩下的特权名。"""
    ctypes, wintypes, k32, adv = _winsec()

    class Luid(ctypes.Structure):
        _fields_ = [("Low", wintypes.DWORD), ("High", wintypes.LONG)]

    class LuidAndAttributes(ctypes.Structure):
        _fields_ = [("Luid", Luid), ("Attributes", wintypes.DWORD)]

    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008 | 0x0020, ctypes.byref(token)):  # QUERY | ADJUST_PRIVILEGES
        raise ctypes.WinError(ctypes.get_last_error())

    def privileges():
        need = wintypes.DWORD()
        adv.GetTokenInformation(token, 3, None, 0, ctypes.byref(need))  # TokenPrivileges
        buf = ctypes.create_string_buffer(max(need.value, 4))
        if not adv.GetTokenInformation(token, 3, buf, len(buf), ctypes.byref(need)):
            raise ctypes.WinError(ctypes.get_last_error())
        n = wintypes.DWORD.from_buffer(buf).value
        out = []
        for la in (LuidAndAttributes * n).from_buffer(buf, ctypes.sizeof(wintypes.DWORD)):
            name = ctypes.create_unicode_buffer(64)
            size = wintypes.DWORD(len(name))
            if not adv.LookupPrivilegeNameW(None, ctypes.byref(la.Luid), name, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            out.append((name.value, Luid(la.Luid.Low, la.Luid.High)))
        return out

    try:
        drop = [luid for name, luid in privileges() if name != KEEP_PRIVILEGE]
        if drop:
            class TokenPrivileges(ctypes.Structure):
                _fields_ = [("Count", wintypes.DWORD), ("Privileges", LuidAndAttributes * len(drop))]

            tp = TokenPrivileges(len(drop))
            for i, luid in enumerate(drop):
                tp.Privileges[i] = LuidAndAttributes(luid, 0x4)  # SE_PRIVILEGE_REMOVED
            ctypes.set_last_error(0)
            if not adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None) or ctypes.get_last_error():
                raise ctypes.WinError(ctypes.get_last_error() or 1300)  # ERROR_NOT_ALL_ASSIGNED
        left = sorted(name for name, _ in privileges())
    finally:
        k32.CloseHandle(token)
    if [n for n in left if n != KEEP_PRIVILEGE]:
        raise RuntimeError("特权没删干净: %s" % left)
    return left
# ---- winsec end ----


def _token_user():
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    buf = ctypes.create_unicode_buffer(257)
    n = wintypes.DWORD(len(buf))
    if not adv.GetUserNameW(buf, ctypes.byref(n)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.value


def _open_pipe():
    """连探针的审计管道，只要 FILE_WRITE_DATA（管道的 DACL 不给任务账户建新实例的权限，GENERIC_WRITE 会被拒）。"""
    import ctypes
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                wintypes.DWORD, wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    invalid = wintypes.HANDLE(-1).value
    deadline = time.monotonic() + 10
    while True:
        h = k32.CreateFileW(PIPE, 0x2, 0, None, 3, 0, None)  # FILE_WRITE_DATA, OPEN_EXISTING
        if h and h != invalid:
            return msvcrt.open_osfhandle(h, os.O_WRONLY | os.O_BINARY)
        err = ctypes.get_last_error()
        if err != 231 or time.monotonic() > deadline:  # ERROR_PIPE_BUSY：探针正在建下一个实例
            raise ctypes.WinError(err)
        k32.WaitNamedPipeW(PIPE, 1000)


def _writer(fd, _w=os.write, _x=os._exit, _RLock=threading.RLock, _c=EXIT_HOOK_FAILED, _B=BaseException):
    """write(bytes)：一次写完一条。依赖都绑成默认参数（os.write 被换掉也照样写管道）。
    RLock：钩子运行中触发的终结器也会写记录（同一个线程）；不可重入的锁会死锁。"""
    lock = _RLock()

    def write(b, _fd=fd, _lock=lock, _write=_w, _exit=_x, _code=_c, _Base=_B):
        try:
            with _lock:
                while b:
                    b = b[_write(_fd, b):]
        except _Base:
            _exit(_code)  # 管道断了：探针那边已经当篡改处理，这边不能没有记录地接着跑

    return write


def _should_install():
    if sys.platform != "win32":
        return False
    if os.environ.get("EPSILON_JOB_DIR"):
        return True
    return _token_user().lower() == JOB_USER


def _install():
    global INSTALLED
    fd = _open_pipe()
    rid = lower_integrity()
    privs = drop_privileges()
    job_dir = os.environ["EPSILON_JOB_DIR"]
    ctx = Ctx(job_dir, ntpath.dirname(sys.executable), sys.executable, os.environ.get("SystemRoot", "C:\\Windows"))
    write = _writer(fd)
    sys.addaudithook(make_hook(ctx, write))
    INSTALLED = True
    write(ready_record(job_dir, rid, privs))


def _main():
    try:
        if _should_install():
            _install()
    except BaseException:
        os._exit(EXIT_HOOK_FAILED)


_main()
