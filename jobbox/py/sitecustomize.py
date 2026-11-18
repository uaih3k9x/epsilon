"""Epsilon 批任务：环境层的审计钩子（PEP 578，能力 35）。见 docs/jobs-sandbox.md 第 5 节。

定位是绊线和取证，不是边界。边界是系统控制：专用账户、Low IL、NTFS ACL、作业对象、独立桌面、防火墙。
由 tools/build-env-layer.py 放进环境层的 Lib/site-packages/（@2 起）。

只在任务进程里装：令牌用户是 epsilon-job，或者探针设了 EPSILON_JOB_DIR。人手工跑层里的 python 不受影响。
装的过程中任何一步出错就 os._exit(97)，因为 site.py 只会打印一句 "Error in sitecustomize" 然后接着跑。
顺序：连审计管道 -> 降到 Low IL -> addaudithook -> 写就绪记录。之后才轮到用户代码。

策略（decide）是纯函数，在 Mac 上用 tools/test_sandbox_hook.py 测；路径一律按 Windows 规则（ntpath）比较。
"""

import json
import ntpath
import os
import re
import reprlib
import sys
import threading
import time

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
PATH_EVENTS = frozenset({"open", "os.listdir", "os.scandir"})
REG_WRITE_EVENTS = frozenset({"winreg.CreateKey", "winreg.DeleteKey", "winreg.DeleteValue", "winreg.SetValue",
                              "winreg.SaveKey", "winreg.LoadKey", "winreg.ConnectRegistry",
                              "winreg.DisableReflectionKey", "winreg.EnableReflectionKey"})
COUNT_EVENTS = frozenset({"ctypes.call_function", "pickle.find_class", "marshal.loads"})
LOG_EVENTS = frozenset({"sys.addaudithook", "cpython.run_command", "cpython.run_module", "cpython.run_file",
                        "cpython.run_interactivehook", "cpython.run_startup", "cpython.run_stdin"})
CODE_SUFFIXES = (".py", ".pyc", ".pyw", ".pth")
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
SPAWN_FLAGS = frozenset({"-B", "-E", "-s"})
SPAWN_MAIN = re.compile(r"from multiprocessing\.spawn import spawn_main; spawn_main\(parent_pid=\d+, pipe_handle=\d+\)")
QUOTED_ARGS = re.compile(r'"[^"]*"(?: "[^"]*")*')

BLOCK = ("block", None)
LOG = ("log", None)

_repr = reprlib.Repr()
_repr.maxstring = 200
_repr.maxother = 120
_repr.maxlong = 40


def norm(p, cwd=None):
    """Windows 规则的规范化：转 str、/ 换 \\、相对路径接上 cwd、去掉 \\\\?\\ 前缀、小写。"""
    if isinstance(p, bytes):
        p = os.fsdecode(p)
    p = os.fspath(p).replace("/", "\\")
    if p[:4] == "\\\\?\\" and len(p) > 6 and p[5] == ":":
        p = p[4:]
    if cwd is not None and not ntpath.isabs(p) and p[:2] != "\\\\":
        p = ntpath.join(cwd, p)
    return ntpath.normpath(p).lower()


def within(p, d):
    return p == d or p.startswith(d.rstrip("\\") + "\\")


def unc_or_device(p):
    """UNC（\\\\host\\share、\\\\?\\UNC\\）和设备路径（\\\\.\\）。命名管道 \\\\.\\pipe\\ 和 \\\\?\\X:\\ 长路径除外。"""
    if isinstance(p, bytes):
        p = os.fsdecode(p)
    s = os.fspath(p).replace("/", "\\").lower()
    if not s.startswith("\\\\"):
        return False
    if s.startswith("\\\\.\\pipe\\"):
        return False
    if s.startswith("\\\\?\\") and len(s) > 6 and s[5] == ":" and s[4].isalpha():
        return False
    return True


class Ctx:
    """一次任务的路径：code\\、环境层、解释器、System32。cwd 默认现取（任务可以 chdir）。"""

    def __init__(self, job_dir, env_dir, executable, system_root, getcwd=os.getcwd):
        self.code_dir = norm(ntpath.join(job_dir, "code"))
        self.env_dir = norm(env_dir)
        self.executable = norm(executable)
        self.system32 = norm(ntpath.join(system_root, "System32"))
        self.getcwd = getcwd
        self._cache = {}

    def path(self, p):
        return norm(p, self.getcwd())

    def trusted(self, p):
        """p（已规范化）在 code\\ 或环境层里。"""
        hit = self._cache.get(p)
        if hit is None:
            hit = within(p, self.code_dir) or within(p, self.env_dir)
            if len(self._cache) < 4096:
                self._cache[p] = hit
        return hit


def loopback_addr(addr):
    if isinstance(addr, tuple) and addr:
        host = addr[0]
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        return isinstance(host, str) and host.lower() in LOOPBACK
    return False


def loopback_lookup(event, args):
    if not args:
        return False
    first = args[0]
    if event == "socket.getnameinfo":
        return loopback_addr(first)
    if first is None and event == "socket.getaddrinfo":  # 只填端口（bind 通配地址）：不查 DNS
        return True
    if isinstance(first, bytes):
        first = first.decode("ascii", "replace")
    return isinstance(first, str) and first.lower() in LOOPBACK


def spawn_ok(args, ctx):
    """_winapi.CreateProcess 只放行 multiprocessing spawn 的那一种：本层 python.exe，参数一个字不差。
    多出 -S、-I 之类就能起一个没有钩子的子进程，所以别的一律拒。"""
    if len(args) < 2 or not isinstance(args[0], str) or not isinstance(args[1], str):
        return False
    if norm(args[0]) != ctx.executable or not QUOTED_ARGS.fullmatch(args[1]):
        return False
    toks = re.findall(r'"([^"]*)"', args[1])
    if len(toks) != 7 or norm(toks[0]) != ctx.executable:
        return False
    flags, rest = toks[1:4], toks[4:]
    return (set(flags) == SPAWN_FLAGS and rest[0] == "-c" and SPAWN_MAIN.fullmatch(rest[1]) is not None
            and rest[2] == "--multiprocessing-fork")


def code_origin(filename, ctx):
    """compile / exec 的来源：import（code\\、环境层、预编译时去掉前缀的相对路径、冻结模块）还是动态执行。"""
    if not isinstance(filename, str):
        return "dynamic"
    if filename.startswith("<frozen "):
        return "import"
    if filename.startswith("<"):
        return "dynamic"
    if not ntpath.isabs(filename.replace("/", "\\")):
        return "import"  # 层内 pyc 用 compileall -s/-p 编译，co_filename 是 Lib/site-packages/...
    return "import" if ctx.trusted(norm(filename)) else "dynamic"


def decide(event, args, ctx):
    """返回 None（不管）、("block", _)、("log", _) 或 ("count", 计数用的名字)。"""
    if event in PROC_EVENTS:
        return BLOCK
    if event == "_winapi.CreateProcess":
        return None if spawn_ok(args, ctx) else BLOCK
    if event in NET_EVENTS:
        return None if len(args) > 1 and loopback_addr(args[1]) else BLOCK
    if event in DNS_EVENTS:
        return None if loopback_lookup(event, args) else BLOCK
    if event in PATH_EVENTS:
        if not args or not isinstance(args[0], (str, bytes, os.PathLike)):
            return None  # fd、None（当前目录）
        if unc_or_device(args[0]):
            return BLOCK
        if event == "open":
            p = ctx.path(args[0])
            if p.endswith(CODE_SUFFIXES) and not ctx.trusted(p):
                return BLOCK  # 写 .py 再导入、在别处埋 .pth
        return None
    if event == "import":
        for entry in (args[2] if len(args) > 2 and args[2] else ()):
            if not isinstance(entry, (str, bytes, os.PathLike)):
                return BLOCK
            if unc_or_device(entry) or not ctx.trusted(ctx.path(entry)):
                return BLOCK
        if len(args) > 1 and isinstance(args[1], str) and ntpath.isabs(args[1]) and not ctx.trusted(norm(args[1])):
            return BLOCK
        return None
    if event == "ctypes.dlopen":
        name = args[0] if args else None
        if isinstance(name, (str, bytes)) and ("\\" in os.fsdecode(name) or "/" in os.fsdecode(name)):
            p = ctx.path(name)
            if unc_or_device(name) or not (within(p, ctx.env_dir) or within(p, ctx.system32)):
                return BLOCK
        return LOG
    if event in COUNT_EVENTS:
        return ("count", event)
    if event == "compile":
        if code_origin(args[1] if len(args) > 1 else None, ctx) == "import":
            return ("count", "compile.import")
        return LOG
    if event == "exec":
        fn = getattr(args[0], "co_filename", None) if args else None
        if code_origin(fn, ctx) == "import":
            return ("count", "exec.import")
        return LOG
    if event in REG_WRITE_EVENTS:
        return BLOCK
    if event in ("os.putenv", "os.unsetenv"):
        key = args[0] if args else ""
        if isinstance(key, bytes):
            key = key.decode("ascii", "replace")
        # 改 EPSILON_JOB_DIR 再起 multiprocessing 子进程，子进程的钩子就按别的目录判了
        if isinstance(key, str) and key.upper().startswith("EPSILON_"):
            return BLOCK
        return None
    if event in LOG_EVENTS:
        return LOG
    return None


def short_args(event, args):
    if event in ("compile",):
        return repr(args[1] if len(args) > 1 else None)
    if event == "exec":
        return repr(getattr(args[0], "co_filename", None) if args else None)
    if event == "marshal.loads":
        return "len=%d" % (len(args[0]) if args and hasattr(args[0], "__len__") else -1)
    s = _repr.repr(args)
    return s.encode("ascii", "backslashreplace").decode("ascii")[:ARGS_MAX]


def record(event, act, args, n=None, now=time.time, pid=os.getpid):
    r = {"t": round(now(), 3), "pid": pid(), "ev": event, "act": act, "args": short_args(event, args)}
    if n is not None:
        r["n"] = n
    return (json.dumps(r, ensure_ascii=True) + "\n").encode("ascii")


def make_hook(ctx, write):
    """write(bytes) 一次写完一条；写不出去由 write 自己 os._exit。"""
    local = threading.local()
    counts = {}

    def hook(event, args):
        if getattr(local, "busy", False):
            return  # 钩子自己触发的事件
        local.busy = True
        try:
            verdict = decide(event, args, ctx)
            if verdict is None:
                return
            act, key = verdict
            if act == "count":
                n = counts.get(key, 0) + 1
                counts[key] = n
                if n <= COUNT_KEEP or n % COUNT_EVERY == 0:
                    write(record(key, "count", args, n=n))
                return
            write(record(event, act, args))
        finally:
            local.busy = False
        if act == "block":
            raise PermissionError("epsilon 沙箱拦截: %s" % event)

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


def _writer(fd):
    lock = threading.Lock()

    def write(b):
        try:
            with lock:
                while b:
                    b = b[os.write(fd, b):]
        except BaseException:
            os._exit(EXIT_HOOK_FAILED)  # 管道断了：探针那边已经当篡改处理，这边不能没有记录地接着跑

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
    ctx = Ctx(os.environ["EPSILON_JOB_DIR"], ntpath.dirname(sys.executable), sys.executable,
              os.environ.get("SystemRoot", "C:\\Windows"))
    write = _writer(fd)
    sys.addaudithook(make_hook(ctx, write))
    INSTALLED = True
    ready = {"t": round(time.time(), 3), "ev": "ready", "pid": os.getpid(), "ppid": os.getppid(),
             "il": "low" if rid <= 0x1000 else hex(rid), "file": __file__, "layer": sys.prefix}
    write((json.dumps(ready, ensure_ascii=True) + "\n").encode("ascii"))


def _main():
    try:
        if _should_install():
            _install()
    except BaseException:
        os._exit(EXIT_HOOK_FAILED)


_main()
