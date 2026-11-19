"""环境层审计钩子（jobbox/py/sitecustomize.py）的策略测试。运行: python3 -m pytest tools/test_sandbox_hook.py

策略是纯函数，路径按 Windows 规则比较，所以在 Mac 上直接测；subprocess、socket、环境变量的拦截在真解释器里端到端跑。
降级、命名管道这些 Windows 专属的部分只能真机验证（docs/jobs-sandbox.md 第 7 节）。
"""

import importlib.util
import json
import os
import subprocess
import sys
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "jobbox", "py", "sitecustomize.py")
_spec = importlib.util.spec_from_file_location("eps_sitecustomize", SRC)
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)  # 不是 win32：只定义函数，不装钩子

JOB = "D:\\epsilon\\jobs\\demo-1"
ENV = "D:\\epsilon\\envs\\py311@2"
EXE = ENV + "\\python.exe"
CODE = JOB + "\\code"


@pytest.fixture
def ctx():
    return sc.Ctx(JOB, ENV, EXE, "C:\\Windows", getcwd=lambda: CODE)


def act(ctx, event, *args):
    v = sc.decide(event, args, ctx)
    return None if v is None else v[0]


def spawn_cmd(exe=EXE, flags=("-B", "-E", "-s"), main="from multiprocessing.spawn import spawn_main; spawn_main(parent_pid=4242, pipe_handle=880)"):
    return " ".join('"%s"' % x for x in [exe, *flags, "-c", main, "--multiprocessing-fork"])


def test_not_installed_off_windows():
    assert sc.INSTALLED is False


@pytest.mark.parametrize("event", sorted(sc.PROC_EVENTS))
def test_process_creation_blocked(ctx, event):
    assert act(ctx, event, "cmd.exe") == "block"


def test_spawn_must_not_set_cwd(ctx):
    assert act(ctx, "_winapi.CreateProcess", EXE, spawn_cmd(), JOB + "\\tmp") == "block"


def test_multiprocessing_spawn_shape_allowed(ctx):
    assert act(ctx, "_winapi.CreateProcess", EXE, spawn_cmd(), None) is None
    # 大小写和 / 不影响
    assert act(ctx, "_winapi.CreateProcess", EXE.upper().replace("\\", "/"), spawn_cmd(exe=EXE.upper()), None) is None
    # 标志顺序不影响（_args_from_interpreter_flags 的顺序是 -B -E -s）
    assert act(ctx, "_winapi.CreateProcess", EXE, spawn_cmd(flags=("-E", "-s", "-B")), None) is None


@pytest.mark.parametrize("cmd", [
    spawn_cmd(flags=("-B", "-E", "-s", "-S")),           # 没有 site 就没有钩子
    spawn_cmd(flags=("-I",)),
    spawn_cmd(flags=("-B", "-E")),                       # 少了 -s：用户 site-packages
    spawn_cmd(main="import os; os.system('x')"),
    spawn_cmd(main="from multiprocessing.spawn import spawn_main; spawn_main(parent_pid=1, pipe_handle=2); evil()"),
    spawn_cmd(exe="D:\\epsilon\\jobs\\demo-1\\tmp\\python.exe"),
    spawn_cmd() + ' "extra"',
    spawn_cmd().replace('"-c"', "-c"),                   # 没加引号的参数
    '"%s" -c pass' % EXE,
])
def test_other_create_process_blocked(ctx, cmd):
    assert act(ctx, "_winapi.CreateProcess", EXE, cmd, None) == "block"


def test_create_process_other_application_blocked(ctx):
    assert act(ctx, "_winapi.CreateProcess", "C:\\Windows\\System32\\cmd.exe", spawn_cmd(), None) == "block"
    assert act(ctx, "_winapi.CreateProcess", None, spawn_cmd(), None) == "block"


@pytest.mark.parametrize("event", sorted(sc.NET_EVENTS))
def test_socket_never_leaves_loopback(ctx, event):
    s = object()
    for addr in [("10.0.0.1", 8090), ("0.0.0.0", 47100), ("", 0), ("example.com", 443), "/tmp/sock", None]:
        assert act(ctx, event, s, addr) == "block", addr


def test_bind_loopback_allowed(ctx):
    for addr in [("127.0.0.1", 0), ("::1", 0, 0, 0), ("localhost", 5000)]:
        assert act(ctx, "socket.bind", object(), addr) is None


@pytest.mark.parametrize("event", ["socket.connect", "socket.sendto", "socket.sendmsg"])
def test_loopback_only_to_own_ports(ctx, event):
    # 回环不过防火墙：本机 epsilon-boot、p2p、推理、rpc、管理软件都在 127.0.0.1 上听。只许连本进程自己 bind 的端口
    import socket
    lsock = socket.socket()
    try:
        lsock.bind(("127.0.0.1", 0))
        assert act(ctx, "socket.bind", lsock, ("127.0.0.1", 0)) is None
        port = lsock.getsockname()[1]
        other = object()
        assert act(ctx, event, other, ("127.0.0.1", port)) is None   # socketpair、asyncio 的自连
        assert act(ctx, event, other, ("localhost", port)) is None
        for p in (port + 1, 47199, 8080, 50052):
            assert act(ctx, event, other, ("127.0.0.1", p)) == "block", p
            assert act(ctx, event, other, ("::1", p, 0, 0)) == "block", p
    finally:
        lsock.close()
    assert act(ctx, event, object(), ("127.0.0.1", port)) == "block"  # 关了就不算自己的了


def test_dns_only_localhost(ctx):
    assert act(ctx, "socket.getaddrinfo", "localhost", 80, 0, 0, 0) is None
    assert act(ctx, "socket.getaddrinfo", None, 0, 0, 0, 0) is None
    assert act(ctx, "socket.getaddrinfo", "exfil.example.com", 80, 0, 0, 0) == "block"
    assert act(ctx, "socket.gethostbyname", "x.example") == "block"
    assert act(ctx, "socket.gethostbyaddr", "8.8.8.8") == "block"
    assert act(ctx, "socket.getnameinfo", ("8.8.8.8", 53), 0) == "block"
    assert act(ctx, "socket.getnameinfo", ("127.0.0.1", 53), 0) is None


@pytest.mark.parametrize("path", [
    "\\\\host\\share\\x.txt", "//host/share/x", "\\\\?\\UNC\\host\\share\\x", "\\\\.\\PhysicalDrive0",
    "\\\\.\\C:", "\\\\?\\GLOBALROOT\\Device\\x", b"\\\\host\\share",
])
def test_unc_and_device_paths_blocked(ctx, path):
    for ev in ("open", "os.listdir", "os.scandir"):
        assert act(ctx, ev, path, "r", 0) == "block", (ev, path)


@pytest.mark.parametrize("event", sorted(sc.PATH_ARGS))
def test_unc_blocked_on_every_path_event(ctx, event):
    # os.mkdir、rename、chdir……也会让内核以 System 身份发 SMB（带任务账户的 NTLM）：防火墙按 SID 管不到
    for i in sc.PATH_ARGS[event]:
        args = [JOB + "\\tmp\\a", JOB + "\\tmp\\b", 0, 0]
        args[i] = "\\\\x.attacker.example\\s\\f"
        assert act(ctx, event, *args) == "block", (event, i)
    assert act(ctx, event, JOB + "\\tmp\\a", JOB + "\\tmp\\b", 0, 0) is None or event == "os.mkdir"


def test_path_events_cover_cpython_ones():
    for ev in ["os.mkdir", "os.rename", "os.remove", "os.rmdir", "os.chdir", "os.chmod", "os.utime", "os.link",
               "os.symlink", "os.truncate", "os.add_dll_directory", "shutil.copyfile", "shutil.copytree",
               "shutil.move", "shutil.rmtree", "shutil.unpack_archive", "tempfile.mkdtemp", "tempfile.mkstemp", "glob.glob"]:
        assert ev in sc.PATH_ARGS, ev


@pytest.mark.parametrize("event", ["os.rename", "os.link", "os.symlink", "shutil.copyfile", "shutil.move"])
def test_cannot_make_code_files_by_rename_or_copy(ctx, event):
    assert act(ctx, event, JOB + "\\tmp\\x.txt", JOB + "\\tmp\\x.py", None, None) == "block"
    assert act(ctx, event, JOB + "\\tmp\\x.txt", JOB + "\\output\\evil.pth", None, None) == "block"
    assert act(ctx, event, JOB + "\\tmp\\x.txt", JOB + "\\output\\y.txt", None, None) is None


def test_private_mkdir_counted(ctx):
    # Python 3.12.4+ 的 mkdir(mode=0o700) 建受保护 DACL 的目录，所有者完全控制：收回权限会失败，至少留痕
    assert sc.decide("os.mkdir", (JOB + "\\tmp\\d", 0o700, None), ctx) == ("count", "os.mkdir.0o700")
    assert act(ctx, "os.mkdir", JOB + "\\tmp\\d", 0o777, None) is None


def test_pipes_and_long_paths_allowed(ctx):
    assert act(ctx, "open", "\\\\.\\pipe\\epsilon-audit", "wb", 0) is None
    assert act(ctx, "open", "\\\\?\\D:\\epsilon\\jobs\\demo-1\\output\\a.txt", "wb", 0) is None
    assert act(ctx, "open", 3, "rb", 0) is None  # fd
    assert act(ctx, "os.listdir", None) is None


def test_code_files_only_in_code_and_env(ctx):
    assert act(ctx, "open", CODE + "\\main.py", "r", 0) is None
    assert act(ctx, "open", "helper.py", "r", 0) is None  # 相对 cwd（code\）
    assert act(ctx, "open", ENV + "\\Lib\\site-packages\\torch\\__init__.py", "rb", 0) is None
    for p in [JOB + "\\tmp\\x.py", JOB + "\\output\\evil.pth", "C:\\ProgramData\\a.pyc", "..\\tmp\\y.PYW",
              CODE + "\\..\\tmp\\z.py"]:
        assert act(ctx, "open", p, "w", 0) == "block", p
    assert act(ctx, "open", JOB + "\\tmp\\data.bin", "wb", 0) is None


def test_import_path_must_stay_in_code_and_env(ctx):
    good = [CODE, ENV + "\\python311.zip", ENV, ENV + "\\Lib\\site-packages", ""]
    assert act(ctx, "import", "torch", None, good, [], []) is None
    assert act(ctx, "import", "evil", None, good + [JOB + "\\tmp"], [], []) == "block"
    assert act(ctx, "import", "evil", None, good + ["\\\\host\\share"], [], []) == "block"
    assert act(ctx, "import", "evil", JOB + "\\tmp\\evil.py", good, [], []) == "block"


def test_dlopen_logged_and_limited_to_env_and_system32(ctx):
    assert act(ctx, "ctypes.dlopen", ENV + "\\Lib\\site-packages\\torch\\lib\\c10.dll") == "log"
    assert act(ctx, "ctypes.dlopen", "C:\\Windows\\System32\\nvcuda.dll") == "log"
    assert act(ctx, "ctypes.dlopen", "kernel32") == "log"
    assert act(ctx, "ctypes.dlopen", None) == "log"
    for p in [JOB + "\\tmp\\x.dll", CODE + "\\x.dll", ".\\x.dll", "C:\\ProgramData\\x.dll", "\\\\host\\s\\x.dll"]:
        assert act(ctx, "ctypes.dlopen", p) == "block", p


@pytest.mark.parametrize("event", sorted(sc.COUNT_EVENTS))
def test_counted_not_blocked(ctx, event):
    assert sc.decide(event, (b"x",), ctx) == ("count", event)


def test_compile_and_exec_classified(ctx):
    assert sc.decide("compile", ("src", CODE + "\\model.py"), ctx) == ("count", "compile.import")
    assert sc.decide("compile", ("src", "<string>"), ctx)[0] == "log"
    def code(fn):
        return compile("pass", fn, "exec")
    assert sc.decide("exec", (code("Lib/site-packages/torch/nn/__init__.py"),), ctx) == ("count", "exec.import")
    assert sc.decide("exec", (code("<frozen os>"),), ctx) == ("count", "exec.import")
    assert sc.decide("exec", (code("<string>"),), ctx)[0] == "log"
    assert sc.decide("exec", (code(JOB + "\\tmp\\gen.py"),), ctx)[0] == "log"
    # 不是真的代码对象（任务自己 sys.audit("exec", ...)）：不读它的属性（可能是任务的 __getattr__），按动态执行记
    assert sc.decide("exec", (types.SimpleNamespace(co_filename=CODE + "\\x.py"),), ctx)[0] == "log"


def test_registry_writes_blocked(ctx):
    for ev in sc.REG_WRITE_EVENTS:
        assert act(ctx, ev, 0, "Software\\x") == "block", ev
    assert act(ctx, "winreg.OpenKey", 0, "Software\\x", 0) is None


def test_epsilon_env_vars_frozen(ctx):
    assert act(ctx, "os.putenv", "EPSILON_JOB_DIR", "C:\\") == "block"
    assert act(ctx, "os.unsetenv", b"epsilon_job_dir") == "block"
    assert act(ctx, "os.putenv", "CUDA_VISIBLE_DEVICES", "0") is None


def test_log_events(ctx):
    for ev in ("sys.addaudithook", "cpython.run_command", "cpython.run_file"):
        assert act(ctx, ev, "x") == "log"


def test_hook_writes_records_and_raises(ctx):
    out = []
    hook = sc.make_hook(ctx, out.append)
    with pytest.raises(PermissionError, match="epsilon"):
        hook("os.system", ("calc",))
    hook("ctypes.dlopen", ("kernel32",))
    hook("os.putenv", ("PATH", "x"))  # 不管：不写
    recs = [json.loads(b) for b in out]
    assert [(r["ev"], r["act"]) for r in recs] == [("os.system", "block"), ("ctypes.dlopen", "log")]
    assert all(r["pid"] == os.getpid() and len(r["args"]) <= sc.ARGS_MAX for r in recs)
    assert all(b.endswith(b"\n") and b.count(b"\n") == 1 for b in out)


def test_hook_counts_keep_first_then_every_thousand(ctx):
    out = []
    hook = sc.make_hook(ctx, out.append)
    for _ in range(2500):
        hook("ctypes.call_function", (0x1234, ()))
    ns = [json.loads(b)["n"] for b in out]
    assert ns == list(range(1, sc.COUNT_KEEP + 1)) + [1000, 2000]


def test_record_args_bounded_and_ascii(ctx):
    b = sc.record("open", "block", ("\U0001F600" * 5000 + "\x00" * 100, "w"))
    r = json.loads(b)
    assert len(r["args"]) <= sc.ARGS_MAX and b.isascii() and len(b) < 4096
    b = sc.record("compile", "log", ("x" * 10_000_000, "<string>"))
    assert len(b) < 200  # 源码不进记录，只记文件名


def test_events_inside_the_hook_are_checked(ctx):
    # 钩子运行中也可能跑到任务的代码（GC 在钩子里触发的 __del__、弱引用回调）：以前一律跳过，等于钩子关掉。现在照样判
    calls = []

    def write(b):
        calls.append(b)
        if len(calls) == 1:
            with pytest.raises(PermissionError):
                hook("os.system", ("nested",))

    hook = sc.make_hook(ctx, write)
    hook("ctypes.dlopen", ("kernel32",))
    assert [json.loads(b)["ev"] for b in calls] == ["ctypes.dlopen", "os.system"]


def test_hook_functions_cannot_be_rewired(ctx):
    # 改钩子用到的函数的 __code__ / __defaults__ 有审计事件（object.__setattr__）：是我们的就拦
    hook = sc.make_hook(ctx, lambda b: None)
    for fn, attr in [(sc.decide, "__defaults__"), (sc.record, "__code__"), (sc.short_args, "__kwdefaults__")]:
        with pytest.raises(PermissionError):
            hook("object.__setattr__", (fn, attr, None))
    hook("object.__setattr__", (lambda: 0, "__defaults__", ()))  # 任务自己的函数不管


@pytest.mark.parametrize("event", ["gc.get_objects", "gc.get_referrers", "gc.get_referents", "sys._current_frames",
                                   "sys._current_exceptions", "sys.settrace", "sys.setprofile",
                                   "sys.monitoring.register_callback"])
def test_introspection_that_reaches_hook_objects_is_logged(ctx, event):
    # 这几个能摸到钩子的对象（函数、默认参数里的字典）或正在跑的钩子帧：正常任务很少用，逐条记
    assert act(ctx, event, None) == "log"


def test_hook_path_reads_no_globals_and_holds_nothing_mutable():
    # 审查 #17 第 1 条：钩子每次调用都按名字查模块全局，任务一句 sys.modules['sitecustomize'].decide = ... 就关掉了它，
    # 而且不留记录。现在钩子用到的一切在装钩子时绑成位置默认参数：没有全局/内建查找、没有闭包（cell_contents 能改）、
    # 没有 __kwdefaults__（那是能改的字典）；模块级函数的默认参数只许是不可变的东西
    import dis
    import socket
    hook = sc.make_hook(sc.Ctx(JOB, ENV, EXE, "C:\\Windows"), lambda b: None)
    immutable_types = (str, bytes, int, float, bool, type(None), frozenset, types.MappingProxyType,
                       type(sc.QUOTED_ARGS), types.BuiltinFunctionType, types.MethodDescriptorType,
                       types.WrapperDescriptorType, types.BuiltinMethodType)

    def frozen(v):
        if isinstance(v, tuple):
            return all(frozen(x) for x in v)
        if v is socket.socket:
            return True  # note_bound 只拿它比 is，不读它的属性
        if isinstance(v, type):
            return bool(v.__flags__ & (1 << 8))  # Py_TPFLAGS_IMMUTABLETYPE：内建类型，类属性改不了
        return type(v) in immutable_types or isinstance(v, types.FunctionType)

    seen, todo = set(), [(hook, True)]
    while todo:
        f, top = todo.pop()
        if id(f) in seen:
            continue
        seen.add(id(f))
        assert f.__code__.co_freevars == (), f.__name__
        assert not f.__kwdefaults__, f.__name__
        assert not [c for c in f.__code__.co_consts if isinstance(c, types.CodeType)], f.__name__ + " 里有嵌套函数/推导式"
        bad = [i.argval for i in dis.get_instructions(f) if i.opname in ("LOAD_GLOBAL", "LOAD_NAME", "LOAD_DEREF",
                                                                          "LOAD_CLASSDEREF", "STORE_GLOBAL")]
        assert not bad, (f.__name__, bad)
        for d in f.__defaults__ or ():
            if isinstance(d, types.FunctionType):
                todo.append((d, False))
            elif not top:  # hook 自己的默认参数里有 ctx、计数（本来就是状态，只有钩子帧摸得到）
                assert frozen(d), (f.__name__, d)
    assert len(seen) >= 8


@pytest.mark.parametrize("name", ["x.py.", "x.py ", "x.py. . ", "x.py::$DATA", "x.PY", "x.pth:s"])
def test_windows_strips_trailing_dots_and_streams(ctx, name):
    # Windows 打开 "x.py." 就是 x.py；"x.py::$DATA" 是它的主数据流
    assert act(ctx, "open", JOB + "\\tmp\\" + name, "w", 0) == "block"
    assert act(ctx, "os.rename", JOB + "\\tmp\\a.txt", JOB + "\\tmp\\" + name) == "block"


def test_path_objects_are_never_asked_for_their_path(ctx):
    # 钩子不调任务的 __fspath__：它在钩子里跑（以前钩子里的事件一律跳过），而且第二次可以返回和系统调用用的不一样的路径
    class P:
        def __fspath__(self):
            raise AssertionError("钩子调了 __fspath__")

    import pathlib
    for p in [P(), pathlib.PureWindowsPath("\\\\x.example\\s\\d")]:
        assert sc.decide("os.mkdir", (p, 0o777, None), ctx) == ("count", "path.opaque")
    assert act(ctx, "os.listdir", 3) is None and act(ctx, "os.listdir", None) is None


def test_hook_never_runs_task_code(ctx):
    # 参数是任务的对象：它的类、元类的 __hash__ / __eq__ / __repr__ / __getattr__ 都不能在钩子里被调到
    class Meta(type):
        def __hash__(cls):
            raise AssertionError("钩子调了元类的 __hash__")

        def __eq__(cls, other):
            raise AssertionError("钩子调了元类的 __eq__")

        __ne__ = __eq__

        def __repr__(cls):
            raise AssertionError("钩子调了元类的 __repr__")

    class Evil(metaclass=Meta):
        def __repr__(self):
            raise AssertionError("钩子调了 __repr__")

        def __eq__(self, other):
            raise AssertionError("钩子调了 __eq__")

        def __getattr__(self, name):
            raise AssertionError("钩子调了 __getattr__ " + name)

        __hash__ = None

    out = []
    hook = sc.make_hook(ctx, out.append)
    e = Evil()
    for event, args in [("socket.bind", (e, ("127.0.0.1", 0))), ("socket.connect", (e, ("127.0.0.1", e))),
                        ("os.mkdir", (e, e, e)), ("open", (e, "r", 0)), ("exec", (e,)), ("compile", (e, e)),
                        ("ctypes.dlopen", (e,)), ("import", ("m", e, [e], [], [])), ("os.putenv", (e, e)),
                        ("_winapi.CreateProcess", (e, e, e)), ("sys.addaudithook", (e, Evil, [e], (e,)))]:
        try:
            hook(event, args)
        except PermissionError:
            pass
    assert out


def test_str_and_tuple_subclasses_are_read_like_c_reads_them(ctx):
    # C 的路径转换和 getsockaddrarg 读的是底层的数据，不调子类重写的方法；钩子也一样
    class S(str):
        def replace(self, *a):
            return JOB + "\\code\\x"

        def lower(self):
            return JOB.lower() + "\\code\\x"

        def startswith(self, *a):
            return False

    assert act(ctx, "os.mkdir", S("\\\\x.example\\s\\d"), 0o777, None) == "block"
    assert act(ctx, "open", S(JOB + "\\tmp\\x.py"), "w", 0) == "block"

    class T(tuple):
        def __getitem__(self, i):
            return ("127.0.0.1", 4242)[i]

        def __len__(self):
            return 2

    assert act(ctx, "socket.connect", object(), T(("10.0.0.1", 80))) == "block"
    assert act(ctx, "socket.bind", object(), T(("0.0.0.0", 0))) == "block"


def test_ready_record_carries_job_dir():
    # 子进程的任务目录从环境变量来，_winapi.CreateProcess 的审计参数不含环境：探针核对就绪记录里的 job_dir
    r = json.loads(sc.ready_record(JOB, 0x1000, ["SeChangeNotifyPrivilege"], now=lambda: 1.0, pid=lambda: 7, ppid=lambda: 1))
    assert r["ev"] == "ready" and r["job_dir"] == JOB and r["il"] == "low" and r["pid"] == 7 and r["ppid"] == 1
    # 审查 #17 第 2 条：探针核对完整性级别和剩下的特权（层里的 sitecustomize 写错了也测得出）
    assert r["privs"] == ["SeChangeNotifyPrivilege"]
    assert json.loads(sc.ready_record(JOB, 0x2000, [], now=lambda: 1.0))["il"] == "0x2000"


def test_unc_helper():
    assert sc.unc_or_device("\\\\host\\x") and not sc.unc_or_device("C:\\x") and not sc.unc_or_device("\\x")


E2E = r'''
import importlib.util, json, os, socket, subprocess, sys
import encodings.idna  # getaddrinfo 懒加载它；这里的 sys.path 不在"环境层"里，装钩子以后导入会被拦
spec = importlib.util.spec_from_file_location("eps_sc", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc)
out = []
ctx = sc.Ctx("D:\\j", "D:\\e", "D:\\e\\python.exe", "C:\\Windows", getcwd=lambda: "D:\\j\\code")
sys.addaudithook(sc.make_hook(ctx, out.append))
res = {}
def probe(name, fn):
    try:
        fn(); res[name] = "ran"
    except PermissionError as e:
        res[name] = "blocked" if "epsilon" in str(e) else "perm:" + str(e)
    except Exception as e:
        res[name] = type(e).__name__
probe("subprocess", lambda: subprocess.run(["/usr/bin/true"]))
probe("os.system", lambda: os.system("true"))
probe("connect", lambda: socket.create_connection(("192.0.2.1", 9), timeout=1))
probe("dns", lambda: socket.getaddrinfo("example.invalid", 80))
probe("env", lambda: os.environ.__setitem__("EPSILON_JOB_DIR", "x"))
probe("socketpair", lambda: socket.socketpair())
def own():
    l = socket.socket(); l.bind(("127.0.0.1", 0)); l.listen(1)
    c = socket.create_connection(l.getsockname()[:2], timeout=5); c.close(); l.close()
probe("own_listener", own)
probe("loopback_other", lambda: socket.create_connection(("127.0.0.1", 9), timeout=1))
probe("unc_mkdir", lambda: os.mkdir("\\\\x.example\\s\\d"))
print(json.dumps({"res": res, "env": os.environ.get("EPSILON_JOB_DIR"), "n": len(out)}))
'''


def test_end_to_end_in_real_interpreter():
    p = subprocess.run([sys.executable, "-I", "-c", E2E, SRC], capture_output=True, text=True, timeout=60,
                       env={"EPSILON_JOB_DIR": "orig", "PATH": os.environ.get("PATH", "")})
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout.strip().splitlines()[-1])
    r = got["res"]
    assert r["subprocess"] == "blocked" and r["os.system"] == "blocked"
    assert r["connect"] == "blocked" and r["dns"] == "blocked" and r["env"] == "blocked"
    assert r["socketpair"] == "ran"  # 回环要放行：Windows 上 socketpair 和 asyncio 都靠它
    assert r["own_listener"] == "ran" and r["loopback_other"] == "blocked" and r["unc_mkdir"] == "blocked"
    assert got["env"] == "orig" and got["n"] >= 5


TAMPER = r"""
import gc, importlib.util, json, ntpath, os, socket, sys, builtins, reprlib
import encodings.idna  # getaddrinfo 懒加载它；这里的 sys.path 不在"环境层"里，装钩子以后导入会被拦
_loads, _isinstance, _issubclass, _getattr = json.loads, isinstance, issubclass, getattr
spec = importlib.util.spec_from_file_location("eps_sc", sys.argv[1])
sc = importlib.util.module_from_spec(spec); spec.loader.exec_module(sc); sys.modules["sitecustomize"] = sc
out = []
ctx = sc.Ctx("D:\\j", "D:\\e", "D:\\e\\python.exe", "C:\\Windows", getcwd=lambda: "D:\\j\\code")
sys.addaudithook(sc.make_hook(ctx, out.append))
rfd, wfd = os.pipe()
pipe_write = sc._writer(wfd)
res = {}
def probe(name, fn):
    try:
        fn(); res[name] = "ran"
    except PermissionError as e:
        res[name] = "blocked" if "epsilon" in str(e) else "perm"
    except Exception as e:
        res[name] = type(e).__name__
own = socket.socket(); own.bind(("127.0.0.1", 0)); own.listen(1); port = own.getsockname()[1]
n0 = len(out)
# 纯 Python 篡改，不用 ctypes，也不触发审计事件：模块全局、标准库函数、类属性、内建
mod = sys.modules["sitecustomize"]
for k, v in list(vars(mod).items()):
    if not k.startswith("__"):
        setattr(mod, k, (lambda *a, **kw: None) if callable(v) else None)
ntpath.normpath = lambda p: "d:\\j\\code\\x"
ntpath.isabs = lambda p: True
ntpath.join = lambda *a: "d:\\j\\code\\x"
os.fspath = lambda p: "d:\\j\\code\\x"
os.write = lambda fd, b: len(b)
json.dumps = lambda *a, **k: "{}"
reprlib.Repr.repr = lambda self, x: ""
socket.socket.getsockname = lambda self: ("127.0.0.1", 9)
builtins.isinstance = lambda a, b: False
builtins.issubclass = lambda a, b: False
builtins.getattr = lambda *a: None
probe("os.system", lambda: os.system("true"))
probe("unc_mkdir", lambda: os.mkdir("\\\\x.example\\s\\d"))
probe("loopback", lambda: socket.socket().connect(("127.0.0.1", 9)))
probe("own_port", lambda: socket.create_connection(("127.0.0.1", port), timeout=5).close())
probe("tmp_py", lambda: open("D:\\j\\tmp\\x.py", "w"))
builtins.isinstance, builtins.issubclass, builtins.getattr = _isinstance, _issubclass, _getattr
pipe_write(b"rec\n")
got = os.read(rfd, 100)

class P:
    calls = 0
    def __fspath__(self):
        P.calls += 1
        if P.calls == 2:  # 第一次是 os.mkdir 自己转换路径；第二次只可能是钩子在调
            try:
                os.system("true"); res["inside_fspath"] = "ran"
            except PermissionError:
                res["inside_fspath"] = "blocked"
        return "made-by-fspath"
probe("pathlike", lambda: os.mkdir(P()))

class S(str):
    def replace(self, *a): return "d:\\j\\code\\x"
    def lower(self): return "d:\\j\\code\\x"
    def startswith(self, *a): return False
probe("str_subclass_unc", lambda: os.mkdir(S("\\\\x.example\\s\\e")))

class T(tuple):
    def __getitem__(self, i): return ("127.0.0.1", port)[i]
    def __len__(self): return 2
probe("tuple_subclass_addr", lambda: socket.socket().connect(T(("127.0.0.1", 9))))

# GC 在钩子里触发终结器：以前钩子里的事件一律跳过
ran_in_del = []
class D:
    def __init__(self): self.me = self
    def __del__(self):
        try:
            os.system("true"); ran_in_del.append(1)
        except PermissionError:
            pass
gc.collect(); gc.set_threshold(1)
for _ in range(300):
    D()
    try:
        os.listdir(".")
    except Exception:
        pass
gc.set_threshold(700); gc.collect()
recs = [_loads(b) for b in out[n0:]]
print(json.JSONEncoder().encode({"res": res, "n": len(recs), "evs": sorted({r["ev"] for r in recs}), "pipe": got.decode(),
                                 "fspath_calls": P.calls, "ran_in_del": len(ran_in_del)}))
"""


def test_tampering_with_globals_does_not_switch_the_hook_off(tmp_path):
    # 审查 #17 第 1 条的复现：改模块全局、标准库函数、类属性、内建，不用 ctypes、不触发任何审计事件
    p = subprocess.run([sys.executable, "-I", "-c", TAMPER, SRC], capture_output=True, text=True, timeout=120, cwd=tmp_path,
                       env={"PATH": os.environ.get("PATH", "")})
    assert p.returncode == 0, p.stderr
    got = json.loads(p.stdout.strip().splitlines()[-1])
    r = got["res"]
    for name in ("os.system", "unc_mkdir", "loopback", "tmp_py", "str_subclass_unc", "tuple_subclass_addr"):
        assert r[name] == "blocked", (name, r)
    assert r["own_port"] == "ran"  # 自己 bind 的回环端口照常
    assert "inside_fspath" not in r and got["fspath_calls"] == 1  # 钩子没调任务的 __fspath__
    assert got["ran_in_del"] == 0  # 钩子里跑到的终结器照样被拦
    assert {"os.system", "os.mkdir", "socket.connect", "open"} <= set(got["evs"]), got  # 照样留记录
    assert got["pipe"] == "rec\n"  # os.write 换掉了，审计管道照样写得进去
