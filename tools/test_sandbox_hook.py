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
    code = types.SimpleNamespace(co_filename="Lib/site-packages/torch/nn/__init__.py")
    assert sc.decide("exec", (code,), ctx) == ("count", "exec.import")
    assert sc.decide("exec", (types.SimpleNamespace(co_filename="<frozen os>"),), ctx) == ("count", "exec.import")
    assert sc.decide("exec", (types.SimpleNamespace(co_filename="<string>"),), ctx)[0] == "log"
    assert sc.decide("exec", (types.SimpleNamespace(co_filename=JOB + "\\tmp\\gen.py"),), ctx)[0] == "log"


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


def test_reentrant_events_ignored(ctx):
    calls = []

    def write(b):
        calls.append(b)
        hook("os.system", ("nested",))  # 钩子自己触发的事件：不递归、不拦

    hook = sc.make_hook(ctx, write)
    with pytest.raises(PermissionError):
        hook("os.system", ("outer",))
    assert len(calls) == 1


def test_ready_record_carries_job_dir():
    # 子进程的任务目录从环境变量来，_winapi.CreateProcess 的审计参数不含环境：探针核对就绪记录里的 job_dir
    r = json.loads(sc.ready_record(JOB, 0x1000, now=lambda: 1.0, pid=lambda: 7, ppid=lambda: 1))
    assert r["ev"] == "ready" and r["job_dir"] == JOB and r["il"] == "low" and r["pid"] == 7 and r["ppid"] == 1


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
