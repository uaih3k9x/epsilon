"""金丝雀一：系统控制检查（docs/jobs-sandbox.md 第 5 节）。

探针以任务账户、独立桌面、作业对象跑：python.exe -I -S -c <本文件> <配置 JSON>。不加载审计钩子，查的是系统本身。
先像 sitecustomize 一样把自己降到 Low IL（降级代码两边一模一样，jobbox 的测试核对），再逐项查。
每一项打印一行 "CANARY ok 名字" 或 "CANARY fail 名字 原因"；一项出异常不影响别的项。名字和 jobbox.SysChecks 一致。
"""

import json
import os
import shutil
import socket
import subprocess
import sys

try:
    CFG = json.loads(sys.argv[1])
except Exception:
    CFG = {}


def report(name, ok, detail=""):
    print("CANARY", "ok" if ok else "fail", name, " ".join(str(detail).split())[:300], flush=True)


def check(name):
    def deco(f):
        try:
            r = f()
            ok, detail = (r, "") if isinstance(r, bool) else r
        except Exception as e:
            ok, detail = False, "%s: %s" % (type(e).__name__, e)
        report(name, ok, detail)
        return f
    return deco


def denied(fn):
    """fn 必须因为没有权限而失败（ERROR_ACCESS_DENIED）。"""
    try:
        fn()
    except PermissionError:
        return True, ""
    except OSError as e:
        return getattr(e, "winerror", None) == 5, "%s: %s" % (type(e).__name__, e)
    return False, "成功了"


def job(*p):
    return os.path.join(CFG["job_dir"], *p)


def env(*p):
    return os.path.join(CFG["env_dir"], *p)


def create(path):
    with open(path, "xb") as f:
        f.write(b"canary")


def create_then_remove(path):
    create(path)
    os.remove(path)


def write_outside(path):
    """往"人人可写"的目录写：必须失败；万一成功了，删掉并报失败。"""
    try:
        create(path)
    except PermissionError:
        return True, ""
    except OSError as e:
        return getattr(e, "winerror", None) == 5, "%s: %s" % (type(e).__name__, e)
    try:
        os.remove(path)
    except OSError:
        pass
    return False, "写进去了: " + path


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


@check("integrity_low")
def _():
    return lower_integrity() <= 0x1000


@check("desktop")
def _():
    import ctypes
    from ctypes import wintypes
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    u32.GetProcessWindowStation.restype = wintypes.HANDLE
    u32.GetThreadDesktop.restype = wintypes.HANDLE
    u32.GetThreadDesktop.argtypes = [wintypes.DWORD]
    u32.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.DWORD)]

    def name(h):
        buf = ctypes.create_unicode_buffer(256)
        need = wintypes.DWORD()
        if not u32.GetUserObjectInformationW(h, 2, buf, ctypes.sizeof(buf), ctypes.byref(need)):  # UOI_NAME
            raise ctypes.WinError(ctypes.get_last_error())
        return buf.value

    got = name(u32.GetProcessWindowStation()) + "\\" + name(u32.GetThreadDesktop(k32.GetCurrentThreadId()))
    return got.lower() == CFG["desktop"].lower(), got


check("read_probe_json")(lambda: denied(lambda: open(CFG["probe_json"], "rb").close()))
check("read_secrets")(lambda: denied(lambda: os.listdir(CFG["secrets_dir"])))
check("write_code")(lambda: denied(lambda: create(job("code", "canary.txt"))))
check("write_params")(lambda: denied(lambda: open(job("params.json"), "ab").close()))
check("delete_params")(lambda: denied(lambda: os.remove(job("params.json"))))
check("write_job_root")(lambda: denied(lambda: create(job("canary.txt"))))
check("write_sitecustomize")(lambda: denied(lambda: open(env("Lib", "site-packages", "sitecustomize.py"), "ab").close()))
check("write_env")(lambda: denied(lambda: create(env("canary.txt"))))


@check("write_tmp")
def _():
    p = job("tmp", "canary.txt")
    create(p)
    with open(p, "rb") as f:
        ok = f.read() == b"canary"
    os.remove(p)
    return ok


check("write_output")(lambda: (create_then_remove(job("output", "canary.txt")), True)[1])


@check("exec_tmp")
def _():
    exe = job("tmp", "canary.exe")
    shutil.copyfile(sys.executable, exe)
    try:
        subprocess.run([exe, "-c", "pass"], timeout=30)
    except OSError as e:
        return getattr(e, "winerror", None) == 5, "%s: %s" % (type(e).__name__, e)
    return False, "tmp 里的 exe 跑起来了"


@check("load_tmp_dll")
def _():
    import ctypes
    dll = job("tmp", "canary.dll")
    shutil.copyfile(env("python3.dll"), dll)
    try:
        ctypes.WinDLL(dll)
    except OSError as e:
        return True, "%s: %s" % (type(e).__name__, e)
    return False, "tmp 里的 dll 加载成功了"


@check("set_dacl_own_file")
def _():
    import ctypes
    from ctypes import wintypes
    p = job("tmp", "dacl.txt")
    create(p)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    # 自己建的文件：想换成空 DACL（人人完全控制）。OWNER RIGHTS 只给所有者 READ_CONTROL，必须 ERROR_ACCESS_DENIED
    rc = adv.SetNamedSecurityInfoW(p, 1, 0x4 | 0x20000000, None, None, None, None)
    return rc == 5, "返回 %d" % rc


check("write_programdata")(lambda: write_outside(os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "epsilon-canary-%d.txt" % os.getpid())))
check("write_windows_temp")(lambda: write_outside(os.path.join(CFG.get("system_root", "C:\\Windows"), "Temp", "epsilon-canary-%d.txt" % os.getpid())))
check("write_users_public")(lambda: write_outside("C:\\Users\\Public\\epsilon-canary-%d.txt" % os.getpid()))


@check("connect_controller")
def _():
    try:
        socket.create_connection((CFG["ctl_host"], CFG["ctl_port"]), timeout=5).close()
    except OSError as e:
        # WSAEACCES：本机过滤平台拦下。超时、被拒绝含义不清，也算失败
        return getattr(e, "winerror", None) == 10013, "%s: %s" % (type(e).__name__, e)
    return False, "连上了"


@check("socketpair")
def _():
    a, b = socket.socketpair()
    with a, b:
        a.sendall(b"x")
        return b.recv(1) == b"x"
