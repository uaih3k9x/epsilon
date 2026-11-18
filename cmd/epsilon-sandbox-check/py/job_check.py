"""真机验证套件的任务侧脚本（tools/sandbox-check，docs/jobs-sandbox.md 第 7 节）。

epsilon-sandbox-check 把它写成测试任务目录的 code\\main.py，以 epsilon-job 跑：
  task / lockdir / mkdir700   经环境层的 sitecustomize（python -E -s -B main.py <模式>，走 jobbox.Box.Run，和真任务一样）
  net / scan / inventory      python -I -S main.py <模式> <cfg.json>（不加载钩子，查系统本身）
每一项打印一行 "CHECK <id> PASS|FAIL|SKIP|MANUAL <证据>"，一项出异常不影响别的项；盘点清单是 "INV <标记> <路径>" 行。
纯函数（classify、connect_verdict、version_at_least）在 Mac 上测：tools/test_sandbox_check.py。
"""

import json
import os
import re
import socket
import sys
import time

MAX_EVIDENCE = 400


def emit(cid, status, evidence=""):
    print("CHECK", cid, status, " ".join(str(evidence).split())[:MAX_EVIDENCE], flush=True)


def guard(cid, fn):
    """跑一项：fn 返回 (状态, 证据)；出异常算 FAIL。"""
    try:
        status, evidence = fn()
    except Exception as e:  # noqa: BLE001 - 每一项都要有一行结果
        status, evidence = "FAIL", "%s: %s" % (type(e).__name__, e)
    emit(cid, status, evidence)
    return status


# ---- 纯函数 ----

INTERESTING_EXT = {
    ".ini", ".conf", ".cfg", ".config", ".xml", ".json", ".yaml", ".yml", ".txt", ".properties", ".reg",
    ".db", ".sqlite", ".mdb", ".dat", ".key", ".pem", ".pfx", ".p12", ".crt", ".cer", ".ovpn", ".rdp", ".kdbx",
}
SECRET_NAME = re.compile(r"pass|pwd|secret|token|credential|licen[cs]e|account|\bkey\b|apikey|api_key", re.I)
SECRET_TEXT = re.compile(rb"pass(word|wd)?\s*[=:]|pwd\s*[=:]|secret\s*[=:]|token\s*[=:]|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY", re.I)


def classify(path, head):
    """盘点：任务账户读得到的这个文件值不值得人看。head 是开头最多 64 KB（读不了是 None）。
    返回 "KEY"（内容像口令、密钥）、"NAME"（名字像）、"EXT"（配置类扩展名）或 None。"""
    if head is not None and SECRET_TEXT.search(head):
        return "KEY"
    base = os.path.basename(path.replace("\\", "/"))
    if SECRET_NAME.search(base):
        return "NAME"
    if os.path.splitext(base)[1].lower() in INTERESTING_EXT:
        return "EXT"
    return None


def connect_verdict(expect, err):
    """连接测试的判定。expect 是 "blocked"（必须 WSAEACCES 10013：本机过滤平台拦下）、"open"（必须连上）
    或 "either"（连上、被拦都记 PASS，只是写明是哪种；本机自己的地址按文档应当和回环一样不过防火墙）。
    err 是 None（连上了）或 OSError。返回 (状态, 证据)。"""
    code = getattr(err, "winerror", None) if err is not None else None
    if expect == "either":
        if err is None:
            return "PASS", "连上了（按回环处理，不过防火墙）"
        if code == 10013:
            return "PASS", "被拦（WSAEACCES 10013）"
        return "FAIL", "%s: %s" % (code, err)
    if expect == "blocked":
        if err is None:
            return "FAIL", "连上了"
        if code == 10013:
            return "PASS", "WSAEACCES 10013"
        return "FAIL", "要 10013，实际 %s: %s" % (code, err)
    if err is None:
        return "PASS", "连上了"
    return "FAIL", "%s: %s" % (code, err)


def version_at_least(v, want):
    """"3.12.4" 这种版本号比较（不认识的部分当 0）。"""
    def parts(s):
        out = []
        for x in str(s).split(".")[:3]:
            m = re.match(r"\d+", x)
            out.append(int(m.group()) if m else 0)
        return out + [0] * (3 - len(out))
    return parts(v) >= parts(want)


# ---- Windows 上的小工具（ctypes） ----

def _token_info():
    """自己令牌的完整性级别 RID 和特权名。"""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    adv.LookupPrivilegeNameW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
        raise ctypes.WinError(ctypes.get_last_error())

    def info(cls):
        need = wintypes.DWORD()
        adv.GetTokenInformation(tok, cls, None, 0, ctypes.byref(need))
        buf = ctypes.create_string_buffer(max(need.value, 4))
        if not adv.GetTokenInformation(tok, cls, buf, len(buf), ctypes.byref(need)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buf

    buf = info(25)  # TokenIntegrityLevel
    sid = ctypes.c_void_p.from_buffer(buf).value
    rid = adv.GetSidSubAuthority(sid, adv.GetSidSubAuthorityCount(sid).contents.value - 1).contents.value
    buf = info(3)  # TokenPrivileges
    n = wintypes.DWORD.from_buffer(buf).value
    names = []
    for i in range(n):
        off = 4 + i * 12  # LUID_AND_ATTRIBUTES：LUID 8 字节 + 属性 4 字节
        name = ctypes.create_unicode_buffer(64)
        size = wintypes.DWORD(len(name))
        if not adv.LookupPrivilegeNameW(None, ctypes.addressof(buf) + off, name, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        names.append(name.value)
    k32.CloseHandle(tok)
    return rid, sorted(names)


def _make_window():
    """在任务的桌面上建一个 STATIC 窗口再销毁：user32 初始化和桌面权限（0x201ff）够不够。"""
    import ctypes
    from ctypes import wintypes
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    u32.CreateWindowExW.restype = wintypes.HWND
    u32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                                    wintypes.HINSTANCE, wintypes.LPVOID]
    u32.DestroyWindow.argtypes = [wintypes.HWND]
    h = u32.CreateWindowExW(0, "STATIC", "epsilon-check", 0, 0, 0, 10, 10, None, None, None, None)
    if not h:
        return "FAIL", "CreateWindowExW 错误 %d" % ctypes.get_last_error()
    u32.DestroyWindow(h)
    return "PASS", "hwnd 0x%x" % h


def _create_protected_dir(path, sddl):
    """以自带安全描述符建目录（文档第 8 节的剩余风险：建的时候自带 DACL，OW 管不到）。"""
    import ctypes
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                                                          ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    k32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
    k32.LocalFree.argtypes = [ctypes.c_void_p]

    class SA(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]

    sd = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = SA(ctypes.sizeof(SA), sd.value, False)
        if not k32.CreateDirectoryW(path, ctypes.byref(sa)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.LocalFree(sd)


# ---- 模式 ----

def job_dir(*p):
    return os.path.join(os.environ.get("EPSILON_JOB_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), *p)


class Squares:
    """DataLoader 的数据集：要在模块顶层，spawn 的 worker 才找得到。"""

    def __len__(self):
        return 16

    def __getitem__(self, i):
        return i * i


def mode_task():
    rid_privs = {}

    def il():
        rid, privs = _token_info()
        rid_privs["v"] = (rid, privs)
        return ("PASS" if rid <= 0x1000 else "FAIL"), "il=0x%x" % rid

    guard("3.low_il", il)

    def privs():
        names = rid_privs.get("v", (0, ["（没读到令牌）"]))[1]
        return ("PASS" if names == ["SeChangeNotifyPrivilege"] else "FAIL"), ",".join(names)

    guard("16.privileges", privs)

    def site_first():
        import builtins
        sc = sys.modules.get("sitecustomize")
        f = getattr(sc, "__file__", "") or ""
        layer = os.path.normcase(os.path.abspath(sys.prefix)) + os.sep
        if getattr(builtins, "EPS_SHADOW_SITECUSTOMIZE", False):
            return "FAIL", "code\\sitecustomize.py 被导入了"
        return ("PASS" if os.path.normcase(f).startswith(layer) else "FAIL"), f

    guard("6.sitecustomize_first", site_first)
    guard("2.user32_window", _make_window)

    def fs_ops():
        import shutil
        n = 0
        for d in ("tmp", "output"):
            base = job_dir(d, "check-tree")
            os.makedirs(os.path.join(base, "a", "b", "c"))
            for i in range(5):
                with open(os.path.join(base, "a", "b", "c", "f%d.bin" % i), "wb") as f:
                    f.write(b"x" * 1024)
            n += sum(len(fs) for _, _, fs in os.walk(base))
            shutil.rmtree(base)
            if os.path.exists(base):
                return "FAIL", "rmtree 之后还在: " + base
        return ("PASS" if n == 10 else "FAIL"), "walk 到 %d 个文件（要 10）" % n

    guard("4.fs_ops", fs_ops)

    def mp_pool():
        import multiprocessing
        with multiprocessing.get_context("spawn").Pool(2) as p:
            got = p.map(abs, [-1, -2, -3])
        return ("PASS" if got == [1, 2, 3] else "FAIL"), str(got)

    guard("7.mp_pool_spawn", mp_pool)

    t0 = time.time()
    try:
        import torch
    except Exception as e:  # noqa: BLE001
        for cid in ("3.torch_import", "3.cuda", "4.cudnn", "3.dataloader", "16.cuda_after_drop"):
            emit(cid, "SKIP", "环境层没有 torch: %s" % e)
        return
    emit("3.torch_import", "PASS", "torch %s 导入 %.1f 秒（Low IL）" % (torch.__version__, time.time() - t0))

    def dataloader():
        from torch.utils.data import DataLoader
        t = time.time()
        got = sum(int(x.sum()) for x in DataLoader(Squares(), batch_size=4, num_workers=2))
        return ("PASS" if got == sum(i * i for i in range(16)) else "FAIL"), "num_workers=2 和 %d，%.1f 秒" % (got, time.time() - t)

    guard("3.dataloader", dataloader)
    has_driver = os.path.exists(os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "nvcuda.dll"))
    if not torch.cuda.is_available():
        st = "FAIL" if has_driver else "SKIP"
        why = "有 nvcuda.dll 但 torch.cuda.is_available() 是 False" if has_driver else "没有 NVIDIA 驱动"
        for cid in ("3.cuda", "4.cudnn", "16.cuda_after_drop"):
            emit(cid, st, why)
        return

    def cuda():
        t = time.time()
        a = torch.randn(512, 512, device="cuda")
        v = float((a @ a).sum().item())
        torch.cuda.synchronize()
        return "PASS", "%s，matmul %.2f 秒，和 %.1f" % (torch.cuda.get_device_name(0), time.time() - t, v)

    st = guard("3.cuda", cuda)
    emit("16.cuda_after_drop", st, "同 3.cuda（sitecustomize 已删特权）")

    def cudnn():
        torch.backends.cudnn.enabled = True
        conv = torch.nn.Conv2d(3, 8, 3).cuda()
        y = conv(torch.randn(2, 3, 32, 32, device="cuda"))
        torch.cuda.synchronize()
        cache = os.environ.get("CUDA_CACHE_PATH", "")
        n = sum(len(fs) for _, _, fs in os.walk(cache)) if cache and os.path.isdir(cache) else 0
        return ("PASS" if torch.backends.cudnn.is_available() else "FAIL"), "cudnn %s，输出 %s，CUDA 缓存 %d 个文件" % (
            torch.backends.cudnn.version(), tuple(y.shape), n)

    guard("4.cudnn", cudnn)


def mode_lockdir():
    def make():
        locked = job_dir("output", "locked")
        _create_protected_dir(locked, "D:P(A;OICI;FA;;;OW)")  # 只给所有者（任务账户自己），探针、管理员、SYSTEM 都不给
        with open(os.path.join(locked, "inside.txt"), "w") as f:
            f.write("locked\n")
        with open(job_dir("output", "plain.txt"), "w") as f:
            f.write("plain\n")
        os.makedirs(job_dir("output", "zz-after"))
        with open(job_dir("output", "zz-after", "after.txt"), "w") as f:
            f.write("after\n")
        return "PASS", locked
    guard("15.lockdir", make)


def mode_mkdir700():
    def make():
        d = job_dir("output", "m700")
        os.mkdir(d, 0o700)
        with open(os.path.join(d, "x.txt"), "w") as f:
            f.write("x\n")
        return "PASS", "Python %s" % sys.version.split()[0]
    guard("15.mkdir700_made", make)


def load_cfg():
    with open(sys.argv[2], "rb") as f:
        return json.load(f)


def mode_net():
    cfg = load_cfg()
    for t in cfg.get("targets", []):
        def one(t=t):
            err = None
            try:
                s = socket.create_connection((t["host"], t["port"]), timeout=t.get("timeout", 5))
                try:
                    s.sendall(b"epsilon-check\n")
                finally:
                    s.close()
            except OSError as e:
                err = e
            st, ev = connect_verdict(t["expect"], err)
            return st, "%s:%s %s" % (t["host"], t["port"], ev)
        guard(t["id"], one)


def mode_scan():
    cfg = load_cfg()
    reach = []
    for p in cfg.get("ports", []):
        try:
            socket.create_connection((p["addr"], p["port"]), timeout=1).close()
            reach.append(p)
            emit("13.port_%s_%d" % (p["addr"].replace(":", "_").replace(".", "_"), p["port"]), "MANUAL",
                 "任务账户（绕过钩子）连得上 %s:%d（%s）：确认它要认证" % (p["addr"], p["port"], p.get("proc", "?")))
        except OSError:
            pass
    emit("13.scan", "PASS" if not reach else "MANUAL", "试了 %d 个监听，连得上 %d 个" % (len(cfg.get("ports", [])), len(reach)))


def mode_inventory():
    cfg = load_cfg()
    limit = cfg.get("max_lines", 3000)
    seen = readable = shown = 0
    by = {"KEY": 0, "NAME": 0, "EXT": 0}
    t0 = time.time()
    timed_out = False
    for root in cfg.get("roots", []):
        for d, dirs, files in os.walk(root):
            if time.time() - t0 > cfg.get("max_seconds", 480):
                timed_out = True
                dirs[:] = []
                continue
            for name in files:
                seen += 1
                p = os.path.join(d, name)
                try:
                    with open(p, "rb") as f:
                        head = f.read(65536)
                except OSError:
                    continue
                readable += 1
                tag = classify(p, head)
                if tag:
                    by[tag] += 1
                    if shown < limit:
                        print("INV", tag, p)
                        shown += 1
    sys.stdout.flush()
    emit("14.inventory", "MANUAL", "%s：%d 个文件，任务账户读得了 %d 个；像口令 %d、名字可疑 %d、配置类 %d（清单见 inventory 文件，%.0f 秒%s）" % (
        "+".join(cfg.get("roots", [])), seen, readable, by["KEY"], by["NAME"], by["EXT"], time.time() - t0,
        "，超时没走完" if timed_out else ""))


MODES = {"task": mode_task, "lockdir": mode_lockdir, "mkdir700": mode_mkdir700,
         "net": mode_net, "scan": mode_scan, "inventory": mode_inventory}

if __name__ == "__main__":  # multiprocessing 的子进程导入主模块时不要再跑一遍
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in MODES:
        emit("0.job_check_mode", "FAIL", "不认识的模式 %r" % mode)
        sys.exit(2)
    MODES[mode]()
