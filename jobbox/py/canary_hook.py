"""金丝雀二：审计钩子检查（docs/jobs-sandbox.md 第 5 节）。

探针以任务账户跑：python.exe -E -s -B -c <引导> canary\\hook.txt canary\\cfg.json，和真任务一样经过环境层的 sitecustomize。
就绪记录（sitecustomize 在环境层里）和 multiprocessing 子进程的就绪由探针从审计管道核对；这里查拦截。
每一项打印一行 "CANARY ok 名字" 或 "CANARY fail 名字 原因"。名字和 jobbox.HookChecks 一致。
"""

import json
import os
import shutil
import socket
import subprocess
import sys

try:  # argv[1] 是探针写的配置文件（命令行装不下）
    with open(sys.argv[1], "rb") as _f:
        CFG = json.load(_f)
except Exception:
    CFG = {}


def report(name, ok, detail=""):
    print("CANARY", "ok" if ok else "fail", name, " ".join(str(detail).split())[:300], flush=True)


CHECKS = []


def check(name):
    def deco(f):
        CHECKS.append((name, f))
        return f
    return deco


def run(name, f):
    try:
        r = f()
        ok, detail = (r, "") if isinstance(r, bool) else r
    except Exception as e:
        ok, detail = False, "%s: %s" % (type(e).__name__, e)
    report(name, ok, detail)


def blocked(fn):
    """fn 必须被钩子拦下（PermissionError，消息里有 epsilon）。"""
    try:
        fn()
    except PermissionError as e:
        return "epsilon" in str(e), str(e)
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)
    return False, "没拦"


@check("hook_installed")
def _():
    sc = sys.modules.get("sitecustomize")
    return bool(getattr(sc, "INSTALLED", False)), getattr(sc, "__file__", "没有 sitecustomize")


check("subprocess_blocked")(lambda: blocked(lambda: subprocess.run([sys.executable, "-c", "pass"])))


@check("spawn_flags_blocked")
def _():
    import _winapi
    cmd = '"%s" "-S" "-c" "pass"' % sys.executable  # 带 -S 就没有钩子
    return blocked(lambda: _winapi.CreateProcess(sys.executable, cmd, None, None, False, 0, None, None, None))


check("connect_blocked")(lambda: blocked(lambda: socket.create_connection((CFG["ctl_host"], CFG["ctl_port"]), timeout=5)))
check("dns_blocked")(lambda: blocked(lambda: socket.getaddrinfo("example.com", 80)))
UNC = "\\\\127.0.0.1\\c$\\epsilon-canary"
check("unc_blocked")(lambda: blocked(lambda: open(UNC + ".txt", "rb")))


@check("unc_paths_blocked")
def _():
    # 不止 open：mkdir、rename、chdir 也会发 SMB。os.stat 没有审计事件，拦不住（文档第 8 节）
    for name, fn in [("mkdir", lambda: os.mkdir(UNC)), ("rename", lambda: os.rename(os.path.join(CFG["job_dir"], "tmp"), UNC)),
                     ("chdir", lambda: os.chdir(UNC))]:
        ok, detail = blocked(fn)
        if not ok:
            return False, name + ": " + detail
    return True
check("env_tamper_blocked")(lambda: blocked(lambda: os.environ.__setitem__("EPSILON_JOB_DIR", "C:\\")))
check("tmp_py_blocked")(lambda: blocked(lambda: open(os.path.join(CFG["job_dir"], "tmp", "x.py"), "w")))


@check("rename_py_blocked")
def _():
    src = os.path.join(CFG["job_dir"], "tmp", "x.txt")
    with open(src, "w") as f:
        f.write("pass\n")
    return blocked(lambda: os.rename(src, os.path.join(CFG["job_dir"], "tmp", "x.py")))


# 回环不过防火墙：本机别的服务（引导器、推理、rpc、管理软件）都在 127.0.0.1 上听。不是自己 bind 的端口就拦
check("loopback_blocked")(lambda: blocked(lambda: socket.create_connection(("127.0.0.1", 9), timeout=5)))


@check("socketpair_ok")
def _():
    a, b = socket.socketpair()  # Windows 上是 bind 回环再自连：asyncio 靠它
    with a, b:
        a.sendall(b"x")
        return b.recv(1) == b"x"


@check("dlopen_tmp_blocked")
def _():
    import ctypes
    dll = os.path.join(CFG["job_dir"], "tmp", "canary-hook.dll")
    shutil.copyfile(os.path.join(CFG["env_dir"], "python3.dll"), dll)
    return blocked(lambda: ctypes.CDLL(dll))


@check("mp_child")
def _():
    import multiprocessing
    p = multiprocessing.get_context("spawn").Process(target=os.getpid)
    p.start()
    p.join(60)
    return p.exitcode == 0, "exitcode %s" % p.exitcode


if __name__ == "__main__":  # multiprocessing 子进程导入主模块时不要再跑一遍
    for name, f in CHECKS:
        run(name, f)
