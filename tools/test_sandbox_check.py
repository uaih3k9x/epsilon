"""真机验证套件（tools/sandbox-check）的检查：run.ps1 的静态检查（这里跑不了 PowerShell）、
任务侧脚本 cmd/epsilon-sandbox-check/py/job_check.py 的纯函数和能在 Mac 上跑的模式。
运行: python3 -m pytest tools/test_sandbox_check.py"""

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "tools", "sandbox-check", "run.ps1")
JOB_CHECK = os.path.join(ROOT, "cmd", "epsilon-sandbox-check", "py", "job_check.py")


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def load_job_check():
    spec = importlib.util.spec_from_file_location("job_check", JOB_CHECK)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---- run.ps1 ----

def test_run_ps1_is_ascii_without_bom():
    # PowerShell 5.1 按 ANSI 读脚本；cmd 读中文输出会乱码
    b = open(RUN, "rb").read()
    assert not b.startswith(b"\xef\xbb\xbf")
    b.decode("ascii")


def test_run_ps1_has_no_powershell7_only_syntax():
    code = _strip_strings_and_comments(read(RUN))
    for bad in ("??", "?.", " && ", " || ", "-Parallel", "$PSStyle", "Join-Path -AdditionalChildPath", "-AsHashtable"):
        assert bad not in code, bad


def _strip_strings_and_comments(s):
    """去掉 PowerShell 的字符串和注释，只留括号（'' 和 `" 是转义）。"""
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "#":
            while i < n and s[i] != "\n":
                i += 1
        elif c == "'":
            i += 1
            while i < n:
                if s[i] == "'" and i + 1 < n and s[i + 1] == "'":
                    i += 2
                    continue
                if s[i] == "'":
                    break
                i += 1
            i += 1
        elif c == '"':
            i += 1
            depth = 0
            while i < n:
                if s[i] == "`":
                    i += 2
                    continue
                if s[i] == "$" and i + 1 < n and s[i + 1] == "(":
                    depth += 1
                    i += 2
                    continue
                if s[i] == ")" and depth:
                    depth -= 1
                elif s[i] == '"' and not depth:
                    break
                i += 1
            i += 1
        elif c == "`":
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_run_ps1_brackets_balance():
    code = _strip_strings_and_comments(read(RUN))
    stack, pairs = [], {")": "(", "]": "[", "}": "{"}
    for c in code:
        if c in "([{":
            stack.append(c)
        elif c in pairs:
            assert stack and stack[-1] == pairs[c], "括号不配对"
            stack.pop()
    assert not stack


def test_prechecks_come_before_any_change():
    s = _strip_strings_and_comments(read(RUN))
    first_change = s.index("New-Item -ItemType Directory -Force $Work")
    for m in re.finditer(r"Stop-Pre ", s):
        if s[m.start() - 9:m.start()] == "function ":
            continue
        assert m.start() < first_change, s[m.start():m.start() + 80]
    for change in ("Register-ScheduledTask", "Add-Result $PsFile", "Stop-Process", "takeown", "icacls"):
        assert s.index(change) > first_change, change
    for need in ("IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", "Get-ScheduledTask -TaskName epsilon-probe",
                 "-IncludeUserName"):
        assert s.index(need) < first_change, need
    raw = read(RUN)
    for need in ("job-sandbox.enabled", "sandbox-check.optin"):
        assert raw.index("Test-Path \"$Root\\" + need + "\"") < raw.index("New-Item -ItemType Directory -Force $Work"), need


def test_limited_phase_uses_the_probe_principal():
    # 和 install.ps1 第 7/8 步的计划任务一样：Users、Limited（非提升），才测得出探针真实的权限
    s = read(RUN)
    principal = "New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited"
    assert principal in s
    assert principal in read(os.path.join(ROOT, "deploy", "install.ps1"))


def test_cleanup_is_in_finally_and_never_removes_the_account():
    s = read(RUN)
    fin = s.index("} finally {")
    report = s.index("# ---------------- report")
    cleanup = s[fin:report]
    for need in ("Unregister-ScheduledTask -TaskName $TaskName", "Stop-Process", "'_check-*'", "'quarantine'", "epsilon-canary-*",
                 "takeown", "epsilon-check-*"):
        assert need in cleanup, need
    code = _strip_strings_and_comments(s)
    for bad in ("Remove-LocalUser", "uninstall.ps1", "rmdir /s /q $Root", "Remove-Item -Recurse -Force $Root"):
        assert bad not in code, bad
    assert "Remove-NetFirewallRule -DisplayName 'epsilon-job" not in s
    assert "} catch {" in s[:fin]  # 出错也要走到清理和报告


def test_report_goes_to_d_epsilon_with_timestamp():
    s = read(RUN)
    assert "$Report = \"$Root\\sandbox-check-$Stamp\"" in s
    assert "& $Helper report -work $Work -out $Report" in s


def test_every_ps_result_id_starts_with_its_item_number():
    s = read(RUN)
    ids = re.findall(r"(?:Add-Result \$\w+|Check) (\d+) '([^']+)'", s)
    assert len(ids) > 15
    for item, cid in ids:
        assert re.match(r"^\d+\.", cid), cid
        assert cid.split(".")[0] == item, (item, cid)
        assert 0 <= int(item) <= 18


def test_ps_statuses_are_known():
    s = read(RUN)
    for st in re.findall(r"s = '(\w+)'", s) + re.findall(r"Add-Result \$\w+ \d+ '[^']+' '(\w+)'", s):
        assert st in ("PASS", "FAIL", "SKIP", "MANUAL"), st


def test_readme_is_public_safe():
    s = read(os.path.join(ROOT, "tools", "sandbox-check", "README.md"))
    # 192.0.2.0/24 是文档专用的 TEST-NET-1，别的地址一个都不许有
    assert not re.search(r"\b(?!192\.0\.2\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", s)
    for need in ("牺牲机", "整盘镜像", "uninstall.ps1", "sandbox-check.optin", "-AfterRestore", "MANUAL"):
        assert need in s, need


# ---- job_check.py：纯函数 ----

def test_classify():
    jc = load_job_check()
    assert jc.classify(r"C:\ProgramData\Vendor\agent.ini", b"[srv]\npassword = hunter2\n") == "KEY"
    assert jc.classify(r"C:\ProgramData\x\y.bin", b"-----BEGIN RSA PRIVATE KEY-----") == "KEY"
    assert jc.classify(r"C:\ProgramData\Vendor\credentials.bin", b"\x00\x01") == "NAME"
    assert jc.classify(r"C:\Users\Public\notes.TXT", b"hello") == "EXT"
    assert jc.classify(r"C:\ProgramData\Microsoft\x.etl", b"\x00") is None
    assert jc.classify(r"C:\ProgramData\x\license.dat", None) == "NAME"  # 读不了也按名字判


class WinErr(OSError):
    def __init__(self, code):
        super().__init__("err %d" % code)
        self.winerror = code


def test_connect_verdict():
    jc = load_job_check()
    assert jc.connect_verdict("blocked", WinErr(10013))[0] == "PASS"
    assert jc.connect_verdict("blocked", WinErr(10060))[0] == "FAIL"  # 超时含义不清：可能是路由不通，不是防火墙
    assert jc.connect_verdict("blocked", None)[0] == "FAIL"
    assert jc.connect_verdict("open", None)[0] == "PASS"
    assert jc.connect_verdict("open", WinErr(10013))[0] == "FAIL"
    assert jc.connect_verdict("either", None)[0] == "PASS"
    assert jc.connect_verdict("either", WinErr(10013))[0] == "PASS"
    assert jc.connect_verdict("either", WinErr(10061))[0] == "FAIL"


def test_version_at_least():
    jc = load_job_check()
    assert jc.version_at_least("3.12.4", "3.12.4")
    assert jc.version_at_least("3.13.0", "3.12.4")
    assert not jc.version_at_least("3.11.9", "3.12.4")
    assert not jc.version_at_least("3.12.3rc1", "3.12.4")


# ---- job_check.py：能在 Mac 上跑的模式（输出格式和 Go 一侧 ParseCheckLines 对得上） ----

LINE = re.compile(r"^CHECK (\d+\.[\w.]+) (PASS|FAIL|SKIP|MANUAL)( .*)?$")


def run_mode(tmp_path, mode, cfg):
    p = tmp_path / (mode + ".json")
    p.write_text(json.dumps(cfg))
    r = subprocess.run([sys.executable, "-I", "-S", JOB_CHECK, mode, str(p)], capture_output=True, text=True, timeout=60)
    lines = [l for l in r.stdout.splitlines() if l.startswith("CHECK ")]
    for l in lines:
        assert LINE.match(l), l
    return r, lines


@pytest.fixture
def listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    got = []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            got.append(c.recv(64))
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], got
    srv.close()


def test_net_mode(tmp_path, listener):
    port, got = listener
    r, lines = run_mode(tmp_path, "net", {"targets": [
        {"id": "5.loopback_open", "host": "127.0.0.1", "port": port, "expect": "open", "timeout": 5},
        {"id": "5.blocked_x", "host": "127.0.0.1", "port": port, "expect": "blocked", "timeout": 5},
    ]})
    assert lines[0].startswith("CHECK 5.loopback_open PASS")
    assert lines[1].startswith("CHECK 5.blocked_x FAIL")  # 连上了 = 没拦
    assert got and got[0].startswith(b"epsilon-check")


def test_scan_mode(tmp_path, listener):
    port, _ = listener
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    free = closed.getsockname()[1]
    closed.close()
    r, lines = run_mode(tmp_path, "scan", {"ports": [{"addr": "127.0.0.1", "port": port, "proc": "demo"},
                                                     {"addr": "127.0.0.1", "port": free, "proc": "gone"}]})
    assert lines[0].startswith("CHECK 13.port_127_0_0_1_%d MANUAL" % port)
    assert "demo" in lines[0]
    assert lines[-1].startswith("CHECK 13.scan MANUAL") and "连得上 1 个" in lines[-1]
    r, lines = run_mode(tmp_path, "scan", {"ports": []})
    assert lines == ["CHECK 13.scan PASS 试了 0 个监听，连得上 0 个"]


def test_inventory_mode(tmp_path):
    root = tmp_path / "pd"
    (root / "Vendor").mkdir(parents=True)
    (root / "Vendor" / "agent.ini").write_text("password=x\n")
    (root / "Vendor" / "blob.bin").write_bytes(b"\x00")
    r, lines = run_mode(tmp_path, "inventory", {"roots": [str(root)], "max_lines": 10, "max_seconds": 30})
    assert "INV KEY " + str(root / "Vendor" / "agent.ini") in r.stdout.splitlines()
    assert len(lines) == 1 and lines[0].startswith("CHECK 14.inventory MANUAL") and "读得了 2 个" in lines[0]


def test_unknown_mode_fails_loudly():
    r = subprocess.run([sys.executable, "-I", "-S", JOB_CHECK, "nope"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 2
    assert r.stdout.startswith("CHECK 0.job_check_mode FAIL")
