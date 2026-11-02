"""裸机安装脚本的静态检查（这里跑不了 PowerShell）。运行: python3 -m pytest tools/test_install_script.py"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    with open(os.path.join(ROOT, "deploy", name), encoding="utf-8", newline="") as f:
        return f.read()


def test_ascii_only():
    # PowerShell 5.1 按 ANSI 读脚本
    read("install.ps1").encode("ascii")


def test_seed_comes_with_the_script_not_from_current_release():
    # 全量发布会换 release/，脚本里钉的 $SeedSha 不会跟着变，装机就全部失败
    s = read("install.ps1")
    assert '"upgrade/seed/$f"' in s
    assert '"release/$f"' not in s


def test_verified_before_touching_the_running_machine():
    # 下载失败或哈希不对时，探针要照常跑，救援槽也要还在
    s = read("install.ps1")
    verified = max(s.index("boot loader hash mismatch"), s.index("rescue probe hash mismatch"))
    for fetch in ("'pkg/probe.json'", "'pkg/vc_redist.x64.exe'"):
        assert s.index(fetch) < verified
    for touch in ("Stop-ScheduledTask", "Stop-Process", 'Remove-Item -Recurse -Force $R -'):
        assert s.index(touch) > verified, touch


def test_probe_json_replaced_only_after_verification():
    s = read("install.ps1")
    assert 'Fetch \'pkg/probe.json\' "$Dst\\probe.json.new"' in s
    assert s.index('Move-Item "$Dst\\probe.json.new"') > s.index("rescue probe hash mismatch")


def test_release_script_ships_seed_next_to_installer():
    s = read("release.sh")
    assert "dist/deploy/upgrade/seed" in s
    assert s.index("dist/deploy/upgrade/seed") < s.index("deploy/install.ps1 > dist/deploy/upgrade/install.ps1")


def test_repair_script_is_safe_to_carry_around():
    s = read("repair.ps1")
    s.encode("ascii")
    assert "sk-" not in s
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", s)  # 地址和密钥都读 U 盘上的文件
    assert "api_key.txt" in s and "controller-ip.txt" in s


def test_repair_script_diagnoses_first_and_skips_healthy_machines():
    # 现场证据要在动机器之前留下；已在线的机器不重装
    s = read("repair.ps1")
    assert s.index("Collect-Diagnostics") < s.index("already-online") < s.index("Invoke-Expression")
    assert 'upgrade/install.ps1' in s


def test_repair_script_never_logs_the_key():
    s = read("repair.ps1")
    for line in s.splitlines():
        if re.search(r"\$Key\b", line):
            assert "Log " not in line and "Add-Content" not in line and "Write-Host" not in line, line


def test_diag_script_is_read_only_and_holds_no_secret():
    s = read("diag.ps1")
    s.encode("ascii")
    assert "sk-" not in s and "@CONTROLLER@" in s
    assert "kind = 'diag'" in s and "/v1/events" in s
    for verb in ("Remove-", "Stop-", "Set-", "New-", "Register-", "Unregister-", "Start-", "Move-", "Add-Content"):
        assert verb not in s, verb


def test_release_script_ships_diag_script():
    s = read("release.sh")
    assert "deploy/diag.ps1 > dist/deploy/upgrade/diag.ps1" in s
