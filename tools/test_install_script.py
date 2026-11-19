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


# ---- 批任务沙箱（docs/jobs-sandbox.md）----

def sandbox_block():
    s = read("install.ps1")
    start = s.index("Step '4/8 job sandbox")
    return s[start:s.index("Step \"5/8 controller")]


def test_users_grant_without_recursion():
    # /T 在每个文件上写显式 Users 允许，显式允许排在继承来的拒绝前面：任务账户的拒绝 ACE 就失效了
    s = read("install.ps1")
    grants = [l for l in s.splitlines() if "S-1-5-32-545:(OI)(CI)M" in l]
    assert grants and all("/T" not in l for l in grants), grants


def test_sandbox_is_opt_in_and_sticky():
    b = sandbox_block()
    assert "$env:EPS_JOB_SANDBOX -eq '1'" in b and "$env:EPS_JOB_SANDBOX -eq '0'" in b
    assert "if (Test-Path $SandboxMarker) {" in b
    assert "OPT-IN" in "\n".join(read("install.ps1").splitlines()[:20])
    assert "job-sandbox.enabled" in b


def test_sandbox_steps_in_order():
    # 先一次性 reset（会冲掉 secrets\ 的受保护 ACL），再建账户（要它的 SID），再写 secrets\ 的 ACL 和密码文件
    b = sandbox_block()
    order = ["icacls \"$Dst\\*\" /reset /T /C /Q", "New-LocalUser", "$JobSid = (Get-LocalUser", "SetSecurityDescriptorSddlForm",
             "ProtectedData]::Protect", "Move-Item \"$SecFile.tmp\" $SecFile", "icacls $Dst /deny", "epsilon-job-out"]
    idx = [b.index(x) for x in order]
    assert idx == sorted(idx), list(zip(order, idx))
    # 探针在第 1 步就停了，沙箱这一步在第 7 步重新拉起探针之前
    s = read("install.ps1")
    assert s.index("Stop-ScheduledTask") < s.index("Step '4/8 job sandbox") < s.index("Start-ScheduledTask")


def test_sandbox_reset_runs_once():
    b = sandbox_block()
    i = b.index("/reset /T")
    assert "if (-not (Test-Path $ResetMarker))" in b[:i] and "Set-Content $ResetMarker" in b[i:]


def test_sandbox_account_never_admin_and_hidden():
    b = sandbox_block()
    assert "Remove-LocalGroupMember -SID 'S-1-5-32-544'" in b
    assert "Add-LocalGroupMember -SID 'S-1-5-32-545'" in b
    assert "SpecialAccounts\\UserList" in b and "-Value 0" in b
    assert "net user" not in b  # 超过 14 位的密码会弹交互提示


def test_sandbox_logon_rights():
    b = sandbox_block()
    for r in ("SeDenyNetworkLogonRight", "SeDenyRemoteInteractiveLogonRight", "SeDenyBatchLogonRight", "SeDenyServiceLogonRight"):
        assert r in b, r
    # seclogon 走的就是本地交互登录，拒了就一个任务都起不来
    code = [l for l in b.splitlines() if not l.strip().startswith("#")]
    assert not any("SeDenyInteractiveLogonRight" in l for l in code)
    assert "seclogon" in b


def test_sandbox_password_never_printed():
    b = sandbox_block()
    for line in b.splitlines():
        if re.search(r"\$(JobPlain|JobSecure|rb|blob|json)\b", line):
            for sink in ("Write-Host", "Write-Output", "Out-Host", "Add-Content", "Set-Content", "echo ", "Write-Verbose"):
                assert sink not in line, line
    assert "Remove-Variable JobPlain" in b


def test_sandbox_secret_file_format():
    b = sandbox_block()
    assert "[Security.Cryptography.DataProtectionScope]::LocalMachine" in b
    assert "'epsilon-job/v1'" in b  # 和 jobbox.SecretEntropy 一致
    assert '"$Sec\\epsilon-job.json"' in b or "$Sec\\epsilon-job.json" in b
    assert '{"version":1,"user":"' in b and '"password_dpapi":"' in b
    assert "D:P(D;OICI;FA;;;$JobSid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)" in b
    go = open(os.path.join(ROOT, "jobbox", "secret.go"), encoding="utf-8").read()
    assert 'SecretEntropy = "epsilon-job/v1"' in go and 'SecretFile    = "epsilon-job.json"' in go


def test_sandbox_root_acl():
    b = sandbox_block()
    # 0xd0157：读数据/列目录、写、追加、写 EA、删子项、写属性、删除、WRITE_DAC、WRITE_OWNER；不拒遍历和 READ_CONTROL
    assert "icacls $Dst /deny \"*${JobSid}:(OI)(CI)(RD,WD,AD,WEA,DC,WA,DE,WDAC,WO)\"" in b
    assert "icacls \"$Dst\\envs\" /grant \"*${JobSid}:(OI)(CI)RX\"" in b
    assert "/remove:d \"*$OldSid\"" in b  # 账户重建过：旧 SID 的拒绝 ACE 清掉


def test_sandbox_firewall_by_account_sid():
    b = sandbox_block()
    for name, direction in (("epsilon-job-out", "Outbound"), ("epsilon-job-in", "Inbound")):
        line = next(l for l in b.splitlines() if "New-NetFirewallRule -DisplayName '%s'" % name in l)
        assert "-Direction %s -Action Block -Protocol Any -Profile Any" % direction in line
        assert '-LocalUser "O:LSD:(A;;CC;;;$JobSid)"' in line
        assert "-Program" not in line and "-RemoteAddress" not in line


def test_sandbox_no_stderr_redirect_under_stop():
    # 5.1 在 Stop 下把重定向的原生 stderr 变成异常
    assert "2>$null" not in sandbox_block() and "2>&1" not in sandbox_block()


def test_uninstall_removes_job_account():
    s = read("uninstall.ps1")
    s.encode("ascii")
    assert "Remove-LocalUser -Name epsilon-job" in s


def test_sandbox_failure_is_contained():
    # 探针在第 1 步就停了：第 4 步出错不能把整个安装中断（不注册计划任务，C: 还原后整台掉线、推理也没了）。
    # 出错就删掉密码文件（健康检查不过、心跳报 jobs:false），接着往下装
    b = sandbox_block()
    i = b.index("if (Test-Path $SandboxMarker) {")
    assert b[i:].split("\n", 2)[1].strip() == "try {", "沙箱整段要包在 try 里"
    end = b.index("\n} else {")
    catch = b[b.rindex("} catch {", 0, end):end]  # 最外层的 catch（里面还有小的 try/catch）
    assert "Remove-Item $SecFile" in catch and "throw" not in catch
    assert b.index("$SecFile =") < i  # catch 里要用


def test_sandbox_keeps_working_password():
    # 每次都换密码：改密码和写密码文件之间任何一步出错，两边就对不上（1326）。账户在、密码文件解得开、SID 对得上就不换
    b = sandbox_block()
    assert "ProtectedData]::Unprotect" in b and b.index("ProtectedData]::Unprotect") < b.index("New-LocalUser")
    assert "$Keep = ($old.sid -eq $Existing.SID.Value)" in b
    # 要换：先写临时文件，再改账户密码，马上改名
    tmp = b.index('[IO.File]::WriteAllText("$SecFile.tmp"')
    setpw = b.index("Set-LocalUser -Name $JobUser -Password $JobSecure")
    move = b.index('Move-Item "$SecFile.tmp" $SecFile')
    assert tmp < setpw < move
    assert b.index("New-LocalUser") < tmp  # 新账户要先有 SID 才写得出密码文件
    assert move < b.index("secedit /export")  # 密码文件紧跟着账户写，不夹别的步骤


def test_sandbox_root_denies_execute():
    # 0xd0157 不含 FILE_EXECUTE：任务账户能执行（也能按映像映射进来读）探针、引导器、llama-server
    b = sandbox_block()
    assert 'icacls $Dst /deny "*${JobSid}:(OI)(IO)(X)" /Q' in b


def test_sandbox_data_volumes_deny_read():
    # 非系统盘根上默认 Users 可读，D: 又不被还原：学生、老师的文件。每个固定 NTFS 数据卷的根上拒读（已有就不重做，免得每次整盘传播）
    b = sandbox_block()
    assert "[IO.DriveInfo]::GetDrives()" in b and "DriveType -eq 'Fixed'" in b and "DriveFormat -eq 'NTFS'" in b
    assert "$env:SystemDrive" in b
    assert 'icacls $v /deny "*${JobSid}:(OI)(CI)(RD)" /C /Q' in b
    assert "GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])" in b
    assert 'icacls $v /remove:d "*$OldSid"' in b


def test_uninstall_removes_data_volume_deny():
    s = read("uninstall.ps1")
    assert s.index('/remove:d "*$($jobUser.SID.Value)"') < s.index("Remove-LocalUser -Name epsilon-job")
