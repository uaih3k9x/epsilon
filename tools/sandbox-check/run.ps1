# Epsilon job sandbox: real-machine verification suite (docs/jobs-sandbox.md section 7, all 18 items).
# Run ONLY on a sacrificial machine (full disk image first, see README.md). One command, from an elevated PowerShell:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\epsilon\sandbox-check\run.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\epsilon\sandbox-check\run.ps1 -EnvDir D:\epsilon\envs\py311-torch2.5-cu124@2
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\epsilon\sandbox-check\run.ps1 -AfterRestore     (after a reboot / C: restore: item 8 only)
#
# Prechecks (if one fails NOTHING is changed): administrator; D:\epsilon\job-sandbox.enabled (install.ps1 ran with
# EPS_JOB_SANDBOX=1); D:\epsilon\sandbox-check.optin (created by you: "this machine may be broken"); kit copied under D:\epsilon;
# probe stopped (Stop-ScheduledTask epsilon-probe); no process of epsilon-job running.
#
# What it does: install-state checks here (elevated), then epsilon-sandbox-check.exe "limited" in a temporary scheduled task
# with the probe's own principal (BUILTIN\Users, RunLevel Limited). That runs epsilon-probe.exe -sandbox-selftest and the
# per-item checks through the probe's own sandbox code (jobbox). Cleanup at the end: the temporary task, test processes,
# test job dirs (jobs\_check-*), quarantined test dirs, stray canary files. The epsilon-job account is NEVER removed
# (this script does not create it); to roll back use deploy\uninstall.ps1 (README.md).
#
# Result: D:\epsilon\sandbox-check-<time>.txt (read this) and .json; raw evidence in <kit>\run-<time>\.
# Exit code: 0 no FAIL, 1 some FAIL, 2 precheck failed.
# ASCII only: PowerShell 5.1 reads scripts as ANSI and cmd mangles non-ASCII output. Compatible with PowerShell 5.1.

[CmdletBinding()]
param(
    [string]$EnvDir = '',
    [switch]$AfterRestore,
    [int]$TimeoutMinutes = 60,
    [string]$Root = 'D:\epsilon'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$JobUser = 'epsilon-job'
$TaskName = 'epsilon-sandbox-check'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Utf8 = New-Object System.Text.UTF8Encoding $false
$Kit = Split-Path -Parent $MyInvocation.MyCommand.Path

function Stop-Pre([string]$msg) {
    Write-Host "PRECHECK FAILED: $msg"
    Write-Host 'Nothing was changed.'
    exit 2
}

# ---------------- prechecks (read-only) ----------------
if ($PSVersionTable.PSVersion.Major -lt 5) { Stop-Pre 'PowerShell 5.1 or later is needed' }
if (-not [Environment]::Is64BitProcess) { Stop-Pre 'use the 64-bit PowerShell' }
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Pre 'run from an elevated PowerShell (Run as administrator)'
}
if (-not (Test-Path "$Root\probe.json")) { Stop-Pre "$Root\probe.json not found (is the probe installed?)" }
if (-not (Test-Path "$Root\job-sandbox.enabled")) {
    Stop-Pre "$Root\job-sandbox.enabled not found: run install.ps1 once with EPS_JOB_SANDBOX=1 first"
}
if (-not (Test-Path "$Root\sandbox-check.optin")) {
    Stop-Pre "create $Root\sandbox-check.optin to confirm this is a sacrificial machine with a disk image backup (README.md)"
}
$KitFull = (Resolve-Path $Kit).Path.TrimEnd('\')
if (-not $KitFull.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase)) {
    Stop-Pre "copy the kit under $Root (e.g. $Root\sandbox-check); it is now at $KitFull"
}
$Helper = Join-Path $KitFull 'epsilon-sandbox-check.exe'
if (-not (Test-Path $Helper)) { Stop-Pre "missing $Helper" }
$ProbeExe = Join-Path $KitFull 'epsilon-probe.exe'
if (-not (Test-Path $ProbeExe)) { $ProbeExe = '' }
$pt = Get-ScheduledTask -TaskName epsilon-probe -ErrorAction SilentlyContinue
if ($pt -and "$($pt.State)" -eq 'Running') { Stop-Pre 'the probe is running: Stop-ScheduledTask epsilon-probe (then wait a few seconds)' }
$running = @(Get-Process epsilon-boot, epsilon-probe, epsilon-sandbox-check, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) {
    Stop-Pre ('still running: ' + (($running | ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ', ') + '. Stop-ScheduledTask epsilon-probe; Get-Process epsilon-boot,epsilon-probe | Stop-Process')
}
$jobProcs = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like "*\$JobUser" })
if ($jobProcs.Count -gt 0) {
    Stop-Pre ("processes of $JobUser are running: " + (($jobProcs | ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ', '))
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-Pre "a previous run left the scheduled task ${TaskName}: Unregister-ScheduledTask $TaskName -Confirm:`$false"
}
$Account = Get-LocalUser -Name $JobUser -ErrorAction SilentlyContinue
if (-not $Account -and -not $AfterRestore) { Stop-Pre "account $JobUser not found: rerun install.ps1 (EPS_JOB_SANDBOX=1)" }
if ($EnvDir) {
    if (-not (Test-Path (Join-Path $EnvDir 'python.exe'))) { Stop-Pre "no python.exe in $EnvDir" }
    $EnvDir = (Resolve-Path $EnvDir).Path.TrimEnd('\')
} else {
    # newest env layer that has the audit hook (sitecustomize.py, layer version @2 or later)
    $cand = @(Get-ChildItem "$Root\envs" -Directory -ErrorAction SilentlyContinue | Where-Object {
            (Test-Path (Join-Path $_.FullName 'python.exe')) -and (Test-Path (Join-Path $_.FullName 'Lib\site-packages\sitecustomize.py'))
        } | Sort-Object LastWriteTime -Descending)
    if ($cand.Count -gt 0) { $EnvDir = $cand[0].FullName }
}

# ---------------- run ----------------
$Work = Join-Path $KitFull "run-$Stamp"
New-Item -ItemType Directory -Force $Work | Out-Null
$PsFile = Join-Path $Work 'ps.jsonl'
$CleanFile = Join-Path $Work 'cleanup.jsonl'
$Report = "$Root\sandbox-check-$Stamp"
Write-Host "epsilon sandbox check on $env:COMPUTERNAME at $(Get-Date)"
Write-Host "kit $KitFull  work $Work"
if ($EnvDir) { Write-Host "env layer $EnvDir" } else { Write-Host 'no env layer with sitecustomize.py found: python/torch checks will be SKIP' }
if (-not $ProbeExe) { Write-Host 'no epsilon-probe.exe in the kit: -sandbox-selftest will be SKIP' }

function Add-Result([string]$file, [int]$item, [string]$id, [string]$status, $evidence) {
    $o = New-Object PSObject -Property ([ordered]@{ item = $item; id = $id; status = $status; evidence = [string]$evidence; source = 'ps' })
    [IO.File]::AppendAllText($file, (ConvertTo-Json -InputObject $o -Compress) + "`n", $Utf8)
    Write-Host ('{0,-6} {1}' -f $status, $id)
}

# Check runs a block that returns @{s='PASS|FAIL|SKIP|MANUAL'; e='evidence'} (last output wins); an exception is a FAIL.
function Check([int]$item, [string]$id, [scriptblock]$body) {
    try {
        $r = @(& $body)[-1]
        Add-Result $PsFile $item $id $r.s $r.e
    } catch {
        Add-Result $PsFile $item $id 'FAIL' ('exception: ' + $_.Exception.Message)
    }
}

function Rules-For([string]$path, [string]$sid) {
    @((Get-Acl -LiteralPath $path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $sid })
}
function Describe-Rules($rules) {
    ($rules | ForEach-Object { '{0} 0x{1:x} inh={2} prop={3} inherited={4}' -f $_.AccessControlType, [int64]$_.FileSystemRights, [int]$_.InheritanceFlags, [int]$_.PropagationFlags, $_.IsInherited }) -join '; '
}
function Has-Rule($rules, [string]$type, [int64]$mask, [int]$inh, [int]$prop) {
    @($rules | Where-Object {
            "$($_.AccessControlType)" -eq $type -and (([int64]$_.FileSystemRights -band $mask) -eq $mask) -and
            (([int]$_.InheritanceFlags -band $inh) -eq $inh) -and (([int]$_.PropagationFlags -band $prop) -eq $prop)
        }).Count -gt 0
}

$Sid = ''
if ($Account) { $Sid = $Account.SID.Value }

try {
    Add-Result $PsFile 0 '0.prechecks' 'PASS' ("admin, markers, probe stopped; account SID $Sid; env '$EnvDir'; selftest exe '$ProbeExe'; AfterRestore=$AfterRestore")

    if ($AfterRestore) {
        Check 8 '8.after_restore_account' {
            if ($Account) { @{ s = 'PASS'; e = "account still there ($Sid)" } } else { @{ s = 'PASS'; e = 'account gone after the C: restore (expected; probe must report jobs:false)' } }
        }
    } else {
        # ---- item 12: what install.ps1 step 4/8 left behind ----
        Check 12 '12.account' {
            $u = Get-LocalUser -Name $JobUser
            $bad = @()
            if (-not $u.Enabled) { $bad += 'disabled' }
            if ($u.PasswordExpires) { $bad += "password expires $($u.PasswordExpires)" }
            if ($u.UserMayChangePassword) { $bad += 'user may change the password' }
            if ($u.AccountExpires) { $bad += "account expires $($u.AccountExpires)" }
            $ev = "enabled=$($u.Enabled) passwordExpires=$($u.PasswordExpires) userMayChangePassword=$($u.UserMayChangePassword) accountExpires=$($u.AccountExpires) lastLogon=$($u.LastLogon)"
            if ($bad.Count -eq 0) { @{ s = 'PASS'; e = $ev } } else { @{ s = 'FAIL'; e = ($bad -join '; ') + ' | ' + $ev } }
        }
        Check 12 '12.groups' {
            $u = [ADSI]"WinNT://$env:COMPUTERNAME/$JobUser,user"
            $sids = @()
            foreach ($g in $u.Groups()) {
                $bytes = $g.GetType().InvokeMember('objectSid', 'GetProperty', $null, $g, $null)
                $sids += (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value
            }
            if ($sids.Count -eq 1 -and $sids[0] -eq 'S-1-5-32-545') { @{ s = 'PASS'; e = 'direct local groups: Users only' } }
            else { @{ s = 'FAIL'; e = 'direct local groups (must be exactly S-1-5-32-545): ' + ($sids -join ', ') } }
        }
        Check 12 '12.hidden_from_logon' {
            $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
            $v = (Get-ItemProperty -Path $k -Name $JobUser -ErrorAction Stop).$JobUser
            if ($v -eq 0) { @{ s = 'PASS'; e = "UserList $JobUser=0" } } else { @{ s = 'FAIL'; e = "UserList $JobUser=$v" } }
        }
        Check 12 '12.secrets_acl' {
            $a = Get-Acl -LiteralPath "$Root\secrets"
            $rules = Rules-For "$Root\secrets" $Sid
            $ok = $a.AreAccessRulesProtected -and (Has-Rule $rules 'Deny' 0x1f01ff 3 0)
            $ev = "protected=$($a.AreAccessRulesProtected) job: $(Describe-Rules $rules) | sddl $($a.Sddl)"
            if ($ok) { @{ s = 'PASS'; e = $ev } } else { @{ s = 'FAIL'; e = 'need a protected DACL with (D;OICI;FA;;;job) | ' + $ev } }
        }
        Check 12 '12.root_acl' {
            $rules = Rules-For $Root $Sid
            $ok = (Has-Rule $rules 'Deny' 0xd0157 3 0) -and (Has-Rule $rules 'Deny' 0x20 2 2)
            $ev = "$Root job: $(Describe-Rules $rules)"
            if ($ok) { @{ s = 'PASS'; e = $ev } } else { @{ s = 'FAIL'; e = 'need deny 0xd0157 (OI)(CI) and deny 0x20 (OI)(IO) | ' + $ev } }
        }
        Check 12 '12.envs_acl' {
            $rules = Rules-For "$Root\envs" $Sid
            $ok = Has-Rule $rules 'Allow' 0x1200a9 3 0
            $ev = "$Root\envs job: $(Describe-Rules $rules)"
            if ($ok) { @{ s = 'PASS'; e = $ev } } else { @{ s = 'FAIL'; e = 'need allow RX (OI)(CI) | ' + $ev } }
        }
        Check 12 '12.data_volume_roots' {
            $good = @(); $bad = @()
            foreach ($d in [IO.DriveInfo]::GetDrives()) {
                if ($d.DriveType -eq 'Fixed' -and $d.IsReady -and $d.DriveFormat -eq 'NTFS' -and $d.Name -ne "$env:SystemDrive\") {
                    if (Has-Rule (Rules-For $d.Name $Sid) 'Deny' 0x1 3 0) { $good += $d.Name } else { $bad += $d.Name }
                }
            }
            $ev = "deny read on: $($good -join ' ') | missing on: $($bad -join ' ')"
            if ($bad.Count -eq 0) { @{ s = 'PASS'; e = $ev } } else { @{ s = 'FAIL'; e = $ev } }
        }
        Check 12 '12.install_log' {
            $log = "$Root\install.log"
            if (-not (Test-Path $log)) { return @{ s = 'SKIP'; e = 'no install.log' } }
            $txt = Get-Content -LiteralPath $log -Raw
            $when = (Get-Item -LiteralPath $log).LastWriteTime
            if ($txt -match 'job sandbox setup FAILED[^\r\n]*') { @{ s = 'FAIL'; e = "$($Matches[0]) (install.log $when)" } }
            elseif ($txt -match 'job sandbox ready[^\r\n]*') { @{ s = 'PASS'; e = "$($Matches[0]) (install.log $when)" } }
            else { @{ s = 'FAIL'; e = "no 'job sandbox ready' line in install.log ($when)" } }
        }
        Add-Result $PsFile 12 '12.fault_injection_and_timing' 'MANUAL' 'not automated: time install.ps1 step 4/8 (one-time /reset, data volume deny propagation) and make one step fail on purpose; README section MANUAL'

        # ---- item 9: seclogon and logon rights ----
        Check 9 '9.seclogon' {
            $s = Get-Service seclogon
            $ev = "status=$($s.Status) start=$($s.StartType)"
            if ("$($s.StartType)" -eq 'Disabled') { @{ s = 'FAIL'; e = $ev } } else { @{ s = 'PASS'; e = $ev } }
        }
        Check 9 '9.secedit_rights' {
            $inf = Join-Path $Work 'rights.inf'
            $ErrorActionPreference = 'Continue'
            secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
            $ErrorActionPreference = 'Stop'
            $cur = @{}
            foreach ($l in (Get-Content $inf)) { if ($l -match '^(Se\w+)\s*=\s*(.*)$') { $cur[$Matches[1]] = $Matches[2] } }
            Remove-Item $inf -Force -ErrorAction SilentlyContinue
            $names = @("*$Sid", $JobUser, "$env:COMPUTERNAME\$JobUser")
            function HasJob($v) { @(($v -split ',') | Where-Object { $names -contains $_.Trim() }).Count -gt 0 }
            $bad = @()
            foreach ($r in 'SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight') {
                if (-not (HasJob $cur[$r])) { $bad += "$r lacks the job account" }
            }
            if (HasJob $cur['SeDenyInteractiveLogonRight']) { $bad += 'SeDenyInteractiveLogonRight has the job account (seclogon needs local logon)' }
            $ev = (('SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyInteractiveLogonRight', 'SeInteractiveLogonRight') |
                    ForEach-Object { "$_=$($cur[$_])" }) -join ' | '
            if ($bad.Count -eq 0) { @{ s = 'PASS'; e = $ev } } else { @{ s = 'FAIL'; e = ($bad -join '; ') + ' || ' + $ev } }
        }

        # ---- item 5: firewall rules by account SID ----
        Check 5 '5.fw_rules' {
            $bad = @(); $ev = @()
            foreach ($n in 'epsilon-job-out', 'epsilon-job-in') {
                $rs = @(Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)
                if ($rs.Count -ne 1) { $bad += "$n x$($rs.Count)"; continue }
                $r = $rs[0]
                $sf = $r | Get-NetFirewallSecurityFilter
                $ev += "$n enabled=$($r.Enabled) action=$($r.Action) dir=$($r.Direction) profile=$($r.Profile) localUser=$($sf.LocalUser) auth=$($sf.Authentication) enc=$($sf.Encryption)"
                if ("$($r.Enabled)" -ne 'True') { $bad += "$n disabled" }
                if ("$($r.Action)" -ne 'Block') { $bad += "$n not Block" }
                if ("$($sf.LocalUser)" -notmatch [regex]::Escape($Sid)) { $bad += "$n LocalUser lacks the job SID" }
                if ("$($sf.Authentication)" -ne 'NotRequired' -or "$($sf.Encryption)" -ne 'NotRequired') { $bad += "$n needs IPsec" }
            }
            if ($bad.Count -eq 0) { @{ s = 'PASS'; e = $ev -join ' | ' } } else { @{ s = 'FAIL'; e = ($bad -join '; ') + ' || ' + ($ev -join ' | ') } }
        }
        Add-Result $PsFile 5 '5.inbound_from_remote' 'MANUAL' 'needs a second machine: the inbound rule exists (5.fw_rules), but blocking a remote connection to a port the job listens on is not tested here'

        # ---- item 13: listening TCP ports (the job account reaches loopback without the firewall) ----
        Check 13 '13.listeners' {
            $lis = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
                    $pn = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                    New-Object PSObject -Property ([ordered]@{ addr = "$($_.LocalAddress)"; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; proc = "$pn" })
                })
            [IO.File]::WriteAllText((Join-Path $Work 'listeners.json'), (ConvertTo-Json -InputObject $lis -Compress), $Utf8)
            $ErrorActionPreference = 'Continue'
            netstat -ano | Out-File -Encoding ascii (Join-Path $Work 'netstat.txt')
            $ErrorActionPreference = 'Stop'
            @{ s = 'MANUAL'; e = 'confirm each needs authentication: ' + (($lis | ForEach-Object { "$($_.addr):$($_.port) $($_.proc)" }) -join ', ') }
        }

        Add-Result $PsFile 8 '8.after_restore' 'MANUAL' 'reboot so C: is restored (if this machine has restore), then run run.ps1 -AfterRestore'

        # ---- docs section 7 steps this kit does not automate (review #17 item 4): one MANUAL each, so the overall is never PASS ----
        Add-Result $PsFile 3 '3.baseline_compare' 'MANUAL' 'not automated (step 3): compare VRAM and wall time of smoke and the torch GPU + DataLoader job with a run before the sandbox'
        Add-Result $PsFile 19 '19.attack_pack' 'MANUAL' 'not automated (step 4): attack job pack with the test keyring: exe in tmp, tmp dll, ProgramData, probe.json, controller, DNS, UNC, subprocess, WMI Win32_Process.Create, schtasks, mklink /J in output, own ACL, CreateFileW with its own DACL, a background process left running, a second job reading the output of the first; each must be blocked and logged, an escaped process must halt the node'
        Add-Result $PsFile 20 '20.kill_probe_midway' 'MANUAL' 'not automated (step 5): kill the probe while a job runs; the whole job tree must die'
        Add-Result $PsFile 21 '21.overhead' 'MANUAL' 'not automated (step 7): canary time per job and torch import time under Low IL (selftest and 3.torch_import show part of it)'
    }

    # ---------------- limited phase: same principal as the probe ----------------
    $hArgs = @('limited', '-config', "`"$Root\probe.json`"", '-work', "`"$Work`"")
    $lisFile = Join-Path $Work 'listeners.json'
    if (Test-Path $lisFile) { $hArgs += @('-listeners', "`"$lisFile`"") }
    if ($EnvDir) { $hArgs += @('-env', "`"$EnvDir`"") }
    if ($ProbeExe) { $hArgs += @('-probe', "`"$ProbeExe`"") }
    if ($AfterRestore) { $hArgs += '-health-only' }
    $act = New-ScheduledTaskAction -Execute $Helper -Argument ($hArgs -join ' ') -WorkingDirectory $Work
    $who = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
    $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes ($TimeoutMinutes + 5)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $act -Principal $who -Settings $set -Force | Out-Null
    $started = Get-Date
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "limited phase started (scheduled task $TaskName, up to $TimeoutMinutes min); a console window shows its progress"
    $done = Join-Path $Work 'limited.done'
    $results = Join-Path $Work 'limited.jsonl'
    $deadline = $started.AddMinutes($TimeoutMinutes)
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $done) { $ok = $true; break }
        if (((Get-Date) - $started).TotalSeconds -gt 120 -and -not (Test-Path $results)) {
            $info = Get-ScheduledTaskInfo -TaskName $TaskName
            Add-Result $PsFile 0 '0.limited_phase' 'FAIL' "the helper did not start within 2 minutes (is a user logged on interactively? LastTaskResult=$($info.LastTaskResult))"
            break
        }
        Start-Sleep 5
    }
    if (-not $ok -and (Test-Path $results)) {
        Add-Result $PsFile 0 '0.limited_phase' 'FAIL' "the helper did not finish within $TimeoutMinutes minutes (partial results kept)"
    } elseif ($ok) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Add-Result $PsFile 0 '0.limited_phase' 'PASS' ("finished in {0:N0} s, LastTaskResult={1}" -f ((Get-Date) - $started).TotalSeconds, $info.LastTaskResult)
    }
} catch {
    Add-Result $PsFile 0 '0.run_ps1_error' 'FAIL' ("$($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)")
} finally {
    # ---------------- cleanup (never removes the epsilon-job account) ----------------
    $ErrorActionPreference = 'Continue'
    Write-Host ''
    Write-Host '== cleanup'
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Add-Result $CleanFile 0 '0.cleanup_task' 'FAIL' "scheduled task $TaskName still there" }
    else { Add-Result $CleanFile 0 '0.cleanup_task' 'PASS' "scheduled task $TaskName removed" }
    $mine = @(Get-Process epsilon-sandbox-check, epsilon-probe -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($KitFull, [StringComparison]::OrdinalIgnoreCase) })
    $mine | Stop-Process -Force -ErrorAction SilentlyContinue
    $left = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like "*\$JobUser" })
    $left | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
    $still = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like "*\$JobUser" })
    $st = 'PASS'; if ($still.Count -gt 0) { $st = 'FAIL' }
    Add-Result $CleanFile 0 '0.cleanup_processes' $st ("helper/selftest stopped: $($mine.Count); $JobUser processes stopped: $($left.Count) (" + (($left | ForEach-Object { $_.ProcessName }) -join ',') + "); still alive: $($still.Count)")

    # test job dirs and quarantined test dirs; a dir the job locked against everyone needs take-ownership first
    $dirs = @()
    $dirs += @(Get-ChildItem "$Root\jobs" -Directory -Force -Filter '_check-*' -ErrorAction SilentlyContinue)
    $dirs += @(Get-ChildItem "$Root\jobs" -Directory -Force -Filter '_selftest' -ErrorAction SilentlyContinue)
    $dirs += @(Get-ChildItem (Join-Path $Work 'quarantine') -Directory -Force -ErrorAction SilentlyContinue)
    $gone = @(); $kept = @()
    foreach ($d in $dirs) {
        $p = $d.FullName
        cmd /c rmdir /s /q "$p" 2>$null
        if (Test-Path -LiteralPath $p) {
            takeown /f "$p" /a /r /d y 2>&1 | Out-Null
            icacls "$p" /reset /t /c /q 2>&1 | Out-Null
            cmd /c rmdir /s /q "$p" 2>$null
        }
        if (Test-Path -LiteralPath $p) { $kept += $p } else { $gone += $p }
    }
    $st = 'PASS'; if ($kept.Count -gt 0) { $st = 'FAIL' }
    Add-Result $CleanFile 0 '0.cleanup_dirs' $st ("removed $($gone.Count) test dirs; could not remove: " + ($kept -join ', '))
    $stray = @()
    foreach ($pat in "$env:ProgramData\epsilon-canary-*", "$env:SystemRoot\Temp\epsilon-canary-*", "$env:PUBLIC\epsilon-canary-*") {
        $stray += @(Get-ChildItem $pat -Force -ErrorAction SilentlyContinue)
    }
    $stray | Remove-Item -Force -ErrorAction SilentlyContinue
    $st = 'PASS'; if ($stray.Count -gt 0) { $st = 'FAIL' }   # a canary file outside the job dir means a write that should have been denied
    Add-Result $CleanFile 0 '0.cleanup_stray_files' $st ("canary files outside the job dir: " + (($stray | ForEach-Object { $_.FullName }) -join ', '))
    $rules = @(Get-NetFirewallRule -DisplayName 'epsilon-check-*' -ErrorAction SilentlyContinue)
    $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Add-Result $CleanFile 0 '0.cleanup_fw_rules' 'PASS' "temporary firewall rules removed: $($rules.Count) (this suite creates none)"
}

# ---------------- report ----------------
Write-Host ''
Write-Host '== report'
& $Helper report -work $Work -out $Report
$rc = $LASTEXITCODE
if ($rc -ge 2 -or -not (Test-Path "$Report.txt")) {
    Get-Content (Join-Path $Work '*.jsonl') | Set-Content -Encoding UTF8 "$Report.raw.jsonl"
    Write-Host "report generation failed (exit $rc); raw results: $Report.raw.jsonl"
    exit 1
}
Write-Host ''
Write-Host "Report: $Report.txt  (JSON: $Report.json, evidence: $Work)"
Write-Host 'The probe is still stopped: Start-ScheduledTask epsilon-probe (or reboot) to bring it back.'
exit $rc
