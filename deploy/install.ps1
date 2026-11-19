# Epsilon installer for a student machine, from bare metal. Safe to run again: big files already on D: are skipped.
# OSEasy restores C: on reboot, so this must bring back everything that lives on C: (task, firewall, VC++ runtime).
#
# OSEasy remote command (runs as SYSTEM), one line:
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:EPS_KEY='<api key>'; iex (iwr http://<controller>:8090/dl/upgrade/install.ps1 -Headers @{Authorization='Bearer '+$env:EPS_KEY} -UseBasicParsing).Content"
#
# Steps: files -> VC++ runtime (+ app-local DLLs) -> firewall -> job sandbox (OPT-IN) -> check controller
#        -> seed the first signed probe into a slot -> scheduled task running the boot loader -> pool heads fetch the big model.
# The boot loader never talks to the network (docs/boot.md): the probe's loader fetches later versions.
# Log: D:\epsilon\install.log. ASCII only (PowerShell 5.1 reads scripts as ANSI).
#
# Job sandbox (docs/jobs-sandbox.md) is OPT-IN: add  $env:EPS_JOB_SANDBOX='1';  to the one-line command once. That leaves
# D:\epsilon\job-sandbox.enabled, so later runs (repair, after a C: restore) rebuild the account without the variable.
# EPS_JOB_SANDBOX='0' removes the marker; the account and rules then disappear with the next C: restore.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Dst = 'D:\epsilon'
$Ctl = '@CONTROLLER@'                                   # @...@ are filled in by deploy/release.sh from dist/deploy/secrets.env
$Base = "http://${Ctl}:8090/dl"
$BootSha = '@BOOT_SHA256@'
$SeedSha = '@SEED_SHA256@'                               # epsilon-probe.exe of the signed release that goes into the rescue slot R
$Heads = '@POOL_HEADS@' -split ','                      # pooling v1: these download the 27B model
$Pool = '@POOL_RANGE@'                                  # pooling v1: rpc-server only talks to the pool machines

function Step($msg) { Write-Host ""; Write-Host "== $msg" }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Run as administrator.'; return
}
if (-not (Test-Path D:\)) { Write-Host 'No D: drive (data disk).'; return }
if (-not $env:EPS_KEY) { Write-Host 'EPS_KEY is not set. Paste the whole line into cmd or OSEasy, not into a PowerShell prompt.'; return }
New-Item -ItemType Directory -Force $Dst | Out-Null
# Boot loader and probe run as a normal user. No /T: the root ACE is inherited by everything below; /T used to write an
# explicit Users ACE on every file, and explicit allows beat the inherited deny for the job account (docs/jobs-sandbox.md).
icacls $Dst /grant "*S-1-5-32-545:(OI)(CI)M" /Q | Out-Null
try { Start-Transcript -Path "$Dst\install.log" -Force | Out-Null } catch {}
Write-Host "epsilon install on $env:COMPUTERNAME as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) at $(Get-Date)"
$Auth = "Authorization: Bearer $env:EPS_KEY"

function Fetch($path, $to) {
    & curl.exe -sS -f -H $Auth -o $to "$Base/$path"
    if ($LASTEXITCODE -ne 0) { throw "download $path failed (curl $LASTEXITCODE)" }
}
function RemoteSize($path) {
    $r = Invoke-WebRequest "$Base/$path" -Method Head -Headers @{ Authorization = "Bearer $env:EPS_KEY" } -UseBasicParsing
    return [int64]$r.Headers['Content-Length']
}
# A zip counts as installed when the marker next to it records the same zip size.
function EnsureZip($name) {
    $dir = "$Dst\$name"; $marker = "$dir\.zip-size"; $size = RemoteSize "pkg/$name.zip"
    if ((Test-Path $marker) -and ((Get-Content $marker) -eq "$size")) { Write-Host "$name already there"; return }
    if (-not (Test-Path $marker) -and (Test-Path "$dir\llama-server.exe")) {   # installed before markers existed
        Set-Content $marker "$size"; Write-Host "$name already there (marker added)"; return
    }
    Write-Host "downloading $name.zip ($([math]::Round($size/1MB)) MB)"
    $zip = "$Dst\$name.zip"
    Fetch "pkg/$name.zip" $zip
    Expand-Archive $zip $dir -Force
    Remove-Item $zip
    Set-Content $marker "$size"
}

Step "1/8 files -> $Dst"
# Download and verify first: a failed download or a bad hash must leave the probe running and slot R in place.
Fetch 'pkg/probe.json' "$Dst\probe.json.new"
Fetch 'pkg/vc_redist.x64.exe' "$Dst\vc_redist.x64.exe"
Fetch 'upgrade/epsilon-boot.exe' "$Dst\epsilon-boot.exe.new"
$got = (Get-FileHash "$Dst\epsilon-boot.exe.new" -Algorithm SHA256).Hash.ToLower()
if ($got -ne $BootSha) { Remove-Item "$Dst\epsilon-boot.exe.new"; throw "boot loader hash mismatch: $got" }
Write-Host "boot loader OK"
# Rescue slot R (docs/boot.md): the signed release, written only by this installer. The boot loader verifies it
# and runs it with -seed when slots A and B cannot run; we also use it below for the first seed.
# It ships in upgrade/seed/ next to this script, so promoting a new release/ cannot make $SeedSha stale;
# the probe's loader then moves the machine on to the current release.
$R = "$Dst\R"; $RNew = "$Dst\R.new"
Remove-Item -Recurse -Force $RNew -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $RNew | Out-Null
foreach ($f in 'release.json', 'epsilon-probe.exe', 'workloads.json') { Fetch "upgrade/seed/$f" "$RNew\$f" }
$got = (Get-FileHash "$RNew\epsilon-probe.exe" -Algorithm SHA256).Hash.ToLower()
if ($got -ne $SeedSha) { Remove-Item -Recurse -Force $RNew; throw "rescue probe hash mismatch: $got" }
Write-Host "rescue slot R OK"
Stop-ScheduledTask -TaskName epsilon-probe -ErrorAction SilentlyContinue
Get-Process epsilon-boot, epsilon-probe, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Move-Item "$Dst\probe.json.new" "$Dst\probe.json" -Force
Move-Item "$Dst\epsilon-boot.exe.new" "$Dst\epsilon-boot.exe" -Force
Remove-Item -Recurse -Force $R -ErrorAction SilentlyContinue
Move-Item $RNew $R
Remove-Item -Recurse -Force "$Dst\seed" -ErrorAction SilentlyContinue   # older installers kept the seed probe here
New-Item -ItemType Directory -Force "$Dst\models" | Out-Null
$model = 'models\Qwen3.5-4B-Q4_K_M.gguf'
if ((Test-Path "$Dst\$model") -and (Get-Item "$Dst\$model").Length -eq (RemoteSize "pkg/models/Qwen3.5-4B-Q4_K_M.gguf")) { Write-Host 'model already there' }
else { Write-Host 'downloading model (2.6 GB)'; Fetch 'pkg/models/Qwen3.5-4B-Q4_K_M.gguf' "$Dst\$model" }
EnsureZip 'llama'
EnsureZip 'llama-vulkan'

Step '2/8 VC++ runtime (the stock MSVCP140 14.31 makes llama-server crash with 0xc0000005)'
Start-Process "$Dst\vc_redist.x64.exe" -ArgumentList '/install','/quiet','/norestart' -Wait
foreach ($d in 'llama','llama-vulkan') {   # keep a copy next to the exe: survives the C: restore
    Copy-Item C:\Windows\System32\msvcp140*.dll, C:\Windows\System32\vcruntime140*.dll, C:\Windows\System32\concrt140.dll "$Dst\$d" -Force
}
$ErrorActionPreference = 'Continue'   # 5.1 turns native stderr into errors under Stop
$v = & "$Dst\llama\llama-server.exe" --version 2>&1 | Select-String version
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -eq 0 -and $v) { Write-Host "llama-server OK: $v" } else { Write-Host "llama-server does not start (exit $LASTEXITCODE)" }

Step '3/8 firewall'
foreach ($d in 'llama','llama-vulkan') {
    Remove-NetFirewallRule -DisplayName "epsilon-$d" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "epsilon-$d" -Direction Inbound -Action Allow -Program "$Dst\$d\llama-server.exe" -RemoteAddress LocalSubnet,$Ctl | Out-Null
}
Remove-NetFirewallRule -DisplayName 'epsilon-p2p' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'epsilon-p2p' -Direction Inbound -Action Allow -Protocol TCP -LocalPort '47100-47119' -RemoteAddress LocalSubnet | Out-Null
Remove-NetFirewallRule -DisplayName 'epsilon-rpc' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'epsilon-rpc' -Direction Inbound -Action Allow -Program "$Dst\llama\ggml-rpc-server.exe" -RemoteAddress $Pool | Out-Null
Write-Host "rules: epsilon-llama, epsilon-llama-vulkan (subnet + controller), epsilon-p2p (47100-47119 subnet), epsilon-rpc ($Pool)"

Step '4/8 job sandbox (OPT-IN, docs/jobs-sandbox.md): account epsilon-job, password on D:, ACLs, firewall'
$SandboxMarker = "$Dst\job-sandbox.enabled"
if ($env:EPS_JOB_SANDBOX -eq '1') { Set-Content $SandboxMarker 'on' }
if ($env:EPS_JOB_SANDBOX -eq '0') { Remove-Item $SandboxMarker -Force -ErrorAction SilentlyContinue }
$JobUser = 'epsilon-job'
$Sec = "$Dst\secrets"
$SecFile = "$Sec\epsilon-job.json"
if (Test-Path $SandboxMarker) {
  try {
    # The probe is stopped (step 1) and only restarted in step 7: a failure here must not abort the install.
    # The catch below deletes the password file, so the probe's health check fails closed (jobs:false).
    # One-time: replace the explicit Users ACEs that older installers (icacls /T) wrote on every file with inherited ones.
    # Effective rights for Users stay the same. Runs before secrets\ gets its own protected ACL below.
    $ResetMarker = "$Dst\.acl-reset-v1"
    if (-not (Test-Path $ResetMarker)) {
        Write-Host 'one-time ACL reset under D:\epsilon (may take a minute with many env layer files)'
        icacls "$Dst\*" /reset /T /C /Q | Out-Null
        Set-Content $ResetMarker (Get-Date -Format s)
    }
    Add-Type -AssemblyName System.Security
    $Entropy = [Text.Encoding]::UTF8.GetBytes('epsilon-job/v1')
    $Scope = [Security.Cryptography.DataProtectionScope]::LocalMachine
    $OldSid = $null
    if (Test-Path $SecFile) { try { $OldSid = (Get-Content $SecFile -Raw | ConvertFrom-Json).sid } catch {} }
    # a) the account, Users only, never Administrators. Keep the password when the account exists and the password
    #    file still decrypts for the same SID: rotating it every run leaves the two out of step (1326) whenever
    #    anything fails in between. Not baked into the OSEasy image: every machine gets its own password.
    $Existing = Get-LocalUser -Name $JobUser -ErrorAction SilentlyContinue
    $Keep = $false
    if ($Existing -and (Test-Path $SecFile)) {
        try {
            $old = Get-Content $SecFile -Raw | ConvertFrom-Json
            $null = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($old.password_dpapi), $Entropy, $Scope)
            $Keep = ($old.sid -eq $Existing.SID.Value)
        } catch { $Keep = $false }
    }
    if (-not $Keep) {
        $rb = New-Object byte[] 32
        [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rb)
        $JobPlain = 'Aa1-' + [Convert]::ToBase64String($rb)   # new random password (never printed)
        $JobSecure = ConvertTo-SecureString $JobPlain -AsPlainText -Force
        if (-not $Existing) {
            New-LocalUser -Name $JobUser -Password $JobSecure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -Description 'Epsilon batch jobs' | Out-Null
        }
    }
    $JobSid = (Get-LocalUser -Name $JobUser).SID.Value
    # b) password file, D: only, right after the account. DPAPI LocalMachine scope (this script is SYSTEM, the probe
    #    is the logged-on user), extra entropy epsilon-job/v1. The deny ACE is what keeps job processes out; DPAPI only
    #    stops reading a copied D:. secrets\ is readable by BU: every local user is trusted like the probe.
    #    Rotating an existing account: write the new file first, then set the password, then rename.
    New-Item -ItemType Directory -Force $Sec | Out-Null
    $acl = Get-Acl $Sec
    $acl.SetSecurityDescriptorSddlForm("D:P(D;OICI;FA;;;$JobSid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)", 'Access')
    Set-Acl -Path $Sec -AclObject $acl
    if (-not $Keep) {
        $blob = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($JobPlain), $Entropy, $Scope)
        $json = '{"version":1,"user":"' + $JobUser + '","sid":"' + $JobSid + '","password_dpapi":"' + [Convert]::ToBase64String($blob) + '"}'
        [IO.File]::WriteAllText("$SecFile.tmp", $json)   # UTF-8, no BOM
        if ($Existing) { Set-LocalUser -Name $JobUser -Password $JobSecure }
        Move-Item "$SecFile.tmp" $SecFile -Force
        Remove-Variable JobPlain, JobSecure, rb, blob, json
    }
    Set-LocalUser -Name $JobUser -PasswordNeverExpires $true -AccountNeverExpires -UserMayChangePassword $false
    Enable-LocalUser -Name $JobUser
    try { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $JobUser -ErrorAction Stop } catch {}   # already a member
    Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $JobUser -ErrorAction SilentlyContinue
    # c) hide it from the logon screen
    $UserList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if (-not (Test-Path $UserList)) { New-Item -Path $UserList -Force | Out-Null }
    New-ItemProperty -Path $UserList -Name $JobUser -Value 0 -PropertyType DWord -Force | Out-Null
    # d) logon rights: deny network / RDP / batch / service. NOT SeDenyInteractiveLogonRight: seclogon logs on interactively.
    $inf = "$env:TEMP\eps-rights.inf"; $sdb = "$env:TEMP\eps-rights.sdb"
    secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    $cur = @{}
    foreach ($l in (Get-Content $inf)) { if ($l -match '^(Se\w+)\s*=\s*(.*)$') { $cur[$Matches[1]] = $Matches[2] } }
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
    foreach ($r in 'SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight') {
        $v = @()
        if ($cur[$r]) { $v = @($cur[$r] -split ',' | Where-Object { $_ -and $_ -ne "*$OldSid" }) }
        if ($v -notcontains "*$JobSid") { $v += "*$JobSid" }
        $lines += "$r = $($v -join ',')"
    }
    Set-Content -Path $inf -Value $lines -Encoding Unicode
    secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
    $seExit = $LASTEXITCODE
    Remove-Item $inf, $sdb -Force -ErrorAction SilentlyContinue
    if ($seExit -ne 0) { throw "secedit failed ($seExit)" }
    # e) CreateProcessWithLogonW goes through Secondary Logon
    if ((Get-Service seclogon).StartType -eq 'Disabled') { Set-Service seclogon -StartupType Manual }
    # f) the job account reads nothing under D:\epsilon (probe.json, secrets\, logs, other jobs), writes nothing
    #    (slots, keyring version, env layers incl. sitecustomize.py) and executes nothing (probe, boot loader, llama-server).
    #    Env layers: read + execute (explicit allow on envs\ comes before the inherited denies). Job dirs get their own
    #    protected ACL from the probe. 0xd0157 = read/list, write, append, write EA, delete child, write attributes, delete, WRITE_DAC, WRITE_OWNER.
    if ($OldSid -and $OldSid -ne $JobSid) {   # the account was recreated (C: restore): drop the dead SID's ACEs
        icacls $Dst /remove:d "*$OldSid" /Q | Out-Null
        if (Test-Path "$Dst\envs") { icacls "$Dst\envs" /remove:g "*$OldSid" /Q | Out-Null }
    }
    icacls $Dst /deny "*${JobSid}:(OI)(CI)(RD,WD,AD,WEA,DC,WA,DE,WDAC,WO)" /Q | Out-Null
    icacls $Dst /deny "*${JobSid}:(OI)(IO)(X)" /Q | Out-Null
    New-Item -ItemType Directory -Force "$Dst\envs" | Out-Null
    icacls "$Dst\envs" /grant "*${JobSid}:(OI)(CI)RX" /Q | Out-Null
    # g) data volumes (D: is not restored; its root lets Users read by default: students' and teachers' files).
    #    Deny read/list on the root of every fixed NTFS volume except the system drive. Only when missing: adding it
    #    propagates through the whole volume. Job dirs and secrets\ are protected; envs\ has its explicit allow.
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -eq 'Fixed' -and $d.DriveFormat -eq 'NTFS' -and $d.Name -ne "$env:SystemDrive\") {
            $v = $d.Name
            if ($OldSid -and $OldSid -ne $JobSid) { icacls $v /remove:d "*$OldSid" /C /Q | Out-Null }
            $rules = (Get-Acl $v).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
            if (-not ($rules | Where-Object { $_.AccessControlType -eq 'Deny' -and $_.IdentityReference.Value -eq $JobSid })) {
                Write-Host "deny read for $JobUser on $v (propagates through the volume)"
                icacls $v /deny "*${JobSid}:(OI)(CI)(RD)" /C /Q | Out-Null
            }
        }
    }
    # h) firewall by account SID, not by program path: covers every process of this account (env layer exes,
    #    System32 tools, anything that escaped the job object). Inbound too: epsilon-p2p allows 47100-47119 to any program.
    #    Not covered (docs/jobs-sandbox.md 4 and 8): DNS (dnscache), UNC (SMB/WebDAV redirectors run as System),
    #    loopback (Windows Firewall does not filter it).
    Remove-NetFirewallRule -DisplayName 'epsilon-job-out' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'epsilon-job-out' -Direction Outbound -Action Block -Protocol Any -Profile Any -LocalUser "O:LSD:(A;;CC;;;$JobSid)" | Out-Null
    Remove-NetFirewallRule -DisplayName 'epsilon-job-in' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'epsilon-job-in' -Direction Inbound -Action Block -Protocol Any -Profile Any -LocalUser "O:LSD:(A;;CC;;;$JobSid)" | Out-Null
    Write-Host "job sandbox ready: account $JobUser ($JobSid), rules epsilon-job-out / epsilon-job-in, $SecFile"
  } catch {
    Remove-Item $SecFile, "$SecFile.tmp" -Force -ErrorAction SilentlyContinue
    Write-Host "job sandbox setup FAILED, password file removed (probe reports jobs:false; rerun install.ps1): $_"
  }
} else {
    Write-Host 'job sandbox off (OPT-IN: pass EPS_JOB_SANDBOX=1 once); probe.json "jobs_sandboxed": true will report jobs:false'
}

Step "5/8 controller $Ctl`:8090"
$ok = (Test-NetConnection $Ctl -Port 8090 -WarningAction SilentlyContinue).TcpTestSucceeded
if ($ok) { Write-Host 'reachable' } else { Write-Host 'NOT reachable' }

Step '6/8 seed: put the current signed release into a free slot (boot loader picks it up and trial-starts it)'
$ErrorActionPreference = 'Continue'
$enc = $null
try { $enc = [Console]::OutputEncoding; [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}   # the probe prints UTF-8; 5.1 would decode it as the ANSI code page
& "$R\epsilon-probe.exe" -seed -config "$Dst\probe.json" -root $Dst 2>&1 | ForEach-Object { Write-Host $_ }
$seedExit = $LASTEXITCODE
if ($enc) { try { [Console]::OutputEncoding = $enc } catch {} }
$ErrorActionPreference = 'Stop'
if ($seedExit -eq 0) { Write-Host 'seed OK' } else { Write-Host "seed failed (exit $seedExit): boot loader will have nothing to start until the probe gets a slot" }

Step '7/8 scheduled task -> boot loader (runs in the logged-on user session: SYSTEM cannot see keyboard and mouse)'
$act = New-ScheduledTaskAction -Execute "$Dst\epsilon-boot.exe" -Argument "-root $Dst" -WorkingDirectory $Dst
$trg = New-ScheduledTaskTrigger -AtLogOn
$who = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited   # BUILTIN\Users = whoever logs on, not elevated
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName epsilon-probe -Action $act -Trigger $trg -Principal $who -Settings $set -Force | Out-Null
Start-ScheduledTask -TaskName epsilon-probe   # starts now if someone is logged on, else at next logon
Start-Sleep 8
if (Get-Process epsilon-boot -ErrorAction SilentlyContinue) { Write-Host 'boot loader running (logs: D:\epsilon\boot.log, probe.log)' }
else { Write-Host 'boot loader not running yet (nobody logged on?) - it starts at next logon' }

Step '8/8 big models for pool heads'
if ($Heads -contains $env:COMPUTERNAME) {
    foreach ($m in 'Qwen3.8-27B-Q4_K_M.gguf', 'mtp-Qwen3.8-27B-Q4_0.gguf') {
        if ((Test-Path "$Dst\models\$m") -and (Get-Item "$Dst\models\$m").Length -eq (RemoteSize "pkg/models/$m")) { Write-Host "$m already there"; continue }
        # detached so the remote command returns now; curl resumes a partial file
        Start-Process curl.exe -WindowStyle Hidden -ArgumentList '-sS', '-f', '-C', '-', '-H', "`"$Auth`"", '-o', "`"$Dst\models\$m`"", "$Base/pkg/models/$m"
        Write-Host "downloading $m in background"
    }
} else { Write-Host 'not a pool head, skipped' }

Write-Host ""
Write-Host "All done on $env:COMPUTERNAME."
try { Stop-Transcript | Out-Null } catch {}
