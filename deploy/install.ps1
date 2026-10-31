# Epsilon installer for a student machine, from bare metal. Safe to run again: big files already on D: are skipped.
# OSEasy restores C: on reboot, so this must bring back everything that lives on C: (task, firewall, VC++ runtime).
#
# OSEasy remote command (runs as SYSTEM), one line:
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:EPS_KEY='<api key>'; iex (iwr http://<controller>:8090/dl/upgrade/install.ps1 -Headers @{Authorization='Bearer '+$env:EPS_KEY} -UseBasicParsing).Content"
#
# Steps: files -> VC++ runtime (+ app-local DLLs) -> firewall -> check controller -> seed the first signed probe into a slot
#        -> scheduled task running the boot loader -> pool heads fetch the big model in the background.
# The boot loader never talks to the network (docs/boot.md): the probe's loader fetches later versions.
# Log: D:\epsilon\install.log. ASCII only (PowerShell 5.1 reads scripts as ANSI).

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
icacls $Dst /grant "*S-1-5-32-545:(OI)(CI)M" /T /Q | Out-Null   # boot loader and probe run as a normal user
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

Step "1/7 files -> $Dst"
Stop-ScheduledTask -TaskName epsilon-probe -ErrorAction SilentlyContinue
Get-Process epsilon-boot, epsilon-probe, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Fetch 'pkg/probe.json' "$Dst\probe.json"
Fetch 'pkg/vc_redist.x64.exe' "$Dst\vc_redist.x64.exe"
Fetch 'upgrade/epsilon-boot.exe' "$Dst\epsilon-boot.exe.new"
$got = (Get-FileHash "$Dst\epsilon-boot.exe.new" -Algorithm SHA256).Hash.ToLower()
if ($got -ne $BootSha) { Remove-Item "$Dst\epsilon-boot.exe.new"; throw "boot loader hash mismatch: $got" }
Move-Item "$Dst\epsilon-boot.exe.new" "$Dst\epsilon-boot.exe" -Force
Write-Host "boot loader OK"
# Rescue slot R (docs/boot.md): the signed release, written only by this installer. The boot loader verifies it
# and runs it with -seed when slots A and B cannot run; we also use it below for the first seed.
$R = "$Dst\R"
Remove-Item -Recurse -Force $R -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $R | Out-Null
foreach ($f in 'release.json', 'epsilon-probe.exe', 'workloads.json') { Fetch "release/$f" "$R\$f" }
$got = (Get-FileHash "$R\epsilon-probe.exe" -Algorithm SHA256).Hash.ToLower()
if ($got -ne $SeedSha) { Remove-Item -Recurse -Force $R; throw "rescue probe hash mismatch: $got" }
Remove-Item -Recurse -Force "$Dst\seed" -ErrorAction SilentlyContinue   # older installers kept the seed probe here
Write-Host "rescue slot R OK"
New-Item -ItemType Directory -Force "$Dst\models" | Out-Null
$model = 'models\Qwen3.5-4B-Q4_K_M.gguf'
if ((Test-Path "$Dst\$model") -and (Get-Item "$Dst\$model").Length -eq (RemoteSize "pkg/models/Qwen3.5-4B-Q4_K_M.gguf")) { Write-Host 'model already there' }
else { Write-Host 'downloading model (2.6 GB)'; Fetch 'pkg/models/Qwen3.5-4B-Q4_K_M.gguf' "$Dst\$model" }
EnsureZip 'llama'
EnsureZip 'llama-vulkan'

Step '2/7 VC++ runtime (the stock MSVCP140 14.31 makes llama-server crash with 0xc0000005)'
Start-Process "$Dst\vc_redist.x64.exe" -ArgumentList '/install','/quiet','/norestart' -Wait
foreach ($d in 'llama','llama-vulkan') {   # keep a copy next to the exe: survives the C: restore
    Copy-Item C:\Windows\System32\msvcp140*.dll, C:\Windows\System32\vcruntime140*.dll, C:\Windows\System32\concrt140.dll "$Dst\$d" -Force
}
$ErrorActionPreference = 'Continue'   # 5.1 turns native stderr into errors under Stop
$v = & "$Dst\llama\llama-server.exe" --version 2>&1 | Select-String version
$ErrorActionPreference = 'Stop'
if ($LASTEXITCODE -eq 0 -and $v) { Write-Host "llama-server OK: $v" } else { Write-Host "llama-server does not start (exit $LASTEXITCODE)" }

Step '3/7 firewall'
foreach ($d in 'llama','llama-vulkan') {
    Remove-NetFirewallRule -DisplayName "epsilon-$d" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "epsilon-$d" -Direction Inbound -Action Allow -Program "$Dst\$d\llama-server.exe" -RemoteAddress LocalSubnet,$Ctl | Out-Null
}
Remove-NetFirewallRule -DisplayName 'epsilon-p2p' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'epsilon-p2p' -Direction Inbound -Action Allow -Protocol TCP -LocalPort '47100-47119' -RemoteAddress LocalSubnet | Out-Null
Remove-NetFirewallRule -DisplayName 'epsilon-rpc' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'epsilon-rpc' -Direction Inbound -Action Allow -Program "$Dst\llama\ggml-rpc-server.exe" -RemoteAddress $Pool | Out-Null
Write-Host "rules: epsilon-llama, epsilon-llama-vulkan (subnet + controller), epsilon-p2p (47100-47119 subnet), epsilon-rpc ($Pool)"

Step "4/7 controller $Ctl`:8090"
$ok = (Test-NetConnection $Ctl -Port 8090 -WarningAction SilentlyContinue).TcpTestSucceeded
if ($ok) { Write-Host 'reachable' } else { Write-Host 'NOT reachable' }

Step '5/7 seed: put the current signed release into a free slot (boot loader picks it up and trial-starts it)'
$ErrorActionPreference = 'Continue'
$enc = $null
try { $enc = [Console]::OutputEncoding; [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}   # the probe prints UTF-8; 5.1 would decode it as the ANSI code page
& "$R\epsilon-probe.exe" -seed -config "$Dst\probe.json" -root $Dst 2>&1 | ForEach-Object { Write-Host $_ }
$seedExit = $LASTEXITCODE
if ($enc) { try { [Console]::OutputEncoding = $enc } catch {} }
$ErrorActionPreference = 'Stop'
if ($seedExit -eq 0) { Write-Host 'seed OK' } else { Write-Host "seed failed (exit $seedExit): boot loader will have nothing to start until the probe gets a slot" }

Step '6/7 scheduled task -> boot loader (runs in the logged-on user session: SYSTEM cannot see keyboard and mouse)'
$act = New-ScheduledTaskAction -Execute "$Dst\epsilon-boot.exe" -Argument "-root $Dst" -WorkingDirectory $Dst
$trg = New-ScheduledTaskTrigger -AtLogOn
$who = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited   # BUILTIN\Users = whoever logs on, not elevated
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName epsilon-probe -Action $act -Trigger $trg -Principal $who -Settings $set -Force | Out-Null
Start-ScheduledTask -TaskName epsilon-probe   # starts now if someone is logged on, else at next logon
Start-Sleep 8
if (Get-Process epsilon-boot -ErrorAction SilentlyContinue) { Write-Host 'boot loader running (logs: D:\epsilon\boot.log, probe.log)' }
else { Write-Host 'boot loader not running yet (nobody logged on?) - it starts at next logon' }

Step '7/7 big models for pool heads'
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
