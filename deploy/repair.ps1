# Repair one student machine by hand from the USB stick (run through repair.bat). ASCII only: PowerShell 5.1 reads ANSI.
# Order: write down what state the machine is in -> if the probe is already online, change nothing ->
#        otherwise run install.ps1 from the controller (safe to repeat, big files on D: are kept) -> wait for a heartbeat.
# Needs <usb>\epsilon\controller-ip.txt and api_key.txt. Reports go to <usb>\repair-logs\ (never contain the key).
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
$Usb = $PSScriptRoot
$Dst = 'D:\epsilon'
$Name = $env:COMPUTERNAME
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$LogDir = "$Usb\repair-logs"
try { New-Item -ItemType Directory -Force $LogDir -ErrorAction Stop | Out-Null } catch { $LogDir = $Dst }
$LogFile = "$LogDir\$Name-$Stamp.txt"

function Log($msg) {
    Write-Host $msg
    try { Add-Content -Path $LogFile -Value $msg -ErrorAction Stop } catch {}
}
function Section($title, [scriptblock]$body) {
    try { Add-Content -Path $LogFile -Value "`r`n== $title" -ErrorAction Stop } catch {}
    try { $text = (& $body 2>&1 | Out-String).TrimEnd() } catch { $text = "ERROR: $_" }
    try { Add-Content -Path $LogFile -Value $text -ErrorAction Stop } catch {}
}
function TailFile($path, $n) {
    if (Test-Path $path) { Get-Content -Path $path -Tail $n } else { "missing: $path" }
}
function Collect-Diagnostics {
    Section 'clock and uptime' { Get-Date; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
    Section 'logged on users' { quser }
    Section 'auto logon' {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
            Select-Object AutoAdminLogon, DefaultUserName, DefaultDomainName | Format-List
    }
    Section 'scheduled task' {
        $t = Get-ScheduledTask epsilon-probe -ErrorAction SilentlyContinue
        if ($t) { $t.State; $t.Actions[0].Execute; $t.Actions[0].Arguments; $t.Triggers | Format-List; Get-ScheduledTaskInfo epsilon-probe | Format-List }
        else { 'MISSING' }
    }
    Section 'firewall rules' { Get-NetFirewallRule -DisplayName 'epsilon-*' -ErrorAction SilentlyContinue | Select-Object DisplayName, Enabled, Action | Format-Table -AutoSize }
    Section 'processes' { Get-Process epsilon-boot, epsilon-probe, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue | Select-Object Name, Id, StartTime | Format-Table -AutoSize }
    Section 'D drive' {
        Get-PSDrive D -ErrorAction SilentlyContinue | Format-List Used, Free
        foreach ($p in 'epsilon-boot.exe', 'probe.json', 'boot-state.json', 'A\release.json', 'B\release.json', 'R\release.json', 'llama\llama-server.exe', 'models\Qwen3.5-4B-Q4_K_M.gguf') {
            "$p = $(Test-Path "$Dst\$p")"
        }
        Get-ChildItem $Dst -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
    }
    Section 'boot-state.json' { TailFile "$Dst\boot-state.json" 40 }
    Section 'boot.log' { TailFile "$Dst\boot.log" 40 }
    Section 'probe.log' { TailFile "$Dst\probe.log" 40 }
    Section 'VC++ runtime' { (Get-Item C:\Windows\System32\msvcp140.dll -ErrorAction SilentlyContinue).VersionInfo.FileVersion }
    Section 'GPU' { nvidia-smi --query-gpu=name,driver_version,memory.used,memory.total,temperature.gpu --format=csv }
    Section 'network' { ipconfig; route print -4 }
    Section 'shutdown and crash events' {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 1074, 6005, 6006, 6008 } -MaxEvents 12 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message | Format-List
    }
}

Log "Epsilon repair on $Name at $(Get-Date)"
$CtlFile = "$Usb\epsilon\controller-ip.txt"; $KeyFile = "$Usb\epsilon\api_key.txt"
if (-not ((Test-Path $CtlFile) -and (Test-Path $KeyFile))) { Log 'FAILED: epsilon\controller-ip.txt or api_key.txt is not on this USB stick.'; return }
$Ctl = (Get-Content -Raw $CtlFile).Trim()
$Key = (Get-Content -Raw $KeyFile).Trim()
$Headers = @{ Authorization = 'Bearer ' + $Key }

function Get-NodeState {
    try {
        $all = Invoke-RestMethod "http://${Ctl}:8090/v1/nodes" -Headers $Headers -TimeoutSec 15 -ErrorAction Stop
        return @($all | ForEach-Object { $_ } | Where-Object { $_.node -eq $Name -and $_.seconds_since_heartbeat -lt 30 })[0]
    } catch { return $null }
}
function Summary($action, $result, $version) {
    $line = "$Name,$Stamp,task=$HadTask,boot=$HadBoot,net=$Reachable,$action,$result,$version"
    try { Add-Content -Path "$LogDir\summary.csv" -Value $line -ErrorAction Stop } catch {}
}
function Banner($color, $text) {
    Write-Host ''
    Write-Host "  $text" -ForegroundColor $color
    Write-Host ''
    try { Add-Content -Path $LogFile -Value "`r`nRESULT: $text" -ErrorAction Stop } catch {}
}

Log 'Collecting diagnostics (read only)...'
Collect-Diagnostics
$HadTask = [bool](Get-ScheduledTask epsilon-probe -ErrorAction SilentlyContinue)
$HadBoot = [bool](Get-Process epsilon-boot -ErrorAction SilentlyContinue)
$Reachable = (Test-NetConnection $Ctl -Port 8090 -WarningAction SilentlyContinue).TcpTestSucceeded
Log "task=$HadTask bootloader_running=$HadBoot controller_reachable=$Reachable"

if (-not $Reachable) {
    Summary 'none' 'no-network' ''
    Banner Red "FAILED: cannot reach controller $Ctl`:8090. Nothing changed. Check the network cable and ipconfig."
    return
}

$before = Get-NodeState
if ($HadBoot -and $before) {
    Summary 'none' 'already-online' $before.version
    Banner Green "OK: already online, version $($before.version). Nothing changed."
    return
}
if ($HadTask -and -not $HadBoot) {
    # The task fires at logon; give it a moment in case we were run right after logging in.
    Log 'Task exists but the boot loader is not running. Waiting 30 seconds for it...'
    Start-Sleep 30
    $HadBootLate = [bool](Get-Process epsilon-boot -ErrorAction SilentlyContinue)
    $before = Get-NodeState
    if ($HadBootLate -and $before) {
        Summary 'none' 'online-after-logon' $before.version
        Banner Green "OK: came online by itself after logon, version $($before.version). Nothing changed."
        return
    }
}

Log 'Running the installer from the controller...'
$action = 'install'
$env:EPS_KEY = $Key
try {
    $installer = (Invoke-WebRequest "http://${Ctl}:8090/dl/upgrade/install.ps1" -Headers $Headers -UseBasicParsing -ErrorAction Stop).Content
    Invoke-Expression $installer
} catch {
    $action = 'install-failed'
    Log "Installer stopped: $_"
    try { Stop-Transcript | Out-Null } catch {}
} finally {
    Remove-Item Env:\EPS_KEY -ErrorAction SilentlyContinue
    $ErrorActionPreference = 'Continue'
}
Section 'install.log' { TailFile "$Dst\install.log" 60 }

Log 'Waiting up to 3 minutes for a heartbeat...'
$after = $null
foreach ($i in 1..18) {
    $after = Get-NodeState
    if ($after) { break }
    Start-Sleep 10
}
Section 'after: processes' { Get-Process epsilon-boot, epsilon-probe, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue | Select-Object Name, Id, StartTime | Format-Table -AutoSize }
Section 'after: probe.log' { TailFile "$Dst\probe.log" 30 }
if ($after) {
    Summary $action 'online' $after.version
    Banner Green "OK: online, version $($after.version). Stay logged on: the probe stops if this user logs off."
} else {
    Summary $action 'no-heartbeat' ''
    Banner Red "FAILED: no heartbeat from $Name. Send the file in repair-logs to Claude."
}
