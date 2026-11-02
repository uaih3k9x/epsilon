# Read-only check of one student machine; the result goes to the controller as a 'diag' event.
# OSEasy truncates long remote commands, so it runs this through the short loader line in dist/deploy/. ASCII only.
# Needs $env:EPS_KEY. The probe token comes from pkg/probe.json, so this works even if D: was wiped.
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$Ctl = '@CONTROLLER@'
$E = 'D:\epsilon'

function Field($name, [scriptblock]$body) {
    try { $v = (& $body | Out-String).Trim() -replace '\s+', ' ' } catch { $v = "ERR:$_" }
    "$name=$v"
}
function Tail($path, $n) { if (Test-Path $path) { Get-Content $path -Tail $n -Encoding UTF8 } else { 'none' } }

$fields = @(
    Field 'dir' { Test-Path $E }
    Field 'boot' { Test-Path "$E\epsilon-boot.exe" }
    Field 'model' { Test-Path "$E\models\Qwen3.5-4B-Q4_K_M.gguf" }
    Field 'd_free_gb' { [math]::Round((Get-PSDrive D).Free / 1GB) }
    Field 'task' { $t = Get-ScheduledTask epsilon-probe; if ($t) { $t.State } else { 'none' } }
    Field 'task_last' { $i = Get-ScheduledTaskInfo epsilon-probe; "$($i.LastRunTime)/$($i.LastTaskResult)" }
    Field 'run_boot' { [bool](Get-Process epsilon-boot) }
    Field 'run_probe' { [bool](Get-Process epsilon-probe) }
    Field 'run_llama' { [bool](Get-Process llama-server, ggml-rpc-server) }
    Field 'fw' { @(Get-NetFirewallRule -DisplayName 'epsilon-*').Count }
    Field 'msvcp' { (Get-Item C:\Windows\System32\msvcp140.dll).VersionInfo.FileVersion }
    Field 'autologon' { $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; "$($w.AutoAdminLogon)/$($w.DefaultUserName)" }
    Field 'user' { (Get-CimInstance Win32_ComputerSystem).UserName }
    Field 'sessions' { (quser 2>&1) -join ';' }
    Field 'clock' { Get-Date -Format 's' }
    Field 'uptime_h' { ((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours.ToString('0.0') }
    Field 'last_power' { Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 1074, 6008 } -MaxEvents 2 | ForEach-Object { "$($_.Id)@$($_.TimeCreated.ToString('s'))" } }
    Field 'state' { Tail "$E\boot-state.json" 40 }
    Field 'boot_log' { Tail "$E\boot.log" 3 }
    Field 'probe_log' { Tail "$E\probe.log" 3 }
)
$detail = $fields -join ' '
$headers = @{ Authorization = 'Bearer ' + $env:EPS_KEY }
$token = (Invoke-RestMethod "http://${Ctl}:8090/dl/pkg/probe.json" -Headers $headers -TimeoutSec 30).token
if (-not $token) { $token = (Get-Content "$E\probe.json" -Raw | ConvertFrom-Json).token }
$body = @{ node = $env:COMPUTERNAME; kind = 'diag'; detail = $detail } | ConvertTo-Json -Compress
Invoke-RestMethod -Method Post -Uri "http://${Ctl}:8090/v1/events" -Headers @{ Authorization = 'Bearer ' + $token } `
    -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 30 | Out-Null
