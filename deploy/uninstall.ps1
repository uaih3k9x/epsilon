# Remove Epsilon from a student machine. Run as administrator. The VC++ runtime is left alone (shared with other software).
# If the scheduled task / firewall rules were baked into the OSEasy image, run this on the image machine and save the image again.
$ProgressPreference = 'SilentlyContinue'
Unregister-ScheduledTask -TaskName epsilon-probe -Confirm:$false -ErrorAction SilentlyContinue
Get-Process epsilon-boot, epsilon-probe, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Get-NetFirewallRule -DisplayName 'epsilon-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# rmdir /s does not follow junctions; Remove-Item -Recurse on 5.1 can
if (Test-Path D:\epsilon) { cmd /c rmdir /s /q D:\epsilon }
Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Join-Path $_.FullName 'AppData\Local\llama.cpp'
    if (Test-Path $d) { cmd /c rmdir /s /q "$d" }
}
'task: ' + [bool](Get-ScheduledTask epsilon-probe -ErrorAction SilentlyContinue)
'firewall: ' + @(Get-NetFirewallRule -DisplayName 'epsilon-*' -ErrorAction SilentlyContinue).Count
'D:\epsilon: ' + (Test-Path D:\epsilon)
'running: ' + [bool](Get-Process epsilon-boot, epsilon-probe, llama-server, ggml-rpc-server -ErrorAction SilentlyContinue)
