@echo off
fltmc >nul 2>&1 || (echo NOT ADMIN: right-click this file - Run as administrator & pause & exit /b 1)
cd /d D:\epsilon

echo [1/3] VC++ runtime (old MSVCP140 14.31 makes llama-server crash with 0xc0000005)
D:\epsilon\vc_redist.x64.exe /install /quiet /norestart
for %%d in (llama llama-vulkan) do (
  copy /y C:\Windows\System32\msvcp140*.dll D:\epsilon\%%d\ >nul
  copy /y C:\Windows\System32\vcruntime140*.dll D:\epsilon\%%d\ >nul
  copy /y C:\Windows\System32\concrt140.dll D:\epsilon\%%d\ >nul
)
D:\epsilon\llama\llama-server.exe --version 2>&1 | findstr /i "version"
if errorlevel 1 (echo llama-server still does not start - tell Claude) else (echo llama-server OK)

echo [2/3] Firewall: llama-server 8080 from this subnet and from 221 (controller)
netsh advfirewall firewall delete rule name="epsilon-llama" >nul 2>&1
netsh advfirewall firewall delete rule name="epsilon-llama-vulkan" >nul 2>&1
netsh advfirewall firewall delete rule name="epsilon-controller" >nul 2>&1
netsh advfirewall firewall add rule name="epsilon-llama" dir=in action=allow program="D:\epsilon\llama\llama-server.exe" remoteip=localsubnet,@CONTROLLER@ profile=any enable=yes >nul
netsh advfirewall firewall add rule name="epsilon-llama-vulkan" dir=in action=allow program="D:\epsilon\llama-vulkan\llama-server.exe" remoteip=localsubnet,@CONTROLLER@ profile=any enable=yes >nul
netsh advfirewall firewall add rule name="epsilon-controller" dir=in action=allow program="D:\epsilon\epsilon-controller.exe" remoteip=localsubnet profile=any enable=yes >nul
netsh advfirewall firewall show rule name=all | findstr /i "epsilon"

echo [3/3] Can we reach the controller on 221?
powershell -NoProfile -Command "if ((Test-NetConnection @CONTROLLER@ -Port 8090 -WarningAction SilentlyContinue).TcpTestSucceeded) {'controller @CONTROLLER@:8090 OK'} else {'controller NOT reachable - use the fallback in the readme'}"
echo.
echo Done. Re-run after the system disk is restored. Next: 2-start-probe.bat
pause
