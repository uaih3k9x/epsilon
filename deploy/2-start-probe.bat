@echo off
cd /d D:\epsilon
set /p IP=<controller-ip.txt
if "%IP%"=="" (echo Put the controller IP into controller-ip.txt first & pause & exit /b 1)
tasklist /fi "imagename eq epsilon-probe.exe" | find /i "epsilon-probe.exe" >nul && (echo probe already running & timeout /t 3 >nul & exit /b 0)
start "" "D:\epsilon\epsilon-probe.exe" -controller http://%IP%:8090
echo Probe started in background. Controller http://%IP%:8090  Log: D:\epsilon\probe.log
timeout /t 5 >nul
