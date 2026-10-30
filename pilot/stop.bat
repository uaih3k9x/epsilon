@echo off
taskkill /im epsilon-probe.exe /f >nul 2>&1
taskkill /im llama-server.exe /f >nul 2>&1
echo Probe and llama-server stopped.
timeout /t 3 >nul
