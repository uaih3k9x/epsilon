@echo off
rem One-shot install from this USB stick. Asks for admin, then runs install.ps1.
fltmc >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
