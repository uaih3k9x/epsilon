@echo off
rem Repair this student machine. Asks for admin, then runs repair.ps1 from this USB stick.
fltmc >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0repair.ps1"
pause
