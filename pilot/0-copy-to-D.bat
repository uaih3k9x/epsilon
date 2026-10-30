@echo off
echo Copying epsilon to D:\epsilon ...
robocopy "%~dp0." "D:\epsilon" /E /NFL /NDL /NJH /NP
echo.
echo Done. Next: right-click 1-firewall.bat - Run as administrator.
pause
