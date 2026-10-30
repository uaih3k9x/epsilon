@echo off
powershell -NoProfile -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Startup')+'\epsilon.lnk'); $s.TargetPath='D:\epsilon\2-start-probe.bat'; $s.WorkingDirectory='D:\epsilon'; $s.WindowStyle=7; $s.Save()"
echo Added to Startup folder. Re-run after the system disk is restored.
pause
