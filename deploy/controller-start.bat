@echo off
rem Only on the machine acting as controller (fallback). Keep this window open.
cd /d D:\epsilon
title epsilon controller
epsilon-controller.exe -config controller.json
pause
