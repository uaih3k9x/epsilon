@echo off
rem Run llama-server in this window to see why it crashes (port 8081, does not clash with the probe)
cd /d D:\epsilon\llama-vulkan
llama-server.exe -m D:\epsilon\models\Qwen3.5-4B-Q4_K_M.gguf --port 8081 -ngl 99
echo.
echo exit code %ERRORLEVEL%
pause
