@echo off
cd /d D:\epsilon
set /p IP=<controller-ip.txt
set /p KEY=<api_key.txt
echo === nodes ===
curl.exe -s -H "Authorization: Bearer %KEY%" http://%IP%:8090/v1/nodes
echo.
echo.
echo === chat via controller ===
curl.exe -s -i -H "Authorization: Bearer %KEY%" -H "Content-Type: application/json" http://%IP%:8090/v1/chat/completions -d "{\"model\":\"qwen3.5-4b\",\"messages\":[{\"role\":\"user\",\"content\":\"hello, who are you?\"}],\"max_tokens\":100,\"chat_template_kwargs\":{\"enable_thinking\":false}}"
echo.
pause
