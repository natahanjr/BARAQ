@echo off
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8001 ^| findstr LISTENING') do taskkill /PID %%a /F >nul 2>&1
taskkill /IM node.exe /F >nul 2>&1
