@echo off
REM Kill any existing instances first
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8001 ^| findstr LISTENING') do taskkill /PID %%a /F >nul 2>&1
taskkill /IM node.exe /F >nul 2>&1
timeout /t 2 /nobreak >nul

REM Launch everything hidden (no windows)
cscript //B //Nologo "F:\My Project\Baraq\start_silent.vbs"
