@echo off
title BARAQ Launcher
echo Starting BARAQ...

REM Kill old processes
taskkill /F /IM python.exe 2>nul
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

REM Ensure PostgreSQL
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\pg_setup.ps1" -Action ensure
timeout /t 2 /nobreak >nul

REM Start Backend
echo Starting Backend...
cd /d "%~dp0"
start "BARAQ-Backend" cmd /c "set BARAQ_TELEMETRY_V2=1 && set BARAQ_ALERTS_V2=1 && set BARAQ_CORRELATION=1 && set BARAQ_RISK=1 && set BARAQ_BEHAVIOR_GROUPS=1 && python start_dev.py"

timeout /t 4 /nobreak >nul

REM Start Frontend
echo Starting Frontend...
cd /d "%~dp0frontend"
start "BARAQ-Frontend" cmd /c "npm run dev"

echo.
echo ========================================
echo BARAQ is starting...
echo Backend:  http://127.0.0.1:8001
echo Frontend: http://127.0.0.1:5173
echo ========================================
pause
