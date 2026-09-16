@echo off
title BARAQ Launcher
echo Starting BARAQ...

REM Kill old processes
taskkill /F /IM python.exe 2>nul
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

REM Ensure PostgreSQL service is running
sc query BaraqPG | findstr "RUNNING" >nul
if errorlevel 1 (net start BaraqPG 2>nul)
timeout /t 2 /nobreak >nul

REM Start Backend (hidden, no console output)
echo Starting Backend...
cd /d "%~dp0"
start "" /B cmd /c "set BARAQ_TELEMETRY_V2=1 && set BARAQ_ALERTS_V2=1 && set BARAQ_CORRELATION=1 && set BARAQ_RISK=1 && set BARAQ_BEHAVIOR_GROUPS=1 && python start_dev.py >nul 2>&1"
timeout /t 5 /nobreak >nul

REM Start Frontend (hidden)
echo Starting Frontend...
cd /d "%~dp0frontend"
start "" /B cmd /c "npm run dev >nul 2>&1"

echo.
echo ========================================
echo BARAQ is running!
echo Backend:  http://127.0.0.1:8001
echo Frontend: http://127.0.0.1:5173
echo ========================================
echo.
echo Close this window freely - BARAQ runs in background.
echo To stop: taskkill /F /IM python.exe & taskkill /F /IM node.exe
