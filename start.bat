@echo off
title BARAQ Launcher
echo Starting BARAQ...

cd /d "%~dp0"

REM Parse arguments
set "HOST=127.0.0.1"
set "MODE=dev"
if /I "%~1"=="lan" (
    set "HOST=0.0.0.0"
    set "MODE=lan"
)

REM Kill only BARAQ-specific processes using PID files
if exist "%~dp0\.backend.pid" (
    set /p PID=<"%~dp0\.backend.pid"
    taskkill /PID !PID! /F 2>nul
    del "%~dp0\.backend.pid" 2>nul
)
if exist "%~dp0\.frontend.pid" (
    set /p PID=<"%~dp0\.frontend.pid"
    taskkill /PID !PID! /F 2>nul
    del "%~dp0\.frontend.pid" 2>nul
)
timeout /t 1 /nobreak >nul

REM Ensure PostgreSQL service is running
sc query BaraqPG | findstr "RUNNING" >nul
if errorlevel 1 (net start BaraqPG 2>nul)
timeout /t 2 /nobreak >nul

REM Start Backend
echo Starting Backend on %HOST%:8001 (%MODE% mode)...
start "" /B cmd /c "set BARAQ_TELEMETRY_V2=1 && set BARAQ_ALERTS_V2=1 && set BARAQ_CORRELATION=1 && set BARAQ_RISK=1 && set BARAQ_BEHAVIOR_GROUPS=1 && python start_dev.py --host %HOST% >nul 2>&1"
timeout /t 5 /nobreak >nul

REM Start Frontend (only in dev mode, not lan)
if /I "%~1" NEQ "lan" (
    echo Starting Frontend...
    cd /d "%~dp0frontend"
    start "" /B cmd /c "npm run dev >nul 2>&1"
    cd /d "%~dp"
)

echo.
echo ========================================
if /I "%~1"=="lan" (
    echo BARAQ is running in LAN mode!
    echo Backend:  http://%HOST%:8001
) else (
    echo BARAQ is running!
    echo Backend:  http://127.0.0.1:8001
    echo Frontend: http://127.0.0.1:5173
)
echo ========================================
echo.
echo Close this window freely - BARAQ runs in background.
