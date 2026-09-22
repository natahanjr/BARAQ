@echo off
setlocal enabledelayedexpansion
title BARAQ Launcher
echo Starting BARAQ...

cd /d "%~dp0"
if not exist "logs" mkdir "logs"

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

REM === PostgreSQL Startup with Readiness Check ===
echo [1/3] Starting PostgreSQL...
set PG_READY=0

REM Try Windows service first
sc query BaraqPG 2>nul | findstr "RUNNING" >nul
if not errorlevel 1 (
    echo   PostgreSQL service already running.
    set PG_READY=1
) else (
    net start BaraqPG 2>nul
    if not errorlevel 1 (
        echo   PostgreSQL service started.
        set PG_READY=1
    )
)

REM Fallback: try pg_ctl directly if service not available
if "%PG_READY%"=="0" (
    echo   Service not available, trying pg_ctl fallback...
    if exist "pg\pgsql\bin\pg_ctl.exe" (
        start "" /B cmd /c "pg\pgsql\bin\pg_ctl.exe start -D pg\data2 -l logs\pg_service.log"
        set PG_READY=1
    )
)

REM Wait for PostgreSQL to accept connections (max 30 seconds)
if not "%PG_READY%"=="1" goto PG_ERROR

echo   Waiting for PostgreSQL to accept connections...
set ATTEMPTS=0
:WAIT_PG
set /a ATTEMPTS+=1
if !ATTEMPTS! GTR 30 (
    echo   [WARNING] PostgreSQL did not become ready in 30s. Continuing anyway...
    goto PG_DONE
)
pg\pgsql\bin\psql.exe -h 127.0.0.1 -p 55432 -U postgres -d postgres -c "SELECT 1" >nul 2>&1
if errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto WAIT_PG
)
echo   PostgreSQL ready.
goto PG_DONE

:PG_ERROR
echo   [ERROR] Could not start PostgreSQL. Check logs\pg_service.log

:PG_DONE

REM === Backend Startup with DB Retry ===
echo [2/3] Starting Backend on %HOST%:8001 (%MODE% mode)...
set "PY=python"
if exist "venv\Scripts\python.exe" set "PY=venv\Scripts\python.exe"
start "" /B cmd /c "set BARAQ_TELEMETRY_V2=1 && set BARAQ_ALERTS_V2=1 && set BARAQ_CORRELATION=1 && set BARAQ_RISK=1 && set BARAQ_BEHAVIOR_GROUPS=1 && !PY! start_dev.py --host %HOST% >logs\backend.log 2>&1"
timeout /t 5 /nobreak >nul

REM === Frontend (dev mode only) ===
echo [3/3] Starting Frontend...
if /I "%~1" NEQ "lan" (
    cd /d "%~dp0frontend"
    start "" /B cmd /c "npm run dev >..\logs\frontend.log 2>&1"
    cd /d "%~dp0"
) else (
    echo   Frontend skipped in LAN mode.
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
