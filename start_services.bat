@echo off
REM BARAQ Development Startup Script
REM Starts PostgreSQL and Backend server

echo ========================================
echo  BARAQ Development Startup
echo ========================================

REM Check if PostgreSQL is already running
netstat -an | findstr ":55432" | findstr "LISTENING" >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [OK] PostgreSQL already running on port 55432
) else (
    echo [..] Starting PostgreSQL...
    start /B "" "F:\My Project\Baraq\pg\pgsql\bin\pg_ctl.exe" start -D "F:\My Project\Baraq\pg\data2" -l "F:\My Project\Baraq\pg\pg_service.log"
    timeout /t 5 /nobreak >nul
    netstat -an | findstr ":55432" | findstr "LISTENING" >nul 2>&1
    if %ERRORLEVEL% == 0 (
        echo [OK] PostgreSQL started on port 55432
    ) else (
        echo [ERROR] PostgreSQL failed to start
        exit /b 1
    )
)

REM Check if Backend is already running
netstat -an | findstr ":8001" | findstr "LISTENING" >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo [OK] Backend already running on port 8001
) else (
    echo [..] Starting Backend server...
    cd /d "F:\My Project\Baraq"
    set BARAQ_SINGLE_INSTANCE=0
    start /B "" python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
    timeout /t 5 /nobreak >nul
    netstat -an | findstr ":8001" | findstr "LISTENING" >nul 2>&1
    if %ERRORLEVEL% == 0 (
        echo [OK] Backend started on port 8001
    ) else (
        echo [ERROR] Backend failed to start
        exit /b 1
    )
)

echo ========================================
echo  All services started successfully!
echo ========================================
echo.
echo  PostgreSQL: http://127.0.0.1:55432
echo  Backend:    http://127.0.0.1:8001
echo  Frontend:   http://localhost:5173
echo.
echo  Press Ctrl+C to stop all services
echo ========================================

REM Keep script running
pause >nul
