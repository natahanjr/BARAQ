@echo off
REM BARAQ Development Stop Script
REM Stops PostgreSQL and Backend server

echo ========================================
echo  BARAQ Development Shutdown
echo ========================================

REM Stop Backend
echo [..] Stopping Backend server...
taskkill /F /IM "python.exe" /FI "WINDOWTITLE eq *uvicorn*" >nul 2>&1
taskkill /F /IM "python.exe" /FI "WINDOWTITLE eq *start_dev*" >nul 2>&1
echo [OK] Backend stopped

REM Stop PostgreSQL
echo [..] Stopping PostgreSQL...
"F:\My Project\Baraq\pg\pgsql\bin\pg_ctl.exe" stop -D "F:\My Project\Baraq\pg\data2" -m fast 2>nul
echo [OK] PostgreSQL stopped

echo ========================================
echo  All services stopped
echo ========================================
pause
