@echo off
REM BARAQ Database Backup Script
REM Backs up the PostgreSQL database to a timestamped SQL file.
REM
REM Usage:
REM   scripts\backup_db.bat
REM   scripts\backup_db.bat --output C:\Backups
REM
REM Schedule daily with Windows Task Scheduler:
REM   schtasks /create /tn "BARAQ Backup" /tr "C:\path\to\BARAQ\scripts\backup_db.bat" /sc daily /st 02:00

setlocal

set PG_BIN=C:\baraq_pg\pgsql\bin
set PG_SERVICE=BaraqPG
set DB_NAME=baraq
set BACKUP_DIR=backups
set TIMESTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"

echo.
echo ========================================
echo   BARAQ Database Backup
echo ========================================
echo.
echo  Database: %DB_NAME%
echo  Service:  %PG_SERVICE%
echo  Output:   %BACKUP_DIR%\baraq_%TIMESTAMP%.sql.gz
echo.

REM Check if service is running
sc query %PG_SERVICE% | find "RUNNING" >nul
if errorlevel 1 (
    echo [ERROR] PostgreSQL service %PG_SERVICE% is not running.
    echo Starting service...
    net start %PG_SERVICE%
    timeout /t 5 >nul
)

REM Backup the database
echo [INFO] Creating backup...
"%PG_BIN%\pg_dump" -h 127.0.0.1 -p 55432 -U sentinelpg -d %DB_NAME% --no-owner --no-acl | "%PG_BIN%\gzip" > "%BACKUP_DIR%\baraq_%TIMESTAMP%.sql.gz"

if errorlevel 1 (
    echo [ERROR] Backup failed!
    exit /b 1
)

REM Get file size
for %%A in ("%BACKUP_DIR%\baraq_%TIMESTAMP%.sql.gz") do set SIZE=%%~zA
set /a SIZE_MB=%SIZE% / 1048576

echo.
echo ========================================
echo   Backup Complete
echo ========================================
echo.
echo  File: %BACKUP_DIR%\baraq_%TIMESTAMP%.sql.gz
echo  Size: %SIZE_MB% MB
echo.
echo  To restore:
echo    gunzip -c %BACKUP_DIR%\baraq_%TIMESTAMP%.sql.gz ^| psql -h 127.0.0.1 -p 55432 -U sentinelpg -d %DB_NAME%
echo.

REM Cleanup backups older than 30 days
echo [INFO] Cleaning backups older than 30 days...
forfiles /p "%BACKUP_DIR%" /m "*.sql.gz" /d -30 /c "cmd /c del @path" 2>nul

endlocal
