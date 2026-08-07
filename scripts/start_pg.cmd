@echo off
rem Start the local SentinelSOC PostgreSQL cluster if it is not already running.
rem Idempotent: safe to call from a scheduled task at every logon.
setlocal
set "PGROOT=C:\Users\Haaraphel\AppData\Local\Temp\opencode\pg\pgsql\bin"
set "PGDATA=C:\Users\Haaraphel\AppData\Local\Temp\opencode\pg\data"
set "PGLOG=C:\Users\Haaraphel\AppData\Local\Temp\opencode\pg\ns.log"

netstat -an | findstr /r "127.0.0.1:55432 .*LISTENING" >nul
if not errorlevel 1 (
    exit /b 0
)

if not exist "%PGROOT%\pg_ctl.exe" (
    exit /b 1
)

"%PGROOT%\pg_ctl.exe" -D "%PGDATA%" -o "-p 55432 -h 127.0.0.1" -l "%PGLOG%" start >nul 2>&1
exit /b 0
