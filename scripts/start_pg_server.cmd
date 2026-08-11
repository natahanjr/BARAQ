@echo off
rem Launch the BARAQ backend against the local PostgreSQL cluster.
rem Usage: scripts\start_pg_server.cmd
rem   All paths are derived from this script's location, so it works from any
rem   folder on any machine. The database URL comes from .env (loaded by the
rem   backend itself); a local-cluster default is only injected when neither
rem   the environment nor .env defines one.
setlocal
cd /d "%~dp0.."

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] No virtualenv at %CD%\venv - run start.bat once first.
    exit /b 1
)

findstr /b /c:"BARAQ_DATABASE_URL" ".env" >nul 2>&1
if errorlevel 1 if not defined BARAQ_DATABASE_URL (
    set "BARAQ_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1:55432/baraq"
)

"venv\Scripts\python.exe" -m uvicorn backend.main:app --host 0.0.0.0 --port 8001 > "logs\uvicorn.out.log" 2> "logs\uvicorn.err.log"