@echo off
rem Launch the SentinelSOC backend against the local PostgreSQL cluster.
rem Usage: scripts\start_pg_server.cmd
rem   The working directory is fixed to the project root, so this can be run
rem   from anywhere (console double-click, scheduled task, WMI, etc.).
cd /d "F:\My Project\SentinelSOC"
set SENTINEL_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1:55432/sentinel
"F:\My Project\SentinelSOC\venv\Scripts\python.exe" -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 > "F:\My Project\SentinelSOC\logs\uvicorn.out.log" 2> "F:\My Project\SentinelSOC\logs\uvicorn.err.log"