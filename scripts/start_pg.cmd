@echo off
rem Start the local BARAQ PostgreSQL cluster if it is not already running.
rem Idempotent and machine-independent: the cluster layout, discovery and
rem initdb are all handled by scripts\pg_setup.ps1 (safe to call from a
rem scheduled task at every logon; no admin rights required).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0pg_setup.ps1" -Action ensure
exit /b %errorlevel%