@echo off
rem ===========================================================================
rem  BARAQ - one-click launcher (Windows)
rem  Usage:
rem    start.bat secure       -> STANDARD: HTTPS (TLS) with self-signed cert
rem    start.bat secure lan   -> standard + exposed to the local network
rem    start.bat              -> local only (127.0.0.1, plain HTTP - dev/lab)
rem    start.bat lan          -> plain HTTP exposed to the network (not recommended)
rem  HTTPS is the documented deployment path for any shared/fleet use; plain
rem  HTTP is intended for local development only - telemetry traverses the
rem  network unencrypted otherwise.
rem  Creates the venv and installs dependencies on first run, builds the
rem  dashboard if missing, then starts the backend and opens the browser.
rem ===========================================================================
setlocal
cd /d "%~dp0"

set LAN_MODE=%~1
set SECURE_MODE=%~2
if /i "%LAN_MODE%"=="lan" ( set "SECURE_MODE=%~2" ) else (
  if /i "%LAN_MODE%"=="secure" (
    set "SECURE_MODE=secure"
    set "LAN_MODE=%~2"
  )
)

echo.
echo  ============================================
echo   BARAQ - Live Threat Detection
if /i "%LAN_MODE%"=="lan" echo   MODE: LAN (accessible from your network)
if /i "%SECURE_MODE%"=="secure" echo   MODE: HTTPS (TLS encrypted)
echo  ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo  [ERROR] Python not found on PATH. Install Python 3.11+ first:
    echo          https://www.python.org/downloads/
    pause
    exit /b 1
)

if not exist "venv\Scripts\python.exe" (
    echo  [SETUP] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Could not create venv.
        pause
        exit /b 1
    )
    echo  [SETUP] Installing dependencies ^(first run only, takes a few minutes^)...
    venv\Scripts\python -m pip install --upgrade pip >nul 2>&1
    venv\Scripts\pip install -r requirements.txt
    if errorlevel 1 (
        echo  [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)

if not exist "frontend\dist\index.html" (
    where node >nul 2>nul
    if errorlevel 1 (
        echo  [WARN] Node.js not found - dashboard UI will not be served.
        echo         Install Node.js 18+ then run:  cd frontend ^&^& npm install ^&^& npm run build
    ) else (
        echo  [SETUP] Building dashboard ^(first run only^)...
        pushd frontend
        call npm install
        if errorlevel 1 (
            echo  [ERROR] npm install failed.
            popd
            pause
            exit /b 1
        )
        call npm run build
        if errorlevel 1 (
            echo  [ERROR] Dashboard build failed.
            popd
            pause
            exit /b 1
        )
        popd
    )
)

if /i "%SECURE_MODE%"=="secure" (
    echo  [SETUP] Generating TLS certificate ^(if needed^)...
    powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\gen_cert.ps1" >nul 2>&1
    if not exist "certs\baraq.crt" (
        echo  [ERROR] Certificate generation failed. Run this from the project
        echo          folder and ensure PowerShell is available.
        pause
        exit /b 1
    )
    echo  [SETUP] TLS certificate ready.
)

if /i "%LAN_MODE%"=="lan" (
    if /i "%SECURE_MODE%"=="secure" (
        set "FW_PORT=8443"
        set "FW_PROTO=https"
    ) else (
        set "FW_PORT=8001"
        set "FW_PROTO=http"
    )
    echo  [SETUP] Opening port %FW_PORT% in Windows Firewall ^(needs admin^)...
    netsh advfirewall firewall add rule name="BARAQ" dir=in action=allow protocol=TCP localport=%FW_PORT% >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] Firewall rule not added - run this as Administrator if
        echo         other devices cannot connect.
    )
echo.
    for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do set "MY_IP=%%a"
    echo  Other devices on your network can now open:
    echo   %FW_PROTO%://%MY_IP%:%FW_PORT%
    echo.
    echo  Create a user account for each person in the dashboard:
    echo  Users ^& Audit -^> Add User ^(analyst role^).
    echo.
    if /i "%SECURE_MODE%"=="secure" (
        echo  Remote agents should pin the TLS certificate when connecting:
        echo  python scripts\agent.py --server https://%MY_IP%:%FW_PORT% --key ^<key^> --tls-ca certs\baraq.crt
        echo.
    )
)

echo  [DB]    Ensuring local PostgreSQL cluster (first run initialises it)...
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\pg_setup.ps1" -Action ensure
if errorlevel 1 (
    echo  [ERROR] PostgreSQL could not be started. Run scripts\download_postgres.ps1
    echo          to bundle PostgreSQL, or install PG 16+ and set BARAQ_PG_BIN.
    pause
    exit /b 1
)

rem ---------------------------------------------------------------------------
rem  Day-1 ML bootstrap: fresh deployments ship with a bundled seed model so
rem  detection is never blind on first launch. Built once (needs the local
rem  database, hence after the PostgreSQL step above).
rem ---------------------------------------------------------------------------
if not exist "backend\ml\assets\bootstrap_model.joblib" (
    echo  [ML]    Building day-1 bootstrap detection model ^(one-time^)...
    venv\Scripts\python tools\build_bootstrap_model.py >nul 2>&1
    if exist "backend\ml\assets\bootstrap_model.joblib" (
        echo  [ML]    Bootstrap model ready.
    ) else (
        echo  [WARN]  Bootstrap build skipped - detection starts cold and arms
        echo         itself after the first auto-training cycle.
    )
)

if /i "%SECURE_MODE%"=="secure" (
    echo  [START] Launching BARAQ in the background ^(HTTPS^) - https://127.0.0.1:8443
    echo  [STOP]  The console closes automatically; the server keeps running
    echo          in the background. Re-run start.bat to restart it.
    echo.
    start "" powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\open_dashboard.ps1" -Url "https://127.0.0.1:8443"
) else (
    echo  [START] Launching BARAQ in the background - open http://127.0.0.1:8001
    echo  [STOP]  The console closes automatically; the server keeps running
    echo          in the background. Re-run start.bat to restart it.
    echo.
    start "" powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\open_dashboard.ps1" -Url "http://127.0.0.1:8001"
)

rem ---------------------------------------------------------------------------
rem  Background start (canonical entry: scripts\run_server.ps1, writes
rem  logs\server.pid). Any previous hidden server on the target port is
rem  killed first so re-running start.bat restarts cleanly instead of
rem  silently failing on the occupied port.
rem ---------------------------------------------------------------------------
set "TARGET_PORT=8001"
if /i "%SECURE_MODE%"=="secure" set "TARGET_PORT=8443"
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:":%TARGET_PORT% .*LISTENING"') do (
    echo  [KILL]  Stopping previous BARAQ server ^(PID %%p^) on port %TARGET_PORT%...
    taskkill /f /pid %%p >nul 2>&1
)

set "SERVER_ARGS=-NoProfile -ExecutionPolicy Bypass -File scripts\run_server.ps1"
if /i "%LAN_MODE%"=="lan" set "SERVER_ARGS=%SERVER_ARGS% -Lan"
set "TLS_PREFIX="
if /i "%SECURE_MODE%"=="secure" set "TLS_PREFIX=$env:BARAQ_TLS='1'; "
powershell -NoProfile -ExecutionPolicy Bypass -Command "%TLS_PREFIX%Start-Process -FilePath 'powershell.exe' -ArgumentList '%SERVER_ARGS%' -WindowStyle Hidden -WorkingDirectory '%CD%' -RedirectStandardOutput 'logs\server.out.log' -RedirectStandardError 'logs\server.err.log'"

echo.
echo  [DONE]  BARAQ is starting in the background. Closing this window...
ping -n 3 127.0.0.1 >nul
exit
