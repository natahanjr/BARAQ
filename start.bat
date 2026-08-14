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

if /i "%SECURE_MODE%"=="secure" (
    echo  [START] Launching BARAQ ^(HTTPS^) - open https://127.0.0.1:8443
    echo  [NOTE]  Your browser will warn about the self-signed certificate.
    echo          Trust it once, or import certs\baraq.crt as a root CA.
    echo  [STOP]  Close this window ^(Ctrl+C^) to shut BARAQ down.
    echo         The browser opens automatically once the app is ready ^(up to 3 min^).
    echo.
    start "" powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\open_dashboard.ps1" -Url "https://127.0.0.1:8443"

    if /i "%LAN_MODE%"=="lan" (
        venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8443 --ssl-certfile certs\baraq.crt --ssl-keyfile certs\baraq.key
    ) else (
        venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8443 --ssl-certfile certs\baraq.crt --ssl-keyfile certs\baraq.key
    )
) else (
    echo  [START] Launching BARAQ - open http://127.0.0.1:8001 in your browser
    echo  [STOP]  Close this window ^(Ctrl+C^) to shut BARAQ down.
    echo         The browser opens automatically once the app is ready ^(up to 3 min^).
    echo.
    start "" powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\open_dashboard.ps1" -Url "http://127.0.0.1:8001"

    if /i "%LAN_MODE%"=="lan" (
        venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
    ) else (
        venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
    )
)
pause
