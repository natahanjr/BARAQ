@echo off
rem ===========================================================================
rem  SentinelSOC - one-click launcher (Windows)
rem  Usage:
rem    start.bat          -> local only (127.0.0.1, HTTP)
rem    start.bat lan      -> exposed to the local network (0.0.0.0) + firewall
rem    start.bat secure   -> HTTPS with self-signed cert (localhost + LAN IPs)
rem    start.bat secure lan -> HTTPS exposed to the network
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
echo   SentinelSOC - Live Threat Detection
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
    echo  [SETUP] Installing dependencies (first run only, takes a few minutes)...
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
        echo  [SETUP] Building dashboard (first run only)...
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
    echo  [SETUP] Generating TLS certificate (if needed)...
    powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\gen_cert.ps1" >nul 2>&1
    if not exist "certs\sentinel.crt" (
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
    echo  [SETUP] Opening port %FW_PORT% in Windows Firewall (needs admin)...
    netsh advfirewall firewall add rule name="SentinelSOC" dir=in action=allow protocol=TCP localport=%FW_PORT% >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] Firewall rule not added - run this as Administrator if
        echo         other devices cannot connect.
    )
    echo.
    echo  Other devices on your network can now open:
    for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do echo   %FW_PROTO%://%%a:%FW_PORT%
    echo.
    echo  Create a user account for each person in the dashboard:
    echo  Users ^& Audit -^> Add User (analyst role).
    echo.
)

if /i "%SECURE_MODE%"=="secure" (
    echo  [START] Launching SentinelSOC (HTTPS) - open https://127.0.0.1:8443
    echo  [NOTE]  Your browser will warn about the self-signed certificate.
    echo          Trust it once, or import certs\sentinel.crt as a root CA.
    echo  [STOP]  Close this window (Ctrl+C) to shut SentinelSOC down.
    echo.
    start "" powershell -NoProfile -Command "Start-Sleep -Seconds 4; Start-Process 'https://127.0.0.1:8443'"

    if /i "%LAN_MODE%"=="lan" (
        venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8443 --ssl-certfile certs\sentinel.crt --ssl-keyfile certs\sentinel.key
    ) else (
        venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8443 --ssl-certfile certs\sentinel.crt --ssl-keyfile certs\sentinel.key
    )
) else (
    echo  [START] Launching SentinelSOC - open http://127.0.0.1:8001 in your browser
    echo  [STOP]  Close this window (Ctrl+C) to shut SentinelSOC down.
    echo.
    start "" powershell -NoProfile -Command "Start-Sleep -Seconds 4; Start-Process 'http://127.0.0.1:8001'"

    if /i "%LAN_MODE%"=="lan" (
        venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
    ) else (
        venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
    )
)
pause
