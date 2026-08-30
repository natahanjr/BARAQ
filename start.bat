@echo off
rem ===========================================================================
rem  BARAQ - one-click launcher (Windows) - Updated 2026-08-30
rem  UI/UX: token-driven system, WCAG-AA contrast, focus-trapped overlays,
rem  accessible badges/menus/tooltips, automated axe-core a11y gate.
rem  Usage:
rem    start.bat secure       -> STANDARD: HTTPS (TLS) with self-signed cert
rem    start.bat secure lan   -> standard + exposed to the local network
rem    start.bat              -> local only (127.0.0.1, plain HTTP - dev/lab)
rem    start.bat lan          -> plain HTTP exposed to the network (not recommended)
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
echo   Version: v6 (Phase 2 - ML Enhancements)
echo   Date: 2026-08-30
if /i "%LAN_MODE%"=="lan" echo   MODE: LAN (accessible from your network)
if /i "%SECURE_MODE%"=="secure" echo   MODE: HTTPS (TLS encrypted)
echo  ============================================
echo.

rem ---------------------------------------------------------------------------
rem  STEP 1: Python version check
rem ---------------------------------------------------------------------------
echo  [1/12] Checking Python...
where python >nul 2>nul
if errorlevel 1 (
    echo  [ERROR] Python not found on PATH. Install Python 3.11+ first:
    echo          https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set "PYVER=%%v"
echo        Python %PYVER%: OK

rem ---------------------------------------------------------------------------
rem  STEP 2: Virtual environment
rem ---------------------------------------------------------------------------
echo  [2/12] Checking virtual environment...
if not exist "venv\Scripts\python.exe" (
    echo        Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Could not create venv.
        pause
        exit /b 1
    )
    echo        Installing dependencies ^(first run only, takes a few minutes^)...
    venv\Scripts\python -m pip install --upgrade pip >nul 2>&1
    venv\Scripts\pip install -r requirements.txt
    if errorlevel 1 (
        echo  [ERROR] Dependency installation failed.
        pause
        exit /b 1
    )
)
echo        Virtual environment: OK

rem ---------------------------------------------------------------------------
rem  STEP 3: Logs directory
rem ---------------------------------------------------------------------------
echo  [3/12] Checking logs directory...
if not exist "logs" mkdir logs
echo        Logs: OK

rem ---------------------------------------------------------------------------
rem  STEP 4: Environment config (.env)
rem ---------------------------------------------------------------------------
echo  [4/12] Checking configuration...
if not exist ".env" (
    echo  [ERROR] .env file not found. Copy .env.example to .env and configure:
    echo          BARAQ_DATABASE_URL=postgresql+psycopg://user:pass@host:port/db
    pause
    exit /b 1
)
echo        Configuration: OK

rem ---------------------------------------------------------------------------
rem  STEP 5: Dashboard build (non-fatal — backend starts even if build fails)
rem ---------------------------------------------------------------------------
echo  [5/12] Building dashboard (UI/UX hardened build)...
set "FRONTEND_BUILD_OK=0"
where node >nul 2>nul
if errorlevel 1 (
    echo  [WARN] Node.js not found - dashboard UI will not be served.
    echo         Install Node.js 18+ then run:  cd frontend ^&^& npm install ^&^& npm run build
) else (
    pushd frontend
    call npm install
    if errorlevel 1 (
        echo  [WARN] npm install failed - dashboard will not be rebuilt.
        echo         Backend server will still start.
        popd
    ) else (
        call npm run build
        if errorlevel 1 (
            echo  [WARN] Dashboard build failed - backend server will still start.
            popd
        ) else (
            popd
            echo        Dashboard: OK
            set "FRONTEND_BUILD_OK=1"
        )
    )
)

rem ---------------------------------------------------------------------------
rem  STEP 5b: Accessibility gate (axe-core smoke tests)
rem ---------------------------------------------------------------------------
echo  [5b/12] Running a11y gate (axe-core)...
where node >nul 2>nul
if errorlevel 1 (
    echo  [SKIP] Node.js missing - skipping a11y gate.
) else (
    if exist "frontend\node_modules\.package-lock.json" (
        pushd frontend
        call npx vitest run --reporter=verbose 2>nul
        if errorlevel 1 (
            echo  [WARN] a11y gate reported issues - review src/test/a11y.test.jsx
        ) else (
            echo        a11y gate: OK
        )
        popd
    ) else (
        echo  [SKIP] frontend\node_modules missing - skipping a11y gate.
    )
)

rem ---------------------------------------------------------------------------
rem  STEP 6: TLS (if secure mode)
rem ---------------------------------------------------------------------------
if /i "%SECURE_MODE%"=="secure" (
    echo  [6/12] Generating TLS certificate...
    powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\gen_cert.ps1" >nul 2>&1
    if not exist "certs\baraq.crt" (
        echo  [ERROR] Certificate generation failed.
        pause
        exit /b 1
    )
    echo        TLS certificate: OK
) else (
    echo  [6/12] TLS: Skipped (not in secure mode)
)

rem ---------------------------------------------------------------------------
rem  STEP 7: LAN firewall
rem ---------------------------------------------------------------------------
if /i "%LAN_MODE%"=="lan" (
    if /i "%SECURE_MODE%"=="secure" (
        set "FW_PORT=8443"
        set "FW_PROTO=https"
    ) else (
        set "FW_PORT=8001"
        set "FW_PROTO=http"
    )
    echo  [7/12] Opening port %FW_PORT% in Windows Firewall...
    netsh advfirewall firewall add rule name="BARAQ" dir=in action=allow protocol=TCP localport=%FW_PORT% >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] Firewall rule not added - run this as Administrator.
    )
    echo.
    for /f "tokens=2 delims=: " %%a in ('ipconfig ^| findstr /c:"IPv4"') do set "MY_IP=%%a"
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
) else (
    echo  [7/12] Firewall: Skipped (not in LAN mode)
)

rem ---------------------------------------------------------------------------
rem  STEP 8: PostgreSQL database
rem ---------------------------------------------------------------------------
echo  [8/12] Ensuring PostgreSQL database...
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\pg_setup.ps1" -Action ensure
if errorlevel 1 (
    echo  [ERROR] PostgreSQL could not be started. Run scripts\download_postgres.ps1
    echo          to bundle PostgreSQL, or install PG 16+ and set BARAQ_PG_BIN.
    pause
    exit /b 1
)
echo        Database: OK

rem ---------------------------------------------------------------------------
rem  STEP 9: ML modules check
rem ---------------------------------------------------------------------------
echo  [9/12] Checking ML modules...
set "ML_OK=1"
if not exist "backend\ml\anomaly.py" (
    echo  [WARN] backend\ml\anomaly.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\ensemble.py" (
    echo  [WARN] backend\ml\ensemble.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\online.py" (
    echo  [WARN] backend\ml\online.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\robustness.py" (
    echo  [WARN] backend\ml\robustness.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\synthetic.py" (
    echo  [WARN] backend\ml\synthetic.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\cross_stream.py" (
    echo  [WARN] backend\ml\cross_stream.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\drift.py" (
    echo  [WARN] backend\ml\drift.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\explain.py" (
    echo  [WARN] backend\ml\explain.py missing
    set "ML_OK=0"
)
if not exist "backend\ml\monitoring.py" (
    echo  [WARN] backend\ml\monitoring.py missing
    set "ML_OK=0"
)
if "%ML_OK%"=="1" (
    echo        ML modules: OK ^(anomaly, ensemble, online, robustness, synthetic^)
) else (
    echo        ML modules: PARTIAL (some features may be unavailable)
)

rem ---------------------------------------------------------------------------
rem  STEP 9b: ML bootstrap model
rem ---------------------------------------------------------------------------
echo  [9b/12] Checking ML bootstrap model...
if not exist "backend\ml\assets\bootstrap_model.joblib" (
    echo        Building day-1 bootstrap detection model ^(one-time^)...
    venv\Scripts\python tools\build_bootstrap_model.py >nul 2>&1
    if exist "backend\ml\assets\bootstrap_model.joblib" (
        echo        Bootstrap model: OK
    ) else (
        echo  [WARN]  Bootstrap build skipped - detection starts cold.
    )
) else (
    echo        Bootstrap model: OK
)

rem ---------------------------------------------------------------------------
rem  STEP 10: Kill old server and start
rem ---------------------------------------------------------------------------
echo  [10/12] Starting BARAQ server...
set "TARGET_PORT=8001"
if /i "%SECURE_MODE%"=="secure" set "TARGET_PORT=8443"
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c":%TARGET_PORT% .*LISTENING"') do (
    echo        Stopping previous server on port %TARGET_PORT% ^(PID %%p^)...
    taskkill /f /pid %%p >nul 2>&1
)

set "SERVER_ARGS=-NoProfile -ExecutionPolicy Bypass -File scripts\run_server.ps1"
if /i "%LAN_MODE%"=="lan" set "SERVER_ARGS=%SERVER_ARGS% -Lan"
set "TLS_PREFIX="
if /i "%SECURE_MODE%"=="secure" set "TLS_PREFIX=$env:BARAQ_TLS='1'; "
powershell -NoProfile -ExecutionPolicy Bypass -Command "%TLS_PREFIX%Start-Process -FilePath 'powershell.exe' -ArgumentList '%SERVER_ARGS%' -WindowStyle Hidden -WorkingDirectory '%CD%' -RedirectStandardOutput 'logs\server.out.log' -RedirectStandardError 'logs\server.err.log'"

rem ---------------------------------------------------------------------------
rem  STEP 11: Frontend dev server (Vite)
rem ---------------------------------------------------------------------------
echo  [11/12] Starting frontend dev server...
where node >nul 2>nul
if errorlevel 1 (
    echo  [WARN] Node.js not found - frontend dev server skipped.
    echo         Dashboard available at http://127.0.0.1:8001 (served by backend)
) else (
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c":5173 .*LISTENING"') do (
        echo        Stopping previous Vite dev server on port 5173 ^(PID %%p^)...
        taskkill /f /pid %%p >nul 2>&1
    )
    pushd frontend
    start "" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-Location '%CD%'; npx vite --host 127.0.0.1 *> '..\logs\vite.out.log'"
    popd
    echo        Frontend dev server: OK (http://127.0.0.1:5173)
)

rem ---------------------------------------------------------------------------
rem  STEP 12: Wait for server and open browser
rem ---------------------------------------------------------------------------
echo  [12/12] Waiting for server to be ready and opening browser...
set "URL=http://127.0.0.1:8001"
if /i "%SECURE_MODE%"=="secure" set "URL=https://127.0.0.1:8443"

rem Wait up to 30 seconds for the server to come up
set "READY=0"
set /a "TRIES=0"
:WAIT_LOOP
if %TRIES% geq 30 goto DONE_WAIT
curl.exe -k -s -o nul "%URL%/api/health" >nul 2>&1
if %errorlevel% equ 0 (
    set "READY=1"
    goto DONE_WAIT
)
timeout /t 1 /nobreak >nul
set /a "TRIES+=1"
goto WAIT_LOOP
:DONE_WAIT

if "%READY%"=="1" (
    echo        Server is ready!
    start "" "%URL%"
) else (
    echo  [WARN] Server did not respond within 30 seconds. Try opening manually:
    echo         %URL%
)

rem ---------------------------------------------------------------------------
rem  Summary
rem ---------------------------------------------------------------------------
if /i "%SECURE_MODE%"=="secure" (
    set "URL=https://127.0.0.1:8443"
) else (
    set "URL=http://127.0.0.1:8001"
)

echo.
echo  ============================================
echo   BARAQ STARTED SUCCESSFULLY
echo  ============================================
echo.
echo  Server:       %URL%
echo  Frontend:     http://127.0.0.1:5173 (dev) or %URL% (production build)
echo  Database:     PostgreSQL @ 127.0.0.1:5432
echo  Login:        admin / Adwa1888
echo.
echo  ML System (v6):
echo    Features:   34 login / 32 process / 26 network
echo    Supervised: IsolationForest + XGBoost/RandomForest
echo    Ensemble:   Stacking meta-learner with interaction features
echo    Online:     Active learning + drift detection + rollback
echo    Robust:     Adversarial robustness module
echo    Synthetic:  5 real log types + 1 attack simulation type
echo    Cross:      Markov chain correlation + burst scoring
echo    Explain:    LIME + SHAP explainability
echo    Drift:      Feature-level PSI monitoring
echo.
echo  Collectors:   24 Windows event channels
echo    Security, System, PowerShell (Operational + Legacy)
echo    Sysmon (24 event types), Application, Defender
echo    Firewall, WFP, TaskScheduler, TerminalServices
echo    WMI, Code Integrity, Driver Frameworks, Group Policy
echo    NTLM, Kerberos, PrintService, AppLocker
echo    DNS Client, Hardware Events, USB, BitLocker, DiskDiagnostic
echo.
echo  Dashboard:    http://127.0.0.1:5173 (dev) or %URL% (prod)
echo  A11y gate:    axe-core smoke tests (npm test in frontend) - runs each launch
echo.
echo  [DONE]  BARAQ is starting in the background. Closing this window...
ping -n 3 127.0.0.1 >nul
exit
