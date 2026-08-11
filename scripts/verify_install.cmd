@echo off
setlocal
title BARAQ install verification
echo ================================================
echo  BARAQ - one-click install verification
echo ================================================
set "APP=%ProgramFiles%\BARAQ"
set FAIL=0

echo.
echo [1/6] Installed files
if exist "%APP%\BARAQ.exe" (echo   [OK] BARAQ.exe) else (echo   [FAIL] BARAQ.exe missing & set FAIL=1)
if exist "%APP%\pg\bin\pg_ctl.exe" (echo   [OK] bundled PostgreSQL) else (echo   [FAIL] pg\bin\pg_ctl.exe missing & set FAIL=1)
if exist "%APP%\scripts\provision_postgres.ps1" (echo   [OK] scripts) else (echo   [FAIL] scripts missing & set FAIL=1)
if exist "%APP%\.env" (echo   [OK] .env) else (echo   [FAIL] .env missing - provisioning did not finish & set FAIL=1)

echo.
echo [2/6] PostgreSQL cluster (127.0.0.1:55432)
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 55432 -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
if %errorlevel%==0 (echo   [OK] listening on 55432) else (echo   [FAIL] no listener on 55432 & set FAIL=1)

echo.
echo [3/6] Backend service (try 8001)
set "PORT=8001"
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
if %errorlevel%==0 (echo   [OK] backend listening on %PORT%) else (echo   [FAIL] nothing on %PORT% & set FAIL=1)

echo.
echo [4/6] API health response
curl.exe -s -o NUL --max-time 5 http://127.0.0.1:%PORT%/api/health
if %errorlevel%==0 (echo   [OK] /api/health responds) else (echo   [FAIL] no health response & set FAIL=1)
curl.exe -s --max-time 5 http://127.0.0.1:%PORT%/api/health
echo.

echo.
echo [5/6] Seeded login (admin / sealed credential of this build)
del /q "%TEMP%\baraq_cookies.txt" > NUL 2>&1
set "BODY=%TEMP%\baraq_login.json"
echo {"username":"admin","password":"u9TPiwIpgJ4D"}> "%BODY%"
curl.exe -s -c "%TEMP%\baraq_cookies.txt" -H "Content-Type: application/json" --data "@%BODY%" http://127.0.0.1:%PORT%/api/auth/login > "%TEMP%\baraq_login_out.json"
findstr /I "token" "%TEMP%\baraq_login_out.json" > NUL
if %errorlevel%==0 (
  echo   [OK] admin login accepted
  curl.exe -s -b "%TEMP%\baraq_cookies.txt" -H "X-API-Key: baraq-admin-e1a5ffece0bc44b0a9f0" http://127.0.0.1:%PORT%/api/dashboard/summary
  echo.
) else (
  echo   [WARN] login rejected - if this console was ever booted with an older
  echo          build, its admin row keeps the older era's credential; otherwise
  echo          re-run the installer to reseed. Response was:
  type "%TEMP%\baraq_login_out.json"
  echo.
)

echo.
echo [6/6] Autostart registration
schtasks /Query /TN "\BARAQ" > NUL 2>&1
if %errorlevel%==0 (echo   [OK] autostart task \BARAQ registered) else (echo   [WARN] no autostart task - rerun installer with autostart enabled)

echo.
echo ================================================
if %FAIL%==1 (echo  RESULT: FAILURES ABOVE - re-run the installer and check %APP%\logs) else (echo  RESULT: looks good. Open http://127.0.0.1:%PORT% in a browser)
echo  Next: change the admin password, enroll MFA, create analysts
echo  (see documentation\deployment_guide.md, sections 1-3)
echo ================================================
endlocal