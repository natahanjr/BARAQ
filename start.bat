@echo off
title BARAQ - Starting...

echo ========================================
echo   BARAQ SOC Platform - Starting...
echo ========================================
echo.

echo [1/2] Starting backend on port 8001...
start "BARAQ Backend" /MIN cmd /c "python start_dev.py > backend.log 2>&1"

timeout /t 3 /nobreak >nul

echo [2/2] Starting frontend on port 5173...
start "BARAQ Frontend" /MIN cmd /c "npm run dev > frontend.log 2>&1"

echo.
echo ========================================
echo   BARAQ is running!
echo   Frontend:  http://127.0.0.1:5173
echo   Backend:   http://127.0.0.1:8001
echo   Logs:      backend.log / frontend.log
echo ========================================
timeout /t 3 /nobreak >nul
