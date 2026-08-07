@echo off
rem ===========================================================================
rem  SentinelSOC - build the standalone Windows executable (PyInstaller)
rem  Prerequisites: venv created and requirements.txt installed (start.bat
rem  does this), frontend built (frontend\dist\index.html must exist).
rem  Output: dist\SentinelSOC\SentinelSOC.exe  (copy that folder anywhere)
rem ===========================================================================
setlocal
cd /d "%~dp0.."

if not exist "venv\Scripts\python.exe" (
    echo  [ERROR] venv not found. Run start.bat once first (or create venv manually).
    pause
    exit /b 1
)
if not exist "frontend\dist\index.html" (
    echo  [ERROR] frontend\dist missing. Build the dashboard first:
    echo          cd frontend ^&^& npm install ^&^& npm run build
    pause
    exit /b 1
)

echo  [BUILD] Installing PyInstaller...
venv\Scripts\pip install pyinstaller
if errorlevel 1 (
    echo  [ERROR] Could not install PyInstaller.
    pause
    exit /b 1
)

echo  [BUILD] Packaging SentinelSOC (this takes several minutes)...
venv\Scripts\pyinstaller --noconfirm --clean sentinel.spec
if errorlevel 1 (
    echo  [ERROR] Build failed.
    pause
    exit /b 1
)

echo.
echo  [DONE]  Executable ready: dist\SentinelSOC\SentinelSOC.exe
echo         Copy the whole "dist\SentinelSOC" folder to any Windows 10/11 PC
echo         and run SentinelSOC.exe (no Python or Node needed).
echo         Usage:  SentinelSOC.exe       - local only
echo                 SentinelSOC.exe --lan - accessible from your network
pause