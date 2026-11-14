@echo off
setlocal
title ThreatPath AI — Windows Setup & Desktop App Installer
cd /d "%~dp0"

echo ====================================================================
echo   ThreatPath AI — Windows Setup ^& Desktop App Installer
echo ==========================================================
echo.

:: Step 1: Verify Python and Node.js
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 is not installed or not in PATH.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js / npm is not installed or not in PATH.
    echo Please install Node.js LTS from https://nodejs.org/
    pause
    exit /b 1
)

echo [1/4] Setting up Python AI Agent Virtual Environment...
cd /d "%~dp0ai-agent-service"
if not exist ".venv" (
    python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt

echo.
echo [2/4] Installing React Frontend Dependencies...
cd /d "%~dp0frontend-react"
if not exist "node_modules" (
    call npm install
)

echo.
echo [3/4] Creating "ThreatPath AI" Shortcut on Windows Desktop ^& Start Menu...
cd /d "%~dp0"
cscript //nologo "%~dp0Install-Windows-Desktop-Shortcut.vbs"

echo.
echo [4/4] Launching ThreatPath AI Desktop Application...
call "%~dp0Launch-ThreatPath-Windows.bat"
endlocal
