@echo off
setlocal
title ThreatPath AI — Standalone Windows .EXE Installer Builder
cd /d "%~dp0"

echo ====================================================================
echo   Building Standalone ThreatPath-AI-Setup.exe for Windows
echo ====================================================================

echo [1/3] Compiling Python AI Agent into threatpath-backend.exe via PyInstaller...
cd /d "%~dp0ai-agent-service"
if not exist ".venv" python -m venv .venv
call .venv\Scripts\activate.bat
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --onefile --name threatpath-backend app\main.py

echo [2/3] Building React Production Bundle...
cd /d "%~dp0frontend-react"
call npm install
call npm install --save-dev electron electron-builder
call npm run build

echo [3/3] Packaging Windows NSIS Setup.exe Installer via electron-builder...
call npx electron-builder --win nsis --config.extraResources="../ai-agent-service/dist/threatpath-backend.exe"

echo.
echo ====================================================================
echo   [SUCCESS] Standalone Windows Installer created in:
echo   frontend-react\dist\ThreatPath AI Setup 1.0.0.exe
echo ====================================================================
pause
endlocal
