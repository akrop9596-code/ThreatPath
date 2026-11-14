@echo off
setlocal
title ThreatPath AI — Defensive Cybersecurity Platform
cd /d "%~dp0"

echo ====================================================================
echo   ThreatPath AI — Starting Desktop Application
echo ====================================================================

:: 1. Start Python AI Agent Service (Port 8000) in minimized background window
echo [1/3] Starting Python AI Agent Service on http://127.0.0.1:8000 ...
start "ThreatPath AI - Agent Service" /min cmd /c "cd /d "%~dp0ai-agent-service" && (if not exist .venv python -m venv .venv) && call .venv\Scripts\activate.bat && pip install -r requirements.txt >nul 2>&1 && python -m app.main"

:: 2. Start React Dashboard (Port 5173) in minimized background window
echo [2/3] Starting ThreatPath AI Dashboard on http://localhost:5173 ...
start "ThreatPath AI - Frontend UI" /min cmd /c "cd /d "%~dp0frontend-react" && (if not exist node_modules call npm install) && call npm run dev -- --port 5173"

:: 3. Wait 3 seconds and open dedicated Chromeless App Window (Edge or Chrome App Mode)
echo [3/3] Opening ThreatPath AI Application Window...
timeout /t 3 /nobreak >nul

where msedge >nul 2>nul
if %errorlevel%==0 (
    start "" msedge --app="http://localhost:5173" --window-size=1440,900
    goto :running
)

where chrome >nul 2>nul
if %errorlevel%==0 (
    start "" chrome --app="http://localhost:5173" --window-size=1440,900
    goto :running
)

start "" "http://localhost:5173"

:running
echo.
echo ====================================================================
echo   [ACTIVE] ThreatPath AI Application is running!
echo   - App Window : http://localhost:5173
echo   - Agent API  : http://127.0.0.1:8000
echo ====================================================================
echo   To close ThreatPath AI completely, run Stop-ThreatPath-Windows.bat
echo   or press any key in this window to stop the background servers.
echo ====================================================================
pause >nul

call "%~dp0Stop-ThreatPath-Windows.bat"
endlocal
