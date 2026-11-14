#!/usr/bin/env bash
set -e
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo "  ThreatPath AI — Defensive Cybersecurity Platform"
echo "=========================================================="

# 1. Ensure frontend/src/main.jsx exists
if [ ! -f "$APP_DIR/frontend-react/src/main.jsx" ]; then
  cat << 'MAIN_EOF' > "$APP_DIR/frontend-react/src/main.jsx"
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
MAIN_EOF
fi

# 2. Start Python AI Agent & Security Tool Service
echo "[1/3] Starting Python AI Agent Service on http://127.0.0.1:8000 ..."
cd "$APP_DIR/ai-agent-service"
if [ ! -d ".venv" ]; then
  echo "      Creating Python virtual environment (.venv)..."
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip >/dev/null 2>&1 || true
  pip install -r requirements.txt
else
  source .venv/bin/activate
fi

python3 -m app.main > /tmp/threatpath-agent.log 2>&1 &
AGENT_PID=$!

# 3. Start React Frontend Dashboard
echo "[2/3] Starting ThreatPath AI Dashboard on http://localhost:5173 ..."
cd "$APP_DIR/frontend-react"
if [ ! -d "node_modules" ]; then
  echo "      Installing frontend packages (first-time setup)..."
  npm install
fi

npm run dev -- --port 5173 > /tmp/threatpath-ui.log 2>&1 &
UI_PID=$!

# Cleanup handler on exit
cleanup() {
  echo ""
  echo "Shutting down ThreatPath AI services..."
  kill "$UI_PID" "$AGENT_PID" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 4. Wait for port 5173 to be ready, then open in App Mode window
echo "[3/3] Opening ThreatPath AI Application Window..."
sleep 2

if command -v chromium >/dev/null 2>&1; then
  chromium --app="http://localhost:5173" >/dev/null 2>&1 &
elif command -v google-chrome >/dev/null 2>&1; then
  google-chrome --app="http://localhost:5173" >/dev/null 2>&1 &
elif command -v firefox >/dev/null 2>&1; then
  firefox --new-window "http://localhost:5173" >/dev/null 2>&1 &
else
  xdg-open "http://localhost:5173" >/dev/null 2>&1 &
fi

echo ""
echo "=========================================================="
echo "  [ACTIVE] ThreatPath AI is running!"
echo "  -> Dashboard UI : http://localhost:5173"
echo "  -> Agent API    : http://127.0.0.1:8000"
echo "  -> Logs         : /tmp/threatpath-agent.log"
echo "=========================================================="
echo "  Keep this window minimized while using ThreatPath AI."
echo "  Press [ENTER] or close this window to stop the app."
echo "=========================================================="
read -r _
