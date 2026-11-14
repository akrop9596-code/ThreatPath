@echo off
title Stopping ThreatPath AI
echo Shutting down ThreatPath AI background services...
taskkill /FI "WINDOWTITLE eq ThreatPath AI - Agent Service*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq ThreatPath AI - Frontend UI*" /T /F >nul 2>&1
echo [OK] ThreatPath AI services stopped.
