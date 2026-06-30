@echo off
cd /d "C:\Users\63aar\OneDrive\Documents\Firewall\firewall-agent"

set ANTHROPIC_API_KEY=sk-ant-api03-...

if not exist logs mkdir logs

echo 🔐 EDR Security Tool Starting...
echo ================================

echo [1/6] Starting Policy Server (port 8000)...
start "Policy Server" cmd /k "python -m uvicorn policy_server:app --port 8000"
timeout /t 2 /nobreak >nul

echo [2/6] Starting AI Engine (port 8001)...
start "AI Engine" cmd /k "python -m uvicorn ai_rule_engine:app --port 8001"
timeout /t 2 /nobreak >nul

echo [3/6] Starting Dashboard (port 5501)...
start "Dashboard" cmd /k "python -m http.server 5501"
timeout /t 2 /nobreak >nul

echo [4/6] Starting Agent Core...
start "Agent Core" cmd /k "python agent_core.py"
timeout /t 2 /nobreak >nul

echo [5/6] Starting DNS Filter...
start "DNS Filter" cmd /k "python dns_filter.py"
timeout /t 2 /nobreak >nul

echo [6/6] Starting Canary Monitor...
start "Canary Monitor" cmd /k "python canary.py"
timeout /t 3 /nobreak >nul

echo ================================
echo ✅ EDR System Started!
echo 📊 Opening Dashboard...
echo ================================

start "" "http://localhost:5501/dashboard.html"

pause
