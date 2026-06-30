
@echo off
echo 🛑 Stopping EDR Security Tool...
echo ================================
 
echo [1/4] Stopping Policy Server...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000"') do taskkill /F /PID %%a >nul 2>&1
 
echo [2/4] Stopping AI Engine...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8001"') do taskkill /F /PID %%a >nul 2>&1
 
echo [3/4] Stopping Dashboard...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5501"') do taskkill /F /PID %%a >nul 2>&1
 
echo [4/4] Stopping Python processes...
taskkill /F /IM python.exe >nul 2>&1
 
echo ================================
echo ✅ EDR System Stopped!
echo ================================
pause
 