@echo off
setlocal enabledelayedexpansion
title PII Shield - One-Click Demo Launcher
color 0B

echo ===============================================================================
echo                SHIELD 2.0 - SMART DATA MASKING SYSTEM
echo                 One-Click Live Laptop Demonstration Launcher
echo ===============================================================================
echo.

cd /d "%~dp0"

:: 1. Verify Python availability
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python is not found in system PATH.
    echo Please install Python 3.10+ and ensure it is added to your PATH.
    pause
    exit /b 1
)

:: 2. Check and start Backend on port 8000
echo [1/3] Checking Backend Gateway (Port 8000)...
netstat -ano | findstr :8000 | findstr LISTENING >nul 2>&1
if %errorlevel% equ 0 (
    echo       [*] Backend service is ALREADY RUNNING on port 8000. Duplicate skipped.
) else (
    echo       [+] Launching FastAPI Gateway on http://127.0.0.1:8000...
    start "PII_Shield_Backend" cmd /k "title PII_Shield_Backend && python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"
)

:: 3. Wait for Backend Health Endpoint
echo [2/3] Verifying Backend Health (/health)...
set /a attempts=0
:WAIT_BACKEND
set /a attempts+=1
powershell -Command "$res = try { (Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -UseBasicParsing -TimeoutSec 1).StatusCode } catch { 0 }; if ($res -eq 200) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo       [*] Backend health check PASSED (HTTP 200 OK).
) else (
    if !attempts! geq 15 (
        color 0C
        echo [ERROR] Backend did not respond within 15 seconds.
        echo Please inspect the "PII_Shield_Backend" console window for details.
        pause
        exit /b 1
    )
    timeout /t 1 /nobreak >nul
    goto WAIT_BACKEND
)

:: 4. Check and start Frontend on port 3000
echo [3/3] Checking Frontend Web Server (Port 3000)...
netstat -ano | findstr :3000 | findstr LISTENING >nul 2>&1
if %errorlevel% equ 0 (
    echo       [*] Frontend server is ALREADY RUNNING on port 3000. Duplicate skipped.
) else (
    echo       [+] Launching HTTP Web Server on http://localhost:3000...
    start "PII_Shield_Frontend" cmd /k "title PII_Shield_Frontend && python -m http.server 3000 --directory frontend"
    timeout /t 1 /nobreak >nul
)

:: 5. Open Browser to Console
echo.
echo ===============================================================================
echo   SUCCESS! PII Shield is ready for offline laptop presentation.
echo   - Web Console:   http://localhost:3000
echo   - API Gateway:   http://127.0.0.1:8000
echo   - API Docs:      http://127.0.0.1:8000/docs
echo   - Demo Accounts: Admin (Anita), Support (Ravi), Analyst (Kavya)
echo.
echo   Opening default web browser now...
echo ===============================================================================
echo.

start http://localhost:3000

echo [INFO] Keep this terminal open or close it at any time.
echo [INFO] To stop all demo servers safely, run STOP_DEMO.bat
echo.
pause

