@echo off
title PII Shield - Safe Demo Stopper
color 0E

echo ===============================================================================
echo                SHIELD 2.0 - SMART DATA MASKING SYSTEM
echo                     Safe Demo Shutdown Utility
echo ===============================================================================
echo.

echo [1/3] Terminating PII Shield console windows...
taskkill /FI "WINDOWTITLE eq PII_Shield_Backend*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq PII_Shield_Frontend*" /T /F >nul 2>&1

echo [2/3] Checking and clearing port 8000 (Backend)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo       [-] Stopping Backend process PID %%a...
    taskkill /PID %%a /F >nul 2>&1
)

echo [3/3] Checking and clearing port 3000 (Frontend)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3000 ^| findstr LISTENING') do (
    echo       [-] Stopping Frontend process PID %%a...
    taskkill /PID %%a /F >nul 2>&1
)

echo.
echo ===============================================================================
echo   PII Shield demonstration services have been safely stopped.
echo   Ports 8000 and 3000 are now released.
echo ===============================================================================
echo.
timeout /t 3 /nobreak >nul
exit /b 0

