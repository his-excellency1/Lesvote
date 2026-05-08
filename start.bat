@echo off
cd /d "%~dp0"
echo.
echo ========================================
echo     LESVOTE - Starting Application
echo ========================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Node.js is not installed!
    echo Download from: https://nodejs.org
    echo.
    pause
    exit /b 1
)

REM Check if node_modules exists
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo Starting server...
echo.
echo ========================================
echo   LESVOTE Server Running
echo ========================================
echo.
echo Open in browser: http://localhost:3000
echo.
echo Super Admin Login:
echo   Username: admin
echo   Password: awards2025
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

call npm start
