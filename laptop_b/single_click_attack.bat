@echo off
setlocal
title DB-IDS/IPS Lab Demo (Laptop B)
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python 3 is required. Install Python and retry.
    pause
    exit /b 1
)

python run_demo.py %*
set "RESULT=%ERRORLEVEL%"
echo.
if not "%RESULT%"=="0" echo Demo failed or completed with warnings; exit code %RESULT%.
pause
exit /b %RESULT%
