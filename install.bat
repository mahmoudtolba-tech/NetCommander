@echo off
REM AutomationNet Installation Script for Windows

echo ================================================
echo   AutomationNet v2.0 - Installation Script
echo ================================================
echo.

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from python.org
    pause
    exit /b 1
)

echo [2/4] Creating virtual environment...
if exist "venv\" (
    echo Virtual environment already exists, removing...
    rmdir /s /q venv
)

python -m venv venv
if errorlevel 1 (
    echo Error: Failed to create virtual environment
    pause
    exit /b 1
)

echo [3/4] Activating virtual environment...
call venv\Scripts\activate.bat

echo [4/4] Installing dependencies...
python -m pip install --upgrade pip setuptools wheel
if exist "requirements.txt" (
    pip install -r requirements.txt
) else (
    echo Warning: requirements.txt not found
)

echo.
echo ================================================
echo Installation complete!
echo ================================================
echo.
echo To run AutomationNet, execute: run.bat
echo.
pause
