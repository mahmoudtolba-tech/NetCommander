@echo off
REM AutomationNet Launcher Script for Windows

cd /d %~dp0

REM Check if virtual environment exists
if not exist "venv\" (
    echo Error: Virtual environment not found
    echo Please run install.bat first
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Run the application
python -m src.gui.main_window

REM Deactivate when done
call venv\Scripts\deactivate.bat
pause
