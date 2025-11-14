#!/bin/bash
# AutomationNet Launcher Script

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ ! -d "venv" ]; then
    echo "Error: Virtual environment not found"
    echo "Please run install.sh first"
    exit 1
fi

source venv/bin/activate

# Run the application
python3 -m src.gui.main_window

# Deactivate when done
deactivate
