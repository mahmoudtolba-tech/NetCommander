#!/bin/bash
# AutomationNet Installation Script

set -e

echo "================================================"
echo "  AutomationNet v2.0 - Installation Script"
echo "================================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "[1/6] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo -e "${GREEN}Found Python $PYTHON_VERSION${NC}"

# Check if virtual environment module is available
echo ""
echo "[2/6] Checking virtual environment support..."
if ! python3 -c "import venv" &> /dev/null; then
    echo -e "${RED}Error: venv module not found${NC}"
    echo "Please install python3-venv:"
    echo "  Ubuntu/Debian: sudo apt-get install python3-venv"
    echo "  Fedora/RHEL: sudo dnf install python3-venv"
    exit 1
fi
echo -e "${GREEN}Virtual environment support available${NC}"

# Create virtual environment
echo ""
echo "[3/6] Creating virtual environment..."
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists, removing...${NC}"
    rm -rf venv
fi

python3 -m venv venv
echo -e "${GREEN}Virtual environment created${NC}"

# Activate virtual environment
echo ""
echo "[4/6] Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}Virtual environment activated${NC}"

# Upgrade pip
echo ""
echo "[5/6] Installing dependencies..."
pip install --upgrade pip setuptools wheel

# Install requirements
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo -e "${GREEN}Dependencies installed${NC}"
else
    echo -e "${YELLOW}Warning: requirements.txt not found${NC}"
fi

# Build C++ module (optional)
echo ""
echo "[6/6] Building C++ fast ping module (optional)..."
cd cpp

if [ -f "build.sh" ]; then
    chmod +x build.sh
    ./build.sh

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}C++ module built successfully${NC}"
    else
        echo -e "${YELLOW}C++ module build failed (application will use fallback)${NC}"
    fi
else
    echo -e "${YELLOW}Build script not found, skipping C++ module${NC}"
fi

cd ..

# Create launcher script
echo ""
echo "Creating launcher script..."
cat > run.sh << 'EOF'
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
EOF

chmod +x run.sh

# Create Windows launcher
cat > run.bat << 'EOF'
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
EOF

# Create Windows installation script
cat > install.bat << 'EOF'
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
EOF

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "To run AutomationNet:"
echo "  Linux/Mac: ./run.sh"
echo "  Windows:   run.bat"
echo ""
echo "The application has been installed in a virtual environment."
echo "All dependencies are isolated from your system Python."
echo ""
echo -e "${YELLOW}Note:${NC} If the C++ module failed to build, the application"
echo "will use a fallback ping implementation (slightly slower)."
echo ""
