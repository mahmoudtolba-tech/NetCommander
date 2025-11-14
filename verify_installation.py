#!/usr/bin/env python3
"""
AutomationNet Installation Verification Script
Checks if all components are properly installed
"""

import os
import sys
import importlib.util

def check_python_version():
    """Check Python version"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} - NEEDS 3.8+")
        return False

def check_directory_structure():
    """Check if required directories exist"""
    print("\nChecking directory structure...")

    required_dirs = [
        'src/core',
        'src/gui',
        'src/utils',
        'src/templates',
        'data/profiles',
        'data/logs',
        'data/history',
        'cpp',
        'bin'
    ]

    all_ok = True
    for dir_path in required_dirs:
        if os.path.isdir(dir_path):
            print(f"  ✓ {dir_path}")
        else:
            print(f"  ✗ {dir_path} - MISSING")
            all_ok = False

    return all_ok

def check_core_files():
    """Check if core Python files exist"""
    print("\nChecking core files...")

    required_files = [
        'src/core/ip_validator.py',
        'src/core/connectivity.py',
        'src/core/ssh_handler.py',
        'src/gui/main_window.py',
        'src/utils/config_manager.py',
        'src/utils/logger.py',
        'src/utils/template_manager.py',
        'requirements.txt',
        'setup.py'
    ]

    all_ok = True
    for file_path in required_files:
        if os.path.isfile(file_path):
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ {file_path} - MISSING")
            all_ok = False

    return all_ok

def check_dependencies():
    """Check if required Python packages are installed"""
    print("\nChecking Python dependencies...")

    required_packages = [
        ('paramiko', 'Paramiko'),
        ('cryptography', 'Cryptography'),
    ]

    all_ok = True
    for module_name, package_name in required_packages:
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            print(f"  ✓ {package_name}")
        else:
            print(f"  ✗ {package_name} - NOT INSTALLED")
            all_ok = False

    return all_ok

def check_cpp_module():
    """Check if C++ fast ping module is available"""
    print("\nChecking C++ fast ping module...")

    cpp_files_exist = os.path.exists('cpp/fast_ping.cpp')
    bin_module_exists = any(f.startswith('fast_ping') and f.endswith('.so')
                           for f in os.listdir('bin') if os.path.isfile(os.path.join('bin', f)))

    if bin_module_exists:
        print("  ✓ C++ module compiled and available")
        print("    (High-performance ping enabled)")
        return True
    elif cpp_files_exist:
        print("  ⚠ C++ source exists but not compiled")
        print("    (Application will use fallback ping)")
        print("    Run: cd cpp && ./build.sh")
        return True
    else:
        print("  ⚠ C++ module not found")
        print("    (Application will use fallback ping)")
        return True

def check_scripts():
    """Check if launcher scripts exist"""
    print("\nChecking launcher scripts...")

    scripts = {
        'install.sh': os.path.isfile('install.sh'),
        'run.sh': os.path.isfile('run.sh'),
        'install.bat': os.path.isfile('install.bat'),
        'run.bat': os.path.isfile('run.bat')
    }

    for script, exists in scripts.items():
        if exists:
            print(f"  ✓ {script}")
        else:
            print(f"  ✗ {script} - MISSING")

    return all(scripts.values())

def check_venv():
    """Check if virtual environment exists"""
    print("\nChecking virtual environment...")

    if os.path.isdir('venv'):
        print("  ✓ Virtual environment exists")

        # Check if it's activated
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            print("  ✓ Virtual environment is ACTIVE")
            return True
        else:
            print("  ⚠ Virtual environment exists but NOT ACTIVE")
            print("    Activate with: source venv/bin/activate (Linux/Mac)")
            print("                   venv\\Scripts\\activate (Windows)")
            return True
    else:
        print("  ✗ Virtual environment NOT FOUND")
        print("    Run install.sh or install.bat")
        return False

def main():
    """Main verification function"""
    print("=" * 60)
    print("  AutomationNet Installation Verification")
    print("=" * 60)

    checks = [
        ("Python Version", check_python_version),
        ("Directory Structure", check_directory_structure),
        ("Core Files", check_core_files),
        ("Python Dependencies", check_dependencies),
        ("C++ Module", check_cpp_module),
        ("Launcher Scripts", check_scripts),
        ("Virtual Environment", check_venv)
    ]

    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"  ✗ Error during check: {e}")
            results.append((name, False))

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)

    critical_checks = ["Python Version", "Directory Structure", "Core Files", "Python Dependencies"]

    critical_passed = all(result for name, result in results if name in critical_checks)
    all_passed = all(result for _, result in results)

    if all_passed:
        print("✓ All checks passed! Installation is complete.")
        print("\nYou can run AutomationNet with:")
        print("  Linux/Mac: ./run.sh")
        print("  Windows:   run.bat")
        return 0
    elif critical_passed:
        print("⚠ Installation is functional but has warnings.")
        print("  The application will work, but some features may be limited.")
        print("\nYou can run AutomationNet with:")
        print("  Linux/Mac: ./run.sh")
        print("  Windows:   run.bat")
        return 0
    else:
        print("✗ Installation has critical issues.")
        print("  Please run install.sh or install.bat")
        return 1

if __name__ == '__main__':
    sys.exit(main())
