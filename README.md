# NetCommander v2.0

**Modern Network Device Automation Tool with GUI**

[![Author](https://img.shields.io/badge/Author-Mahmoud%20Tolba-blue.svg)](https://github.com/mahmoudtolba)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python: 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)

NetCommander is a powerful Python-based network automation tool designed to configure multiple network devices simultaneously via SSH. Created by **Mahmoud Tolba**, it features a modern graphical user interface, configuration profiles, command templates, and comprehensive reporting capabilities.

## Features

### Core Functionality
- **Multi-Device SSH Automation**: Execute commands on multiple devices concurrently
- **IP Validation**: Automatic validation of IP addresses and CIDR notation support
- **Connectivity Checking**: Pre-execution ping tests to verify device reachability
- **Concurrent Execution**: Configurable parallel SSH connections for faster deployment
- **Error Handling**: Comprehensive error detection and reporting

### User Interface
- **Modern GUI**: Clean, tabbed interface built with Tkinter
- **Real-time Progress**: Live progress tracking and logging during execution
- **Interactive Results**: Detailed view of execution results per device
- **Easy Configuration**: Intuitive setup for credentials, IPs, and commands

### Configuration Management
- **Profiles**: Save and load complete configurations including credentials
- **Command Templates**: Pre-defined command sets for common tasks
- **Execution History**: Track previous automation runs
- **Secure Credential Storage**: Encrypted password storage using cryptography

### Reporting
- **Multiple Formats**: Export reports in Text, CSV, JSON, and HTML formats
- **Detailed Output**: Complete command output and error information
- **Execution Statistics**: Success rates, timing, and summary information
- **Visual Reports**: Professional HTML reports with styling

### Performance
- **C++ Fast Ping Module**: Optional high-performance ping implementation
- **Multi-threading**: Efficient concurrent operations
- **Fallback Support**: Automatic fallback if C++ module unavailable

## Installation

### Prerequisites
- Python 3.8 or higher
- Linux, macOS, or Windows
- For C++ module (optional): Python development headers

### Quick Install

#### Linux/macOS
```bash
# Clone or download the repository
cd NetCommander

# Run installation script
chmod +x install.sh
./install.sh
```

#### Windows
```cmd
# Clone or download the repository
cd NetCommander

# Run installation script
install.bat
```

### Manual Installation
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Build C++ module for better performance
cd cpp
python3 setup.py build_ext --inplace
mv fast_ping*.so ../bin/
cd ..
```

## Usage

### Starting the Application

#### Linux/macOS
```bash
./run.sh
```

#### Windows
```cmd
run.bat
```

### Using the GUI

#### 1. Setup Tab
- **IP Configuration**:
  - Manual entry: Enter IPs one per line (supports CIDR notation)
  - From file: Browse to a file containing IP addresses
  - Click "Validate IPs" to check validity

- **SSH Credentials**:
  - Enter username and password
  - Optionally provide enable password for privileged mode
  - Set SSH port (default: 22)

- **Commands**:
  - Enter commands one per line
  - Load from file or use pre-defined templates
  - Save custom templates for reuse

#### 2. Execution Tab
- Configure concurrent connections (1-20)
- Enable/disable pre-execution ping checks
- Monitor real-time progress and logs
- Start/stop execution

#### 3. Results Tab
- View summary statistics
- Browse detailed results per device
- Double-click devices to see full output
- Export reports in multiple formats

### Command Templates

NetCommander includes pre-defined templates for common tasks:

- **VLAN Setup**: Configure multiple VLANs
- **NTP Configuration**: Set up NTP servers
- **Backup Configuration**: Save running config
- **Show Device Info**: Display device information

Create custom templates via the GUI or manually in `src/templates/`.

### Configuration Profiles

Save complete configurations including:
- IP addresses
- Commands
- Credentials (encrypted)
- Execution settings

Load profiles quickly for repeated tasks.

## Project Structure

```
NetCommander/
├── src/
│   ├── core/                # Core functionality
│   │   ├── ip_validator.py  # IP validation
│   │   ├── connectivity.py  # Ping operations
│   │   └── ssh_handler.py   # SSH connections
│   ├── gui/                 # GUI components
│   │   └── main_window.py   # Main application
│   ├── utils/               # Utilities
│   │   ├── config_manager.py    # Profile management
│   │   ├── logger.py            # Logging & reporting
│   │   └── template_manager.py  # Templates & history
│   └── templates/           # Command templates
├── cpp/                     # C++ fast ping module
│   ├── fast_ping.cpp
│   ├── setup.py
│   └── build.sh
├── data/                    # Application data
│   ├── profiles/            # Saved profiles
│   ├── logs/                # Execution logs
│   └── history/             # Execution history
├── bin/                     # Compiled binaries
├── requirements.txt         # Python dependencies
├── setup.py                 # Package setup
├── install.sh               # Installation script (Linux/Mac)
├── install.bat              # Installation script (Windows)
├── run.sh                   # Launcher script (Linux/Mac)
└── run.bat                  # Launcher script (Windows)
```

## Examples

### Example 1: Configure VLANs on Multiple Switches

1. Enter IP addresses in Setup tab:
   ```
   192.168.1.10
   192.168.1.11
   192.168.1.12
   ```

2. Select "VLAN Setup" template or enter commands:
   ```
   enable
   conf t
   vlan 10
   name MANAGEMENT
   vlan 20
   name USERS
   exit
   ```

3. Enter credentials and click "Start Execution"

### Example 2: Collect Information from Routers

1. Load IP addresses from file
2. Select "Show Device Info" template
3. Execute and export results as HTML report

### Example 3: Subnet Configuration

1. Enter subnet in CIDR notation:
   ```
   192.168.1.0/24
   ```
   (This will expand to all host IPs in the subnet)

2. Configure commands and execute

## Security Considerations

- **Credential Storage**: Passwords are encrypted using Fernet (symmetric encryption)
- **Key Management**: Encryption keys stored in `.key` file with restricted permissions
- **SSH Security**: Uses Paramiko with configurable host key policies
- **Local Storage**: All data stored locally, no external communication

## Performance Optimization

### C++ Fast Ping Module
The optional C++ module provides significantly faster ping operations:
- 5-10x faster than system ping
- Lower overhead for large device counts
- Automatic fallback if unavailable

### Concurrent Connections
Adjust based on your network and system:
- Small networks: 5-10 concurrent connections
- Large networks: 10-20 concurrent connections
- Monitor system resources and adjust accordingly

## Troubleshooting

### Application won't start
- Ensure Python 3.8+ is installed
- Verify virtual environment is activated
- Check all dependencies are installed

### C++ module won't build
- Install Python development headers:
  - Ubuntu/Debian: `sudo apt-get install python3-dev`
  - Fedora/RHEL: `sudo dnf install python3-devel`
- The application works fine without it (uses fallback)

### SSH connections fail
- Verify credentials are correct
- Check network connectivity
- Ensure SSH is enabled on target devices
- Verify firewall rules allow SSH traffic

### Permission denied for ping
- C++ module requires root for raw sockets
- Application automatically uses fallback system ping
- No action needed

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

If you find this project useful, please consider:
- Starring the repository
- Sharing it with others
- Contributing improvements

## Changelog

### Version 2.0.0
- Complete rewrite with modern GUI
- Added configuration profile management
- Implemented command templates
- Added multiple report formats
- Secure credential storage
- C++ fast ping module
- Execution history tracking
- CIDR notation support
- Concurrent execution controls
- Real-time progress tracking

### Version 1.0.0
- Initial CLI-based implementation
- Basic SSH automation
- IP validation
- Multi-threading support

## Author

**Mahmoud Tolba** - Network Automation Engineer

Specialized in network automation, DevOps, and infrastructure management. NetCommander was created to simplify bulk network device configuration and management tasks.

## Acknowledgments

- Built with Python and Tkinter
- SSH functionality via Paramiko
- Encryption via Cryptography library
- Inspired by network automation best practices

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**NetCommander** - Simplifying network device configuration at scale.

Created by [Mahmoud Tolba](https://github.com/mahmoudtolba-tech)
