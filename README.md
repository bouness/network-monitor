# Network Monitor

A powerful, real-time network connection monitoring application with comprehensive analytics and security features. Built with Python and PySide6 for Windows.

![Network Monitor Screenshot](assets/icon.png)

## Features

### 🎯 **Real-time Monitoring**
- Live network connection tracking
- Process identification and categorization
- Automatic IP resolution to hostnames
- Connection status monitoring (ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)

### 🔒 **Security Features**
- New IP detection and alerts
- Automatic firewall rule generation for suspicious connections
- Microsoft/LAN/External connection categorization
- Whitelist for trusted applications
- Tray notifications for security events

### 📊 **Comprehensive Analytics**
- Real-time statistics dashboard
- Connection timeline and hourly distribution
- Top processes and destination tracking
- Session duration and connection counts
- Export capabilities (CSV, JSON, HTML, Text)

### 🎨 **User-Friendly Interface**
- Modern, responsive UI with system theme
- Tabbed interface with connection table, statistics, and logs
- Advanced filtering and search capabilities
- Context menu actions (copy, export, ping, WHOIS)
- System tray integration with background operation

### ⚙️ **Advanced Features**
- Configurable refresh intervals (1-60 seconds)
- Customizable alerts and notifications
- Auto-export functionality
- DNS cache flushing
- Firewall rules management
- Multi-format data export

## Installation

### Prerequisites
- Windows 10/11 (Linux/macOS support planned)
- Python 3.8 or higher
- Administrator privileges (for firewall rule generation)

### Quick Install
1. Clone the repository:
```bash
git clone https://github.com/bouness/network-monitor.git
cd network-monitor
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

### Manual Installation
If requirements.txt is not available:
```bash
pip install PySide6 psutil
```

## Usage

### Basic Usage
1. **Start Monitoring**: Click the "Start Monitoring" button or use the toolbar
2. **View Connections**: See all active network connections in the main table
3. **Filter Results**: Use the filter box to search by process, IP, or hostname
4. **Check Statistics**: Monitor real-time stats in the right panel
5. **Review Logs**: Check the Event Log tab for detailed connection history

### Advanced Features

#### **Connection Filtering**
- **Text Filter**: Search by process name, IP address, or hostname
- **Category Filter**: Filter by connection type (New IPs, Microsoft, External, LAN)
- **Quick Actions**: Right-click on connections for:
  - Copy selected data
  - Export selected connections
  - WHOIS lookup
  - Ping remote address

#### **Statistics Dashboard**
- **Summary**: Session duration, connection counts, unique processes/IPs
- **Timeline**: Hourly connection distribution
- **Top Lists**: Most active processes and destination IPs

#### **Export Options**
- **CSV**: Tabular data for spreadsheet analysis
- **JSON**: Structured data for programmatic use
- **HTML**: Formatted report with color coding
- **Text**: Simple text format for quick review

#### **Security Monitoring**
- **New IP Alerts**: Get notified when new external IPs are detected
- **Firewall Rules**: Automatic generation of Windows Firewall blocking rules
- **Whitelist**: Pre-configured list of trusted applications
- **Microsoft Services**: Automatic categorization of Microsoft services

### Command Line Options
```bash
# Start minimized to system tray
python napp.py --minimized

# Run with specific configuration
python napp.py --config custom_config.json
```

## Configuration

### Settings File
Settings are stored in `%APPDATA%\NetworkMonitor\App.ini` (Windows) or system-appropriate location.

### Available Settings
```ini
[Settings]
refresh_interval=1          ; Refresh rate in seconds (1-60)
enable_alerts=true          ; Enable/disable alerts
enable_sound=true           ; Enable/disable sound notifications
log_to_file=true           ; Enable/disable file logging
notify_new_ip=true         ; Notify on new IP detection
auto_export=false          ; Enable automatic data export
export_interval=60         ; Auto-export interval in minutes
max_table_rows=10000       ; Maximum rows in connection table
start_minimized=false      ; Start application minimized
```

### Whitelist Configuration
Edit the `WHITELIST_APPS` set in the source code to add trusted applications:
```python
WHITELIST_APPS = {
    "firefox.exe", "chrome.exe", "brave.exe",
    "explorer.exe", "svchost.exe", "taskhost.exe"
}
```

## Building from Source

### Development Setup
```bash
# Clone the repository
git clone https://github.com/bouness/network-monitor.git

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python napp.py
```

### Building Executable
```bash
# Using PyInstaller
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico napp.py

# The executable will be in dist/ folder
```

## File Structure
```
network-monitor/
├── napp.py      # Main application file
├── LICENSE.md              # License file
├── README.md              # This file
├── requirements.txt       # Python dependencies
├── seen_ips_live.json    # Tracked IP addresses
├── network_live_log.txt  # Application log file
└── firewall_block_suggestions.txt  # Generated firewall rules
```

## Generated Files
- **`seen_ips_live.json`**: Database of previously seen IP addresses
- **`network_live_log.txt`**: Application event log
- **`firewall_block_suggestions.txt`**: Generated Windows Firewall rules
- **`apply_firewall_blocks_*.bat`**: Batch files for applying firewall rules
- **`auto_export_*.json`**: Auto-exported data files
- **`network_export_*.{csv,json,html,txt}`**: Manual export files

## Troubleshooting

### Common Issues

#### **Application Won't Start**
- Ensure Python 3.8+ is installed
- Check all dependencies are installed: `pip install PySide6 psutil`
- Run as Administrator for full functionality

#### **No Connections Showing**
- Check if you have administrator privileges
- Ensure Windows Firewall isn't blocking the application
- Verify psutil has proper permissions

#### **High CPU Usage**
- Increase refresh interval in Settings
- Reduce maximum table rows
- Close unnecessary tabs/features

#### **Missing Features on Linux/macOS**
- Sound alerts require Windows
- Firewall rule generation is Windows-specific
- Some process details may differ

### Performance Tips
- Set higher refresh intervals for long-term monitoring
- Clear old data periodically
- Use filters to reduce table size
- Disable auto-scroll for better performance

## Security Considerations

### Data Privacy
- All data is stored locally
- No network transmission of collected data
- IP resolution uses local DNS cache

### Permissions Required
- **Network monitoring**: Requires elevated privileges
- **Process information**: Requires permission to query system processes
- **Firewall rules**: Requires Administrator rights

### Security Best Practices
1. Review generated firewall rules before applying
2. Regularly update whitelist with trusted applications
3. Monitor new IP alerts carefully
4. Export and review logs periodically
5. Keep the application updated

## Contributing

### How to Contribute
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

### Development Guidelines
- Follow PEP 8 coding standards
- Add comments for complex logic
- Update documentation for new features
- Test on multiple Windows versions
- Ensure backward compatibility

### Planned Features
- [ ] Cross-platform support (Linux/macOS)
- [ ] Network traffic analysis
- [ ] Historical data visualization
- [ ] Plugin system for custom analyzers
- [ ] Remote monitoring capabilities
- [ ] API for integration with other tools

## License

MIT License

Copyright (c) 2024 Network Monitor Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Support

### Documentation
- [Wiki](https://github.com/bouness/network-monitor/wiki)
- [API Reference](https://github.com/bouness/network-monitor/wiki/API)
- [Troubleshooting Guide](https://github.com/bouness/network-monitor/wiki/Troubleshooting)

### Community
- [GitHub Issues](https://github.com/bouness/network-monitor/issues)
- [Discussions](https://github.com/bouness/network-monitor/discussions)
- [Feature Requests](https://github.com/bouness/network-monitor/issues/new?template=feature_request.md)

### Professional Support
For enterprise features or custom development, contact: support@example.com

---

## Quick Start Commands

```bash
# Basic installation
git clone https://github.com/bouness/network-monitor.git
cd network-monitor
pip install -r requirements.txt
python napp.py

# Run with administrator privileges (Windows)
runas /user:Administrator "python napp.py"

# Create desktop shortcut (Windows)
python -c "import os; os.system('powershell \"$s=(New-Object -COM WScript.Shell).CreateShortcut(\\\"$env:USERPROFILE\\Desktop\\Network Monitor.lnk\\\"); $s.TargetPath=\\\"python\\\"; $s.Arguments=\\\"\\\"' + os.path.abspath('napp.py') + '\\\"\\\"; $s.WorkingDirectory=\\\"' + os.getcwd() + '\\\"; $s.Save()\"')"
```

## Acknowledgments

- **psutil** for cross-platform process and system utilities
- **PySide6** for the Qt Python bindings
- **Qt** for the application framework
- **Contributors** who help improve this project

---

**Note**: This tool is for legitimate network monitoring and security purposes only. Always ensure you have proper authorization before monitoring network traffic on any system.
