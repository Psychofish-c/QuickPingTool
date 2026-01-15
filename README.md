# QuickPingTool

A lightweight and efficient local network scanning tool built with Python and Tkinter for Windows environments.

## Features
- **Network Discovery**: Scan IP ranges to find active devices on your local network
- **Host Information**: Display IP addresses, MAC addresses, hostnames, and response times
- **Ping Testing**: Test device connectivity with configurable timeout settings
- **Tracert Integration**: Perform route tracing on selected hosts
- **Export Results**: Save scan results to a text file for documentation
- **Simple GUI**: User-friendly interface with responsive controls

## Requirements
- Windows OS
- Python 3.x
- No external dependencies (uses standard libraries only)

## Usage
1. Run `main.py`
2. Configure your IP range (e.g., 192.168.1.1 to 192.168.1.30)
3. Click "Start Scan" to begin network discovery
4. Right-click any IP in the results table to perform a Tracert
5. Save results using the "Save Results" button
### OR JUST DOWNLOAD THE MAIN.EXE FILE IN DIST FOLDER

## How It Works
The tool uses Windows command-line utilities (`ping`, `arp`, `tracert`) to gather network information and presents it in a structured table format. All scanning operations run in separate threads to keep the interface responsive.

## Limitations
- Designed for Windows (uses Windows-specific commands)
- Requires administrative privileges for certain network operations
- Only scans IPv4 addresses
