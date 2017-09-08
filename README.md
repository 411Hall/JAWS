# JAWS - Just Another Windows (Enum) Script

JAWS is PowerShell script designed to help Penetration Testers quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so is designed to work on as many operating systems as possible. It has currently been tested on Windows 7 and Windows 10.

## Usage:

```
CMD C:\>powershell.exe -ExecutionPolicy Bypass -C Invoke-Expression .\jaws-enum.ps1
```

## Current Features
  - Network Information (interfaces, arp, netstat)
  - Firewall Status and Rules
  - Running Processes
  - Files and Folders with Full Control or Modify Access
  - Mapped Drives
  - Unquoted Service Paths
  - Recent Documents
  - System Install Files 
  - AlwaysInstallElevated Registry Key Check
  - Stored Credentials
  - Installed Applications
  - Potentially Vulnerable Services
  - MuiCache Files
  - Scheduled Tasks

## To Do:
  - Add file search for common strings (password, keys etc.)
  - Add last 25 modified files
  - Add full directory listing with user defined depth
  - Add CMD line switches
  - Read SAM file permissions
  - Improve output
