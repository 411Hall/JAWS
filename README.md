# JAWS - Just Another Windows (Enum) Script

JAWS is PowerShell script designed to help Penetration Testers quickly identify potential privilege escalation vectors on Windows systems. It is written using PowerShell 2.0 so is designed to work on as many operating systems as possible. It has currently been tested on Windows 7 and Windows 10.

Its recommended you use the pre compiled standalone binary or compile the script yourself using the [PS2EXE tool](https://gallery.technet.microsoft.com/PS2EXE-Convert-PowerShell-9e4e07f1)

## Usage:

```
Powershell Script
C:\> powershell.exe -ExecutionPolicy Bypass -file C:\jaws-enum.ps1

Standalone Exe
C:\> jaws-enum.exe

```

Currently the output is a bit messy, its recommended you dump into a text file for now.

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
