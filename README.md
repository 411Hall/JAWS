# JAWS - Just Another Windows (Enum) Script

JAWS is PowerShell script designed to help Penetration Testers quickly identify potential privilege escalation vectors on Windows systems. 

Its recommended you use the pre compiled standalone binary or compile the script yourself using the [PS2EXE tool] (https://gallery.technet.microsoft.com/PS2EXE-Convert-PowerShell-9e4e07f1)

## Usage:

```
Powershell Script
C:\> powershell.exe -ExecutionPolicy Bypass -file C:\jaws-enum.ps1

Standalone Exe
C:\> jaws-enum.exe

```

Currently the output to screen is a bit messy, its recommended you dump into a text file for now.
