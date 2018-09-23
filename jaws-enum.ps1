<#
.SYNOPSIS
Windows enumeration script
.DESCRIPTION
This script is designed to be used in a penetration test or CTF
enviroment. It will enumerate useful information from the host
for privilege escalation.
.EXAMPLE
PS > .\jaws-enum.ps1 
will write results out to screen.
.EXAMPLE
PS > .\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt
Writes out results to Jaws-Enum.txt in current directory.
.LINK
https://github.com/411Hall/JAWS
#>
Param(
    [String]$OutputFilename = ""
)

function JAWS-ENUM {
    write-output "`nRunning J.A.W.S. Enumeration"
    $output = "" 
    $output += "############################################################`r`n"
    $output += "##     J.A.W.S. (Just Another Windows Enum Script)        ##`r`n"
    $output += "##                                                        ##`r`n"
    $output += "##           https://github.com/411Hall/JAWS              ##`r`n"
    $output += "##                                                        ##`r`n"
    $output += "############################################################`r`n"
    $output += "`r`n"
    $win_version = (Get-WmiObject -class Win32_OperatingSystem)
    $output += "Windows Version: " + (($win_version.caption -join $win_version.version) + "`r`n")
    $output += "Architecture: " + (($env:processor_architecture) + "`r`n")
    $output += "Hostname: " + (($env:ComputerName) + "`r`n")
    $output += "Current User: " + (($env:username) + "`r`n")
    $output += "Current Time\Date: " + (get-date)
    $output += "`r`n"
    $output += "`r`n"
    write-output "	- Gathering User Information"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Users`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $output += "----------`r`n"
        $output += "Username: " + $_.Name +  "`r`n"
        $output += "Groups:   "  + $groups +  "`r`n"
    }
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Network Information`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (ipconfig | out-string)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Arp`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (arp -a | out-string) 
    $output += "`r`n"
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " NetStat`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (netstat -ano | out-string)
    $output += "`r`n"
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Firewall Status`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += "`r`n"
    $Firewall = New-Object -com HNetCfg.FwMgr
    $FireProfile = $Firewall.LocalPolicy.CurrentProfile  
    if ($FireProfile.FirewallEnabled -eq $False) {
        $output += ("Firewall is Disabled" + "`r`n")
        } else {
        $output += ("Firewall is Enabled" + "`r`n")
        }
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " FireWall Rules`r`n"
    $output += "-----------------------------------------------------------`r`n"
    Function Get-FireWallRule
    {Param ($Name, $Direction, $Enabled, $Protocol, $profile, $action, $grouping)
    $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
    If ($name)      {$rules= $rules | where-object {$_.name     -like $name}}
    If ($direction) {$rules= $rules | where-object {$_.direction  -eq $direction}}
    If ($Enabled)   {$rules= $rules | where-object {$_.Enabled    -eq $Enabled}}
    If ($protocol)  {$rules= $rules | where-object {$_.protocol   -eq $protocol}}
    If ($profile)   {$rules= $rules | where-object {$_.Profiles -bAND $profile}}
    If ($Action)    {$rules= $rules | where-object {$_.Action     -eq $Action}}
    If ($Grouping)  {$rules= $rules | where-object {$_.Grouping -like $Grouping}}
    $rules}
    $output += (Get-firewallRule -enabled $true | sort direction,applicationName,name | format-table -property Name , localPorts,applicationname | out-string)
    $output += "-----------------------------------------------------------`r`n"
    $output += " Hosts File Content`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += "`r`n"
    $output += ((get-content $env:windir\System32\drivers\etc\hosts | out-string) + "`r`n")
    $output += "`r`n"
    write-output "	- Gathering Processes, Services and Scheduled Tasks"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Processes`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += ((Get-WmiObject win32_process | Select-Object Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | sort name | format-table -wrap -autosize | out-string) + "`r`n")
    $output += "-----------------------------------------------------------`r`n"
    $output += " Scheduled Tasks`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += "Current System Time: " + (get-date)
    $output += (schtasks /query /FO CSV /v | convertfrom-csv | where { $_.TaskName -ne "TaskName" } | select "TaskName","Run As User", "Task to Run"  | fl | out-string)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Services`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (get-service | Select Name,DisplayName,Status | sort status | Format-Table -Property * -AutoSize | Out-String -Width 4096)
    $output += "`r`n"
    write-output "	- Gathering Installed Software"
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Installed Programs`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Installed Patches`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select HotFixID, InstalledOn| ft -autosize | out-string )
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Program Folders`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += "`n`rC:\Program Files`r`n"
    $output += "-------------"
    $output += (get-childitem "C:\Program Files"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string)
    $output += "C:\Program Files (x86)`r`n"
    $output += "-------------------"
    $output += (get-childitem "C:\Program Files (x86)"  -EA SilentlyContinue  | select Name  | ft -hidetableheaders -autosize| out-string)
    $output += "`r`n"
    write-output "	- Gathering File System Information"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Files with Full Control and Modify Access`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $files = get-childitem C:\
    foreach ($file in $files){
        try {
            $output += (get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf,*.ini -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
            where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
            ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
            }
        catch {
            $output += "`nFailed to read more files`r`n"
        }
        }

    $output += "-----------------------------------------------------------`r`n"
    $output += " Folders with Full Control and Modify Access`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $folders = get-childitem C:\
    foreach ($folder in $folders){
        try {
            $output += (Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  
            where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | 
            select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
             }
        catch {
            $output += "`nFailed to read more folders`r`n"
        }
        }
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Mapped Drives`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (Get-WmiObject -Class Win32_LogicalDisk | select DeviceID, VolumeName | ft -hidetableheaders -autosize | out-string -Width 4096)
    $output += "-----------------------------------------------------------`r`n"
    $output += " Unquoted Service Paths`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (cmd /c  'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """')
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Recent Documents`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent"  -EA SilentlyContinue | select Name | ft -hidetableheaders | out-string )
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Potentially Interesting Files in Users Directory `r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " 10 Last Modified Files in C:\User`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (Get-ChildItem 'C:\Users' -recurse -EA SilentlyContinue | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 10 | ft -hidetableheaders | out-string)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " MUICache Files`r`n"
    $output += "-----------------------------------------------------------`r`n"
    get-childitem "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\" -EA SilentlyContinue |
    foreach { $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
       if ($CurrentKey -match "C:\\") {
          $output += ($_.Property -join "`r`n")
       }
    }
    $output += "`r`n"
    $output += "`r`n"
    write-output "	- Looking for Simple Priv Esc Methods"
    $output += "-----------------------------------------------------------`r`n"
    $output += " System Files with Passwords`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $files = ("unattended.xml", "sysprep.xml", "autounattended.xml","unattended.inf", "sysprep.inf", "autounattended.inf","unattended.txt", "sysprep.txt", "autounattended.txt")
    $output += (get-childitem C:\ -recurse -include $files -EA SilentlyContinue  | Select-String -pattern "<Value>" | out-string)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Security Accounts Manager (SAM)`r`n"
    $output += "-----------------------------------------------------------`r`n "
    $output += ("$env:windir\System32\Config\sam", "$env:windir\System32\config\RegBack\SAM", "$env:windir\repair\sam",
                "$env:windir\System32\Config\SYSTEM","$env:windir\System32\Config\system.sav", "$env:windir\System32\config\RegBack\SYSTEM", "$env:windir\repair\SYSTEM") |
            ForEach-Object { $_+ 
                ((Get-Acl $_ -EA SilentlyContinue).Access |
                Where-Object {$_.IdentityReference -ne "NT AUTHORITY\SYSTEM"} |
                Format-List -Property IdentityReference, FileSystemRights |
                Out-String)}
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " AlwaysInstalledElevated Registry Key`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $HKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $HKCU =  "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (($HKLM | test-path) -eq "True") 
    {
        if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
        {
            $output += "AlwaysInstallElevated enabled on this host!"
        }
    }
    if (($HKCU | test-path) -eq "True") 
    {
        if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
        {
            $output += "AlwaysInstallElevated enabled on this host!"
        }
    }
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Stored Credentials`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += (cmdkey /list | out-string)
    $output += "`r`n"
    $output += "-----------------------------------------------------------`r`n"
    $output += " Checking for AutoAdminLogon `r`n"
    $output += "-----------------------------------------------------------`r`n"
    $Winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (get-itemproperty -path $Winlogon -Name AutoAdminLogon -ErrorAction SilentlyContinue) 
        {
        if ((get-itemproperty -path $Winlogon -Name AutoAdminLogon).AutoAdminLogon -eq 1) 
            {
            $Username = (get-itemproperty -path $Winlogon -Name DefaultUserName).DefaultUsername
            $output += "The default username is $Username `r`n"
            $Password = (get-itemproperty -path $Winlogon -Name DefaultPassword).DefaultPassword
            $output += "The default password is $Password `r`n"
            $DefaultDomainName = (get-itemproperty -path $Winlogon -Name DefaultDomainName).DefaultDomainName
            $output += "The default domainname is $DefaultDomainName `r`n"
            }
        }
    $output += "`r`n"
    if ($OutputFilename.length -gt 0)
       {
        $output | Out-File -FilePath $OutputFileName -encoding utf8
        }
    else
        {
        clear-host
        write-output $output
        }
}

if ($OutputFilename.length -gt 0)
    {
        Try 
            { 
                [io.file]::OpenWrite($OutputFilename).close()  
                JAWS-ENUM
            }
        Catch 
            { 
                Write-Warning "`nUnable to write to output file $OutputFilename, Check path and permissions" 
            }
    } 
else 
    {
    JAWS-ENUM
    }
