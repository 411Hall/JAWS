write-host "#################################################################################################"
write-host "## 				         Windows Enum Script                               ##"
write-host "#################################################################################################"
write-host "`n"
$win_version = Get-WmiObject -class Win32_OperatingSystem
write-host "Windows Version: "$win_version.caption$win_version.version
write-host "Architecture: "$env:processor_architecture
write-host "Hostname: " $env:ComputerName
write-host "Current User: " $env:username


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Network Information                                       "
write-host "-------------------------------------------------------------------------------------------------"
Get-WmiObject Win32_NetworkAdapterConfiguration -filter 'IPEnabled= True' | select IpAddress, DNSDomain, DefaultIPGateway | ft -hidetableheaders -autosize | out-string


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					NetStat                                       "
write-host "-------------------------------------------------------------------------------------------------"
netstat -ano


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Users                                       "
write-host "-------------------------------------------------------------------------------------------------"
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$adsi.Children | where {$_.SchemaClassName -eq 'user'} | Foreach-Object {
    $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
    write-host "----------"
    write-host "Username: " $_.Name 
    write-host "Groups:   " $groups
}


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Processes                                       "
write-host "-------------------------------------------------------------------------------------------------"
Get-WmiObject win32_process | Select-Object Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | sort name | format-table -wrap -autosize | out-string


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Files with Full Control and Modify Access                                   "
write-host "-------------------------------------------------------------------------------------------------"
$files = get-childitem C:\
foreach ($file in $files){
    try {
        get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
        where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | ft @{Label="";Expression={Convert-Path $_.Path}} | ft | out-string
        }
    catch {
        write "Failed to read more files"
    }
    }
    
write-host "`n-------------------------------------------------------------------------------------------------"
write-host "				   Folders with Full Control and Modify Access                                       "
write-host "-------------------------------------------------------------------------------------------------"
$folders = get-childitem C:\
foreach ($folder in $folders){
    try {
        Get-ChildItem -Recurse "C:\$folder" | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}
         }
    catch {
        write "Failed to read more folders"
    }
    }
    

write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Mapped Drives                                    "
write-host "-------------------------------------------------------------------------------------------------"
Get-WmiObject -Class Win32_LogicalDisk | select DeviceID, VolumeName | ft -hidetableheaders -autosize | out-string


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Unquoted Service Path                                   "
write-host "-------------------------------------------------------------------------------------------------"
cmd /c  'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """'


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Recent Documents                                  "
write-host "-------------------------------------------------------------------------------------------------"
get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent" | select Name | ft -hidetableheaders | out-string


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Installed Applications                                  "
write-host "-------------------------------------------------------------------------------------------------"
get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize|  out-String


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Installed Pacthes                                  "
write-host "-------------------------------------------------------------------------------------------------"
Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select-object -Property HotFixID | Out-String


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Potentially Vulnerable Services                                "
write-host "-------------------------------------------------------------------------------------------------"
#Stolen from https://helvick.blogspot.co.uk/2007/08/checking-service-permissions-with.html
$services = get-wmiobject -query 'select * from win32_service'
foreach ($service in $services) {
    $path=$Service.Pathname
    if (-not( test-path $path -ea silentlycontinue)) {
        if ($Service.Pathname -match "(\""([^\""]+)\"")|((^[^\s]+)\s)|(^[^\s]+$)") {
            $path = $matches[0] –replace """",""
        }
    }
    if (test-path "$path") {
        $ServiceName = $service.Displayname
        $secure=get-acl $path
        foreach ($item in $secure.Access) {
            if ( ($item.IdentityReference -match "NT AUTHORITY\\SYSTEM"   ) -or
                 ($item.IdentityReference -match "NT AUTHORITY\\NETWORK"  ) -or
                 ($item.IdentityReference -match "BUILTIN\\Administrators") -or
                 ($item.IdentityReference -match "NT SERVICE\\TrustedInstaller") -or
                ($item.IdentityReference -match "BUILTIN\\Power Users"   ) ) {
            } else {         
                if ($item.FileSystemRights.tostring() -match "Modify|Full|Change") {
                    write-host "------------"
                    write-host $ServiceName 
                    write-host $item.IdentityReference.value 
                    write-host $item.AccessControlType.tostring() $item.FileSystemRights.tostring()
                }
            }
        }
     }
}
write-host "`n-------------------------------------------------------------------------------------------------"
write-host "					Scheduled Tasks                                "
write-host "-------------------------------------------------------------------------------------------------"
