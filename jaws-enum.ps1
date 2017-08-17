Windows Priv Esc Enum

Overall
	- OS Version #
	- Hostname #
	- Current User #
Drives
	- HDS #
	- Mapped network drives #
	- Mounted devices #
Network
	- ipconfig#
	- route
	- arp #
	- firewall #
	- hosts file #
	- netstat #
Users
	- admin users #
	- logged in users#
Folders\Files
	- World writeable folders # 
	- World writeable files #
	- Recent docs #
	- Interesting files (.rdp, .sql, .bat, .ps1, .vbs, inf, conf, .xml) #
	- Read\Copy SAM file?
	- Files\Apps in startup directory
Processes
	- Running process (with cmd line) #
Install Apps
	- Install progs with version number #
Scheduled Tasks #
Unquoted Service Paths #
Tree\Dir List



----------
Command line args
Better output


write-host "`n-------------------------------------------------------------------------------------------------"
write-host "				   Keyword Search                                       "
write-host "-------------------------------------------------------------------------------------------------"
$lastmodified = get-childitem C:\
foreach ($modified in $lastmodified){
    try {
        Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue  | Select-String -pattern "password|admin" | group path | select name
         }
    catch {
        write "Failed to read more files"
    }
    }
    
    write-host "`n-------------------------------------------------------------------------------------------------"
write-host "				   10 Last Modified Files                                       "
write-host "-------------------------------------------------------------------------------------------------"
$lastmodified = get-childitem C:\Users
foreach ($modified in $lastmodified){
    try {
        Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue  | Sort {$_.LastWriteTime} | select -last 10
         }
    catch {
        write "Failed to read more files"
    }
    }

write-host "`n-------------------------------------------------------------------------------------------------"
write-host "				   SAM File Permissions                                       "
write-host "-------------------------------------------------------------------------------------------------"

get-acl "$env:SYSTEMROOT\System32\config\SAM" -EA SilentlyContinue | select path -expand access
get-acl "$env:SYSTEMROOT\repair\SAM" -EA SilentlyContinue
get-acl "$env:SYSTEMROOT\System32\config\RegBack\SAM" -EA SilentlyContinue


$files = get-childitem C:\
foreach ($file in $files){
    try {
        get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
        where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
        ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize
        }
    catch {
        write "Failed to read more files"
    }
    }
    
    
