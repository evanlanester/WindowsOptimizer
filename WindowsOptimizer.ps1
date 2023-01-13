#requires -RunAsAdministrator

$SysInfo = Get-WmiObject -class Win32_OperatingSystem
$OS = $SysInfo.Caption

### Turn off Hibernation + Power Sleep Options
powercfg /S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /h off
powercfg /X monitor-timeout-ac 5
powercfg /X standby-timeout-ac 0
powercfg /Change monitor-timeout-dc 5
powercfg /Change standby-timeout-dc 0

### Turn off Suggestions in Start Menu
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -Value 0

### Removes 3D Object Folder
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force

if ($OS -like "Microsoft Windows 11 *") { # Windows 11 Context Menu Fix...
    # Windows 11 Context Menu Fix...    
    reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
    taskkill /IM explorer.exe /f
    Start-Process explorer.exe
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
	# Windows 11 Widgets Fix...
	Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarDa -Value 0
	Set-ItemProperty -Path HKCU:\S-1–5–21–2083603442–1438595618–1533545154–1001\Software\Microsoft\Windows\CurrentVersion\Dsh -Name IsPrelaunchEnabled -Value 0
}

## Optimize Windows
$services = @("Downloaded Maps Manager",
              "Geolocation Service",
			  "Internet Connection Sharing (ICS)",
			  "Parental Controls",
			  "Phone Service",
			  "Remote Procedure Call (RPC) Locator",
			  "Retail Demo Service",
			  "Wi-Fi Direct Services Connection Manager Service",
			  "Windows Camera Frame Server",
			  "Windows Connect Now - Config Registrar",
			  "Windows Insider Service",
			  "Windows Media Player Network Sharing Service",
			  "Windows Mobile Hotspot Service"
)

Foreach ($service in $services) {
    Write-Host "$service"
    $serviceName = (Get-Service -DisplayName $service).ServiceName
	Stop-Service -Name $serviceName -Force
	Set-Service -Name $serviceName -Status Stopped -StartupType Disabled
}

$GoodApps =	"store|calculator|stickynotes|ScreenSketch"
$SafeApps = "sechealth|secureas|desktopappinstaller|store"

Write-Host "***Removing many apps and provisioned appx packages for this machine...***"      
Get-AppxPackage -allusers | where-object {($_.name -notmatch $GoodApps) -and ($_.name -notmatch $SafeApps)} | Remove-AppxPackage -erroraction silentlycontinue
Get-AppxPackage -allusers | where-object {($_.name -notmatch $GoodApps) -and ($_.name -notmatch $SafeApps)} | Remove-AppxPackage -erroraction silentlycontinue
Get-AppxProvisionedPackage -online | where-object {($_.displayname -notmatch $GoodApps) -and ($_.displayname -notmatch $SafeApps)} | Remove-AppxProvisionedPackage -online -erroraction silentlycontinue

$FWRules = Get-NetFirewallRule
Foreach ($Rule in $FWRules) {
    If ($Rule.DisplayName -like "*XBOX*") {
        Disable-NetFirewallRule -Name $Rule.Name
    }
}

# Cleanup-UserProfiles
takeown /f c:\users\default\appdata\local\Microsoft\WindowsApps /r /a /d Y
icacls c:\users\default\appdata\local\Microsoft\WindowsApps /grant Administrators:F /T /C /L
get-childitem C:\Users\Default\AppData\Local\Microsoft -exclude "Windows" -Force | foreach ($_) {remove-item $_.fullname -force -recurse -confirm:$false}
get-childitem C:\Users\Default\AppData\Roaming\Microsoft\Windows -exclude "Start Menu","SendTo" -Force | foreach ($_) {remove-item $_.fullname -force -recurse -confirm:$false}
get-childitem C:\Users\Default\AppData\Roaming\Microsoft -exclude "Windows" -Force | foreach ($_) {remove-item $_.fullname -force -recurse -confirm:$false}
get-childitem C:\Users\Default\AppData\Roaming -exclude "Microsoft" -Force | foreach ($_) {remove-item $_.fullname -force -recurse -confirm:$false}
Get-ChildItem c:\users\default -Filter "*.log*" -Force | Remove-Item -Force
Get-ChildItem c:\users\default -Filter "*.blf*" -Force | Remove-Item -Force
Get-ChildItem c:\users\default -Filter "*.REGTRANS-MS" -Force | Remove-Item -Force

Remove-Item -Recurse $env:USERPROFILE\..\Default\AppData\Local
Remove-Item -Recurse $env:USERPROFILE\..\Default\AppData\LocalLow 
MKDIR $env:USERPROFILE\..\Default\AppData\Local\Microsoft\Windows
MKDIR $env:USERPROFILE\..\Default\AppData\Local\Temp
XCOPY /E $env:APPDATA\..\Local\Microsoft\Windows\WinX $env:USERPROFILE\..\Default\AppData\Local\Microsoft\Windows\WinX\ /y
Remove-Item -Force $env:USERPROFILE\..\Default\*.regtrans-ms
Remove-Item -Force $env:USERPROFILE\..\Default\ntuser.dat.log*
Remove-Item -Force $env:USERPROFILE\..\Default\*.blf
If (!(test-path "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell")) {
    MKDIR C:\Users\Default\AppData\Local\Microsoft\Windows\Shell
}

# Cleanup-Windows
Remove-Item -Force -Recurse $env:USERPROFILE\AppData\Local\Microsoft\Windows\WER\ReportArchive\*
Remove-Item -Force -Recurse $env:USERPROFILE\AppData\Local\Microsoft\Windows\WER\ReportQueue\*
Remove-Item -Force -Recurse $env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportArchive\*
Remove-Item -Force -Recurse $env:ALLUSERSPROFILE\Microsoft\Windows\WER\ReportQueue\*
Remove-Item -Force -Recurse $env:ALLUSERSPROFILE\Microsoft\Windows\WER\Temp\*
Remove-Item -Force -Recurse $env:ProgramData\Microsoft\Diagnosis\EventTranscript\*
Remove-Item -Force -Recurse $env:TEMP\*
Remove-Item -Force -Recurse $env:windir\Temp\*
Remove-Item -Force -Recurse $env:windir\Logs\*
Remove-Item -Force -Recurse $env:windir\System32\LogFiles\*
Remove-Item -Force -Recurse $env:windir\Windows\msdownld.tmp\*.tmp
Remove-Item -Force -Recurse $env:SystemDrive\msdownld.tmp\*.tmp
Remove-Item -Force -Recurse $env:SystemDrive\Catalog.wci\*
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.000\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.001\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.002\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.003\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.004\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.005\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.006\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.007\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.008\*.CHK
Remove-Item -Force -Recurse $env:SystemDrive\FOUND.009\*.CHK
Remove-Item -Force -Recurse $env:ProgramData\Microsoft\Windows\RetailDemo\*
Remove-Item -Force -Recurse $env:windir\setup*.log
Remove-Item -Force -Recurse $env:windir\setup*.old
Remove-Item -Force -Recurse $env:windir\setuplog.txt
Remove-Item -Force -Recurse $env:windir\winnt32.log
Remove-Item -Force -Recurse $env:windir\*.dmp
Remove-Item -Force -Recurse $env:windir\minidump\*.dmp
Remove-Item -Force -Recurse "$env:ProgramData\Microsoft\Windows Defender\LocalCopy\*"
Remove-Item -Force -Recurse "$env:ProgramData\Microsoft\Windows Defender\Support\*"
Write-Host "Enable components to cleanup"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v StateFlags0100 /d 2 /t REG_DWORD /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /v StateFlags0100 /d 2 /t REG_DWORD /f

#Cleanup Free Space
<#
Function ZeroFreeSpace {
    $cipherjob = @()
    $Job = start-job -ScriptBlock {cipher /w:C:\ }
    while ($cipherjob -notcontains "Writing 0xFF") {
        Write-host "." -nonewline 
        Start-Sleep 2
        $cipherjob += $job | Receive-Job 
    }
    Stop-Process -processname cipher
    Start-Sleep -s 3
    Remove-Item -recurse C:\EFSTMPWP
    $Job | Stop-Job | Remove-Job -Force
}
ZeroFreeSpace
#>

        #1# This function will convert byte Data to megabyte.
        function foldersize($folder) {
            $folderSizeinbyte = (Get-ChildItem $folder -Recurse | Measure-Object -property length -sum)
            $folderSizeinMB=($folderSizeinbyte.sum / 1MB).ToDecimal(2)
            return $folderSizeinMB
        }

        #2# This function will display the folder size before deletion.
        function before($folder1){
            $x=foldersize($folder1)
            write-host "Total size before deletion $x MB"
            return $x
        }

        #3# This function will display the folder size after deletion.
        function post($folder2){
            $y=foldersize($folder2)
            write-host "Total size after deletion $y MB"
            return $y
        }

        #4# This function will display the warning message.
        function msg($folder3){
            write-Host "Removing Junk files in $folder3." -ForegroundColor Yellow -background black
        }

        #5# This function will display the total spcae cleared.
        function totalmsg($folder4,$sum){
            write-Host "Total space cleared in MB from $folder4" $Sum  -ForegroundColor Green
        }

        ## This function will cleanup the specified folder
        function delete($folder5){
            [double]$a=before($folder5)
            msg($folder5)
            Remove-Item -Recurse  $folder5 -Force -Verbose
            [double]$b=post($folder5)

            $total=$a-$b
            totalmsg($folder5,$total)
            $a=0
            $b=0
            $total=0
        }

### Variables Declaration ###
        $temp = get-ChildItem "env:\TEMP"
        $temp2 = $temp.Value
        $WinTemp = "$env:SystemDrive\Windows\Temp\*"
        $CBS="$env:SystemDrive\Windows\Logs\CBS\"
        $swtools="$env:SystemDrive\swtools\*"
        $drivers="$env:SystemDrive\drivers\*"
        $swsetup="$env:SystemDrive\swsetup\*"
        $Prefetch="$env:SystemDrive\Windows\Prefetch\*"
        $DowloadUpdate="$env:SystemDrive\Windows\SoftwareDistribution\Download\*"
### End of variable Declaration ###

    # Remove temp files located in "C:\Users\USERNAME\AppData\Local\Temp"
        [double]$a=before($temp2)
        msg($temp2)
        Remove-Item -Recurse  "$temp2\*" -Force -Verbose
        [double]$b=post($temp2)

        $total=$a-$b
        totalmsg($temp2,$total)

    # Remove content of folder created during installation of driver
        delete($swtools)

    # Remove content of folder created during installation of Lenovo driver
        delete($drivers)

    # Remove content of folder created during installation of HP driver
        delete($swsetup)

    # Remove Windows Temp Directory
        delete($WinTemp)

    # Remove Prefetch folder content
        delete($Prefetch)

    # Remove CBS log file
        delete($CBS)

    # Remove downloaded update
        delete($DowloadUpdate)
        write-Host "**Clean Up completed**"

#DISM Component Cleanup (WinSxS)
DISM.exe /online /Cleanup-Image /StartComponentCleanup
#DISM CompactOS Feature
Compact.exe /CompactOS:always
