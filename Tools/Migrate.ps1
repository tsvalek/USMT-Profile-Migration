#Requires -Version 3.0
<#
.SYNOPSIS
    USMT Profile Migration Tool
    Instrument dlya perenosa profiley polzovateley Windows

.DESCRIPTION
    Interaktivnyy skript dlya eksporta i importa profiley polzovateley
    s ispolzovaniem Microsoft USMT (User State Migration Tool)

.NOTES
    Versiya: 1.1
    Trebuet: Prava administratora, USMT v papke Tools\USMT\amd64\
#>

#region === CONFIGURATION ===

# Setevaya papka dlya hraneniya profiley
$script:NetworkShare = "\\truenas\Share\Profiles"

# Uchetnye dannye dlya podklyucheniya (dlya ne-domennyh PK)
$script:ShareUsername = "rh\prd13"
$script:SharePassword = "123456"

# Puti otnositelno skripta
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:USMTNetworkPath = Join-Path $ScriptDir "USMT\amd64"
$script:ConfigPath = Join-Path $ScriptDir "Config"
$script:MigExcludeXml = Join-Path $ConfigPath "MigExclude.xml"
$script:MigCustomXml = Join-Path $ConfigPath "MigCustom.xml"

# Lokalnaya papka dlya USMT (USMT ne rabotaet s setevyh putey)
$script:USMTLocalPath = "$env:TEMP\USMT_Migration"
$script:USMTPath = Join-Path $USMTLocalPath "amd64"

# Imya diska dlya mappinga setevoy papki
$script:MappedDrive = "Z:"

# Flag chto USMT skopirovan lokalno
$script:USMTCopiedLocally = $false

#endregion

#region === HELPER FUNCTIONS ===

function Write-ColorText {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::White,
        [switch]$NoNewline
    )
    $prevColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    if ($NoNewline) {
        Write-Host $Text -NoNewline
    }
    else {
        Write-Host $Text
    }
    $Host.UI.RawUI.ForegroundColor = $prevColor
}

function Write-Header {
    param([string]$Title)
    Clear-Host
    Write-Host ""
    Write-ColorText "================================================================" -Color Cyan
    Write-ColorText "  $Title" -Color Yellow
    Write-ColorText "================================================================" -Color Cyan
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    switch ($Type) {
        "Info" { $symbol = "[i]"; $color = [ConsoleColor]::Cyan }
        "Success" { $symbol = "[+]"; $color = [ConsoleColor]::Green }
        "Warning" { $symbol = "[!]"; $color = [ConsoleColor]::Yellow }
        "Error" { $symbol = "[X]"; $color = [ConsoleColor]::Red }
    }
    Write-ColorText $symbol -Color $color -NoNewline
    Write-Host " $Message"
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-USMTPresent {
    # Proveryaem sperva lokalnuyu kopiyu
    $localScanstate = Join-Path $USMTPath "scanstate.exe"
    if (Test-Path $localScanstate) {
        return $true
    }
    
    # Proveryaem setevuyu kopiyu
    $networkScanstate = Join-Path $USMTNetworkPath "scanstate.exe"
    $networkLoadstate = Join-Path $USMTNetworkPath "loadstate.exe"
    return (Test-Path $networkScanstate) -and (Test-Path $networkLoadstate)
}

function Copy-USMTLocally {
    <#
    .SYNOPSIS
        Kopiruet USMT na lokalnyy disk (USMT ne rabotaet s setevyh putey)
    #>
    
    # Proveryaem, mozhet uzhe skopirovano
    $localScanstate = Join-Path $USMTPath "scanstate.exe"
    $localConfigPath = Join-Path $USMTLocalPath "Config"
    
    if (Test-Path $localScanstate) {
        Write-Status "USMT already cached locally" -Type Success
        $script:USMTCopiedLocally = $true
        # Vazno: obnovlyaem put k MigExclude i MigCustom dazhe esli uzhe skopirovano
        $script:MigExcludeXml = Join-Path $localConfigPath "MigExclude.xml"
        $script:MigCustomXml = Join-Path $localConfigPath "MigCustom.xml"
        return $true
    }
    
    Write-Status "Copying USMT to local disk (required for execution)..." -Type Info
    
    try {
        # Sozdaem papku
        if (-not (Test-Path $USMTLocalPath)) {
            New-Item -Path $USMTLocalPath -ItemType Directory -Force | Out-Null
        }
        
        # Kopiruem USMT
        Copy-Item -Path $USMTNetworkPath -Destination $USMTLocalPath -Recurse -Force
        
        # Kopiruem Config
        $localConfigPath = Join-Path $USMTLocalPath "Config"
        if (-not (Test-Path $localConfigPath)) {
            New-Item -Path $localConfigPath -ItemType Directory -Force | Out-Null
        }
        Copy-Item -Path "$ConfigPath\*" -Destination $localConfigPath -Recurse -Force
        
        # Obnovlyaem put k MigExclude i MigCustom
        $script:MigExcludeXml = Join-Path $localConfigPath "MigExclude.xml"
        $script:MigCustomXml = Join-Path $localConfigPath "MigCustom.xml"
        
        $script:USMTCopiedLocally = $true
        Write-Status "USMT copied to: $USMTLocalPath" -Type Success
        return $true
    }
    catch {
        Write-Status "Error copying USMT: $_" -Type Error
        return $false
    }
}

function Remove-LocalUSMT {
    <#
    .SYNOPSIS
        Udalyaet lokalnuyu kopiyu USMT (opciya)
    #>
    if ($USMTCopiedLocally -and (Test-Path $USMTLocalPath)) {
        try {
            # Ne udalyaem - pust ostaetsya dlya sleduyushchego raza (cache)
            # Remove-Item -Path $USMTLocalPath -Recurse -Force
            # Write-Status "Local USMT copy removed" -Type Info
        }
        catch { }
    }
}

function Connect-NetworkShare {
    # Proveryaem, dostupna li papka napryamuyu (domen)
    if (Test-Path $NetworkShare -ErrorAction SilentlyContinue) {
        Write-Status "Network share accessible" -Type Success
        return $true
    }
    
    Write-Status "Connecting to network share..." -Type Info
    
    # Probuem podklyuchit s uchetnymi dannymi
    try {
        # Udalyaem staroe podklyuchenie esli est
        net use $MappedDrive /delete 2>$null | Out-Null
        
        # Podklyuchaem s uchetnymi dannymi
        $result = net use $MappedDrive $NetworkShare /user:$ShareUsername $SharePassword 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Network share connected as $MappedDrive" -Type Success
            return $true
        }
        else {
            Write-Status "Connection error: $result" -Type Error
            return $false
        }
    }
    catch {
        Write-Status "Connection error: $_" -Type Error
        return $false
    }
}

function Disconnect-NetworkShare {
    if (Test-Path $MappedDrive -ErrorAction SilentlyContinue) {
        net use $MappedDrive /delete /y 2>$null | Out-Null
    }
}

function Get-EffectiveSharePath {
    if (Test-Path $NetworkShare -ErrorAction SilentlyContinue) {
        return $NetworkShare
    }
    elseif (Test-Path $MappedDrive -ErrorAction SilentlyContinue) {
        return $MappedDrive
    }
    return $null
}

function Get-LocalUserProfiles {
    $profiles = @()
    
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object {
        -not $_.Special -and
        $_.LocalPath -like "C:\Users\*" -and
        $_.LocalPath -notlike "*\Default*" -and
        $_.LocalPath -notlike "*\Public*"
    }
    
    foreach ($profile in $userProfiles) {
        $username = Split-Path $profile.LocalPath -Leaf
        $lastUse = $null
        
        if ($profile.LastUseTime) {
            try {
                $lastUse = [System.Management.ManagementDateTimeConverter]::ToDateTime($profile.LastUseTime)
            }
            catch { }
        }
        
        # Poluchaem SID i probuem opredelit domennoe imya
        $sid = $profile.SID
        $domainUser = $username
        
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
            $domainUser = $objUser.Value
        }
        catch { }
        
        $profiles += [PSCustomObject]@{
            Username   = $username
            DomainUser = $domainUser
            LocalPath  = $profile.LocalPath
            SID        = $sid
            LastUsed   = $lastUse
            Loaded     = $profile.Loaded
        }
    }
    
    return $profiles | Sort-Object LastUsed -Descending
}

function Get-SavedProfiles {
    $sharePath = Get-EffectiveSharePath
    if (-not $sharePath) {
        return @()
    }
    
    $profiles = @()
    
    $folders = Get-ChildItem -Path $sharePath -Directory -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -ne "Tools" }
    
    foreach ($folder in $folders) {
        $usmtFolder = Join-Path $folder.FullName "USMT"
        $logFile = Join-Path $folder.FullName "scanstate.log"
        
        $hasUSMT = Test-Path $usmtFolder
        $hasLog = Test-Path $logFile
        
        # Parsim imya i datu iz imeni papki
        if ($folder.Name -match "^(.+)_(\d{4}-\d{2}-\d{2})") {
            $username = $Matches[1]
            $dateStr = $Matches[2]
        }
        else {
            $username = $folder.Name
            $dateStr = $null
        }
        
        # Schitaem razmer
        $size = 0
        if ($hasUSMT) {
            $size = (Get-ChildItem -Path $usmtFolder -Recurse -File -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum).Sum
        }
        
        $profiles += [PSCustomObject]@{
            FolderName = $folder.Name
            Username   = $username
            Date       = $dateStr
            Path       = $folder.FullName
            HasUSMT    = $hasUSMT
            HasLog     = $hasLog
            SizeMB     = [math]::Round($size / 1MB, 2)
            Created    = $folder.CreationTime
        }
    }
    
    return $profiles | Sort-Object Created -Descending
}

function Write-Log {
    param(
        [string]$LogPath,
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logMessage -Encoding UTF8
}

#endregion

#region === EXPORT FUNCTIONS ===

function Start-ProfileExport {
    Write-Header "EXPORT PROFILE"
    
    # Proveryaem nalichie USMT
    if (-not (Test-USMTPresent)) {
        Write-Status "USMT not found in: $USMTNetworkPath" -Type Error
        Write-Host ""
        Write-Host "Please download Windows ADK and copy USMT to the specified folder."
        Write-Host "Details: https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install"
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    # Podklyuchaem setevuyu papku
    if (-not (Connect-NetworkShare)) {
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    # Kopiruem USMT lokalno (obyazatelno!)
    if (-not (Copy-USMTLocally)) {
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    $sharePath = Get-EffectiveSharePath
    Write-Host ""
    
    # Poluchaem spisok profiley
    Write-Status "Getting user profiles list..." -Type Info
    $profiles = Get-LocalUserProfiles
    
    if ($profiles.Count -eq 0) {
        Write-Status "No user profiles found" -Type Warning
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    Write-Host ""
    Write-ColorText "Available profiles:" -Color Yellow
    Write-Host ""
    Write-Host "  #   User                                Last Login            Status"
    Write-Host "  --- ----------------------------------- --------------------- ----------"
    
    $i = 1
    foreach ($profile in $profiles) {
        $num = $i.ToString().PadRight(3)
        $user = $profile.DomainUser
        if ($user.Length -gt 35) { $user = $user.Substring(0, 32) + "..." }
        $user = $user.PadRight(35)
        $lastUsed = if ($profile.LastUsed) { $profile.LastUsed.ToString("dd.MM.yyyy HH:mm") } else { "N/A" }
        $lastUsed = $lastUsed.PadRight(21)
        $status = if ($profile.Loaded) { "Active" } else { "Inactive" }
        
        if ($profile.Loaded) {
            Write-Host "  $num " -NoNewline
            Write-ColorText $user -Color Cyan -NoNewline
            Write-Host " $lastUsed " -NoNewline
            Write-ColorText $status -Color Green
        }
        else {
            Write-Host "  $num $user $lastUsed $status"
        }
        $i++
    }
    
    Write-Host ""
    Write-Host "  0   Return to main menu"
    Write-Host ""
    
    # Vybor polzovatelya
    $selection = Read-Host "Select profile to export (number)"
    
    if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
        return
    }
    
    $index = [int]$selection - 1
    if ($index -lt 0 -or $index -ge $profiles.Count) {
        Write-Status "Invalid selection" -Type Error
        Start-Sleep -Seconds 2
        return
    }
    
    $selectedProfile = $profiles[$index]
    $username = $selectedProfile.Username
    
    Write-Host ""
    Write-Status "Selected profile: $($selectedProfile.DomainUser)" -Type Info
    
    # Sozdayom papku dlya eksporta
    $dateStr = Get-Date -Format "yyyy-MM-dd"
    $exportFolderName = "${username}_${dateStr}"
    $exportPath = Join-Path $sharePath $exportFolderName
    
    # Proveryaem sushchestvovanie
    if (Test-Path $exportPath) {
        Write-Status "Folder $exportFolderName already exists" -Type Warning
        $timeStr = Get-Date -Format "HHmmss"
        $exportFolderName = "${username}_${dateStr}_${timeStr}"
        $exportPath = Join-Path $sharePath $exportFolderName
        Write-Status "Will create: $exportFolderName" -Type Info
    }
    
    # Sozdayom strukturu papok
    $usmtExportPath = Join-Path $exportPath "USMT"
    New-Item -Path $usmtExportPath -ItemType Directory -Force | Out-Null
    
    $logFile = Join-Path $exportPath "migration.log"
    $scanstateLog = Join-Path $exportPath "scanstate.log"
    $progressLog = Join-Path $exportPath "progress.log"
    
    Write-Log -LogPath $logFile -Message "Export started for profile: $($selectedProfile.DomainUser)"
    Write-Log -LogPath $logFile -Message "Source computer: $env:COMPUTERNAME"
    Write-Log -LogPath $logFile -Message "Export folder: $exportPath"
    Write-Log -LogPath $logFile -Message "USMT local path: $USMTPath"
    
    Write-Host ""
    Write-ColorText "================================================================" -Color DarkGray
    Write-Status "Starting USMT ScanState..." -Type Info
    Write-Status "This may take several minutes, please wait..." -Type Info
    Write-ColorText "================================================================" -Color DarkGray
    Write-Host ""
    
    # Formiruem komandu scanstate
    $scanstate = Join-Path $USMTPath "scanstate.exe"
    $migapp = Join-Path $USMTPath "migapp.xml"
    # migdocs.xml ubrali - on skaniruet vse diski, nam nuzhna tolko papka profilya
    $miguser = Join-Path $USMTPath "miguser.xml"
    
    # Opredelyaem domen i polzovatelya dlya /ui parametra
    $userInclude = $selectedProfile.DomainUser
    if (-not $userInclude.Contains("\")) {
        $userInclude = "$env:USERDOMAIN\$username"
    }
    
    $arguments = @(
        "`"$usmtExportPath`""
        "/i:`"$migapp`""
        "/i:`"$miguser`""
        "/i:`"$MigExcludeXml`""
        "/i:`"$MigCustomXml`""
        "/ue:*\*"
        "/ui:$userInclude"
        "/l:`"$scanstateLog`""
        "/progress:`"$progressLog`""
        "/c"
        "/o"
        "/vsc"
    )
    
    $argumentString = $arguments -join " "
    
    Write-Log -LogPath $logFile -Message "Command: scanstate.exe $argumentString"
    
    # Zapuskaem scanstate cherez vremennyy batch fayl
    $startTime = Get-Date
    
    try {
        # Sozdaem vremennyy batch fayl
        $batchFile = Join-Path $env:TEMP "usmt_scanstate_$([guid]::NewGuid().ToString('N').Substring(0,8)).bat"
        
        $batchContent = @"
@echo off
cd /d "$USMTPath"
scanstate.exe "$usmtExportPath" /i:"$migapp" /i:"$miguser" /i:"$MigExcludeXml" /i:"$MigCustomXml" /ue:*\* /ui:$userInclude /l:"$scanstateLog" /progress:"$progressLog" /c /o /vsc
exit /b %ERRORLEVEL%
"@
        
        Set-Content -Path $batchFile -Value $batchContent -Encoding ASCII
        Write-Log -LogPath $logFile -Message "Created batch file: $batchFile"
        Write-Log -LogPath $logFile -Message "Batch content: $batchContent"
        
        # Zapuskaem batch fayl
        $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchFile`"" -NoNewWindow -Wait -PassThru
        $exitCode = $process.ExitCode
        
        # Udalyaem vremennyy fayl
        Remove-Item -Path $batchFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Status "Error starting USMT: $_" -Type Error
        Write-Log -LogPath $logFile -Message "Start error: $_" -Level "ERROR"
        if ($batchFile -and (Test-Path $batchFile)) { Remove-Item -Path $batchFile -Force -ErrorAction SilentlyContinue }
        Read-Host "Press Enter to return to menu"
        return
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host ""
    Write-ColorText "================================================================" -Color DarkGray
    
    # Proveryaem rezultat
    if ($exitCode -eq 0) {
        Write-Status "Export completed successfully!" -Type Success
        Write-Log -LogPath $logFile -Message "Export completed successfully. Code: $exitCode"
        
        # Podschityvaem razmer
        $size = (Get-ChildItem -Path $usmtExportPath -Recurse -File -ErrorAction SilentlyContinue | 
            Measure-Object -Property Length -Sum).Sum / 1MB
        
        Write-Host ""
        Write-Host "  Profile:  $($selectedProfile.DomainUser)"
        Write-Host "  Folder:   $exportFolderName"
        Write-Host "  Size:     $([math]::Round($size, 2)) MB"
        Write-Host "  Time:     $([math]::Round($duration.TotalMinutes, 1)) min."
        
        Write-Log -LogPath $logFile -Message "Size: $([math]::Round($size, 2)) MB, Time: $([math]::Round($duration.TotalMinutes, 1)) min."
    }
    elseif ($exitCode -eq 2 -or $exitCode -eq 3) {
        Write-Status "Export completed with warnings (code: $exitCode)" -Type Warning
        Write-Log -LogPath $logFile -Message "Export completed with warnings. Code: $exitCode" -Level "WARN"
        Write-Host ""
        Write-Host "  Some files may have been skipped. Check the log:"
        Write-Host "  $scanstateLog"
    }
    else {
        Write-Status "Export error (code: $exitCode)" -Type Error
        Write-Log -LogPath $logFile -Message "Export error. Code: $exitCode" -Level "ERROR"
        Write-Host ""
        Write-Host "  Check the error log:"
        Write-Host "  $scanstateLog"
    }
    
    Write-Host ""
    Read-Host "Press Enter to return to menu"
}

#endregion

#region === IMPORT FUNCTIONS ===

function Start-ProfileImport {
    Write-Header "IMPORT PROFILE"
    
    # Proveryaem nalichie USMT
    if (-not (Test-USMTPresent)) {
        Write-Status "USMT not found in: $USMTNetworkPath" -Type Error
        Write-Host ""
        Write-Host "Please download Windows ADK and copy USMT to the specified folder."
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    # Podklyuchaem setevuyu papku
    if (-not (Connect-NetworkShare)) {
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    # Kopiruem USMT lokalno (obyazatelno!)
    if (-not (Copy-USMTLocally)) {
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    Write-Host ""
    
    # Poluchaem spisok sohranennyh profiley
    Write-Status "Getting saved profiles list..." -Type Info
    $profiles = Get-SavedProfiles | Where-Object { $_.HasUSMT }
    
    if ($profiles.Count -eq 0) {
        Write-Status "No saved profiles found" -Type Warning
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    Write-Host ""
    Write-ColorText "Available profiles for import:" -Color Yellow
    Write-Host ""
    Write-Host "  #   Username              Export Date       Size"
    Write-Host "  --- --------------------- ----------------- ----------"
    
    $i = 1
    foreach ($profile in $profiles) {
        $num = $i.ToString().PadRight(3)
        $user = $profile.Username
        if ($user.Length -gt 21) { $user = $user.Substring(0, 18) + "..." }
        $user = $user.PadRight(21)
        $date = if ($profile.Date) { $profile.Date } else { "N/A" }
        $date = $date.PadRight(17)
        $size = "$($profile.SizeMB) MB"
        
        Write-Host "  $num $user $date $size"
        $i++
    }
    
    Write-Host ""
    Write-Host "  0   Return to main menu"
    Write-Host ""
    
    # Vybor profilya
    $selection = Read-Host "Select profile to import (number)"
    
    if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
        return
    }
    
    $index = [int]$selection - 1
    if ($index -lt 0 -or $index -ge $profiles.Count) {
        Write-Status "Invalid selection" -Type Error
        Start-Sleep -Seconds 2
        return
    }
    
    $selectedProfile = $profiles[$index]
    $usmtImportPath = Join-Path $selectedProfile.Path "USMT"
    
    Write-Host ""
    Write-Status "Selected profile: $($selectedProfile.Username) ($($selectedProfile.Date))" -Type Info
    
    # Podtverzhdenie
    Write-Host ""
    Write-ColorText "WARNING!" -Color Yellow
    Write-Host "Profile data will be imported to this computer."
    Write-Host "Existing user settings may be overwritten."
    Write-Host ""
    $confirm = Read-Host "Continue? (Y/N)"
    
    if ($confirm -notmatch "^[Yy]") {
        Write-Status "Import cancelled" -Type Warning
        Start-Sleep -Seconds 2
        return
    }
    
    # Log importa
    $logFile = Join-Path $selectedProfile.Path "migration.log"
    $loadstateLog = Join-Path $selectedProfile.Path "loadstate.log"
    $progressLog = Join-Path $selectedProfile.Path "progress_load.log"
    
    Write-Log -LogPath $logFile -Message "Import started on computer: $env:COMPUTERNAME"
    Write-Log -LogPath $logFile -Message "USMT local path: $USMTPath"
    
    Write-Host ""
    Write-ColorText "================================================================" -Color DarkGray
    Write-Status "Starting USMT LoadState..." -Type Info
    Write-Status "This may take several minutes, please wait..." -Type Info
    Write-ColorText "================================================================" -Color DarkGray
    Write-Host ""
    
    # Formiruem komandu loadstate
    $loadstate = Join-Path $USMTPath "loadstate.exe"
    $migapp = Join-Path $USMTPath "migapp.xml"
    # migdocs.xml ubrali - sootvetstvuet eksportu
    $miguser = Join-Path $USMTPath "miguser.xml"
    
    $arguments = @(
        "`"$usmtImportPath`""
        "/i:`"$migapp`""
        "/i:`"$miguser`""
        "/i:`"$MigCustomXml`""
        "/l:`"$loadstateLog`""
        "/progress:`"$progressLog`""
        "/c"
    )
    
    $argumentString = $arguments -join " "
    
    Write-Log -LogPath $logFile -Message "Command: loadstate.exe $argumentString"
    
    # Zapuskaem loadstate cherez vremennyy batch fayl
    $startTime = Get-Date
    
    try {
        # Sozdaem vremennyy batch fayl
        $batchFile = Join-Path $env:TEMP "usmt_loadstate_$([guid]::NewGuid().ToString('N').Substring(0,8)).bat"
        
        $batchContent = @"
@echo off
cd /d "$USMTPath"
loadstate.exe "$usmtImportPath" /i:"$migapp" /i:"$miguser" /i:"$MigCustomXml" /l:"$loadstateLog" /progress:"$progressLog" /c
exit /b %ERRORLEVEL%
"@
        
        Set-Content -Path $batchFile -Value $batchContent -Encoding ASCII
        Write-Log -LogPath $logFile -Message "Created batch file: $batchFile"
        Write-Log -LogPath $logFile -Message "Batch content: $batchContent"
        
        # Zapuskaem batch fayl
        $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchFile`"" -NoNewWindow -Wait -PassThru
        $exitCode = $process.ExitCode
        
        # Udalyaem vremennyy fayl
        Remove-Item -Path $batchFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Status "Error starting USMT: $_" -Type Error
        Write-Log -LogPath $logFile -Message "Start error: $_" -Level "ERROR"
        if ($batchFile -and (Test-Path $batchFile)) { Remove-Item -Path $batchFile -Force -ErrorAction SilentlyContinue }
        Read-Host "Press Enter to return to menu"
        return
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host ""
    Write-ColorText "================================================================" -Color DarkGray
    
    # Proveryaem rezultat
    if ($exitCode -eq 0) {
        Write-Status "Import completed successfully!" -Type Success
        Write-Log -LogPath $logFile -Message "Import completed successfully. Code: $exitCode"
        
        Write-Host ""
        Write-Host "  Profile:  $($selectedProfile.Username)"
        Write-Host "  Time:     $([math]::Round($duration.TotalMinutes, 1)) min."
        Write-Host ""
        Write-ColorText "  ========================================================" -Color Yellow
        Write-ColorText "  RECOMMENDED: RESTART THE COMPUTER" -Color Yellow
        Write-ColorText "  to apply all profile settings." -Color Yellow
        Write-ColorText "  ========================================================" -Color Yellow
    }
    elseif ($exitCode -eq 2 -or $exitCode -eq 3) {
        Write-Status "Import completed with warnings (code: $exitCode)" -Type Warning
        Write-Log -LogPath $logFile -Message "Import completed with warnings. Code: $exitCode" -Level "WARN"
        Write-Host ""
        Write-Host "  Some files may have been skipped. Check the log:"
        Write-Host "  $loadstateLog"
        Write-Host ""
        Write-ColorText "  RECOMMENDED: RESTART THE COMPUTER" -Color Yellow
    }
    else {
        Write-Status "Import error (code: $exitCode)" -Type Error
        Write-Log -LogPath $logFile -Message "Import error. Code: $exitCode" -Level "ERROR"
        Write-Host ""
        Write-Host "  Check the error log:"
        Write-Host "  $loadstateLog"
    }
    
    Write-Host ""
    Read-Host "Press Enter to return to menu"
}

#endregion

#region === VIEW FUNCTIONS ===

function Show-SavedProfiles {
    Write-Header "SAVED PROFILES"
    
    # Podklyuchaem setevuyu papku
    if (-not (Connect-NetworkShare)) {
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    $sharePath = Get-EffectiveSharePath
    Write-Host ""
    
    Write-Status "Path: $sharePath" -Type Info
    Write-Host ""
    
    # Poluchaem spisok profiley
    $profiles = Get-SavedProfiles
    
    if ($profiles.Count -eq 0) {
        Write-Status "No saved profiles found" -Type Warning
        Write-Host ""
        Read-Host "Press Enter to return to menu"
        return
    }
    
    Write-ColorText "Found profiles: $($profiles.Count)" -Color Yellow
    Write-Host ""
    Write-Host "  Folder                          Size        Created             Status"
    Write-Host "  -------------------------------- ----------- ------------------- --------"
    
    foreach ($profile in $profiles) {
        $folder = $profile.FolderName
        if ($folder.Length -gt 32) {
            $folder = $folder.Substring(0, 29) + "..."
        }
        $folder = $folder.PadRight(32)
        
        $size = "$($profile.SizeMB) MB".PadRight(11)
        $created = $profile.Created.ToString("dd.MM.yyyy HH:mm").PadRight(19)
        
        $status = if ($profile.HasUSMT) { "OK" } else { "Incomplete" }
        
        if ($profile.HasUSMT) {
            Write-Host "  $folder $size $created " -NoNewline
            Write-ColorText $status -Color Green
        }
        else {
            Write-Host "  $folder $size $created " -NoNewline
            Write-ColorText $status -Color Red
        }
    }
    
    # Obshchiy razmer
    $totalSize = ($profiles | Measure-Object -Property SizeMB -Sum).Sum
    Write-Host ""
    Write-Host "  --------------------------------------------------------------------"
    Write-Host "  Total size: $([math]::Round($totalSize, 2)) MB"
    
    Write-Host ""
    Read-Host "Press Enter to return to menu"
}

#endregion

#region === MAIN MENU ===

function Show-MainMenu {
    while ($true) {
        Write-Header "USMT Profile Migration Tool"
        
        # Informaciya o sisteme
        Write-Host "  Computer: $env:COMPUTERNAME"
        Write-Host "  OS:       Windows $([System.Environment]::OSVersion.Version.Major)"
        Write-Host "  Network:  $NetworkShare"
        Write-Host ""
        
        # Status USMT
        if (Test-USMTPresent) {
            Write-Status "USMT found" -Type Success
        }
        else {
            Write-Status "USMT not found in $USMTNetworkPath" -Type Warning
        }
        
        Write-Host ""
        Write-ColorText "================================================================" -Color DarkCyan
        Write-Host ""
        Write-Host "   1. Export profile (from old PC)"
        Write-Host "   2. Import profile (to new PC)"
        Write-Host "   3. View saved profiles"
        Write-Host ""
        Write-Host "   0. Exit"
        Write-Host ""
        Write-ColorText "================================================================" -Color DarkCyan
        
        Write-Host ""
        $choice = Read-Host "Select action"
        
        switch ($choice) {
            "1" { Start-ProfileExport }
            "2" { Start-ProfileImport }
            "3" { Show-SavedProfiles }
            "0" { 
                Disconnect-NetworkShare
                Remove-LocalUSMT
                Write-Host ""
                Write-Status "Goodbye!" -Type Info
                Start-Sleep -Seconds 1
                return 
            }
            default {
                Write-Status "Invalid selection. Try again." -Type Warning
                Start-Sleep -Seconds 1
            }
        }
    }
}

#endregion

#region === ENTRY POINT ===

# Proverka prav administratora
if (-not (Test-Administrator)) {
    Write-Host ""
    Write-ColorText "ERROR: Administrator rights required!" -Color Red
    Write-Host ""
    Write-Host "Please run the script as administrator."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Proveryaem nalichie konfiga isklyucheniy v setevoy papke
if (-not (Test-Path $MigExcludeXml)) {
    Write-Host ""
    Write-ColorText "WARNING: MigExclude.xml file not found!" -Color Yellow
    Write-Host "Path: $MigExcludeXml"
    Write-Host ""
    Write-Host "Export will be performed WITHOUT excluding cache and temp files."
    Write-Host ""
    Read-Host "Press Enter to continue"
}

# Zapusk glavnogo menyu
Show-MainMenu

#endregion
