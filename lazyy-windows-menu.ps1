# =========================================================
# LAZYY Windows Optimizer – Interactive Menu
# Inspired by CTT
# Author: LAZYY
# =========================================================

# Ensure running as Admin
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run PowerShell as Administrator"
    exit 1
}

# Backup registry for undo
$backup = "$env:USERPROFILE\lazyy_backup.reg"
if (-not (Test-Path $backup)) {
    Write-Host "[INFO] Creating registry backup..."
    reg export HKLM $backup /y | Out-Null
}

# ---------------------------------------------------------
# Functions
# ---------------------------------------------------------
function Disable-Services {
    param([string[]]$services)
    foreach ($svc in $services) {
        Get-Service -Name $svc -ErrorAction SilentlyContinue | `
        Where-Object {$_.Status -ne "Stopped"} | `
        Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

function Optimize-Gaming {
    Write-Host "[INFO] Applying Gaming optimizations..."
    # Disable unnecessary services
    Disable-Services -services @(
        "DiagTrack","SysMain","WSearch","Fax",
        "MapsBroker","RetailDemo","PrintSpooler",
        "XboxGipSvc","XboxNetApiSvc"
    )
    # Game DVR off
    reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
    # Visual effects
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
    Write-Host "[OK] Gaming optimizations applied"
}

function Optimize-LowEnd {
    Write-Host "[INFO] Applying Low-End PC optimizations..."
    # Disable services
    Disable-Services -services @("DiagTrack","SysMain","WSearch","Fax","MapsBroker")
    # Disable hibernation
    powercfg -h off
    # Limit background apps
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
    # Pagefile system managed
    wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True
    Write-Host "[OK] Low-End PC optimizations applied"
}

function Optimize-Server {
    Write-Host "[INFO] Applying Server optimizations..."
    # Disable GUI if desktop
    if (Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty BootDevice) {
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
    }
    # Disable unnecessary services
    Disable-Services -services @("DiagTrack","Fax","MapsBroker","RetailDemo")
    # Reduce logging
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v MaxSize /t REG_DWORD /d 32768 /f
    Write-Host "[OK] Server optimizations applied"
}

function Undo-Optimizations {
    Write-Host "[INFO] Restoring registry backup..."
    if (Test-Path $backup) {
        reg import $backup
        Write-Host "[OK] Registry restored. Reboot recommended."
    } else {
        Write-Host "[ERROR] No backup found."
    }
}

function Schedule-AutoOptimize {
    Write-Host "[INFO] Scheduling daily auto-optimizer..."
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $Trigger = New-ScheduledTaskTrigger -Daily -At 03:00AM
    Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "LAZYY Auto Optimize" -Description "Daily memory optimization" -Force
    Write-Host "[OK] Auto-optimizer scheduled at 3AM daily"
}

# ---------------------------------------------------------
# Menu
# ---------------------------------------------------------
function Show-Menu {
    Clear-Host
    Write-Host "=========================================="
    Write-Host " LAZYY Windows Optimizer – Interactive Menu"
    Write-Host "=========================================="
    Write-Host "1. Gaming PC"
    Write-Host "2. Low-End PC (4–8GB RAM)"
    Write-Host "3. Server Optimizations"
    Write-Host "4. Undo / Restore"
    Write-Host "5. Schedule Auto-Optimizer"
    Write-Host "6. Exit"
    Write-Host "=========================================="
    $choice = Read-Host "Select an option [1-6]"
    return $choice
}

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
while ($true) {
    $selection = Show-Menu
    switch ($selection) {
        "1" { Optimize-Gaming }
        "2" { Optimize-LowEnd }
        "3" { Optimize-Server }
        "4" { Undo-Optimizations }
        "5" { Schedule-AutoOptimize }
        "6" { Write-Host "Exiting..."; break }
        default { Write-Host "[ERROR] Invalid option" }
    }
    Write-Host "Press Enter to continue..."
    Read-Host
}
