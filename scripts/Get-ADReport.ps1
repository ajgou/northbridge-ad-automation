# Get-ADReport.ps1  (version 1.0.0)
# Thesis lab: Northbridge, domain northbridge.internal
#
# Reads all user accounts in OU=Northbridge and reports:
#   - accounts per department
#   - locked accounts
#   - inactive accounts (enabled, but not used for more than -InactiveDays days)
# The script only READS from Active Directory and never changes anything,
# so it can be run as often as needed.
#
# Output: console, a CSV file in C:\NorthbridgeAD\reports and a log in C:\NorthbridgeAD\logs
#
# Note: AD updates LastLogonDate only every 9-14 days, so the inactivity
# check is not exact for short periods.
#
# Usage:  .\Get-ADReport.ps1
#         .\Get-ADReport.ps1 -InactiveDays 0

param(
    [ValidateRange(0, 3650)]
    [int]$InactiveDays = 30      # days without use before an account counts as inactive
)

$ErrorActionPreference = 'Stop'  # any error jumps to the catch block

# ----- Settings -----
$Version    = '1.0.0'
$DomainName = 'northbridge.internal'
$Root       = 'C:\NorthbridgeAD'
$LogFile    = "$Root\logs\Get-ADReport_$(Get-Date -Format 'yyyyMMdd').log"
$CsvFile    = "$Root\reports\ADReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$Cutoff     = (Get-Date).AddDays(-$InactiveDays)

New-Item -ItemType Directory -Force -Path "$Root\logs", "$Root\reports" | Out-Null

# ----- Helper functions -----
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line  = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = @{ INFO = 'White'; WARN = 'Yellow'; ERROR = 'Red' }[$Level]
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

function Show-List {
    param([string]$Title, [object[]]$Items)
    Write-Host "`n$Title ($($Items.Count))" -ForegroundColor Cyan
    if ($Items.Count -eq 0) {
        Write-Host '  none'
    }
    else {
        $Items | Format-Table Username, Name, Department, LastLogon -AutoSize | Out-Host
    }
}

# ----- Main -----
$timer = [System.Diagnostics.Stopwatch]::StartNew()

try {
    Import-Module ActiveDirectory

    # Domain guard: stop if this is not the lab domain
    $domain = Get-ADDomain
    if ($domain.DNSRoot -ne $DomainName) {
        throw "Wrong domain '$($domain.DNSRoot)', expected '$DomainName'."
    }
    $searchBase = "OU=Northbridge,$($domain.DistinguishedName)"
    Write-Log "Get-ADReport v$Version started (inactive = unused for more than $InactiveDays days)"

    # One query for all users of the company OU
    $props = 'LockedOut', 'LastLogonDate', 'Created', 'CanonicalName'
    $users = @(Get-ADUser -Filter * -SearchBase $searchBase -Properties $props)
    Write-Log "Read $($users.Count) user accounts from $searchBase"

    # One report row per user
    $report = @(foreach ($u in $users) {
        if ($u.LastLogonDate) {
            $lastUse   = $u.LastLogonDate
            $lastLogon = $lastUse.ToString('yyyy-MM-dd HH:mm')
        }
        else {
            $lastUse   = $u.Created    # never used: count from the day it was created
            $lastLogon = 'Never'
        }
        [pscustomobject]@{
            Username   = $u.SamAccountName
            Name       = $u.Name
            Department = ($u.CanonicalName -split '/')[-2]    # name of the OU the user is in
            Enabled    = $u.Enabled
            Locked     = [bool]$u.LockedOut
            LastLogon  = $lastLogon
            Inactive   = ($u.Enabled -and ($lastUse -lt $Cutoff))
        }
    })

    $locked   = @($report | Where-Object { $_.Locked })
    $inactive = @($report | Where-Object { $_.Inactive })
    $disabled = @($report | Where-Object { -not $_.Enabled })

    # Show the result
    Write-Host "`nAccounts per department" -ForegroundColor Cyan
    $report | Group-Object Department | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Department = $_.Name
            Users      = $_.Count
            Enabled    = @($_.Group | Where-Object { $_.Enabled }).Count
            Locked     = @($_.Group | Where-Object { $_.Locked }).Count
            Inactive   = @($_.Group | Where-Object { $_.Inactive }).Count
        }
    } | Format-Table -AutoSize | Out-Host

    Show-List 'Locked accounts' $locked
    Show-List 'Inactive accounts' $inactive
    Write-Host ''

    # Save the report as CSV (a new file for every run)
    $report | Sort-Object Department, Username | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved: $CsvFile"

    $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1)
    Write-Log "Report done: Users $($report.Count), Enabled $($report.Count - $disabled.Count), Disabled $($disabled.Count), Locked $($locked.Count), Inactive $($inactive.Count) in $seconds s"
}
catch {
    Write-Log "Report failed: $($_.Exception.Message)" 'ERROR'
    exit 1
}