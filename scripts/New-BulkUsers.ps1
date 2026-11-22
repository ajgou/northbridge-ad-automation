#Requires -Modules ActiveDirectory, SmbShare
# New-BulkUsers.ps1  (Version 1.0.0)
# Reads employees from a CSV file (FirstName, LastName, Department), checks every row,
# and creates the account, the group membership and the home folder.
# Safe to run again and again: existing accounts are skipped, missing parts are repaired.
# Run on DC01 as administrator (take a checkpoint first).

param(
    [string]$CsvPath = "C:\NorthbridgeAD\data\employees.csv"
)

$Version = "1.0.0"
$ErrorActionPreference = "Stop"  # errors become exceptions, so try/catch can log them
$Count   = @{ Created = 0; Skipped = 0; Rejected = 0; Failed = 0 }
$Results = @()

# --- Settings (the design from the thesis) -----------------------------------
$LogDir   = "C:\NorthbridgeAD\logs"
$HomesDir = "C:\Shares\Homes"              # folder behind the \\DC01\Homes share
$Depts    = @("IT", "HR", "Finance", "Sales")

$Domain   = Get-ADDomain
if ($Domain.DNSRoot -ne "northbridge.internal") { throw "Unexpected domain: $($Domain.DNSRoot)" }
$NetBios  = $Domain.NetBIOSName            # NORTHBRIDGE
$RootDn   = "OU=Northbridge,$($Domain.DistinguishedName)"

# --- Logging -----------------------------------------------------------------
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Stamp   = Get-Date -Format yyyyMMdd_HHmmss
$LogFile = "$LogDir\New-BulkUsers_$Stamp.log"

function Write-Log($Msg, $Level = "INFO") {
    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Msg"
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
    Write-Host $Line
}

# --- Helper functions ----------------------------------------------------------
# Returns the reason why a row is invalid (nothing if the row is fine).
function Get-RowProblem($First, $Last, $Dept) {
    if (-not $First -or -not $Last -or -not $Dept)                          { return "Missing field" }
    if ($First -notmatch '^[A-Za-z]+$' -or $Last -notmatch '^[A-Za-z]+$')  { return "Invalid characters in name" }
    if ($Depts -notcontains $Dept)                                          { return "Unknown department: $Dept" }
    if (("$First.$Last").Length -gt 20)                                     { return "Username longer than 20 characters" }
}

# The same pattern as in Setup-ADEnvironment.ps1, but it only answers: did I have to create it?
function Ensure([scriptblock]$Exists, [scriptblock]$Create) {
    if (& $Exists) { return $false }
    & $Create | Out-Null
    return $true
}

# NTFS rights: no inheritance, Administrators and SYSTEM = Full control, the user = Modify
function Set-Perms($Path, $Account) {
    icacls $Path /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "${NetBios}\${Account}:(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

# One line per row: screen, log file and results table all get the same facts.
function Record($No, $User, $Outcome, $Why, $Ms) {
    $script:Count[$Outcome]++
    $script:Results += [pscustomobject]@{ Row = $No; Username = $User; Outcome = $Outcome; Reason = $Why; Ms = $Ms }
    $level = if ($Outcome -eq "Failed") { "ERROR" } elseif ($Outcome -eq "Rejected") { "WARN" } else { "INFO" }
    Write-Log ("Row {0,2} | {1,-24} | {2,-8} | {3} ({4} ms)" -f $No, $User, $Outcome, $Why, $Ms) $level
}

# --- Checks before we start (fail early with a clear message) --------------------
if (-not (Test-Path $CsvPath)) { throw "CSV file not found: $CsvPath" }
if (-not (Get-SmbShare -Name "Homes" -ErrorAction SilentlyContinue)) { throw "Share Homes not found - run Setup-ADEnvironment.ps1 first" }
$Rows = @(Import-Csv -Path $CsvPath -Encoding UTF8)
if ($Rows.Count -eq 0) { throw "The CSV file is empty" }
foreach ($col in "FirstName", "LastName", "Department") {
    if ($Rows[0].PSObject.Properties.Name -notcontains $col) { throw "CSV column missing: $col" }
}
$TempPassword = Read-Host "Temporary password for the new accounts (at least 14 characters)" -AsSecureString
if ($TempPassword.Length -lt 14) { throw "The password needs at least 14 characters" }

$Start = Get-Date
Write-Log "New-BulkUsers v$Version started: $($Rows.Count) rows from $CsvPath"

# --- Main loop: one CSV row per round ------------------------------------------
$Seen = @{}
$No   = 0
foreach ($row in $Rows) {
    $No++
    $sw    = [System.Diagnostics.Stopwatch]::StartNew()
    $First = "$($row.FirstName)".Trim()
    $Last  = "$($row.LastName)".Trim()
    $Dept  = "$($row.Department)".Trim()
    $user  = "$First.$Last".ToLower()

    # 1. Validate: missing field, invalid characters, unknown department, name too long, duplicate in the CSV
    $problem = Get-RowProblem $First $Last $Dept
    if (-not $problem -and $Seen.ContainsKey($user)) { $problem = "Duplicate username in the CSV" }
    if ($problem) { Record $No $user "Rejected" $problem $sw.ElapsedMilliseconds; continue }
    $Seen[$user] = $true
    $Dept = $Depts | Where-Object { $_ -eq $Dept }        # official spelling, e.g. Finance

    try {
        # 2. Username already used by somebody else? Then stop here: a human decides.
        $existing = Get-ADUser -Filter "SamAccountName -eq '$user'" -Properties GivenName, Surname
        if ($existing -and ($existing.GivenName -ne $First -or $existing.Surname -ne $Last)) {
            Record $No $user "Rejected" "Username already used by $($existing.Name)" $sw.ElapsedMilliseconds
            continue
        }

        $group   = "${Dept}_Staff"
        $homeDir = "$HomesDir\$user"
        $props = @{
            Name = "$First $Last"; GivenName = $First; Surname = $Last; DisplayName = "$First $Last"
            SamAccountName = $user; UserPrincipalName = "$user@$($Domain.DNSRoot)"; Department = $Dept
            Path = "OU=$Dept,$RootDn"; AccountPassword = $TempPassword; Enabled = $true
            ChangePasswordAtLogon = $true
            HomeDirectory = "\\$env:COMPUTERNAME\Homes\$user"; HomeDrive = "H:"
        }

        # 3. Ensure the four parts. $did lists what had to be created.
        $did = @()
        if (Ensure { $existing }                                                                  { New-ADUser @props })                              { $did += "account" }
        if (Ensure { Get-ADGroupMember -Identity $group | Where-Object SamAccountName -eq $user } { Add-ADGroupMember -Identity $group -Members $user }) { $did += "group" }
        if (Ensure { Test-Path $homeDir }                                                         { New-Item -ItemType Directory -Path $homeDir })    { $did += "home folder" }
        if (Ensure { (Get-Acl $homeDir).AreAccessRulesProtected }                                 { Set-Perms $homeDir $user })                       { $did += "permissions" }

        # 4. Report the row
        if ($did -contains "account") { Record $No $user "Created" ($did -join ", ") $sw.ElapsedMilliseconds }
        elseif ($did.Count -gt 0)     { Record $No $user "Skipped" "account exists, repaired: $($did -join ', ')" $sw.ElapsedMilliseconds }
        else                          { Record $No $user "Skipped" "already complete" $sw.ElapsedMilliseconds }
    }
    catch { Record $No $user "Failed" "$_" $sw.ElapsedMilliseconds }
}

# --- Summary -----------------------------------------------------------------
$Sec = [math]::Round(((Get-Date) - $Start).TotalSeconds, 1)
$Results | Export-Csv -Path "$LogDir\New-BulkUsers_$Stamp.csv" -NoTypeInformation -Encoding UTF8
Write-Log "Created $($Count.Created), Skipped $($Count.Skipped), Rejected $($Count.Rejected), Failed $($Count.Failed) in $Sec s"
if ($Count.Failed -gt 0) { exit 1 }