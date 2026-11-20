#Requires -Modules ActiveDirectory, GroupPolicy, SmbShare
# Setup-ADEnvironment.ps1  (Version 1.3.0)
# Builds the Northbridge environment: OUs, groups, shared folders and GPO links.
# Safe to run again and again: every step first checks whether the object already exists.
# Run on DC01 as administrator.

$Version = "1.3.0"
$Start   = Get-Date
$ErrorActionPreference = "Stop"  # errors become exceptions, so try/catch can log them
$Created = 0; $Skipped = 0; $Failed = 0

# --- Settings (the design from the thesis) -----------------------------------
$Root      = "Northbridge"
$SharesDir = "C:\Shares"
$LogDir    = "C:\NorthbridgeAD\logs"
$Depts     = @("IT", "HR", "Finance", "Sales")
$SubOus    = $Depts + @("Groups", "Workstations")

$Domain    = Get-ADDomain
if ($Domain.DNSRoot -ne "northbridge.internal") { throw "Unexpected domain: $($Domain.DNSRoot)" }
$DomainDn  = $Domain.DistinguishedName     # DC=northbridge,DC=internal
$NetBios   = $Domain.NetBIOSName           # NORTHBRIDGE
$RootDn    = "OU=$Root,$DomainDn"

# --- Logging -----------------------------------------------------------------
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = "$LogDir\Setup-ADEnvironment_$(Get-Date -Format yyyyMMdd_HHmmss).log"

function Write-Log($Msg, $Level = "INFO") {
    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Msg"
    Add-Content -Path $LogFile -Value $Line -Encoding ASCII
    Write-Host $Line
}

# --- The one pattern used everywhere: CHECK -> skip if it exists -> otherwise CREATE ---
function Ensure($Label, [scriptblock]$Exists, [scriptblock]$Create) {
    try {
        if (& $Exists) { $script:Skipped++; Write-Log "Exists:  $Label" }
        else           { & $Create | Out-Null; $script:Created++; Write-Log "Created: $Label" }
    }
    catch { $script:Failed++; Write-Log "FAILED:  $Label - $_" "ERROR" }
}

# NTFS rights: no inheritance, Administrators and SYSTEM = Full control, the group = Modify
function Set-Perms($Path, $Group) {
    $rights = @("Administrators:(OI)(CI)F", "SYSTEM:(OI)(CI)F")
    if ($Group) { $rights += "${NetBios}\${Group}:(OI)(CI)M" }
    icacls $Path /inheritance:r /grant:r $rights | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

Write-Log "Setup-ADEnvironment v$Version started (root OU: $Root)"

# 1. Organizational units: the parent first, then the six child OUs
Ensure "OU $Root" { Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$RootDn'" } { New-ADOrganizationalUnit -Name $Root -Path $DomainDn -ProtectedFromAccidentalDeletion $true }
foreach ($ou in $SubOus) {
    $dn = "OU=$ou,$RootDn"
    Ensure "OU $ou" { Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" } { New-ADOrganizationalUnit -Name $ou -Path $RootDn -ProtectedFromAccidentalDeletion $true }
}

# 2. One global security group per department, inside the Groups OU
foreach ($d in $Depts) {
    $group = "${d}_Staff"
    Ensure "Group $group" { Get-ADGroup -Filter "SamAccountName -eq '$group'" } { New-ADGroup -Name $group -GroupScope Global -Path "OU=Groups,$RootDn" }
}

# 3. Department shares: folder, share (Everyone = Full control), NTFS permissions (group = Modify)
foreach ($d in $Depts) {
    $path = "$SharesDir\$d"; $group = "${d}_Staff"
    Ensure "Folder $path"      { Test-Path $path }                                         { New-Item -ItemType Directory -Path $path -Force }
    Ensure "Share $d"          { Get-SmbShare -Name $d -ErrorAction SilentlyContinue }     { New-SmbShare -Name $d -Path $path -FullAccess Everyone }
    Ensure "Permissions $d"    { (Get-Acl $path).AreAccessRulesProtected }                 { Set-Perms $path $group }
}

# 4. Homes share for the personal folders (filled later by New-BulkUsers.ps1): administrators only
$homesPath = "$SharesDir\Homes"
Ensure "Folder $homesPath"  { Test-Path $homesPath }                                         { New-Item -ItemType Directory -Path $homesPath -Force }
Ensure "Share Homes"        { Get-SmbShare -Name "Homes" -ErrorAction SilentlyContinue }    { New-SmbShare -Name "Homes" -Path $homesPath -FullAccess Everyone }
Ensure "Permissions Homes"  { (Get-Acl $homesPath).AreAccessRulesProtected }                 { Set-Perms $homesPath $null }

# 5. GPO links (the two GPOs were created in Phase 2): password at the domain, screen lock on Workstations
$Gpos = @(
    @{ Name = "GPO_Password_Lockout";       Target = $DomainDn },
    @{ Name = "GPO_Workstation_ScreenLock"; Target = "OU=Workstations,$RootDn" }
)
foreach ($gpo in $Gpos) {
    $n = $gpo.Name; $t = $gpo.Target
    Ensure "Link $n" { (Get-GPInheritance -Target $t).GpoLinks | Where-Object DisplayName -eq $n } { New-GPLink -Name $n -Target $t -LinkEnabled Yes -Order 1 }
}

# --- Summary -----------------------------------------------------------------
$Sec = [math]::Round(((Get-Date) - $Start).TotalSeconds, 1)
Write-Log "Created $Created, Skipped $Skipped, Failed $Failed in $Sec s"
if ($Failed -gt 0) { exit 1 }