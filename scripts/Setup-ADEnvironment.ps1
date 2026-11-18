#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy, SmbShare
# Builds the Northbridge environment: OUs, groups, shared folders and GPO links.
# Safe to run again and again: every step first checks whether the object already exists.
# Use -WhatIf for a dry run that changes nothing. Run on DC01 as administrator.

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RootOuName = "Northbridge",
    [string]$SharesRoot = "C:\Shares",
    [string]$GpoBackup  = "C:\NorthbridgeAD\gpo-backup",
    [string]$LogDir     = "C:\NorthbridgeAD\logs",
    [string]$Suffix     = ""     # only for tests: adds e.g. _Test to every name
)

$Version = "1.1.0"
$Start   = Get-Date
$ErrorActionPreference = "Stop"  # errors become exceptions, so try/catch can log them
$Created = 0; $Skipped = 0; $Failed = 0; $WouldCreate = 0

# --- Names (the design from the thesis) --------------------------------------
$Domain   = Get-ADDomain
$DomainDn = $Domain.DistinguishedName      # DC=northbridge,DC=internal
$NetBios  = $Domain.NetBIOSName            # NORTHBRIDGE
$RootName = "$RootOuName$Suffix"
$RootDn   = "OU=$RootName,$DomainDn"
$Depts    = @("IT", "HR", "Finance", "Sales")
$SubOus   = $Depts + @("Groups", "Workstations")

# --- Logging (-WhatIf:$false = the log is also written during a dry run) ------
New-Item -ItemType Directory -Path $LogDir -Force -WhatIf:$false | Out-Null
$LogFile = "$LogDir\Setup-ADEnvironment_$(Get-Date -Format yyyyMMdd_HHmmss).log"

function Write-Log($Msg, $Level = "INFO") {
    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Msg"
    Add-Content -Path $LogFile -Value $Line -Encoding ASCII -WhatIf:$false
    Write-Host $Line
}

# --- The one pattern used everywhere: CHECK -> skip if it exists -> otherwise CREATE ---
# ShouldProcess is what makes -WhatIf work: it returns $false during a dry run.
function Ensure($Label, [scriptblock]$Exists, [scriptblock]$Create) {
    try {
        if (& $Exists) { $script:Skipped++; Write-Log "Exists:  $Label" }
        elseif ($PSCmdlet.ShouldProcess($Label, "Create")) { & $Create | Out-Null; $script:Created++; Write-Log "Created: $Label" }
        else { $script:WouldCreate++; Write-Log "WhatIf:  would create $Label" }
    }
    catch {
        # In a dry run a check can fail only because its parent does not exist yet: not an error.
        if ($WhatIfPreference) { $script:WouldCreate++; Write-Log "WhatIf:  would create $Label (parent does not exist yet)" }
        else { $script:Failed++; Write-Log "FAILED:  $Label - $_" "ERROR" }
    }
}

# NTFS rights: no inheritance, Administrators and SYSTEM = Full control, the group = Modify
function Set-Perms($Path, $Group) {
    $rights = @("Administrators:(OI)(CI)F", "SYSTEM:(OI)(CI)F")
    if ($Group) { $rights += "${NetBios}\${Group}:(OI)(CI)M" }
    icacls $Path /inheritance:r /grant:r $rights | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

Write-Log "Setup-ADEnvironment v$Version started (root OU: $RootName, WhatIf: $([bool]$WhatIfPreference))"

# 1. Organizational units: the parent first, then the six child OUs
Ensure "OU $RootName" { Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$RootDn'" } { New-ADOrganizationalUnit -Name $RootName -Path $DomainDn -ProtectedFromAccidentalDeletion $true }
foreach ($ou in $SubOus) {
    $dn = "OU=$ou,$RootDn"
    Ensure "OU $ou" { Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" } { New-ADOrganizationalUnit -Name $ou -Path $RootDn -ProtectedFromAccidentalDeletion $true }
}

# 2. One global security group per department, inside the Groups OU
foreach ($d in $Depts) {
    $group = "${d}_Staff$Suffix"
    Ensure "Group $group" { Get-ADGroup -Filter "SamAccountName -eq '$group'" } { New-ADGroup -Name $group -GroupScope Global -Path "OU=Groups,$RootDn" }
}

# 3. Department shares: folder, share (Everyone = Full control), NTFS permissions (group = Modify)
foreach ($d in $Depts) {
    $share = "$d$Suffix"; $path = "$SharesRoot\$share"; $group = "${d}_Staff$Suffix"
    Ensure "Folder $path"      { Test-Path $path }                                          { New-Item -ItemType Directory -Path $path -Force }
    Ensure "Share $share"      { Get-SmbShare -Name $share -ErrorAction SilentlyContinue }  { New-SmbShare -Name $share -Path $path -FullAccess Everyone }
    Ensure "Permissions $share" { (Test-Path $path) -and (Get-Acl $path).AreAccessRulesProtected } { Set-Perms $path $group }
}

# 4. Homes share for the personal folders (filled later by New-BulkUsers.ps1): administrators only
$homes = "Homes$Suffix"; $homesPath = "$SharesRoot\$homes"
Ensure "Folder $homesPath"   { Test-Path $homesPath }                                       { New-Item -ItemType Directory -Path $homesPath -Force }
Ensure "Share $homes"        { Get-SmbShare -Name $homes -ErrorAction SilentlyContinue }    { New-SmbShare -Name $homes -Path $homesPath -FullAccess Everyone }
Ensure "Permissions $homes"  { (Test-Path $homesPath) -and (Get-Acl $homesPath).AreAccessRulesProtected } { Set-Perms $homesPath $null }

# 5. GPOs: import from the backup only if the GPO does not exist yet, then link it
$Gpos = @(
    @{ Name = "GPO_Password_Lockout";       Target = $DomainDn },
    @{ Name = "GPO_Workstation_ScreenLock"; Target = "OU=Workstations,$RootDn" }
)
foreach ($gpo in $Gpos) {
    $n = $gpo.Name; $t = $gpo.Target
    Ensure "GPO $n"  { Get-GPO -Name $n -ErrorAction SilentlyContinue }                            { Import-GPO -BackupGpoName $n -TargetName $n -Path $GpoBackup -CreateIfNeeded }
    Ensure "Link $n" { (Get-GPInheritance -Target $t).GpoLinks | Where-Object DisplayName -eq $n } { New-GPLink -Name $n -Target $t -LinkEnabled Yes -Order 1 }
}

# --- Summary -----------------------------------------------------------------
$Sec = [math]::Round(((Get-Date) - $Start).TotalSeconds, 1)
$Summary = "Created $Created, Skipped $Skipped, Failed $Failed"
if ($WhatIfPreference) { $Summary += ", WouldCreate $WouldCreate" }
Write-Log "$Summary in $Sec s"
if ($Failed -gt 0) { exit 1 }
