<#
.SYNOPSIS
  Audit AD forest for RC4 usage and optionally remediate.

.DESCRIPTION
  - Enumerates all domains in the forest
  - Checks Users, Computers, and Trusts
  - Flags objects with RC4 enabled or no msDS-SupportedEncryptionTypes set
  - By default: report only
  - With -ApplyFixes: prompt per object to apply AES-only (0x18) setting

.PARAMETER ApplyFixes
  Switch to enable interactive remediation mode

.EXAMPLE
  .\RC4_AD_SCAN.ps1
  Run in audit-only mode to identify RC4 usage

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -ApplyFixes
  Run with interactive remediation prompts

.NOTES
  Author: Jan Tiedemann
  Version: 1.0
  Created: October 2025
  
  Requires: PowerShell 5.1+, ActiveDirectory module
  Permissions: Domain Admin (scanning), Enterprise Admin (trust remediation)
#>

param(
    [switch]$ApplyFixes
)

Import-Module ActiveDirectory

function Get-EncryptionTypes {
    param([int]$EncValue)

    if (-not $EncValue) { return "Not Set (RC4 fallback)" }

    $map = @{
        0x1  = "DES-CBC-CRC"
        0x2  = "DES-CBC-MD5"
        0x4  = "RC4-HMAC"
        0x8  = "AES128-CTS-HMAC-SHA1-96"
        0x10 = "AES256-CTS-HMAC-SHA1-96"
        0x20 = "Future"
    }

    $enabled = @()
    foreach ($k in $map.Keys) {
        if ($EncValue -band $k) { $enabled += $map[$k] }
    }
    return ($enabled -join ", ")
}

$results = @()
$forest = Get-ADForest

foreach ($domain in $forest.Domains) {
    Write-Host "Scanning domain: $domain" -ForegroundColor Cyan

    # Users
    Get-ADUser -Filter * -Server $domain -Properties msDS-SupportedEncryptionTypes |
    ForEach-Object {
        $enc = $_."msDS-SupportedEncryptionTypes"
        if (-not $enc -or ($enc -band 0x4)) {
            $obj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "User"
                Name       = $_.SamAccountName
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
            }
            $results += $obj

            if ($ApplyFixes) {
                $answer = Read-Host "Remediate User $($_.SamAccountName) in $domain? (Y/N)"
                if ($answer -match '^[Yy]') {
                    Set-ADUser -Identity $_ -Replace @{"msDS-SupportedEncryptionTypes" = 24 }
                    Write-Host " -> Fixed" -ForegroundColor Green
                }
            }
        }
    }

    # Computers
    Get-ADComputer -Filter * -Server $domain -Properties msDS-SupportedEncryptionTypes |
    ForEach-Object {
        $enc = $_."msDS-SupportedEncryptionTypes"
        if (-not $enc -or ($enc -band 0x4)) {
            $obj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "Computer"
                Name       = $_.SamAccountName
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
            }
            $results += $obj

            if ($ApplyFixes) {
                $answer = Read-Host "Remediate Computer $($_.SamAccountName) in $domain? (Y/N)"
                if ($answer -match '^[Yy]') {
                    Set-ADComputer -Identity $_ -Replace @{"msDS-SupportedEncryptionTypes" = 24 }
                    Write-Host " -> Fixed" -ForegroundColor Green
                }
            }
        }
    }

    # Trusts
    Get-ADTrust -Filter * -Server $domain -Properties msDS-SupportedEncryptionTypes |
    ForEach-Object {
        $enc = $_."msDS-SupportedEncryptionTypes"
        if (-not $enc -or ($enc -band 0x4)) {
            $obj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "Trust"
                Name       = $_.Name
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
            }
            $results += $obj

            if ($ApplyFixes) {
                $answer = Read-Host "Remediate Trust $($_.Name) in $domain? (Y/N)"
                if ($answer -match '^[Yy]') {
                    Set-ADTrust -Identity $_.Name -Replace @{"msDS-SupportedEncryptionTypes" = 24 }
                    Write-Host " -> Fixed" -ForegroundColor Green
                }
            }
        }
    }
}

# Output summary
$results |
Sort-Object Domain, ObjectType, Name |
Format-Table Domain, ObjectType, Name, EncTypes -AutoSize

# Optional export
# $results | Export-Csv ".\\RC4_Audit_Results.csv" -NoTypeInformation -Encoding UTF8
