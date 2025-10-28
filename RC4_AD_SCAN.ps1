<#
.SYNOPSIS
  Audit AD forest for RC4 usage and optionally remediate.

.DESCRIPTION
  - Enumerates all domains in the forest
  - Checks Users, Computers, and Trusts
  - Flags objects with RC4 enabled or no msDS-SupportedEncryptionTypes set
  - By default: report only
  - With -ApplyFixes: prompt per object to apply AES-only (0x18) setting
  - Provides warnings for Windows Server 2025 compatibility issues

.PARAMETER ApplyFixes
  Switch to enable interactive remediation mode

.PARAMETER ExportResults
  Switch to export results to CSV file

.EXAMPLE
  .\RC4_AD_SCAN.ps1
  Run in audit-only mode to identify RC4 usage

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -ApplyFixes
  Run with interactive remediation prompts

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -ExportResults
  Run audit and export results to CSV file

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -ApplyFixes -ExportResults
  Run with remediation prompts and export results to CSV

.NOTES
  Author: Jan Tiedemann
  Version: 1.0
  Created: October 2025
  
  Requires: PowerShell 5.1+, ActiveDirectory module
  Permissions: Domain Admin (scanning), Enterprise Admin (trust remediation)
#>

param(
    [switch]$ApplyFixes,
    [switch]$ExportResults
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
if ($results.Count -eq 0) {
    Write-Host "`n✅ AUDIT COMPLETE: No objects with RC4 encryption or weak settings found!" -ForegroundColor Green
    Write-Host "All objects in the forest are using strong AES encryption." -ForegroundColor Green
}
else {
    Write-Host "`n⚠️  AUDIT RESULTS: Found $($results.Count) object(s) with weak encryption settings:" -ForegroundColor Yellow
    
    $results |
    Sort-Object Domain, ObjectType, Name |
    Format-Table Domain, ObjectType, Name, EncTypes -AutoSize
    
    # Check for objects with undefined encryption types (fallback scenario)
    $undefinedObjects = $results | Where-Object { $_.EncTypes -eq "Not Set (RC4 fallback)" }
    if ($undefinedObjects.Count -gt 0) {
        Write-Host "`n🚨 CRITICAL WARNING - Windows Server 2025 Compatibility:" -ForegroundColor Red
        Write-Host "Found $($undefinedObjects.Count) object(s) with undefined encryption types (msDS-SupportedEncryptionTypes not set)." -ForegroundColor Red
        Write-Host "Windows Server 2025 disables the RC4 fallback mechanism by default." -ForegroundColor Red
        Write-Host "These objects will experience authentication failures on Windows Server 2025 domain controllers!" -ForegroundColor Red
        Write-Host "`nRECOMMENDATION:" -ForegroundColor Yellow
        Write-Host "- Run this script with -ApplyFixes to set AES encryption (value 24)" -ForegroundColor Yellow
        Write-Host "- Or configure via Group Policy: 'Network security: Configure encryption types allowed for Kerberos'" -ForegroundColor Yellow
        Write-Host "- Test thoroughly before deploying to production environments" -ForegroundColor Yellow
    }
}

# Export results if requested
if ($ExportResults) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = ".\RC4_Audit_Results_$timestamp.csv"
    $results | Export-Csv $exportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n📄 Results exported to: $exportPath" -ForegroundColor Cyan
}

# Optional export
# $results | Export-Csv ".\\RC4_Audit_Results.csv" -NoTypeInformation -Encoding UTF8
