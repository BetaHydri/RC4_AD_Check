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
  - Requires Administrator privileges for proper AD access

.PARAMETER ApplyFixes
  Switch to enable interactive remediation mode

.PARAMETER ExportResults
  Switch to export results to CSV file

.PARAMETER SkipGPOCheck
  Switch to skip Group Policy settings verification

.PARAMETER GPOScope
  Specify where to check for GPO links: Domain, DomainControllers, or Both (default)

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

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -SkipGPOCheck
  Run audit without checking Group Policy settings

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -GPOScope DomainControllers
  Check GPO settings only on Domain Controllers OU

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -GPOScope Domain
  Check GPO settings only at Domain level

.NOTES
  Author: Jan Tiedemann
  Version: 1.0
  Created: October 2025
  
  Requires: PowerShell 5.1+, ActiveDirectory module
  Permissions: Domain Admin (scanning), Enterprise Admin (trust remediation)
#>

param(
    [switch]$ApplyFixes,
    [switch]$ExportResults,
    [switch]$SkipGPOCheck,
    [ValidateSet("Domain", "DomainControllers", "Both")]
    [string]$GPOScope = "Both"
)

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "❌ ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Required privileges:" -ForegroundColor Yellow
    Write-Host "- Domain Administrator (for scanning and fixing users/computers)" -ForegroundColor Yellow
    Write-Host "- Enterprise Administrator (for fixing domain trusts)" -ForegroundColor Yellow
    Write-Host "`nPlease restart PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

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

function Test-KerberosGPOSettings {
    param(
        [string]$Domain,
        [string]$Scope = "Both"
    )
    
    Write-Host "Checking GPO settings for Kerberos encryption in domain: $Domain" -ForegroundColor Cyan
    Write-Host "Scope: $Scope" -ForegroundColor Gray
    
    try {
        # Get domain information
        $domainDN = (Get-ADDomain -Server $Domain).DistinguishedName
        $domainControllersOU = "OU=Domain Controllers,$domainDN"
        
        # Get all GPOs in the domain
        $gpos = Get-GPO -All -Domain $Domain -ErrorAction Stop
        $kerberosGPOs = @()
        
        # Check each GPO for Kerberos settings
        foreach ($gpo in $gpos) {
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue
                
                if ($gpoReport -and $gpoReport -match "Configure encryption types allowed for Kerberos") {
                    # Get GPO links
                    $gpoLinks = Get-GPInheritance -Target $domainDN -Domain $Domain -ErrorAction SilentlyContinue
                    $dcGpoLinks = Get-GPInheritance -Target $domainControllersOU -Domain $Domain -ErrorAction SilentlyContinue
                    
                    $linkedToDomain = $gpoLinks.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                    $linkedToDC = $dcGpoLinks.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                    
                    # Analyze settings
                    $hasAES128 = $gpoReport -match "AES128_HMAC_SHA1.*?Enabled"
                    $hasAES256 = $gpoReport -match "AES256_HMAC_SHA1.*?Enabled"
                    $hasRC4Disabled = $gpoReport -match "RC4_HMAC_MD5.*?Disabled"
                    $hasDESDisabled = $gpoReport -match "DES_CBC.*?Disabled"
                    
                    $isOptimal = $hasAES128 -and $hasAES256 -and $hasRC4Disabled -and $hasDESDisabled
                    
                    $kerberosGPO = [PSCustomObject]@{
                        Name           = $gpo.DisplayName
                        Id             = $gpo.Id
                        LinkedToDomain = [bool]$linkedToDomain
                        LinkedToDC     = [bool]$linkedToDC
                        IsOptimal      = $isOptimal
                        HasAES128      = $hasAES128
                        HasAES256      = $hasAES256
                        HasRC4Disabled = $hasRC4Disabled
                        HasDESDisabled = $hasDESDisabled
                    }
                    $kerberosGPOs += $kerberosGPO
                }
            }
            catch {
                continue
            }
        }
        
        if ($kerberosGPOs.Count -eq 0) {
            Write-Host "  ❌ No Kerberos encryption GPOs found in domain: $Domain" -ForegroundColor Red
            Write-Host "  💡 RECOMMENDATION: Create and link GPO with 'Network security: Configure encryption types allowed for Kerberos'" -ForegroundColor Yellow
            Write-Host "     • For Domain Controllers: Link to 'Domain Controllers' OU (affects DC authentication)" -ForegroundColor Yellow
            Write-Host "     • For All Objects: Link to Domain root (affects all computers and users)" -ForegroundColor Yellow
            Write-Host "     • Best Practice: Use both for comprehensive coverage" -ForegroundColor Yellow
        }
        else {
            # Report findings based on scope
            foreach ($gpo in $kerberosGPOs) {
                Write-Host "  📋 Found Kerberos encryption GPO: $($gpo.Name)" -ForegroundColor Green
                
                # Check linking based on scope
                $scopeCompliant = $false
                if ($Scope -eq "Domain" -and $gpo.LinkedToDomain) { $scopeCompliant = $true }
                elseif ($Scope -eq "DomainControllers" -and $gpo.LinkedToDC) { $scopeCompliant = $true }
                elseif ($Scope -eq "Both" -and ($gpo.LinkedToDomain -or $gpo.LinkedToDC)) { $scopeCompliant = $true }
                
                # Report linking status
                if ($gpo.LinkedToDomain -and $gpo.LinkedToDC) {
                    Write-Host "    🔗 Linked to: Domain + Domain Controllers OU (Complete coverage)" -ForegroundColor Green
                }
                elseif ($gpo.LinkedToDomain) {
                    Write-Host "    🔗 Linked to: Domain level (All objects)" -ForegroundColor Cyan
                    if ($Scope -eq "DomainControllers" -or $Scope -eq "Both") {
                        Write-Host "    ⚠️  Consider also linking to Domain Controllers OU for DC-specific settings" -ForegroundColor Yellow
                    }
                }
                elseif ($gpo.LinkedToDC) {
                    Write-Host "    🔗 Linked to: Domain Controllers OU only" -ForegroundColor Cyan
                    if ($Scope -eq "Domain" -or $Scope -eq "Both") {
                        Write-Host "    ⚠️  Consider also linking to Domain level for complete coverage" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "    ❌ Not linked to checked scopes" -ForegroundColor Red
                }
                
                # Report settings compliance
                if ($gpo.IsOptimal) {
                    Write-Host "    ✅ Optimal settings (AES128+256 enabled, RC4+DES disabled)" -ForegroundColor Green
                }
                else {
                    Write-Host "    ⚠️  Sub-optimal settings detected:" -ForegroundColor Yellow
                    if (-not $gpo.HasAES128) { Write-Host "      - AES128 not enabled" -ForegroundColor Yellow }
                    if (-not $gpo.HasAES256) { Write-Host "      - AES256 not enabled" -ForegroundColor Yellow }
                    if (-not $gpo.HasRC4Disabled) { Write-Host "      - RC4 not disabled" -ForegroundColor Yellow }
                    if (-not $gpo.HasDESDisabled) { Write-Host "      - DES not disabled" -ForegroundColor Yellow }
                }
            }
            
            # Provide scope-specific recommendations
            Write-Host "  💡 GPO LINKING BEST PRACTICES:" -ForegroundColor Cyan
            Write-Host "     • Domain Level: Affects all users and computers (recommended for organization-wide policy)" -ForegroundColor Gray
            Write-Host "     • Domain Controllers OU: Affects only DCs (recommended for DC-specific requirements)" -ForegroundColor Gray
            Write-Host "     • Both Levels: Provides comprehensive coverage and allows for different settings if needed" -ForegroundColor Gray
        }
        
    }
    catch {
        Write-Host "  ⚠️  Unable to check GPO settings in domain: $Domain" -ForegroundColor Yellow
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

$results = @()
$forest = Get-ADForest

# Check GPO settings for each domain
if (-not $SkipGPOCheck) {
    Write-Host "🔍 Checking Group Policy settings..." -ForegroundColor Magenta
    foreach ($domain in $forest.Domains) {
        Test-KerberosGPOSettings -Domain $domain -Scope $GPOScope
    }
}

Write-Host "🔍 Scanning for objects with weak encryption..." -ForegroundColor Magenta
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
