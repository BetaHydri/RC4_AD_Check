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
                    # Get all GPO links for this GPO across the domain
                    $allGPOLinks = @()
                    
                    # Get GPO links using Get-GPO and search for all links
                    try {
                        $gpoData = Get-GPO -Guid $gpo.Id -Domain $Domain -ErrorAction SilentlyContinue
                        if ($gpoData) {
                            # Search for all containers where this GPO is linked
                            $searchBase = (Get-ADDomain -Server $Domain).DistinguishedName
                            $allContainers = @()
                            
                            # Add domain root
                            $allContainers += $searchBase
                            
                            # Add Domain Controllers OU
                            $allContainers += "OU=Domain Controllers,$searchBase"
                            
                            # Get all OUs in the domain
                            try {
                                $allOUs = Get-ADOrganizationalUnit -Filter * -Server $Domain -ErrorAction SilentlyContinue
                                foreach ($ou in $allOUs) {
                                    $allContainers += $ou.DistinguishedName
                                }
                            }
                            catch {
                                # Continue if we can't enumerate OUs
                            }
                            
                            # Check each container for this GPO link
                            foreach ($container in $allContainers) {
                                try {
                                    $inheritance = Get-GPInheritance -Target $container -Domain $Domain -ErrorAction SilentlyContinue
                                    if ($inheritance -and $inheritance.GpoLinks) {
                                        $linkedGPO = $inheritance.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                                        if ($linkedGPO) {
                                            $containerName = if ($container -eq $searchBase) { 
                                                "Domain Root" 
                                            }
                                            elseif ($container -eq "OU=Domain Controllers,$searchBase") { 
                                                "Domain Controllers OU" 
                                            }
                                            else {
                                                # Extract OU name from DN
                                                if ($container -match "OU=([^,]+)") {
                                                    $matches[1]
                                                }
                                                else {
                                                    $container
                                                }
                                            }
                                            
                                            $allGPOLinks += [PSCustomObject]@{
                                                Container   = $container
                                                DisplayName = $containerName
                                                Enabled     = $linkedGPO.Enabled
                                                Enforced    = $linkedGPO.Enforced
                                                Order       = $linkedGPO.Order
                                            }
                                        }
                                    }
                                }
                                catch {
                                    # Continue if we can't check a specific container
                                    continue
                                }
                            }
                        }
                    }
                    catch {
                        # Fallback to basic checking if advanced search fails
                        $gpoLinks = Get-GPInheritance -Target $domainDN -Domain $Domain -ErrorAction SilentlyContinue
                        $dcGpoLinks = Get-GPInheritance -Target $domainControllersOU -Domain $Domain -ErrorAction SilentlyContinue
                        
                        $linkedToDomain = $gpoLinks.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                        $linkedToDC = $dcGpoLinks.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                        
                        if ($linkedToDomain) {
                            $allGPOLinks += [PSCustomObject]@{
                                Container   = $domainDN
                                DisplayName = "Domain Root"
                                Enabled     = $linkedToDomain.Enabled
                                Enforced    = $linkedToDomain.Enforced
                                Order       = $linkedToDomain.Order
                            }
                        }
                        
                        if ($linkedToDC) {
                            $allGPOLinks += [PSCustomObject]@{
                                Container   = $domainControllersOU
                                DisplayName = "Domain Controllers OU"
                                Enabled     = $linkedToDC.Enabled
                                Enforced    = $linkedToDC.Enforced
                                Order       = $linkedToDC.Order
                            }
                        }
                    }
                    
                    # Analyze settings
                    $hasAES128 = $gpoReport -match "AES128_HMAC_SHA1.*?Enabled"
                    $hasAES256 = $gpoReport -match "AES256_HMAC_SHA1.*?Enabled"
                    $hasRC4Disabled = $gpoReport -match "RC4_HMAC_MD5.*?Disabled"
                    $hasDESDisabled = $gpoReport -match "DES_CBC.*?Disabled"
                    
                    $isOptimal = $hasAES128 -and $hasAES256 -and $hasRC4Disabled -and $hasDESDisabled
                    
                    $kerberosGPO = [PSCustomObject]@{
                        Name           = $gpo.DisplayName
                        Id             = $gpo.Id
                        LinkedToDomain = $null -ne ($allGPOLinks | Where-Object { $_.DisplayName -eq "Domain Root" })
                        LinkedToDC     = $null -ne ($allGPOLinks | Where-Object { $_.DisplayName -eq "Domain Controllers OU" })
                        AllLinks       = $allGPOLinks
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
                
                # Show detailed linking information
                if ($gpo.AllLinks -and $gpo.AllLinks.Count -gt 0) {
                    Write-Host "    🔗 Linked to the following locations:" -ForegroundColor Cyan
                    foreach ($link in $gpo.AllLinks | Sort-Object Order) {
                        $statusIcon = if ($link.Enabled) { "✅" } else { "❌" }
                        $enforcedText = if ($link.Enforced) { " (Enforced)" } else { "" }
                        Write-Host "      $statusIcon $($link.DisplayName) [Order: $($link.Order)]$enforcedText" -ForegroundColor Gray
                    }
                    
                    # Provide coverage summary
                    $domainLinked = $gpo.LinkedToDomain
                    $dcLinked = $gpo.LinkedToDC
                    $otherOUs = $gpo.AllLinks | Where-Object { $_.DisplayName -notin @("Domain Root", "Domain Controllers OU") }
                    
                    if ($domainLinked -and $dcLinked) {
                        Write-Host "    📈 Coverage: Complete (Domain + DCs + $($otherOUs.Count) additional OUs)" -ForegroundColor Green
                    }
                    elseif ($domainLinked) {
                        Write-Host "    � Coverage: Domain-wide (All objects + $($otherOUs.Count) additional OUs)" -ForegroundColor Cyan
                        if ($Scope -eq "DomainControllers" -or $Scope -eq "Both") {
                            Write-Host "    ⚠️  Consider linking to Domain Controllers OU for explicit DC coverage" -ForegroundColor Yellow
                        }
                    }
                    elseif ($dcLinked) {
                        Write-Host "    � Coverage: Domain Controllers + $($otherOUs.Count) additional OUs" -ForegroundColor Cyan
                        if ($Scope -eq "Domain" -or $Scope -eq "Both") {
                            Write-Host "    ⚠️  Consider linking to Domain level for complete coverage" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "    📈 Coverage: $($gpo.AllLinks.Count) specific OUs only" -ForegroundColor Yellow
                        Write-Host "    💡 Consider linking to Domain level for broader coverage" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "    ❌ No active links found for this GPO" -ForegroundColor Red
                    Write-Host "    💡 GPO exists but is not linked to any organizational units" -ForegroundColor Yellow
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
            
            # Check GPO application on objects if scope includes both or we have GPOs
            if ($Scope -eq "Both" -and $kerberosGPOs.Count -gt 0) {
                Test-GPOApplication -Domain $Domain -KerberosGPOs $kerberosGPOs
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

function Test-GPOApplication {
    param(
        [string]$Domain,
        [array]$KerberosGPOs
    )
    
    Write-Host "  🔍 Checking GPO application status..." -ForegroundColor Cyan
    
    try {
        # Get domain information
        $domainDN = (Get-ADDomain -Server $Domain).DistinguishedName
        $domainControllersOU = "OU=Domain Controllers,$domainDN"
        
        # Sample a few computers and users to check GPO application
        $sampleComputers = Get-ADComputer -Filter * -Server $Domain -Properties msDS-SupportedEncryptionTypes -ResultSetSize 10
        $sampleUsers = Get-ADUser -Filter * -Server $Domain -Properties msDS-SupportedEncryptionTypes -ResultSetSize 10
        $domainControllers = Get-ADComputer -SearchBase $domainControllersOU -Filter * -Server $Domain -Properties msDS-SupportedEncryptionTypes
        
        $gpoAppliedCount = 0
        $manualSetCount = 0
        $notSetCount = 0
        $dcGpoAppliedCount = 0
        $dcManualSetCount = 0
        $dcNotSetCount = 0
        
        # Check regular computers
        foreach ($computer in $sampleComputers) {
            $enc = $computer."msDS-SupportedEncryptionTypes"
            if ($enc -eq 24) {
                # AES128 + AES256 = 8 + 16 = 24 (typical GPO setting)
                $gpoAppliedCount++
            }
            elseif ($enc -and $enc -ne 24) {
                $manualSetCount++
            }
            else {
                $notSetCount++
            }
        }
        
        # Check domain controllers separately
        foreach ($dc in $domainControllers) {
            $enc = $dc."msDS-SupportedEncryptionTypes"
            if ($enc -eq 24) {
                $dcGpoAppliedCount++
            }
            elseif ($enc -and $enc -ne 24) {
                $dcManualSetCount++
            }
            else {
                $dcNotSetCount++
            }
        }
        
        # Check users
        $userGpoAppliedCount = 0
        $userManualSetCount = 0
        $userNotSetCount = 0
        
        foreach ($user in $sampleUsers) {
            $enc = $user."msDS-SupportedEncryptionTypes"
            if ($enc -eq 24) {
                $userGpoAppliedCount++
            }
            elseif ($enc -and $enc -ne 24) {
                $userManualSetCount++
            }
            else {
                $userNotSetCount++
            }
        }
        
        # Report GPO application status
        Write-Host "    📊 GPO Application Status (sample analysis):" -ForegroundColor White
        
        if ($domainControllers.Count -gt 0) {
            Write-Host "    🖥️  Domain Controllers ($($domainControllers.Count) total):" -ForegroundColor Yellow
            Write-Host "      • GPO Applied (AES-only): $dcGpoAppliedCount" -ForegroundColor Green
            Write-Host "      • Manual Settings: $dcManualSetCount" -ForegroundColor Cyan
            Write-Host "      • Not Set (RC4 fallback): $dcNotSetCount" -ForegroundColor Red
            
            if ($dcGpoAppliedCount -eq $domainControllers.Count) {
                Write-Host "      ✅ All DCs have optimal encryption settings!" -ForegroundColor Green
            }
            elseif ($dcNotSetCount -gt 0) {
                Write-Host "      ⚠️  Some DCs are using RC4 fallback" -ForegroundColor Yellow
            }
        }
        
        if ($sampleComputers.Count -gt 0) {
            Write-Host "    💻 Regular Computers (sample of $($sampleComputers.Count)):" -ForegroundColor Yellow
            Write-Host "      • GPO Applied (AES-only): $gpoAppliedCount" -ForegroundColor Green
            Write-Host "      • Manual Settings: $manualSetCount" -ForegroundColor Cyan
            Write-Host "      • Not Set (RC4 fallback): $notSetCount" -ForegroundColor Red
        }
        
        if ($sampleUsers.Count -gt 0) {
            Write-Host "    👤 Users (sample of $($sampleUsers.Count)):" -ForegroundColor Yellow
            Write-Host "      • GPO Applied (AES-only): $userGpoAppliedCount" -ForegroundColor Green
            Write-Host "      • Manual Settings: $userManualSetCount" -ForegroundColor Cyan
            Write-Host "      • Not Set (RC4 fallback): $userNotSetCount" -ForegroundColor Red
        }
        
        # Provide recommendations based on findings
        if ($dcNotSetCount -gt 0 -or $notSetCount -gt 0 -or $userNotSetCount -gt 0) {
            Write-Host "    💡 RECOMMENDATIONS:" -ForegroundColor Yellow
            if ($dcNotSetCount -gt 0) {
                Write-Host "      • Ensure GPO is linked to Domain Controllers OU and refreshed" -ForegroundColor Yellow
            }
            if ($notSetCount -gt 0 -or $userNotSetCount -gt 0) {
                Write-Host "      • Ensure GPO is linked to Domain level and refreshed" -ForegroundColor Yellow
                Write-Host "      • Run 'gpupdate /force' on affected systems" -ForegroundColor Yellow
            }
            Write-Host "      • Objects with 'Not Set' status will be flagged in detailed scan below" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Host "    ⚠️  Could not analyze GPO application status: $($_.Exception.Message)" -ForegroundColor Yellow
    }
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
