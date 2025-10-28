<#
.SYNOPSIS
  Audit AD forest for RC4 usage and optionally remediate.

.DESCRIPTION
  This script enumerates all domains in the forest and checks Users, Computers, and Trusts.
  It flags objects with RC4 enabled or no msDS-SupportedEncryptionTypes set.
  By default it provides report only functionality.
  With ApplyFixes parameter it prompts per object to apply AES-only (0x18) setting.
  Provides warnings for Windows Server 2025 compatibility issues.
  Requires Administrator privileges for proper AD access.

.PARAMETER ApplyFixes
  Switch to enable interactive remediation mode

.PARAMETER ExportResults
  Switch to export results to CSV file

.PARAMETER SkipGPOCheck
  Switch to skip Group Policy settings verification

.PARAMETER GPOScope
  Specify where to check for GPO links: Domain, DomainControllers, or Both (default)

.PARAMETER Debug
  Enable debug output for troubleshooting GPO detection

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

.PARAMETER Server
  Specify a domain controller server to connect to (e.g., dc01.contoso.com)

.PARAMETER TargetForest
  Specify a target forest to scan when using forest trusts (e.g., target.com)

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -Server dc01.contoso.com
  Connect to a specific domain controller for scanning

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -Debug -Server dc01.contoso.com
  Run with debug output using a specific domain controller

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -TargetForest target.com
  Scan a different forest via forest trust

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -TargetForest target.com -Server dc01.target.com
  Scan a specific forest using a specific domain controller

.NOTES
  Author: Jan Tiedemann
  Version: 2.0
  Created: October 2025
  Updated: October 2025
  
  Requires: PowerShell 5.1+, ActiveDirectory module, GroupPolicy module
  Permissions: Domain Admin (scanning), Enterprise Admin (trust remediation)
#>

param(
    [switch]$ApplyFixes,
    [switch]$ExportResults,
    [switch]$SkipGPOCheck,
    [ValidateSet("Domain", "DomainControllers", "Both")]
    [string]$GPOScope = "Both",
    [switch]$Debug,
    [string]$Server,
    [string]$TargetForest
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
        [string]$Scope = "Both",
        [switch]$Debug,
        [string]$Server,
        [string]$TargetForest
    )
    
    Write-Host "Checking GPO settings for Kerberos encryption in domain: $Domain" -ForegroundColor Cyan
    Write-Host "Scope: $Scope" -ForegroundColor Gray
    
    # Set up server parameter for AD commands
    $adParams = @{}
    if ($Server) {
        $adParams['Server'] = $Server
        if ($Debug) {
            Write-Host "      🌐 Using server: $Server" -ForegroundColor Gray
        }
    }
    
    # Handle target forest context
    if ($TargetForest -and $Debug) {
        Write-Host "      🌲 Operating in target forest: $TargetForest" -ForegroundColor Gray
    }
    
    try {
        # Get domain information - use appropriate server context
        $domainDN = (Get-ADDomain -Server $Domain @adParams).DistinguishedName
        $domainControllersOU = "OU=Domain Controllers,$domainDN"
        
        if ($Debug) {
            Write-Host "      📍 Domain DN: $domainDN" -ForegroundColor Gray
            Write-Host "      📍 Domain Controllers OU: $domainControllersOU" -ForegroundColor Gray
        }
        
        # Get all GPOs in the domain
        $gpoParams = @{
            All         = $true
            Domain      = $Domain
            ErrorAction = 'Stop'
        }
        if ($Server) {
            # Note: Get-GPO doesn't accept -Server parameter, but uses current session context
            if ($Debug) {
                Write-Host "      ℹ️  Note: Get-GPO uses current session context" -ForegroundColor Gray
            }
        }
        
        $gpos = Get-GPO @gpoParams
        $kerberosGPOs = @()
        
        # Check each GPO for Kerberos settings
        foreach ($gpo in $gpos) {
            if ($Debug) {
                Write-Host "      🔍 Checking GPO: $($gpo.DisplayName)" -ForegroundColor Gray
            }
            
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue
                
                if ($Debug -and $gpoReport) {
                    Write-Host "      📄 GPO report retrieved successfully" -ForegroundColor Gray
                    if ($gpoReport -match "Configure encryption types allowed for Kerberos") {
                        Write-Host "      ✅ Found Kerberos encryption configuration" -ForegroundColor Gray
                    }
                }
                
                if ($gpoReport -and $gpoReport -match "Configure encryption types allowed for Kerberos") {
                    # Get all GPO links for this GPO across the domain
                    $allGPOLinks = @()
                    
                    # Use Get-GPO with XML report to find all links
                    try {
                        # Get the GPO report which includes link information
                        $fullGpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue
                        
                        if ($fullGpoReport) {
                            if ($Debug) {
                                Write-Host "      📋 Full GPO report retrieved for link analysis" -ForegroundColor Gray
                            }
                            
                            # Parse XML to find SOM (Scope of Management) links
                            $xmlDoc = [xml]$fullGpoReport
                            $linkNodes = $xmlDoc.SelectNodes("//LinksTo")
                            
                            if ($Debug) {
                                Write-Host "      🔗 Found $($linkNodes.Count) potential link nodes" -ForegroundColor Gray
                            }
                            
                            foreach ($linkNode in $linkNodes) {
                                $somPath = $linkNode.SOMPath
                                $enabled = $linkNode.Enabled -eq "true"
                                $noOverride = $linkNode.NoOverride -eq "true"
                                
                                if ($Debug) {
                                    Write-Host "      🎯 Link found: $somPath (Enabled: $enabled)" -ForegroundColor Gray
                                }
                                
                                # Convert SOM path to friendly name
                                $containerName = if ($somPath -eq $domainDN) { 
                                    "Domain Root" 
                                }
                                elseif ($somPath -eq $domainControllersOU) { 
                                    "Domain Controllers OU" 
                                }
                                else {
                                    # Extract OU name from DN
                                    if ($somPath -match "OU=([^,]+)") {
                                        $matches[1] + " OU"
                                    }
                                    elseif ($somPath -match "CN=([^,]+)") {
                                        $matches[1] + " Container"
                                    }
                                    else {
                                        $somPath
                                    }
                                }
                                
                                $allGPOLinks += [PSCustomObject]@{
                                    Container   = $somPath
                                    DisplayName = $containerName
                                    Enabled     = $enabled
                                    Enforced    = $noOverride
                                    Order       = 1  # Default order, actual order would need additional query
                                }
                            }
                        }
                        
                        # If no links found in XML, try alternative method
                        if ($allGPOLinks.Count -eq 0) {
                            if ($Debug) {
                                Write-Host "      🔍 XML parsing found no links, trying alternative GPO link detection..." -ForegroundColor Gray
                            }
                            
                            # Search for containers where this GPO might be linked
                            $searchContainers = @($domainDN, $domainControllersOU)
                            
                            if ($Debug) {
                                Write-Host "      🎯 Checking primary containers:" -ForegroundColor Gray
                                Write-Host "         - Domain DN: $domainDN" -ForegroundColor Gray
                                Write-Host "         - Domain Controllers OU: $domainControllersOU" -ForegroundColor Gray
                            }
                            
                            # Add some common OUs
                            try {
                                $commonOUs = Get-ADOrganizationalUnit -Filter "Name -like '*'" -Server $Domain -ErrorAction SilentlyContinue | Select-Object -First 10
                                foreach ($ou in $commonOUs) {
                                    $searchContainers += $ou.DistinguishedName
                                }
                                if ($Debug) {
                                    Write-Host "      📂 Added $($commonOUs.Count) additional OUs to search" -ForegroundColor Gray
                                }
                            }
                            catch {
                                if ($Debug) {
                                    Write-Host "      ⚠️  Could not enumerate additional OUs: $($_.Exception.Message)" -ForegroundColor Gray
                                }
                            }
                            
                            foreach ($container in $searchContainers) {
                                try {
                                    if ($Debug) {
                                        Write-Host "      🔍 Checking container: $container" -ForegroundColor Gray
                                    }
                                    
                                    $inheritance = Get-GPInheritance -Target $container -Domain $Domain -ErrorAction SilentlyContinue
                                    if ($inheritance -and $inheritance.GpoLinks) {
                                        if ($Debug) {
                                            Write-Host "      📋 Found $($inheritance.GpoLinks.Count) GPO links in this container" -ForegroundColor Gray
                                        }
                                        
                                        $linkedGPO = $inheritance.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                                        if ($linkedGPO) {
                                            if ($Debug) {
                                                Write-Host "      ✅ Found matching GPO link! GPO ID: $($gpo.Id)" -ForegroundColor Green
                                            }
                                            
                                            $containerName = if ($container -eq $domainDN) { 
                                                "Domain Root" 
                                            }
                                            elseif ($container -eq $domainControllersOU) { 
                                                "Domain Controllers OU" 
                                            }
                                            else {
                                                # Extract OU name from DN
                                                if ($container -match "OU=([^,]+)") {
                                                    $matches[1] + " OU"
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
                                        else {
                                            if ($Debug) {
                                                Write-Host "      ❌ No matching GPO found in this container (checked $($inheritance.GpoLinks.Count) links)" -ForegroundColor Gray
                                            }
                                        }
                                    }
                                    else {
                                        if ($Debug) {
                                            Write-Host "      ❌ No GPO inheritance found for this container" -ForegroundColor Gray
                                        }
                                    }
                                }
                                catch {
                                    if ($Debug) {
                                        Write-Host "      ⚠️  Error checking container $container : $($_.Exception.Message)" -ForegroundColor Gray
                                    }
                                    continue
                                }
                            }
                        }
                        
                        # Final fallback: Try to get GPO links directly from Active Directory
                        if ($allGPOLinks.Count -eq 0) {
                            if ($Debug) {
                                Write-Host "      🔄 Final fallback: Searching AD for GPO links..." -ForegroundColor Gray
                            }
                            
                            try {
                                # Search for objects that have gPLink attribute containing this GPO's GUID
                                $gpoGuid = $gpo.Id.ToString()
                                $filter = "gPLink -like '*$gpoGuid*'"
                                
                                if ($Debug) {
                                    Write-Host "      🔍 Searching for gPLink containing: $gpoGuid" -ForegroundColor Gray
                                }
                                
                                $linkedObjects = Get-ADObject -Filter $filter -Server $Domain -Properties gPLink, Name -ErrorAction SilentlyContinue
                                
                                if ($linkedObjects) {
                                    if ($Debug) {
                                        Write-Host "      📋 Found $($linkedObjects.Count) objects with gPLink containing this GPO" -ForegroundColor Gray
                                    }
                                    
                                    foreach ($obj in $linkedObjects) {
                                        if ($Debug) {
                                            Write-Host "      🎯 Found link in: $($obj.Name) ($($obj.DistinguishedName))" -ForegroundColor Gray
                                            Write-Host "      🔗 gPLink value: $($obj.gPLink)" -ForegroundColor Gray
                                        }
                                        
                                        # Parse gPLink to determine if this GPO is enabled
                                        $gpoEnabled = $true
                                        if ($obj.gPLink -match "\[LDAP://[^;]*$gpoGuid[^;]*;(\d+)\]") {
                                            $linkOptions = [int]$matches[1]
                                            $gpoEnabled = ($linkOptions -band 1) -eq 0  # Bit 0 = disabled when set
                                        }
                                        
                                        $containerName = if ($obj.DistinguishedName -eq $domainDN) { 
                                            "Domain Root" 
                                        }
                                        elseif ($obj.DistinguishedName -eq $domainControllersOU) { 
                                            "Domain Controllers OU" 
                                        }
                                        else {
                                            # Extract OU name from DN
                                            if ($obj.DistinguishedName -match "OU=([^,]+)") {
                                                $matches[1] + " OU"
                                            }
                                            elseif ($obj.DistinguishedName -match "CN=([^,]+)") {
                                                $matches[1] + " Container"
                                            }
                                            else {
                                                $obj.Name
                                            }
                                        }
                                        
                                        $allGPOLinks += [PSCustomObject]@{
                                            Container   = $obj.DistinguishedName
                                            DisplayName = $containerName
                                            Enabled     = $gpoEnabled
                                            Enforced    = $false  # Would need additional parsing to determine
                                            Order       = 1  # Would need additional parsing to determine
                                        }
                                    }
                                }
                                else {
                                    if ($Debug) {
                                        Write-Host "      ❌ No objects found with gPLink containing this GPO GUID" -ForegroundColor Gray
                                    }
                                }
                            }
                            catch {
                                if ($Debug) {
                                    Write-Host "      ⚠️  Error in AD search fallback: $($_.Exception.Message)" -ForegroundColor Gray
                                }
                            }
                        }
                    }
                    catch {
                        Write-Host "      ⚠️  Error detecting GPO links: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Analyze settings with more detailed checking
                    Write-Host "      🔍 Analyzing GPO settings..." -ForegroundColor Gray
                    
                    # Check for different possible setting patterns
                    $hasAES128 = $gpoReport -match "AES128_HMAC_SHA1.*?(?:Enabled|True)" -or $gpoReport -match "AES128.*?1"
                    $hasAES256 = $gpoReport -match "AES256_HMAC_SHA1.*?(?:Enabled|True)" -or $gpoReport -match "AES256.*?1"
                    $hasRC4Disabled = $gpoReport -match "RC4_HMAC_MD5.*?(?:Disabled|False)" -or $gpoReport -notmatch "RC4.*?1"
                    $hasDESDisabled = $gpoReport -match "DES_CBC.*?(?:Disabled|False)" -or $gpoReport -notmatch "DES.*?1"
                    
                    # Also check for numeric values that might indicate the settings
                    if ($gpoReport -match "SupportedEncryptionTypes.*?(\d+)") {
                        $encValue = [int]$matches[1]
                        if ($Debug) {
                            Write-Host "      📝 Found numeric encryption value: $encValue" -ForegroundColor Gray
                            Write-Host "      🔍 Decoding value: $(Get-EncryptionTypes $encValue)" -ForegroundColor Gray
                        }
                        
                        # Decode the value using bitwise operations
                        $hasAES128 = $hasAES128 -or (($encValue -band 0x8) -ne 0)   # Bit 3 = AES128
                        $hasAES256 = $hasAES256 -or (($encValue -band 0x10) -ne 0)  # Bit 4 = AES256
                        $hasRC4Disabled = $hasRC4Disabled -or (($encValue -band 0x4) -eq 0)  # Bit 2 = RC4 (disabled when bit not set)
                        $hasDESDisabled = $hasDESDisabled -or (($encValue -band 0x3) -eq 0)  # Bits 0-1 = DES (disabled when bits not set)
                    }
                    
                    Write-Host "      📊 Settings analysis: AES128=$hasAES128, AES256=$hasAES256, RC4Disabled=$hasRC4Disabled, DESDisabled=$hasDESDisabled" -ForegroundColor Gray
                    
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
                    if (-not $gpo.HasDESDisabled) { 
                        Write-Host "      - DES not disabled" -ForegroundColor Yellow 
                        Write-Host "        💡 Note: If your numeric value doesn't include DES bits (1,2), DES is already disabled" -ForegroundColor Gray
                        Write-Host "        💡 To explicitly disable DES: Ensure GPO unchecks 'DES-CBC-CRC' and 'DES-CBC-MD5'" -ForegroundColor Gray
                    }
                }
            }
            
            # Check GPO application on objects if scope includes both or we have GPOs
            if ($Scope -eq "Both" -and $kerberosGPOs.Count -gt 0) {
                Test-GPOApplication -Domain $Domain -KerberosGPOs $kerberosGPOs -Server $Server
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
        [array]$KerberosGPOs,
        [string]$Server
    )
    
    Write-Host "  🔍 Checking GPO application status..." -ForegroundColor Cyan
    
    # Set up server parameters for consistent access
    $serverParams = @{}
    if ($Server) {
        $serverParams['Server'] = $Server
    }
    else {
        $serverParams['Server'] = $Domain
    }
    
    try {
        # Get domain information
        $domainDN = (Get-ADDomain @serverParams).DistinguishedName
        $domainControllersOU = "OU=Domain Controllers,$domainDN"
        
        # Sample a few computers and users to check GPO application
        $sampleComputers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes -ResultSetSize 10 @serverParams
        $sampleUsers = Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes -ResultSetSize 10 @serverParams
        $domainControllers = Get-ADComputer -SearchBase $domainControllersOU -Filter * -Properties msDS-SupportedEncryptionTypes @serverParams
        
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
        Write-Host "    ℹ️  Legend:" -ForegroundColor Gray
        Write-Host "      • GPO Applied (AES-only): Objects with msDS-SupportedEncryptionTypes = 24 (AES128+AES256)" -ForegroundColor Gray
        Write-Host "      • Manual Settings (custom): Objects with non-standard encryption values (not 24)" -ForegroundColor Gray
        Write-Host "      • Not Set (RC4 fallback): Objects without msDS-SupportedEncryptionTypes attribute" -ForegroundColor Gray
        Write-Host ""
        
        if ($domainControllers.Count -gt 0) {
            Write-Host "    🖥️  Domain Controllers ($($domainControllers.Count) total):" -ForegroundColor Yellow
            Write-Host "      • GPO Applied (AES-only): $dcGpoAppliedCount" -ForegroundColor Green
            Write-Host "      • Manual Settings (custom values): $dcManualSetCount" -ForegroundColor Cyan
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
            Write-Host "      • Manual Settings (custom values): $manualSetCount" -ForegroundColor Cyan
            Write-Host "      • Not Set (RC4 fallback): $notSetCount" -ForegroundColor Red
        }
        
        if ($sampleUsers.Count -gt 0) {
            Write-Host "    👤 Users (sample of $($sampleUsers.Count)):" -ForegroundColor Yellow
            Write-Host "      • GPO Applied (AES-only): $userGpoAppliedCount" -ForegroundColor Green
            Write-Host "      • Manual Settings (custom values): $userManualSetCount" -ForegroundColor Cyan
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

# Set up server parameter for AD commands
$adParams = @{}
if ($Server) {
    $adParams['Server'] = $Server
    Write-Host "🌐 Connecting to specified server: $Server" -ForegroundColor Cyan
}

# Handle target forest specification
$forestParams = @{}
if ($TargetForest) {
    $forestParams['Identity'] = $TargetForest
    Write-Host "🌲 Targeting forest: $TargetForest" -ForegroundColor Cyan
    
    # If TargetForest is specified but no specific server, try to find a DC in the target forest
    if (-not $Server) {
        try {
            Write-Host "🔍 Attempting to discover domain controller in target forest..." -ForegroundColor Gray
            $targetForestInfo = Get-ADForest -Identity $TargetForest
            $rootDomain = $targetForestInfo.RootDomain
            
            # Try to get a DC from the root domain of the target forest
            $targetDC = Get-ADDomainController -DomainName $rootDomain -Discover -ErrorAction SilentlyContinue
            if ($targetDC) {
                $adParams['Server'] = $targetDC.HostName[0]
                Write-Host "✅ Found target domain controller: $($targetDC.HostName[0])" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "⚠️  Could not auto-discover DC in target forest. Consider using -Server parameter." -ForegroundColor Yellow
        }
    }
}

try {
    if ($TargetForest) {
        $forest = Get-ADForest @forestParams @adParams
        Write-Host "✅ Successfully connected to target forest: $($forest.Name)" -ForegroundColor Green
        Write-Host "📊 Forest contains domains: $($forest.Domains -join ', ')" -ForegroundColor Cyan
    }
    else {
        $forest = Get-ADForest @adParams
    }
}
catch {
    Write-Host "❌ ERROR: Could not connect to Active Directory forest" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($TargetForest) {
        Write-Host "💡 FOREST TRUST TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "• Verify forest trust exists between your forest and target forest" -ForegroundColor Yellow
        Write-Host "• Ensure your account has permissions in the target forest" -ForegroundColor Yellow
        Write-Host "• Try specifying a domain controller: -Server dc01.targetforest.com" -ForegroundColor Yellow
        Write-Host "• Check network connectivity to target forest domain controllers" -ForegroundColor Yellow
    }
    elseif (-not $Server) {
        Write-Host "💡 TIP: Try specifying a domain controller with -Server parameter" -ForegroundColor Yellow
        Write-Host "Example: .\RC4_AD_SCAN.ps1 -Server dc01.contoso.com" -ForegroundColor Yellow
    }
    exit 1
}

# Check GPO settings for each domain
if (-not $SkipGPOCheck) {
    Write-Host "🔍 Checking Group Policy settings..." -ForegroundColor Magenta
    foreach ($domain in $forest.Domains) {
        Test-KerberosGPOSettings -Domain $domain -Scope $GPOScope -Debug:$Debug -Server $Server -TargetForest $TargetForest
    }
}

Write-Host "🔍 Scanning for objects with weak encryption..." -ForegroundColor Magenta
foreach ($domain in $forest.Domains) {
    Write-Host "Scanning domain: $domain" -ForegroundColor Cyan

    # Set up AD command parameters for target forest context
    $domainParams = @{}
    if ($Server) {
        $domainParams['Server'] = $Server
    }
    else {
        # Use the domain itself as server when no specific server is provided
        $domainParams['Server'] = $domain
    }
    
    if ($TargetForest -and $Debug) {
        Write-Host "  🌲 Scanning in target forest context: $TargetForest" -ForegroundColor Gray
    }

    # Users
    Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes @domainParams |
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
    Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes @domainParams |
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
    Get-ADTrust -Filter * -Properties msDS-SupportedEncryptionTypes @domainParams |
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
