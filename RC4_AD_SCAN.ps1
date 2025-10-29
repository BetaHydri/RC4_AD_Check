<#
.SYNOPSIS
  Audit AD forest for RC4/DES Kerberos encryption usage and optionally remediate.

.DESCRIPTION
  This script enumerates all domains in the forest and checks Computers and Trusts.
  It flags computer objects with RC4 enabled or no msDS-SupportedEncryptionTypes set.
  Note: User objects do not use msDS-SupportedEncryptionTypes as this is a computer-based setting only.
  User Kerberos encryption is controlled by computer-side settings and domain policy.
  By default it provides report only functionality.
  With ApplyFixes parameter it prompts per object to apply AES-only (0x18) setting.
  Provides warnings for Windows Server 2025 compatibility issues.
  Requires Administrator privileges for proper AD access.

.PARAMETER ApplyFixes
  Switch to enable interactive remediation mode

.PARAMETER ExportResults
  Switch to export results to CSV file

.PARAMETER SkipGPOCheck
  Switch to skip Group Policy settings verification (mutually exclusive with GPOCheckOnly and GPOScope)

.PARAMETER GPOCheckOnly
  Switch to perform only Group Policy analysis without scanning objects (mutually exclusive with SkipGPOCheck and ApplyFixes)

.PARAMETER GPOScope
  Specify where to check for GPO links (only valid with Standard or GPOOnly modes).
  Use tab completion for common values: Domain, DomainControllers, Both, AllOUs
  Or specify custom OU path: "OU=IT,DC=contoso,DC=com"
  - Domain: Check domain root only
  - DomainControllers: Check Domain Controllers OU only  
  - Both: Check both domain root and Domain Controllers OU (default)
  - AllOUs: Check all OUs in the domain
  - OU=<Distinguished Name>: Check specific OU path (e.g., "OU=IT,DC=contoso,DC=com")

.PARAMETER DebugMode
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
  .\RC4_AD_SCAN.ps1 -GPOCheckOnly
  Run only Group Policy analysis without scanning objects

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -GPOScope DomainControllers
  Check GPO settings only on Domain Controllers OU

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -GPOScope Domain
  Check GPO settings only at Domain level

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -GPOScope AllOUs
  Check GPO settings on all OUs in the domain

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -GPOScope "OU=IT,DC=contoso,DC=com"
  Check GPO settings on a specific OU only

.PARAMETER Server
  Specify a domain controller server to connect to (e.g., dc01.contoso.com)

.PARAMETER TargetForest
  Specify a target forest to scan when using forest trusts (e.g., target.com)

.PARAMETER Help
  Display this help information

.PARAMETER QuickHelp
  Display quick reference guide

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -Help
  Display help information

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -QuickHelp
  Display quick reference guide

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -Server dc01.contoso.com
  Connect to a specific domain controller for scanning

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -DebugMode -Server dc01.contoso.com
  Run with debug output using a specific domain controller

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -TargetForest target.com
  Scan a different forest via forest trust

.EXAMPLE
  .\RC4_AD_SCAN.ps1 -TargetForest target.com -Server dc01.target.com
  Scan a specific forest using a specific domain controller

.NOTES
  Author: Jan Tiedemann
  Version: 3.4
  Created: October 2025
  Updated: October 2025
  
  Requires: PowerShell 5.1+, ActiveDirectory module, GroupPolicy module
  Permissions: Domain Admin (scanning), Enterprise Admin (trust remediation)
  
  Parameter Sets:
  - Standard: Normal operation with optional GPO scope
  - SkipGPO: Skip all GPO checks (mutually exclusive with GPOScope/GPOCheckOnly)
  - GPOOnly: GPO analysis only (mutually exclusive with SkipGPOCheck/ApplyFixes)
  - Help: Display detailed help information
  - QuickHelp: Display quick reference guide
#>

[CmdletBinding(DefaultParameterSetName = 'Standard')]
param(
    [Parameter(ParameterSetName = 'Standard')]
    [Parameter(ParameterSetName = 'SkipGPO')]
    [Parameter(ParameterSetName = 'Help')]
    [Parameter(ParameterSetName = 'QuickHelp')]
    [switch]$ApplyFixes,
    
    [Parameter(ParameterSetName = 'Standard')]
    [Parameter(ParameterSetName = 'SkipGPO')]
    [Parameter(ParameterSetName = 'GPOOnly')]
    [Parameter(ParameterSetName = 'Help')]
    [Parameter(ParameterSetName = 'QuickHelp')]
    [switch]$ExportResults,
    
    [Parameter(ParameterSetName = 'SkipGPO', Mandatory)]
    [switch]$SkipGPOCheck,
    
    [Parameter(ParameterSetName = 'GPOOnly', Mandatory)]
    [switch]$GPOCheckOnly,
    
    [Parameter(ParameterSetName = 'Standard')]
    [Parameter(ParameterSetName = 'GPOOnly')]
    [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
            $completions = @('Domain', 'DomainControllers', 'Both', 'AllOUs')
            $completions | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { "'$_'" }
        })]
    [string]$GPOScope = "Both",
    
    [Parameter(ParameterSetName = 'Standard')]
    [Parameter(ParameterSetName = 'SkipGPO')]
    [Parameter(ParameterSetName = 'GPOOnly')]
    [Parameter(ParameterSetName = 'Help')]
    [Parameter(ParameterSetName = 'QuickHelp')]
    [switch]$DebugMode,
    
    [Parameter(ParameterSetName = 'Standard')]
    [Parameter(ParameterSetName = 'SkipGPO')]
    [Parameter(ParameterSetName = 'GPOOnly')]
    [Parameter(ParameterSetName = 'Help')]
    [Parameter(ParameterSetName = 'QuickHelp')]
    [string]$Server,
    
    [Parameter(ParameterSetName = 'Standard')]
    [Parameter(ParameterSetName = 'SkipGPO')]
    [Parameter(ParameterSetName = 'GPOOnly')]
    [Parameter(ParameterSetName = 'Help')]
    [Parameter(ParameterSetName = 'QuickHelp')]
    [string]$TargetForest,
    
    [Parameter(ParameterSetName = 'Help', Mandatory)]
    [switch]$Help,
    
    [Parameter(ParameterSetName = 'QuickHelp', Mandatory)]
    [switch]$QuickHelp
)

# Import required modules first
Import-Module ActiveDirectory

# Define helper functions before parameter validation
function Show-QuickHelp {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ">> RC4 ACTIVE DIRECTORY AUDIT TOOL - QUICK REFERENCE" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host ">> BASIC USAGE:" -ForegroundColor Yellow
    Write-Host "  .\RC4_AD_SCAN.ps1                     # Audit only (read-only scan)" -ForegroundColor White
    Write-Host "  .\RC4_AD_SCAN.ps1 -ApplyFixes         # Interactive remediation" -ForegroundColor White
    Write-Host "  .\RC4_AD_SCAN.ps1 -ExportResults      # Export results to CSV" -ForegroundColor White
    Write-Host "  .\RC4_AD_SCAN.ps1 -Help               # Show detailed help" -ForegroundColor White
    
    Write-Host ""
    Write-Host ">> GPO SCOPE OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -GPOScope Domain                      # Check domain root only" -ForegroundColor White
    Write-Host "  -GPOScope DomainControllers           # Check DC OU only" -ForegroundColor White
    Write-Host "  -GPOScope Both                        # Check both (default)" -ForegroundColor White
    Write-Host "  -GPOScope AllOUs                      # Check all OUs" -ForegroundColor White
    Write-Host "  -GPOScope `"OU=IT,DC=contoso,DC=com`"   # Check specific OU" -ForegroundColor White
    
    Write-Host ""
    Write-Host ">> ADVANCED OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -SkipGPOCheck                         # Skip GPO verification" -ForegroundColor White
    Write-Host "  -GPOCheckOnly                         # GPO analysis only" -ForegroundColor White
    Write-Host "  -DebugMode                            # Enable debug output" -ForegroundColor White
    Write-Host "  -Server dc01.contoso.com              # Specific domain controller" -ForegroundColor White
    Write-Host "  -TargetForest target.com              # Cross-forest scanning" -ForegroundColor White
    
    Write-Host ""
    Write-Host ">> EXAMPLE COMBINATIONS:" -ForegroundColor Yellow
    Write-Host "  .\RC4_AD_SCAN.ps1 -GPOScope AllOUs -DebugMode -ExportResults" -ForegroundColor Cyan
    Write-Host "  .\RC4_AD_SCAN.ps1 -ApplyFixes -GPOScope DomainControllers" -ForegroundColor Cyan
    Write-Host "  .\RC4_AD_SCAN.ps1 -TargetForest remote.com -Server dc01.remote.com" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host ">> For detailed help: Get-Help .\RC4_AD_SCAN.ps1 -Detailed" -ForegroundColor Gray
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

# Display help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# Display quick help if requested
if ($QuickHelp) {
    Show-QuickHelp
    exit 0
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Required privileges:" -ForegroundColor Yellow
    Write-Host "- Domain Administrator (for scanning and fixing computers)" -ForegroundColor Yellow
    Write-Host "- Enterprise Administrator (for fixing domain trusts)" -ForegroundColor Yellow
    Write-Host "`nPlease restart PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# Validate GPOScope parameter (only relevant for Standard and GPOOnly parameter sets)
if ($PSCmdlet.ParameterSetName -in @('Standard', 'GPOOnly')) {
    $validScopes = @("Domain", "DomainControllers", "Both", "AllOUs")
    if ($GPOScope -notin $validScopes -and $GPOScope -notmatch "^OU=.*") {
        Write-Host "ERROR: Invalid GPOScope value: '$GPOScope'" -ForegroundColor Red
        Write-Host "Valid options:" -ForegroundColor Yellow
        Write-Host "  Domain - Check domain root only" -ForegroundColor Yellow
        Write-Host "  DomainControllers - Check Domain Controllers OU only" -ForegroundColor Yellow
        Write-Host "  Both - Check both domain root and Domain Controllers OU (default)" -ForegroundColor Yellow
        Write-Host "  AllOUs - Check all OUs in the domain" -ForegroundColor Yellow
        Write-Host "  OU=<Distinguished Name> - Check specific OU (example: OU=IT,DC=contoso,DC=com)" -ForegroundColor Yellow
        exit 1
    }
}

# Validate logical parameter combinations that parameter sets can't handle
if ($GPOCheckOnly -and $ApplyFixes) {
    Write-Host "ERROR: Cannot specify both -GPOCheckOnly and -ApplyFixes parameters!" -ForegroundColor Red
    Write-Host "GPO-only mode is for analysis purposes and does not modify objects." -ForegroundColor Yellow
    exit 1
}

function Write-BoxedMessage {
    param(
        [string[]]$Messages,
        [string]$Color = "White"
    )
    
    # Calculate the maximum width needed
    $maxLength = ($Messages | Measure-Object -Property Length -Maximum).Maximum
    $boxWidth = [Math]::Max($maxLength + 4, 50)  # Minimum width of 50, or content + padding
    
    # Top border
    Write-Host ("+" + ("-" * ($boxWidth - 2)) + "+") -ForegroundColor $Color
    
    # Content lines
    foreach ($message in $Messages) {
        $padding = " " * ($boxWidth - $message.Length - 3)
        Write-Host ("| " + $message + $padding + "|") -ForegroundColor $Color
    }
    
    # Bottom border
    Write-Host ("+" + ("-" * ($boxWidth - 2)) + "+") -ForegroundColor $Color
}

function Write-BoxedMessageWithDivider {
    param(
        [string[]]$HeaderMessages,
        [string[]]$ContentMessages,
        [string]$Color = "White"
    )
    
    # Calculate the maximum width needed from all messages
    $allMessages = $HeaderMessages + $ContentMessages
    $maxLength = ($allMessages | Measure-Object -Property Length -Maximum).Maximum
    $boxWidth = [Math]::Max($maxLength + 4, 50)  # Minimum width of 50, or content + padding
    
    # Top border
    Write-Host ("+" + ("-" * ($boxWidth - 2)) + "+") -ForegroundColor $Color
    
    # Header content
    foreach ($message in $HeaderMessages) {
        $padding = " " * ($boxWidth - $message.Length - 3)
        Write-Host ("| " + $message + $padding + "|") -ForegroundColor $Color
    }
    
    # Divider
    Write-Host ("+" + ("-" * ($boxWidth - 2)) + "+") -ForegroundColor $Color
    
    # Content lines
    foreach ($message in $ContentMessages) {
        $padding = " " * ($boxWidth - $message.Length - 3)
        Write-Host ("| " + $message + $padding + "|") -ForegroundColor $Color
    }
    
    # Bottom border
    Write-Host ("+" + ("-" * ($boxWidth - 2)) + "+") -ForegroundColor $Color
}

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
        [switch]$DebugMode,
        [string]$Server,
        [string]$TargetForest
    )
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
    Write-Host ">> DOMAIN: $($Domain.ToUpper())" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
    Write-Host ">> Checking GPO settings for Kerberos encryption" -ForegroundColor White
    Write-Host ">> Scope: $Scope" -ForegroundColor Gray
    
    # Set up server parameter for AD commands
    $adParams = @{}
    if ($Server) {
        $adParams['Server'] = $Server
        if ($DebugMode) {
            Write-Host "      >> Using server: $Server" -ForegroundColor Gray
        }
    }
    
    # Handle target forest context
    if ($TargetForest -and $DebugMode) {
        Write-Host "      >> Operating in target forest: $TargetForest" -ForegroundColor Gray
    }
    
    try {
        # Get domain information - use appropriate server context
        $domainDN = (Get-ADDomain -Server $Domain @adParams).DistinguishedName
        $domainControllersOU = "OU=Domain Controllers,$domainDN"
        
        if ($DebugMode) {
            Write-Host "      >> Domain DN: $domainDN" -ForegroundColor Gray
            Write-Host "      >> Domain Controllers OU: $domainControllersOU" -ForegroundColor Gray
        }
        
        # Get all GPOs in the domain
        $gpoParams = @{
            All         = $true
            Domain      = $Domain
            ErrorAction = 'Stop'
        }
        if ($Server) {
            # Note: Get-GPO doesn't accept -Server parameter, but uses current session context
            if ($DebugMode) {
                Write-Host "      >>  Note: Get-GPO uses current session context" -ForegroundColor Gray
            }
        }
        
        $gpos = Get-GPO @gpoParams
        $kerberosGPOs = @()
        
        # Check each GPO for Kerberos settings
        foreach ($gpo in $gpos) {
            if ($DebugMode) {
                Write-Host "      >> Checking GPO: $($gpo.DisplayName)" -ForegroundColor Gray
            }
            
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain -ErrorAction SilentlyContinue
                
                if ($DebugMode -and $gpoReport) {
                    Write-Host "      >> GPO report retrieved successfully" -ForegroundColor Gray
                    if ($gpoReport -match "Configure encryption types allowed for Kerberos") {
                        Write-Host "      > Found Kerberos encryption configuration" -ForegroundColor Gray
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
                            if ($DebugMode) {
                                Write-Host "      >> Full GPO report retrieved for link analysis" -ForegroundColor Gray
                            }
                            
                            # Parse XML to find SOM (Scope of Management) links
                            $xmlDoc = [xml]$fullGpoReport
                            $linkNodes = $xmlDoc.SelectNodes("//LinksTo")
                            
                            if ($DebugMode) {
                                Write-Host "      >> Found $($linkNodes.Count) potential link nodes" -ForegroundColor Gray
                            }
                            
                            foreach ($linkNode in $linkNodes) {
                                $somPath = $linkNode.SOMPath
                                $enabled = $linkNode.Enabled -eq "true"
                                $noOverride = $linkNode.NoOverride -eq "true"
                                
                                if ($DebugMode) {
                                    Write-Host "      >> Link found: $somPath (Enabled: $enabled)" -ForegroundColor Gray
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
                            if ($DebugMode) {
                                Write-Host "      >> XML parsing found no links, trying alternative GPO link detection..." -ForegroundColor Gray
                            }
                            
                            # Determine search containers based on scope
                            $searchContainers = @()
                            
                            switch ($Scope) {
                                "Domain" {
                                    $searchContainers = @($domainDN)
                                    if ($DebugMode) {
                                        Write-Host "      >> Scope: Domain - checking domain root only" -ForegroundColor Gray
                                    }
                                }
                                "DomainControllers" {
                                    $searchContainers = @($domainControllersOU)
                                    if ($DebugMode) {
                                        Write-Host "      >> Scope: DomainControllers - checking DC OU only" -ForegroundColor Gray
                                    }
                                }
                                "Both" {
                                    $searchContainers = @($domainDN, $domainControllersOU)
                                    if ($DebugMode) {
                                        Write-Host "      >> Scope: Both - checking domain root and DC OU" -ForegroundColor Gray
                                    }
                                }
                                "AllOUs" {
                                    $searchContainers = @($domainDN, $domainControllersOU)
                                    # Add all OUs in the domain
                                    try {
                                        $allOUs = Get-ADOrganizationalUnit -Filter * -Server $Domain -ErrorAction SilentlyContinue
                                        foreach ($ou in $allOUs) {
                                            $searchContainers += $ou.DistinguishedName
                                        }
                                        if ($DebugMode) {
                                            Write-Host "      >> Scope: AllOUs - checking domain root, DC OU, and $($allOUs.Count) additional OUs" -ForegroundColor Gray
                                        }
                                    }
                                    catch {
                                        if ($DebugMode) {
                                            Write-Host "      >>  Could not enumerate all OUs: $($_.Exception.Message)" -ForegroundColor Gray
                                        }
                                    }
                                }
                                default {
                                    # Custom OU specified
                                    if ($Scope -match "^OU=.*") {
                                        # Validate that the OU exists
                                        try {
                                            $null = Get-ADOrganizationalUnit -Identity $Scope -Server $Domain -ErrorAction Stop
                                            $searchContainers = @($Scope)
                                            if ($DebugMode) {
                                                Write-Host "      >> Scope: Custom OU - checking specified OU: $Scope" -ForegroundColor Gray
                                            }
                                        }
                                        catch {
                                            Write-Host "      > ERROR: Specified OU not found: $Scope" -ForegroundColor Red
                                            Write-Host "      >> Using fallback to domain root and DC OU" -ForegroundColor Yellow
                                            $searchContainers = @($domainDN, $domainControllersOU)
                                        }
                                    }
                                    else {
                                        # Fallback to default behavior
                                        $searchContainers = @($domainDN, $domainControllersOU)
                                        if ($DebugMode) {
                                            Write-Host "      >> Fallback: Using domain root and DC OU" -ForegroundColor Gray
                                        }
                                    }
                                }
                            }
                            
                            if ($DebugMode) {
                                Write-Host "      >> Final search containers ($($searchContainers.Count) total):" -ForegroundColor Gray
                                foreach ($container in $searchContainers) {
                                    Write-Host "         - $container" -ForegroundColor Gray
                                }
                            }
                            
                            foreach ($container in $searchContainers) {
                                try {
                                    if ($DebugMode) {
                                        Write-Host "      >> Checking container: $container" -ForegroundColor Gray
                                    }
                                    
                                    $inheritance = Get-GPInheritance -Target $container -Domain $Domain -ErrorAction SilentlyContinue
                                    if ($inheritance -and $inheritance.GpoLinks) {
                                        if ($DebugMode) {
                                            Write-Host "      >> Found $($inheritance.GpoLinks.Count) GPO links in this container" -ForegroundColor Gray
                                        }
                                        
                                        $linkedGPO = $inheritance.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
                                        if ($linkedGPO) {
                                            if ($DebugMode) {
                                                Write-Host "      > Found matching GPO link! GPO ID: $($gpo.Id)" -ForegroundColor Green
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
                                            if ($DebugMode) {
                                                Write-Host "      > No matching GPO found in this container (checked $($inheritance.GpoLinks.Count) links)" -ForegroundColor Gray
                                            }
                                        }
                                    }
                                    else {
                                        if ($DebugMode) {
                                            Write-Host "      > No GPO inheritance found for this container" -ForegroundColor Gray
                                        }
                                    }
                                }
                                catch {
                                    if ($DebugMode) {
                                        Write-Host "      >>  Error checking container $container : $($_.Exception.Message)" -ForegroundColor Gray
                                    }
                                    continue
                                }
                            }
                        }
                        
                        # Final fallback: Try to get GPO links directly from Active Directory (only if still no links found)
                        if ($allGPOLinks.Count -eq 0) {
                            if ($DebugMode) {
                                Write-Host "      >> Final fallback: Searching AD for GPO links..." -ForegroundColor Gray
                            }
                            
                            try {
                                # Search for objects that have gPLink attribute containing this GPO's GUID
                                $gpoGuid = $gpo.Id.ToString()
                                $filter = "gPLink -like '*$gpoGuid*'"
                                
                                if ($DebugMode) {
                                    Write-Host "      >> Searching for gPLink containing: $gpoGuid" -ForegroundColor Gray
                                }
                                
                                $linkedObjects = Get-ADObject -Filter $filter -Server $Domain -Properties gPLink, Name -ErrorAction SilentlyContinue
                                
                                if ($linkedObjects) {
                                    if ($DebugMode) {
                                        Write-Host "      >> Found $($linkedObjects.Count) objects with gPLink containing this GPO" -ForegroundColor Gray
                                    }
                                    
                                    foreach ($obj in $linkedObjects) {
                                        if ($DebugMode) {
                                            Write-Host "      >> Found link in: $($obj.Name) ($($obj.DistinguishedName))" -ForegroundColor Gray
                                            Write-Host "      >> gPLink value: $($obj.gPLink)" -ForegroundColor Gray
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
                                    if ($DebugMode) {
                                        Write-Host "      > No objects found with gPLink containing this GPO GUID" -ForegroundColor Gray
                                    }
                                }
                            }
                            catch {
                                if ($DebugMode) {
                                    Write-Host "      >>  Error in AD search fallback: $($_.Exception.Message)" -ForegroundColor Gray
                                }
                            }
                        }
                        
                        # Remove any duplicate links (same container) that might have been added by multiple detection methods
                        if ($allGPOLinks.Count -gt 0) {
                            $uniqueLinks = @()
                            $seenContainers = @()
                            
                            foreach ($link in $allGPOLinks) {
                                if ($link.Container -notin $seenContainers) {
                                    $uniqueLinks += $link
                                    $seenContainers += $link.Container
                                }
                                elseif ($DebugMode) {
                                    Write-Host "      >>  Removing duplicate link for container: $($link.Container)" -ForegroundColor Yellow
                                }
                            }
                            
                            $allGPOLinks = $uniqueLinks
                            
                            if ($DebugMode) {
                                Write-Host "      > Final unique links count: $($allGPOLinks.Count)" -ForegroundColor Green
                            }
                        }
                    }
                    catch {
                        Write-Host "      >>  Error detecting GPO links: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    
                    # Analyze settings with more detailed checking
                    Write-Host "      >> Analyzing GPO settings..." -ForegroundColor Gray
                    
                    # Check for different possible setting patterns
                    $hasAES128 = $gpoReport -match "AES128_HMAC_SHA1.*>(>:Enabled|True)" -or $gpoReport -match "AES128.*>1"
                    $hasAES256 = $gpoReport -match "AES256_HMAC_SHA1.*>(>:Enabled|True)" -or $gpoReport -match "AES256.*>1"
                    $hasRC4Disabled = $gpoReport -match "RC4_HMAC_MD5.*>(>:Disabled|False)" -or $gpoReport -notmatch "RC4.*>1"
                    $hasDESDisabled = $gpoReport -match "DES_CBC.*>(>:Disabled|False)" -or $gpoReport -notmatch "DES.*>1"
                    
                    # Also check for numeric values that might indicate the settings
                    $encValue = $null
                    if ($gpoReport -match "SupportedEncryptionTypes.*>(\d+)") {
                        $encValue = [int]$matches[1]
                        if ($DebugMode) {
                            Write-Host "      >> Found numeric encryption value: $encValue" -ForegroundColor Gray
                            Write-Host "      >> Decoding value: $(Get-EncryptionTypes $encValue)" -ForegroundColor Gray
                        }
                        
                        # Decode the value using bitwise operations
                        $hasAES128 = $hasAES128 -or (($encValue -band 0x8) -ne 0)   # Bit 3 = AES128
                        $hasAES256 = $hasAES256 -or (($encValue -band 0x10) -ne 0)  # Bit 4 = AES256
                        $hasRC4Disabled = $hasRC4Disabled -or (($encValue -band 0x4) -eq 0)  # Bit 2 = RC4 (disabled when bit not set)
                        $hasDESDisabled = $hasDESDisabled -or (($encValue -band 0x3) -eq 0)  # Bits 0-1 = DES (disabled when bits not set)
                    }
                    
                    Write-Host "      >> Settings analysis: AES128=$hasAES128, AES256=$hasAES256, RC4Disabled=$hasRC4Disabled, DESDisabled=$hasDESDisabled" -ForegroundColor Gray
                    
                    $isOptimal = $hasAES128 -and $hasAES256 -and $hasRC4Disabled -and $hasDESDisabled
                    $isSecure = $hasAES128 -and $hasAES256 -and $hasRC4Disabled  # Secure even if DES status is unclear
                    
                    $kerberosGPO = [PSCustomObject]@{
                        Name            = $gpo.DisplayName
                        Id              = $gpo.Id
                        LinkedToDomain  = $null -ne ($allGPOLinks | Where-Object { $_.DisplayName -eq "Domain Root" })
                        LinkedToDC      = $null -ne ($allGPOLinks | Where-Object { $_.DisplayName -eq "Domain Controllers OU" })
                        AllLinks        = $allGPOLinks
                        IsOptimal       = $isOptimal
                        IsSecure        = $isSecure
                        HasAES128       = $hasAES128
                        HasAES256       = $hasAES256
                        HasRC4Disabled  = $hasRC4Disabled
                        HasDESDisabled  = $hasDESDisabled
                        EncryptionValue = $encValue
                    }
                    $kerberosGPOs += $kerberosGPO
                }
            }
            catch {
                continue
            }
        }
        
        if ($kerberosGPOs.Count -eq 0) {
            Write-Host "`n> RESULT: No Kerberos encryption GPOs found in domain: $Domain" -ForegroundColor Red
            
            $headerMessages = @(">> RECOMMENDATION: Create and link GPO with Kerberos encryption settings")
            $contentMessages = @(
                "> Setting: 'Network security: Configure encryption types allowed for",
                "          Kerberos'",
                "> For Domain Controllers: Link to 'Domain Controllers' OU",
                "> For All Objects: Link to Domain root",
                "> Best Practice: Use both for comprehensive coverage"
            )
            Write-BoxedMessageWithDivider -HeaderMessages $headerMessages -ContentMessages $contentMessages -Color "Yellow"
        }
        else {
            Write-Host "`n> RESULT: Found $($kerberosGPOs.Count) Kerberos encryption GPO(s) in domain: $Domain" -ForegroundColor Green
            Write-Host (">" * 73) -ForegroundColor Green
            
            # Report findings based on scope
            foreach ($gpo in $kerberosGPOs) {
                Write-Host "`n>> GPO: $($gpo.Name)" -ForegroundColor Cyan
                
                # Show detailed linking information
                if ($gpo.AllLinks -and $gpo.AllLinks.Count -gt 0) {
                    Write-Host "   >> Linked to the following locations:" -ForegroundColor White
                    foreach ($link in $gpo.AllLinks | Sort-Object Order) {
                        $statusIcon = if ($link.Enabled) { ">" } else { ">" }
                        $enforcedText = if ($link.Enforced) { " (Enforced)" } else { "" }
                        Write-Host "     $statusIcon $($link.DisplayName) [Order: $($link.Order)]$enforcedText" -ForegroundColor Gray
                    }
                    
                    # Provide coverage summary
                    $domainLinked = $gpo.LinkedToDomain
                    $dcLinked = $gpo.LinkedToDC
                    $otherOUs = $gpo.AllLinks | Where-Object { $_.DisplayName -notin @("Domain Root", "Domain Controllers OU") }
                    
                    if ($domainLinked -and $dcLinked) {
                        Write-Host "    >> Coverage: Complete (Domain + DCs + $($otherOUs.Count) additional OUs)" -ForegroundColor Green
                    }
                    elseif ($domainLinked) {
                        Write-Host "    > Coverage: Domain-wide (All objects + $($otherOUs.Count) additional OUs)" -ForegroundColor Cyan
                        if ($Scope -in @("DomainControllers", "Both", "AllOUs")) {
                            Write-Host "    >>  Consider linking to Domain Controllers OU for explicit DC coverage" -ForegroundColor Yellow
                        }
                    }
                    elseif ($dcLinked) {
                        Write-Host "    > Coverage: Domain Controllers + $($otherOUs.Count) additional OUs" -ForegroundColor Cyan
                        if ($Scope -in @("Domain", "Both", "AllOUs")) {
                            Write-Host "    >>  Consider linking to Domain level for complete coverage" -ForegroundColor Yellow
                        }
                    }
                    else {
                        Write-Host "    >> Coverage: $($gpo.AllLinks.Count) specific OUs only" -ForegroundColor Yellow
                        if ($Scope -notin @("AllOUs") -and $Scope -notmatch "^OU=.*") {
                            Write-Host "    >> Consider linking to Domain level for broader coverage" -ForegroundColor Yellow
                        }
                    }
                }
                else {
                    Write-Host "    > No active links found for this GPO" -ForegroundColor Red
                    Write-Host "    >> GPO exists but is not linked to any organizational units" -ForegroundColor Yellow
                }
                
                # Report settings compliance
                if ($gpo.IsOptimal) {
                    Write-Host "    > EXCELLENT: Optimal security settings" -ForegroundColor Green
                    Write-Host "      > AES128+256 enabled, RC4+DES explicitly disabled" -ForegroundColor Green
                    if ($gpo.EncryptionValue) {
                        Write-Host "      > Encryption value: $($gpo.EncryptionValue) = $(Get-EncryptionTypes $gpo.EncryptionValue)" -ForegroundColor Green
                    }
                }
                elseif ($gpo.IsSecure) {
                    Write-Host "    > GOOD: Secure settings (weak ciphers disabled)" -ForegroundColor Green
                    Write-Host "      > AES128+256 enabled, RC4 disabled" -ForegroundColor Green
                    if ($gpo.EncryptionValue) {
                        Write-Host "      > Encryption value: $($gpo.EncryptionValue) = $(Get-EncryptionTypes $gpo.EncryptionValue)" -ForegroundColor Green
                    }
                    if (-not $gpo.HasDESDisabled) {
                        Write-Host "      > DES status: Not explicitly configured (DES disabled by omission - GOOD)" -ForegroundColor Green
                        Write-Host "        >> Note: When DES bits (1,2) are not set in the value, DES is effectively disabled" -ForegroundColor Gray
                    }
                }
                else {
                    Write-Host "    >>  NEEDS IMPROVEMENT: Sub-optimal settings detected:" -ForegroundColor Yellow
                    if (-not $gpo.HasAES128) { Write-Host "      > AES128 not enabled" -ForegroundColor Red }
                    if (-not $gpo.HasAES256) { Write-Host "      > AES256 not enabled" -ForegroundColor Red }
                    if (-not $gpo.HasRC4Disabled) { Write-Host "      > RC4 not disabled (SECURITY RISK)" -ForegroundColor Red }
                    if (-not $gpo.HasDESDisabled) { 
                        if ($gpo.EncryptionValue -and ($gpo.EncryptionValue -band 0x3) -eq 0) {
                            Write-Host "      > DES disabled by omission (bits 1,2 not set - GOOD)" -ForegroundColor Green
                        }
                        else {
                            Write-Host "      >>  DES status unclear - verify DES is not enabled" -ForegroundColor Yellow
                        }
                    }
                    if ($gpo.EncryptionValue) {
                        Write-Host "      > Current encryption value: $($gpo.EncryptionValue) = $(Get-EncryptionTypes $gpo.EncryptionValue)" -ForegroundColor Cyan
                    }
                }
            }
            
            # Check GPO application on objects if we have GPOs and scope is appropriate
            if ($kerberosGPOs.Count -gt 0 -and $Scope -in @("Both", "AllOUs", "Domain", "DomainControllers")) {
                Test-GPOApplication -Domain $Domain -KerberosGPOs $kerberosGPOs -Server $Server
            }
        }
        
    }
    catch {
        Write-Host "`n> ERROR: Unable to check GPO settings in domain: $Domain" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
    Write-Host "> COMPLETED GPO CHECK FOR DOMAIN: $($Domain.ToUpper())" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor DarkCyan
}

function Test-GPOApplication {
    param(
        [string]$Domain,
        [array]$KerberosGPOs,
        [string]$Server
    )
    
    Write-Host "`n  " + ("=" * 75) -ForegroundColor Magenta
    Write-Host "  || CHECKING GPO APPLICATION STATUS IN: $($Domain.ToUpper())" -ForegroundColor Magenta
    Write-Host "  " + ("=" * 75) -ForegroundColor Magenta
    
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
        
        # Sample a few computers to check GPO application (users don't use msDS-SupportedEncryptionTypes)
        $sampleComputers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes -ResultSetSize 10 @serverParams
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
        
        # Note: Users don't use msDS-SupportedEncryptionTypes - this is computer-based only
        # User Kerberos encryption is determined by the computer they authenticate from
        
        # Report GPO application status
        Write-Host "    >> GPO Application Status (sample analysis):" -ForegroundColor White
        Write-Host "    >>  Legend:" -ForegroundColor Gray
        Write-Host "      > GPO Applied (AES-only): Objects with msDS-SupportedEncryptionTypes = 24 (AES128+AES256)" -ForegroundColor Gray
        Write-Host "      > Manual Settings (custom): Objects with non-standard encryption values (not 24)" -ForegroundColor Gray
        Write-Host "      > Not Set (RC4 fallback): Objects without msDS-SupportedEncryptionTypes attribute" -ForegroundColor Gray
        Write-Host "      >>  Note: Users don't use msDS-SupportedEncryptionTypes (computer-based setting only)" -ForegroundColor Gray
        Write-Host ""
        
        if ($domainControllers.Count -gt 0) {
            Write-Host "    >>>  Domain Controllers ($($domainControllers.Count) total):" -ForegroundColor Yellow
            Write-Host "      > GPO Applied (AES-only): $dcGpoAppliedCount" -ForegroundColor Green
            Write-Host "      > Manual Settings (custom values): $dcManualSetCount" -ForegroundColor Cyan
            Write-Host "      > Not Set (RC4 fallback): $dcNotSetCount" -ForegroundColor Red
            
            if ($dcGpoAppliedCount -eq $domainControllers.Count) {
                Write-Host "      > All DCs have optimal encryption settings!" -ForegroundColor Green
            }
            elseif ($dcNotSetCount -gt 0) {
                Write-Host "      >>  Some DCs are using RC4 fallback" -ForegroundColor Yellow
            }
        }
        
        if ($sampleComputers.Count -gt 0) {
            Write-Host "    >> Regular Computers (sample of $($sampleComputers.Count)):" -ForegroundColor Yellow
            Write-Host "      > GPO Applied (AES-only): $gpoAppliedCount" -ForegroundColor Green
            Write-Host "      > Manual Settings (custom values): $manualSetCount" -ForegroundColor Cyan
            Write-Host "      > Not Set (RC4 fallback): $notSetCount" -ForegroundColor Red
        }
        
        # Provide recommendations based on findings
        if ($dcNotSetCount -gt 0 -or $notSetCount -gt 0) {
            Write-Host "    >> RECOMMENDATIONS:" -ForegroundColor Yellow
            if ($dcNotSetCount -gt 0) {
                Write-Host "      > Ensure GPO is linked to Domain Controllers OU and refreshed" -ForegroundColor Yellow
            }
            if ($notSetCount -gt 0) {
                Write-Host "      > Ensure GPO is linked to Domain level and refreshed" -ForegroundColor Yellow
                Write-Host "      > Run 'gpupdate /force' on affected systems" -ForegroundColor Yellow
            }
            Write-Host "      > Objects with 'Not Set' status will be flagged in detailed scan below" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Host "    >>  Could not analyze GPO application status: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$results = @()
$secureObjects = @()  # Track objects that already have secure settings

# Set up server parameter for AD commands
$adParams = @{}
if ($Server) {
    $adParams['Server'] = $Server
    Write-Host ">> Connecting to specified server: $Server" -ForegroundColor Cyan
}

# Handle target forest specification
$forestParams = @{}
if ($TargetForest) {
    $forestParams['Identity'] = $TargetForest
    Write-Host ">> Targeting forest: $TargetForest" -ForegroundColor Cyan
    
    # If TargetForest is specified but no specific server, try to find a DC in the target forest
    if (-not $Server) {
        try {
            Write-Host ">> Attempting to discover domain controller in target forest..." -ForegroundColor Gray
            $targetForestInfo = Get-ADForest -Identity $TargetForest
            $rootDomain = $targetForestInfo.RootDomain
            
            # Try to get a DC from the root domain of the target forest
            $targetDC = Get-ADDomainController -DomainName $rootDomain -Discover -ErrorAction SilentlyContinue
            if ($targetDC) {
                $adParams['Server'] = $targetDC.HostName[0]
                Write-Host "> Found target domain controller: $($targetDC.HostName[0])" -ForegroundColor Green
            }
        }
        catch {
            Write-Host ">>  Could not auto-discover DC in target forest. Consider using -Server parameter." -ForegroundColor Yellow
        }
    }
}

try {
    if ($TargetForest) {
        $forest = Get-ADForest @forestParams @adParams
        Write-Host "> Successfully connected to target forest: $($forest.Name)" -ForegroundColor Green
        Write-Host ">> Forest contains domains: $($forest.Domains -join ', ')" -ForegroundColor Cyan
    }
    else {
        $forest = Get-ADForest @adParams
    }
}
catch {
    Write-Host "> ERROR: Could not connect to Active Directory forest" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($TargetForest) {
        Write-Host ">> FOREST TRUST TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "> Verify forest trust exists between your forest and target forest" -ForegroundColor Yellow
        Write-Host "> Ensure your account has permissions in the target forest" -ForegroundColor Yellow
        Write-Host "> Try specifying a domain controller: -Server dc01.targetforest.com" -ForegroundColor Yellow
        Write-Host "> Check network connectivity to target forest domain controllers" -ForegroundColor Yellow
    }
    elseif (-not $Server) {
        Write-Host ">> TIP: Try specifying a domain controller with -Server parameter" -ForegroundColor Yellow
        Write-Host "Example: .\RC4_AD_SCAN.ps1 -Server dc01.contoso.com" -ForegroundColor Yellow
    }
    exit 1
}

# Check GPO settings for each domain
if (-not $SkipGPOCheck) {
    Write-Host ">> Checking Group Policy settings..." -ForegroundColor Magenta
    foreach ($domain in $forest.Domains) {
        Test-KerberosGPOSettings -Domain $domain -Scope $GPOScope -DebugMode:$DebugMode -Server $Server -TargetForest $TargetForest
    }
    
    # Show recommendations once after all domains are checked
    Write-Host ""
    Write-Host (">" * 80) -ForegroundColor Cyan
    Write-Host ">> GPO CONFIGURATION RECOMMENDATIONS" -ForegroundColor Cyan
    Write-Host (">" * 80) -ForegroundColor Cyan
    
    $headerMessages = @(">> GPO ENCRYPTION SETTINGS RECOMMENDATIONS")
    $contentMessages = @(
        "OPTIMAL CONFIGURATION (Recommended):",
        "> AES128-CTS-HMAC-SHA1-96: > Enabled",
        "> AES256-CTS-HMAC-SHA1-96: > Enabled", 
        "> RC4-HMAC: > Disabled (uncheck in GPO)",
        "> DES-CBC-CRC: > Disabled (uncheck in GPO)",
        "> DES-CBC-MD5: > Disabled (uncheck in GPO)",
        "",
        "ENCRYPTION VALUE EXAMPLES:",
        "> Value 24 (0x18): AES128+AES256 only - EXCELLENT",
        "> Value 28 (0x1C): AES+RC4 mixed - NEEDS IMPROVEMENT",
        "> Value 31 (0x1F): All types enabled - SECURITY RISK",
        "",
        "LINKING BEST PRACTICES:",
        "> Domain Level: Organization-wide policy",
        "> Domain Controllers OU: DC-specific requirements",
        "> Both Levels: Comprehensive coverage"
    )
    Write-BoxedMessageWithDivider -HeaderMessages $headerMessages -ContentMessages $contentMessages -Color "Cyan"
    
    Write-Host ""
    $headerMessages = @(">>  CRITICAL: GPO LIMITATIONS FOR TRUST OBJECTS")
    $contentMessages = @(
        "IMPORTANT: GPO settings DO NOT apply to trust objects!",
        "",
        "> What GPO Controls:",
        "> Domain Controllers (computer accounts)",
        "> Member computers and servers", 
        "> What encryption types DCs accept/request",
        "",
        "> What GPO Does NOT Control:",
        "> Trust objects (forest/domain trusts)",
        "> Trust encryption type offerings",
        "> Inter-domain authentication preferences",
        "",
        ">> Trust Remediation Requires:",
        "> Manual attribute modification: msDS-SupportedEncryptionTypes",
        "> Use this script with -ApplyFixes for trust objects",
        "> Or PowerShell: Set-ADObject -Identity '<TrustDN>'",
        "  -Add @{msDS-SupportedEncryptionTypes=24}",
        "",
        ">> Complete Security Strategy:",
        "1. Deploy GPO for computers and DCs",
        "2. Manually fix trust objects (this script helps)",
        "3. Monitor Event IDs 4768/4769 for verification"
    )
    Write-BoxedMessageWithDivider -HeaderMessages $headerMessages -ContentMessages $contentMessages -Color "Red"
}

# Exit early if only GPO check was requested
if ($GPOCheckOnly) {
    Write-Host ""
    Write-Host (">" * 80) -ForegroundColor Magenta
    Write-Host ">> GPO ANALYSIS COMPLETE" -ForegroundColor Magenta
    Write-Host (">" * 80) -ForegroundColor Magenta
    Write-Host ">> GPO-only mode: Object scanning was skipped as requested." -ForegroundColor Cyan
    Write-Host ">> To scan objects as well, run the script without -GPOCheckOnly parameter." -ForegroundColor Gray
    exit 0
}

Write-Host ""
Write-Host ">> SCANNING FOR OBJECTS WITH WEAK ENCRYPTION..." -ForegroundColor Magenta
Write-Host (">" * 80) -ForegroundColor Magenta

$computerTotal = 0
$computerRC4Count = 0
$trustTotal = 0
$trustRC4Count = 0

foreach ($domain in $forest.Domains) {
    Write-Host ""
    Write-Host (">" * 80) -ForegroundColor DarkYellow
    Write-Host ">> SCANNING DOMAIN: $($domain.ToUpper())" -ForegroundColor Yellow
    Write-Host (">" * 80) -ForegroundColor DarkYellow

    # Set up AD command parameters for target forest context
    $domainParams = @{}
    if ($Server) {
        $domainParams['Server'] = $Server
    }
    else {
        # Use the domain itself as server when no specific server is provided
        $domainParams['Server'] = $domain
    }
    
    if ($TargetForest -and $DebugMode) {
        Write-Host "  >> Scanning in target forest context: $TargetForest" -ForegroundColor Gray
    }

    # Note: Users are not scanned as msDS-SupportedEncryptionTypes is a computer-based setting only
    # User Kerberos encryption is controlled by the computer they authenticate from and domain GPO settings

    Write-Host "  >> Scanning Computer Objects..." -ForegroundColor Cyan
    $domainComputerCount = 0
    $domainComputerRC4Count = 0
    
    # Computers
    Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes @domainParams |
    ForEach-Object {
        $domainComputerCount++
        $computerTotal++
        
        $enc = $_."msDS-SupportedEncryptionTypes"
        if (-not $enc -or ($enc -band 0x4)) {
            $domainComputerRC4Count++
            $computerRC4Count++
            
            $obj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "Computer"
                Name       = $_.SamAccountName
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
            }
            $results += $obj

            if ($ApplyFixes) {
                $answer = Read-Host "    >> Remediate Computer $($_.SamAccountName) in $domain> (Y/N)"
                if ($answer -match '^[Yy]') {
                    Set-ADComputer -Identity $_ -Replace @{"msDS-SupportedEncryptionTypes" = 24 }
                    Write-Host "    > Fixed" -ForegroundColor Green
                }
            }
        }
        else {
            # Track computers with secure encryption settings
            $secureObj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "Computer"
                Name       = $_.SamAccountName
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
            }
            $secureObjects += $secureObj
            
            if ($DebugMode) {
                Write-Host "    > Computer '$($_.SamAccountName)' has secure encryption: $(Get-EncryptionTypes $enc)" -ForegroundColor Green
            }
        }
    }
    
    Write-Host "  >> Computer scan complete: $domainComputerCount total, $domainComputerRC4Count with RC4/weak encryption" -ForegroundColor Gray

    Write-Host "  >> Scanning Trust Objects..." -ForegroundColor Cyan
    $domainTrustCount = 0
    $domainTrustRC4Count = 0
    
    # Trusts
    Get-ADTrust -Filter * -Properties msDS-SupportedEncryptionTypes, Direction, TrustType @domainParams |
    ForEach-Object {
        $domainTrustCount++
        $trustTotal++
        
        if ($DebugMode) {
            Write-Host "    >> Found trust: $($_.Name) | Type: $($_.TrustType) | Direction: $($_.Direction) | DN: $($_.DistinguishedName)" -ForegroundColor Gray
        }
        
        $enc = $_."msDS-SupportedEncryptionTypes"
        if (-not $enc -or ($enc -band 0x4)) {
            $domainTrustRC4Count++
            $trustRC4Count++
            
            Write-Host "    >>  Trust '$($_.Name)' has weak encryption: $(Get-EncryptionTypes $enc)" -ForegroundColor Yellow
            Write-Host "       Type: $($_.TrustType) | Direction: $($_.Direction)" -ForegroundColor Gray
            
            $obj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "Trust"
                Name       = $_.Name
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
                TrustType  = $_.TrustType
                Direction  = $_.Direction
            }
            $results += $obj

            if ($ApplyFixes) {
                $answer = Read-Host "    >> Remediate Trust $($_.Name) in $domain> (Y/N)"
                if ($answer -match '^[Yy]') {
                    $trustName = $_.Name
                    $trustType = $_.TrustType
                    $trustDirection = $_.Direction
                    
                    Write-Host "`n    >> TRUST AES ENCRYPTION REMEDIATION" -ForegroundColor Cyan
                    Write-Host "    >> Trust: $trustName (Type: $trustType, Direction: $trustDirection)" -ForegroundColor White
                    Write-Host "    >> Domain: $domain" -ForegroundColor White
                    
                    # Method 1: Use ksetup command (most reliable programmatic method)
                    $remediated = $false
                    try {
                        Write-Host "`n    >> Attempting ksetup method (MICROSOFT METHOD 3 - AES ONLY)..." -ForegroundColor Green
                        
                        # Microsoft Method 3: AES-only configuration (matches GUI checkbox behavior)
                        # This is equivalent to checking "The other domain supports Kerberos AES Encryption"
                        $ksetupCmd = "ksetup /setenctypeattr $trustName AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96"
                        Write-Host "    >> Command: $ksetupCmd" -ForegroundColor Gray
                        Write-Host "    >> Note: AES-only mode (same as GUI checkbox in Domains and Trusts)" -ForegroundColor Gray
                        
                        # Execute ksetup command with AES-only (Microsoft Method 3)
                        $ksetupResult = & ksetup /setenctypeattr $trustName AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "    > SUCCESS: Trust configured with AES-only encryption (Microsoft Method 3)" -ForegroundColor Green
                            Write-Host "    >> $ksetupResult" -ForegroundColor Green
                            Write-Host "    >> This matches the 'AES Encryption' checkbox in AD Domains and Trusts" -ForegroundColor Green
                            $remediated = $true
                            
                            # Verify the setting
                            Write-Host "    >> Verifying setting..." -ForegroundColor Gray
                            $verifyResult = & ksetup /getenctypeattr $trustName 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "    >> Verification result: $verifyResult" -ForegroundColor Green
                            }
                        }
                        else {
                            Write-Host "    > AES-only method failed with exit code: $LASTEXITCODE" -ForegroundColor Red
                            Write-Host "    >> Output: $ksetupResult" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "    > ksetup method failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    
                    # If ksetup failed, provide manual guidance
                    if (-not $remediated) {
                        Write-Host "`n    >>  KSETUP METHOD FAILED - MANUAL REMEDIATION REQUIRED" -ForegroundColor Red
                        Write-Host "    >> Trust: $trustName" -ForegroundColor Yellow
                        
                        Write-Host "`n    >> MICROSOFT OFFICIAL REMEDIATION METHODS:" -ForegroundColor Cyan
                        Write-Host "    >> Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/unsupported-etype-error-accessing-trusted-domain" -ForegroundColor Gray
                        
                        Write-Host "`n    >> Method 1 - GUI (RECOMMENDED - matches checkbox behavior):" -ForegroundColor White
                        Write-Host "       1. Open 'Active Directory Domains and Trusts' (domain.msc)" -ForegroundColor Gray
                        Write-Host "       2. Right-click '$domain' > Properties > Trusts tab" -ForegroundColor Gray
                        Write-Host "       3. Select trust '$trustName' > Properties" -ForegroundColor Gray
                        Write-Host "       4. Check 'The other domain supports Kerberos AES Encryption'" -ForegroundColor Gray
                        Write-Host "       5. Click OK" -ForegroundColor Gray
                        Write-Host "       >> This checkbox sets AES-only mode (same as Method 2 below)" -ForegroundColor Green
                        if ($trustDirection -eq "BiDirectional") {
                            Write-Host "       6. IMPORTANT: Repeat on the OTHER domain ($trustName) for bidirectional trust" -ForegroundColor Yellow
                        }
                        
                        Write-Host "`n    >> Method 2 - ksetup AES-only (equivalent to GUI checkbox):" -ForegroundColor White
                        Write-Host "       From domain controller in '$domain':" -ForegroundColor Gray
                        Write-Host "       ksetup /setenctypeattr $trustName AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96" -ForegroundColor Gray
                        Write-Host "       >> This is exactly what the GUI checkbox does programmatically" -ForegroundColor Green
                        if ($trustDirection -eq "BiDirectional") {
                            Write-Host "       From domain controller in '$trustName':" -ForegroundColor Gray
                            Write-Host "       ksetup /setenctypeattr $domain AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96" -ForegroundColor Gray
                        }
                        
                        Write-Host "`n    >> Method 3 - ksetup with RC4+AES (for compatibility issues only):" -ForegroundColor White
                        Write-Host "       Use only if AES-only mode causes authentication problems:" -ForegroundColor Yellow
                        Write-Host "       ksetup /setenctypeattr $trustName RC4-HMAC-MD5 AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96" -ForegroundColor Gray
                        Write-Host "       >> This maintains RC4 fallback for legacy systems" -ForegroundColor Yellow
                        
                        Write-Host "`n    >> Method 3 - Verification commands:" -ForegroundColor White
                        Write-Host "       ksetup /getenctypeattr $trustName" -ForegroundColor Gray
                        Write-Host "       Get-ADTrust -Filter \"Name -eq '$trustName'\" -Properties msDS-SupportedEncryptionTypes" -ForegroundColor Gray
                        
                        Write-Host "`n    >> IMPORTANT NOTES ABOUT TRUST AES SETTINGS:" -ForegroundColor Yellow
                        Write-Host "       - Trust encryption settings are DIFFERENT from computer/user settings" -ForegroundColor Gray
                        Write-Host "       - Each side of the trust must be configured separately" -ForegroundColor Gray
                        Write-Host "       - ksetup command must be run from the correct domain controller" -ForegroundColor Gray
                        Write-Host "       - GUI method (domain.msc) is often most reliable" -ForegroundColor Gray
                        Write-Host "       - Settings control inter-domain authentication encryption" -ForegroundColor Gray
                        Write-Host "       - GPO settings do NOT apply to trust objects" -ForegroundColor Gray
                        
                        Write-Host "`n    >> COMMON ksetup ERROR CODES:" -ForegroundColor Yellow
                        Write-Host "       - 0xc0000034: Must run from correct domain/context" -ForegroundColor Gray
                        Write-Host "       - Access denied: Need Domain/Enterprise Admin rights" -ForegroundColor Gray
                        Write-Host "       - Target not found: Trust name or direction issue" -ForegroundColor Gray
                        
                        Write-Host "`n    >> REFERENCE:" -ForegroundColor Cyan
                        Write-Host "       https://serverfault.com/questions/1099053/" -ForegroundColor Gray
                        Write-Host "       Microsoft Docs: ksetup /setenctypeattr command" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "`n    >>  SUCCESS: Trust AES encryption configured!" -ForegroundColor Green
                        if ($trustDirection -eq "BiDirectional") {
                            Write-Host "    >> REMINDER: For bidirectional trusts, also configure the other side:" -ForegroundColor Yellow
                            Write-Host "       Run from domain controller in '$trustName':" -ForegroundColor Yellow
                            Write-Host "       ksetup /setenctypeattr $domain AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96" -ForegroundColor Yellow
                        }
                    }
                }
            }
            else {
                Write-Host "    > ERROR: Could not determine trust object identity" -ForegroundColor Red
                Write-Host "    >> Trust name: $($_.Name)" -ForegroundColor Yellow
                Write-Host "    >> DistinguishedName property: '$($_.DistinguishedName)'" -ForegroundColor Yellow
                Write-Host "    >> Manual remediation required:" -ForegroundColor Yellow
                Write-Host "       1. Find trust DN: Get-ADObject -Filter \"ObjectClass -eq 'trustedDomain' -and Name -eq '$($_.Name)'\"" -ForegroundColor Yellow
                Write-Host "       2. Apply fix: Set-ADObject -Identity '<TrustDN>' -Replace @{msDS-SupportedEncryptionTypes=24}" -ForegroundColor Yellow
            }
        }
        else {
            # Track trusts with secure encryption settings
            $secureObj = [PSCustomObject]@{
                Domain     = $domain
                ObjectType = "Trust"
                Name       = $_.Name
                DN         = $_.DistinguishedName
                EncTypes   = Get-EncryptionTypes $enc
                TrustType  = $_.TrustType
                Direction  = $_.Direction
            }
            $secureObjects += $secureObj
            
            if ($DebugMode) {
                Write-Host "    > Trust '$($_.Name)' has secure encryption: $(Get-EncryptionTypes $enc)" -ForegroundColor Green
            }
        }
    }
    
    Write-Host "  >> Trust scan complete: $domainTrustCount total, $domainTrustRC4Count with RC4/weak encryption" -ForegroundColor Gray
    
    Write-Host "`n  > Domain scan completed: $($domain.ToUpper())" -ForegroundColor Green
    Write-Host "  >> Computers: $domainComputerCount scanned ($domainComputerRC4Count flagged)" -ForegroundColor White
    Write-Host "  >> Trusts: $domainTrustCount scanned ($domainTrustRC4Count flagged)" -ForegroundColor White
}

# Output summary
Write-Host ""
Write-Host (">" * 80) -ForegroundColor Magenta
Write-Host ">> FINAL AUDIT SUMMARY" -ForegroundColor Magenta
Write-Host (">" * 80) -ForegroundColor Magenta

Write-Host ">> Forest: $($forest.Name)" -ForegroundColor Cyan
Write-Host ">> Total domains scanned: $($forest.Domains.Count)" -ForegroundColor Cyan
Write-Host ">> Total computers scanned: $computerTotal" -ForegroundColor White
Write-Host ">> Total trusts scanned: $trustTotal" -ForegroundColor White
Write-Host ">>  User objects: Not scanned (msDS-SupportedEncryptionTypes is computer-based only)" -ForegroundColor Gray

if ($results.Count -eq 0) {
    Write-Host "`n> AUDIT RESULT: SUCCESS!" -ForegroundColor Green
    
    $messages = @(
        "No objects with RC4 encryption or weak settings found!",
        "All objects in the forest are using strong AES encryption."
    )
    Write-BoxedMessage -Messages $messages -Color "Green"
}
else {
    Write-Host "`n>>  AUDIT RESULT: ISSUES FOUND!" -ForegroundColor Yellow
    
    $headerMessages = @("Found $($results.Count) object(s) with weak encryption settings:")
    $contentMessages = @(
        "> Computers with RC4: $computerRC4Count out of $computerTotal total",
        "> Trusts with RC4: $trustRC4Count out of $trustTotal total"
    )
    Write-BoxedMessageWithDivider -HeaderMessages $headerMessages -ContentMessages $contentMessages -Color "Yellow"
    
    Write-Host "`nDETAILED RESULTS:" -ForegroundColor White
    $results |
    Sort-Object Domain, ObjectType, Name |
    Format-Table Domain, ObjectType, Name, EncTypes, @{Name = "TrustType"; Expression = { if ($_.TrustType) { $_.TrustType }else { "N/A" } } }, @{Name = "Direction"; Expression = { if ($_.Direction) { $_.Direction }else { "N/A" } } } -AutoSize
    
    # Show trust type breakdown if trusts were found
    $trustObjects = $results | Where-Object { $_.ObjectType -eq "Trust" }
    if ($trustObjects.Count -gt 0) {
        Write-Host "`n>> TRUST TYPE BREAKDOWN:" -ForegroundColor Cyan
        $trustTypes = $trustObjects | Group-Object TrustType | Sort-Object Name
        foreach ($trustType in $trustTypes) {
            Write-Host "  > $($trustType.Name): $($trustType.Count) trust(s)" -ForegroundColor White
            foreach ($trust in $trustType.Group) {
                Write-Host "    - $($trust.Name) (Direction: $($trust.Direction))" -ForegroundColor Gray
            }
        }
        Write-Host ""
        Write-Host ">> TRUST TYPE EXPLANATIONS:" -ForegroundColor Yellow
        Write-Host "  > TreeRoot: Root domain of forest tree" -ForegroundColor Gray
        Write-Host "  > ParentChild: Child domain to parent domain" -ForegroundColor Gray
        Write-Host "  > External: Trust to external domain/forest" -ForegroundColor Gray
        Write-Host "  > Forest: Forest-level trust relationship" -ForegroundColor Gray
        Write-Host "  > Shortcut: Shortcut trust for optimization" -ForegroundColor Gray
        Write-Host "  > Unknown: Unrecognized trust type" -ForegroundColor Gray
    }
    
    # Check for objects with undefined encryption types (fallback scenario)
    $undefinedObjects = $results | Where-Object { $_.EncTypes -eq "Not Set (RC4 fallback)" }
    $trustObjects = $results | Where-Object { $_.ObjectType -eq "Trust" }
    
    if ($undefinedObjects.Count -gt 0) {
        Write-Host "`n>> CRITICAL WARNING - Windows Server 2025 Compatibility:" -ForegroundColor Red
        Write-Host "Found $($undefinedObjects.Count) object(s) with undefined encryption types (msDS-SupportedEncryptionTypes not set)." -ForegroundColor Red
        Write-Host "Windows Server 2025 disables the RC4 fallback mechanism by default." -ForegroundColor Red
        Write-Host "These objects will experience authentication failures on Windows Server 2025 domain controllers!" -ForegroundColor Red
        Write-Host "`nRECOMMENDATION:" -ForegroundColor Yellow
        Write-Host "- Run this script with -ApplyFixes to set AES encryption (value 24)" -ForegroundColor Yellow
        Write-Host "- Or configure via Group Policy: 'Network security: Configure encryption types allowed for Kerberos'" -ForegroundColor Yellow
        Write-Host "- Test thoroughly before deploying to production environments" -ForegroundColor Yellow
    }
    
    if ($trustObjects.Count -gt 0) {
        Write-Host "`n>>  TRUST OBJECT REMEDIATION NOTICE:" -ForegroundColor Red
        Write-Host "Found $($trustObjects.Count) trust object(s) with weak encryption settings." -ForegroundColor Red
        
        $headerMessages = @(">> TRUST OBJECTS REQUIRE MANUAL REMEDIATION")
        $contentMessages = @(
            "> GPO Settings DO NOT Apply to Trust Objects",
            "",
            "Trust objects store their own msDS-SupportedEncryptionTypes",
            "attribute and are not affected by computer GPO policies.",
            "",
            "> Required Actions for Trust Objects:",
            "> GUI Method: AD Domains and Trusts > Trust Properties >",
            "  Check 'The other domain supports Kerberos AES Encryption'",
            "> Script Method: Use this script with -ApplyFixes parameter",
            "> Manual PowerShell:",
            "  Set-ADObject -Identity '<TrustDN>'",
            "    -Add @{msDS-SupportedEncryptionTypes=24}",
            "",
            ">> Verification Commands:",
            "> Get-ADObject -Filter 'ObjectClass -eq `"trustedDomain`"'",
            "    -Properties msDS-SupportedEncryptionTypes",
            "> Monitor Event IDs 4768/4769 for trust authentication",
            "",
            ">>  Without fixing trusts, RC4 will persist in inter-domain",
            "   authentication even with optimal GPO settings!"
        )
        Write-BoxedMessageWithDivider -HeaderMessages $headerMessages -ContentMessages $contentMessages -Color "Red"
    }
}

# Show secure objects summary
if ($secureObjects.Count -gt 0) {
    Write-Host ""
    Write-Host (">" * 80) -ForegroundColor Green
    Write-Host "> OBJECTS WITH SECURE ENCRYPTION SETTINGS" -ForegroundColor Green
    Write-Host (">" * 80) -ForegroundColor Green
    
    $secureComputers = $secureObjects | Where-Object { $_.ObjectType -eq "Computer" }
    $secureTrusts = $secureObjects | Where-Object { $_.ObjectType -eq "Trust" }
    
    Write-Host ">> Summary: Found $($secureObjects.Count) object(s) with secure AES encryption" -ForegroundColor Green
    Write-Host "  > Computers with secure encryption: $($secureComputers.Count)" -ForegroundColor White
    Write-Host "  > Trusts with secure encryption: $($secureTrusts.Count)" -ForegroundColor White
    
    if ($secureObjects.Count -le 50) {
        # Show detailed list if manageable number
        Write-Host "`n>> DETAILED SECURE OBJECTS:" -ForegroundColor White
        $secureObjects |
        Sort-Object Domain, ObjectType, Name |
        Format-Table Domain, ObjectType, Name, EncTypes, @{Name = "TrustType"; Expression = { if ($_.TrustType) { $_.TrustType }else { "N/A" } } }, @{Name = "Direction"; Expression = { if ($_.Direction) { $_.Direction }else { "N/A" } } } -AutoSize
    }
    else {
        # Show summary by domain if too many objects
        Write-Host "`n>> SECURE OBJECTS BY DOMAIN:" -ForegroundColor White
        $secureByDomain = $secureObjects | Group-Object Domain | Sort-Object Name
        foreach ($domainGroup in $secureByDomain) {
            $domainComputers = $domainGroup.Group | Where-Object { $_.ObjectType -eq "Computer" }
            $domainTrusts = $domainGroup.Group | Where-Object { $_.ObjectType -eq "Trust" }
            Write-Host "  >> $($domainGroup.Name): $($domainGroup.Count) total ($($domainComputers.Count) computers, $($domainTrusts.Count) trusts)" -ForegroundColor Cyan
        }
        Write-Host ""
        Write-Host ">> Use -DebugMode parameter to see detailed secure object listings" -ForegroundColor Gray
    }
    
    # Show encryption type breakdown for secure objects
    Write-Host "`n>> SECURE ENCRYPTION TYPES BREAKDOWN:" -ForegroundColor Cyan
    $encryptionBreakdown = $secureObjects | Group-Object EncTypes | Sort-Object Name
    foreach ($encGroup in $encryptionBreakdown) {
        Write-Host "  > $($encGroup.Name): $($encGroup.Count) object(s)" -ForegroundColor White
    }
}

# Export results if requested
if ($ExportResults) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = ".\RC4_Audit_Results_$timestamp.csv"
    $results | Export-Csv $exportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n>> Results exported to: $exportPath" -ForegroundColor Cyan
}

# Optional export
# $results | Export-Csv ".\\RC4_Audit_Results.csv" -NoTypeInformation -Encoding UTF8
