# RC4 Active Directory Security Audit Tool

**Version**: 2.6  
**Author**: Jan Tiedemann  
**Created**: October 2025  
**Updated**: October 2025

A comprehensive PowerShell script to audit and remediate RC4 encryption usage in Active Directory forests. This tool helps identify security vulnerabilities related to weak RC4 encryption and provides options to upgrade to stronger AES encryption.

## Overview

RC4 is a deprecated encryption algorithm that is considered cryptographically weak. This tool scans your entire Active Directory forest to identify:
- Computers with RC4 encryption enabled
- Domain trusts with RC4 encryption enabled
- Computer objects with no encryption types specified (which fall back to RC4)

**Important Note**: User objects are not scanned because `msDS-SupportedEncryptionTypes` is a computer-based setting only. User Kerberos encryption is controlled by:
- The computer they authenticate from
- Domain-level Group Policy settings
- Domain Controller configuration

## Features

- **Forest-wide scanning**: Automatically discovers and scans all domains in the forest
- **Comprehensive object coverage**: Audits Computers and Domain Trusts (User objects not applicable for msDS-SupportedEncryptionTypes)
- **Advanced GPO verification**: Comprehensive analysis of Group Policy settings with detailed linking information
- **Enhanced GPO security analysis**: Explicit categorization of GPO settings as "Excellent", "Good", or "Needs Improvement"
- **Improved weak cipher detection**: Clear identification when DES is properly disabled by omission
- **Detailed encryption value reporting**: Shows numeric encryption values and their decoded meanings
- **Critical trust object documentation**: Explains why GPO settings don't apply to trust objects and provides remediation guidance
- **Flexible server connectivity**: Support for connecting to specific domain controllers
- **Intelligent GPO link detection**: Multiple detection methods for reliable GPO link discovery
- **Detailed application status**: Analysis of current encryption settings across object types
- **Clear categorization**: Distinguishes between GPO-applied, manual, and unset encryption settings
- **Detailed reporting**: Shows current encryption types for each flagged object
- **Clear success/failure feedback**: Displays appropriate messages when no issues are found vs. when problems are detected
- **Windows Server 2025 compatibility warnings**: Alerts for objects that will fail authentication on Server 2025 DCs
- **Optional remediation**: Interactive mode to fix issues by setting AES-only encryption
- **Export capability**: Results can be exported to CSV for further analysis

## Requirements

- **Administrator privileges**: Must run PowerShell as Administrator
- PowerShell 5.1 or later
- Active Directory PowerShell module
- Group Policy Management Tools (for GPO verification)
- Domain Administrator privileges (for scanning and fixing computers)
- Enterprise Administrator privileges (for remediation of domain trusts)

## Installation

1. Clone or download this repository
2. **Run PowerShell as Administrator**
3. Ensure the Active Directory PowerShell module is installed:
   ```powershell
   Import-Module ActiveDirectory
   ```

## Usage

### Audit Mode (Read-Only)

Run a scan to identify RC4 usage without making any changes:

```powershell
# Run PowerShell as Administrator, then:
.\RC4_AD_SCAN.ps1
```

### Remediation Mode

Run with interactive remediation prompts:

```powershell
.\RC4_AD_SCAN.ps1 -ApplyFixes
```

### Export Results

Export audit results to a timestamped CSV file:

```powershell
.\RC4_AD_SCAN.ps1 -ExportResults
```

### Combined Operations

Run remediation and export results:

```powershell
.\RC4_AD_SCAN.ps1 -ApplyFixes -ExportResults
```

### Skip GPO Checking

Skip Group Policy verification (faster execution):

```powershell
.\RC4_AD_SCAN.ps1 -SkipGPOCheck
```

### GPO Analysis Only

Perform only Group Policy analysis without scanning objects:

```powershell
.\RC4_AD_SCAN.ps1 -GPOCheckOnly
```

### GPO Scope Selection

Check GPO settings at specific organizational levels:

```powershell
# Check only Domain Controllers OU
.\RC4_AD_SCAN.ps1 -GPOScope DomainControllers

# Check only Domain level
.\RC4_AD_SCAN.ps1 -GPOScope Domain

# Check both levels (default)
.\RC4_AD_SCAN.ps1 -GPOScope Both
```

### Cross-Forest Scanning

Scan a different forest via forest trust relationships:

```powershell
# Scan a target forest using forest trust
.\RC4_AD_SCAN.ps1 -TargetForest target.com

# Specify both target forest and domain controller
.\RC4_AD_SCAN.ps1 -TargetForest target.com -Server dc01.target.com

# Debug cross-forest scanning
.\RC4_AD_SCAN.ps1 -TargetForest target.com -Debug -ExportResults
```

### Server Connectivity

Connect to a specific domain controller:

```powershell
# Specify domain controller
.\RC4_AD_SCAN.ps1 -Server dc01.contoso.com

# Combine with other parameters
.\RC4_AD_SCAN.ps1 -Server dc01.contoso.com -Debug -ExportResults
```

When using `-ApplyFixes`, the script will:
- Prompt for each object that needs remediation
- Allow you to choose whether to fix each individual object
- Apply AES-only encryption settings (value 24 = 0x18)

When using `-ExportResults`, the script will:
- Create a timestamped CSV file with all audit results
- Save the file in the current directory with format: `RC4_Audit_Results_YYYYMMDD_HHMMSS.csv`
- Display the export path upon completion

When using `-SkipGPOCheck`, the script will:
- Skip the Group Policy verification phase
- Provide faster execution for object-only auditing
- Still perform comprehensive object scanning

When using `-GPOCheckOnly`, the script will:
- Perform only Group Policy analysis without scanning objects
- Provide detailed GPO configuration analysis and recommendations
- Skip the potentially time-consuming object enumeration phase
- Exit after GPO analysis is complete
- Useful for policy validation and compliance checking

When using `-GPOScope`, you can specify:
- **Domain**: Check GPOs linked to the domain root (affects all objects)
- **DomainControllers**: Check GPOs linked to Domain Controllers OU (affects DCs only)
- **Both**: Check both levels for comprehensive coverage (default)

### Debug Mode

Enable detailed troubleshooting output for GPO detection:

```powershell
# Enable debug output
.\RC4_AD_SCAN.ps1 -Debug

# Combine with other parameters
.\RC4_AD_SCAN.ps1 -Debug -GPOScope DomainControllers -ExportResults
```

When using `-TargetForest`, you can:
- Scan a different forest when your user account is in a different forest
- Leverage existing forest trust relationships for cross-forest auditing
- Combine with `-Server` to target specific domain controllers in the target forest
- Audit multiple forests from a central management forest

When using `-Server`, you can:
- Connect to a specific domain controller when having connectivity issues
- Target testing against particular DCs
- Work around network or authentication issues

When using `-Debug`, the script will:
- Show detailed GPO processing steps
- Display GPO link detection progress with multiple detection methods
- Report encryption setting analysis details with decoded values
- Help troubleshoot GPO detection issues with comprehensive logging

## Critical Security Information: Trust Objects and GPO Limitations

### ⚠️ Why GPO Doesn't Fix Trust Objects

**IMPORTANT**: The Group Policy "Network security: Configure encryption types allowed for Kerberos" **DOES NOT** apply to trust objects. Here's why:

#### What GPO Controls
- ✅ **Domain Controllers** (computer accounts)
- ✅ **Member computers and servers**
- ✅ **What encryption types DCs accept/request**

#### What GPO Does NOT Control  
- ❌ **Trust objects** (forest/domain trusts)
- ❌ **Trust encryption type offerings**
- ❌ **Inter-domain authentication preferences**

### 🔧 Trust Object Remediation Requirements

Trust objects store their own `msDS-SupportedEncryptionTypes` attribute and require explicit modification:

#### Manual Remediation Methods

**Option 1: Use This Script**
```powershell
.\RC4_AD_SCAN.ps1 -ApplyFixes
```
The script will prompt for each trust object and apply the fix automatically.

**Option 2: Manual PowerShell Commands**
```powershell
# Audit current trust encryption settings
Get-ADObject -Filter 'ObjectClass -eq "trustedDomain"' -Properties msDS-SupportedEncryptionTypes | 
    Select Name, msDS-SupportedEncryptionTypes

# Fix trust objects (replace <TrustDN> with actual Distinguished Name)
Set-ADObject -Identity "<TrustDN>" -Add @{msDS-SupportedEncryptionTypes=24}

# Example for a specific trust
Set-ADObject -Identity "CN=subdomain,CN=System,DC=contoso,DC=com" -Add @{msDS-SupportedEncryptionTypes=24}
```

#### Verification Commands
```powershell
# Verify trust settings after modification
Get-ADObject -Filter 'ObjectClass -eq "trustedDomain"' -Properties msDS-SupportedEncryptionTypes | 
    Select Name, msDS-SupportedEncryptionTypes

# Monitor Kerberos authentication events for trusts
# Check Event IDs 4768/4769 in Security log for AES usage confirmation
```

### 💡 Complete Security Strategy

For comprehensive RC4 elimination, you need **both**:

1. **GPO Deployment**
   - Controls what DCs and computers accept/request
   - Applies to computer accounts automatically
   - Configured via Group Policy Management

2. **Trust Object Remediation**  
   - Controls what trust objects offer during inter-domain authentication
   - Requires manual attribute modification
   - Not affected by GPO settings

**Without updating trust objects, RC4 can still appear in inter-domain authentication even with optimal GPO settings!**

### 🚨 Common Misconception

Many administrators assume that applying the Kerberos encryption GPO will fix all RC4 issues. This is **incorrect** for trust objects. The script specifically identifies and helps remediate trust objects separately from computer objects.

### 📊 Trust Object Impact

Trust objects affect:
- **Forest-to-forest authentication**
- **Domain-to-domain authentication within forest**
- **Cross-domain resource access**
- **Distributed application authentication**

Leaving trust objects with RC4 creates security gaps that GPO cannot address.

## Understanding msDS-SupportedEncryptionTypes

### Computer-Based Setting Only

The `msDS-SupportedEncryptionTypes` attribute is a **computer-based setting only** and does not apply to user objects. This is a common misconception in Kerberos security auditing.

**CRITICAL NOTE**: Trust objects are a special case - they DO use `msDS-SupportedEncryptionTypes` but are NOT controlled by computer GPO policies. See the "Trust Objects and GPO Limitations" section above for details.

#### Why Users Are Not Scanned
- **User Kerberos encryption** is determined by the computer they authenticate from, not by a user attribute
- **Domain policy** controls user authentication encryption types through GPO settings
- **Domain Controllers** enforce encryption requirements based on computer and domain settings

- **Setting user attributes** for encryption types has no effect on Kerberos authentication

#### How User Kerberos Encryption Works
1. **Computer-Side Control**: The computer account's `msDS-SupportedEncryptionTypes` determines what encryption types the computer supports
2. **Domain Policy**: GPO settings like "Network security: Configure encryption types allowed for Kerberos" control domain-wide encryption requirements
3. **DC Configuration**: Domain Controllers enforce these policies during authentication

4. **Result**: User Kerberos tickets use encryption types based on computer capabilities and domain policy, not user attributes

#### What This Tool Audits
- ✅ **Computer Objects**: Have `msDS-SupportedEncryptionTypes` attribute that controls their Kerberos encryption capabilities
- ✅ **Domain Trusts**: Have encryption type settings that affect cross-domain authentication (require manual remediation - see Trust Objects section)
- ✅ **Domain Controllers**: Special computer objects that need secure encryption for all authentication

- ❌ **User Objects**: Do not have relevant encryption type attributes (not scanned by this tool)

### Practical Implications
- **User Security**: Controlled by ensuring all computers have strong encryption settings
- **Domain Security**: Managed through Group Policy that applies to computer objects
- **Audit Focus**: Concentrate on computer objects and domain trust relationships
- **Remediation**: Fix computer encryption settings via GPO; fix trust objects manually (see Trust Objects section)

## Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `ApplyFixes` | Switch | Enable interactive remediation mode | False |
| `ExportResults` | Switch | Export results to timestamped CSV file | False |
| `SkipGPOCheck` | Switch | Skip Group Policy settings verification | False |
| `GPOCheckOnly` | Switch | Perform only GPO analysis without object scanning | False |
| `GPOScope` | String | Where to check GPO links: Domain, DomainControllers, Both | Both |
| `Debug` | Switch | Enable detailed troubleshooting output | False |
| `Server` | String | Specify domain controller to connect to | Auto-discover |
| `TargetForest` | String | Target forest to scan via forest trust | Current forest |

### Parameter Combinations

**Valid Combinations:**
- `-ApplyFixes -ExportResults` ✅ Remediate and export results
- `-GPOCheckOnly -Debug` ✅ Detailed GPO analysis only
- `-SkipGPOCheck -ApplyFixes` ✅ Fast object remediation without GPO check
- `-TargetForest domain.com -Server dc01.domain.com` ✅ Cross-forest with specific DC

**Invalid Combinations:**
- `-SkipGPOCheck -GPOCheckOnly` ❌ Conflicting GPO options
- `-GPOCheckOnly -ApplyFixes` ❌ GPO-only mode cannot modify objects

- Test thoroughly before deploying to production environments" -ForegroundColor Yellow

## Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `ApplyFixes` | Switch | Enable interactive remediation mode | False |
| `ExportResults` | Switch | Export results to timestamped CSV file | False |
| `SkipGPOCheck` | Switch | Skip Group Policy settings verification | False |
| `GPOCheckOnly` | Switch | Perform only GPO analysis without object scanning | False |
| `GPOScope` | String | Where to check GPO links: Domain, DomainControllers, Both | Both |
| `Debug` | Switch | Enable detailed troubleshooting output | False |
| `Server` | String | Specify domain controller to connect to | Auto-discover |
| `TargetForest` | String | Target forest to scan via forest trust | Current forest |

### Parameter Combinations

**Valid Combinations:**
- `-ApplyFixes -ExportResults` ✅ Remediate and export results
- `-GPOCheckOnly -Debug` ✅ Detailed GPO analysis only
- `-SkipGPOCheck -ApplyFixes` ✅ Fast object remediation without GPO check
- `-TargetForest domain.com -Server dc01.domain.com` ✅ Cross-forest with specific DC

**Invalid Combinations:**
- `-SkipGPOCheck -GPOCheckOnly` ❌ Conflicting GPO options
- `-GPOCheckOnly -ApplyFixes` ❌ GPO-only mode cannot modify objects

## Understanding the Output

The script displays encryption types for each flagged computer object:
- **Not Set (RC4 fallback)**: No encryption types specified, defaults to RC4
- **AES128-CTS-HMAC-SHA1-96**: Strong AES 128-bit encryption
- **AES256-CTS-HMAC-SHA1-96**: Strong AES 256-bit encryption

### Encryption Type Values

The `msDS-SupportedEncryptionTypes` attribute uses bitwise flags:
- `0x1` - DES-CBC-CRC (deprecated)
- `0x2` - DES-CBC-MD5 (deprecated)
- `0x4` - RC4-HMAC (weak)
- `0x8` - AES128-CTS-HMAC-SHA1-96 (recommended)
- `0x10` - AES256-CTS-HMAC-SHA1-96 (recommended)
- `0x20` - Future use

Recommended setting: `24` (0x18) = AES128 + AES256

## Cross-Forest Trust Requirements

When using `-TargetForest` to scan a different forest, ensure the following requirements are met:

### Forest Trust Configuration
- **Forest Trust Relationship**: A two-way forest trust must exist between your current forest and the target forest
- **Trust Direction**: The trust must allow authentication from your forest to the target forest
- **Trust Authentication**: The forest trust should be configured for both authentication and authorization

### Account Permissions
- **Cross-Forest Permissions**: Your user account must have appropriate permissions in the target forest
- **Delegation Rights**: Consider using account delegation or service accounts with cross-forest permissions
- **Domain Admin/Enterprise Admin**: Required permissions in the target forest for full auditing capabilities

### Network Connectivity
- **DNS Resolution**: Ensure DNS can resolve domain controllers in the target forest
- **Firewall Rules**: Required ports (135, 389, 636, 445, 49152-65535) must be open between forests
- **Domain Controller Discovery**: The script will attempt to auto-discover DCs in the target forest

### Troubleshooting Cross-Forest Issues
If you encounter authentication or connectivity issues:

```powershell
# Test basic forest trust connectivity
nltest /trusted_domains

# Test authentication to target forest
runas /netonly /user:TARGETFOREST\username powershell

# Verify trust relationship status
netdom trust SOURCEFOREST /domain:TARGETFOREST /verify

# Use specific domain controller if auto-discovery fails
.\RC4_AD_SCAN.ps1 -TargetForest target.com -Server dc01.target.com
```

## Windows Server 2025 Compatibility

**Critical Update**: Windows Server 2025 introduces significant changes to Kerberos encryption handling:
- Windows Server 2025 domain controllers **disable RC4 fallback by default**
- Objects with undefined `msDS-SupportedEncryptionTypes` will **fail authentication**
- This affects objects that previously relied on automatic RC4 fallback

### RC4 Fallback Mechanism Disabled
- **Immediate Action Required**: Audit all objects before upgrading to Server 2025
- **Test Environment**: Validate encryption settings in non-production first
- **Production Planning**: Set explicit AES encryption for all objects

### Identifying At-Risk Objects
This script specifically identifies objects showing **"Not Set (RC4 fallback)"** which will be affected by Server 2025 changes. These objects require immediate attention to prevent authentication failures.

## Group Policy Configuration

You can also configure encryption types through Group Policy instead of manually setting the `msDS-SupportedEncryptionTypes` attribute:

### Automatic GPO Verification
The script automatically checks for existing Kerberos encryption Group Policy settings and reports:
- ✅ **Compliant GPOs**: Policies with recommended AES-only settings
- ⚠️ **Non-optimal GPOs**: Policies that may still allow weak encryption
- ❌ **Missing GPOs**: Domains without Kerberos encryption policies
- 🔗 **Detailed Linking Status**: Shows all OUs where GPOs are applied with link order and enforcement status
- 📈 **Coverage Analysis**: Summarizes the scope of GPO application across the domain
- 📊 **Application Status**: Shows which objects already have GPO-applied settings vs manual/unset

### GPO Linking Strategy

**Critical Decision Point**: Where to apply the Kerberos encryption policy:

#### Option 1: Domain Level (Recommended for Most Organizations)
- **Target**: Domain root
- **Scope**: All users and computers in the domain
- **Use Case**: Organization-wide security policy
- **Pros**: Comprehensive coverage, consistent policy
- **Cons**: May affect legacy applications

#### Option 2: Domain Controllers OU Only
- **Target**: Domain Controllers OU
- **Scope**: Domain Controllers only
- **Use Case**: DC-specific hardening while maintaining compatibility
- **Pros**: Secures critical infrastructure, minimal application impact
- **Cons**: Client computers still vulnerable to RC4

#### Option 3: Both Levels (Maximum Security)
- **Target**: Domain root + Domain Controllers OU
- **Scope**: Different policies for DCs vs other objects
- **Use Case**: Graduated security approach
- **Pros**: Flexible, allows different settings per object type
- **Cons**: More complex to manage

#### GPO Application Status Analysis

The script provides detailed categorization of encryption settings for computer objects:

- **GPO Applied (AES-only)**: Computer objects with `msDS-SupportedEncryptionTypes = 24` (AES128+AES256)
- **Manual Settings (custom)**: Computer objects with non-standard encryption values (not 24) 
- **Not Set (RC4 fallback)**: Computer objects without `msDS-SupportedEncryptionTypes` attribute

This analysis helps you understand:
- How effectively your GPO policies are being applied to computer objects
- Which computer objects have been manually configured with custom encryption settings
- Which computer objects are at risk due to undefined encryption types

**Note**: User objects are not included in this analysis as they don't use the `msDS-SupportedEncryptionTypes` attribute.

### Understanding GPO Link Details

When checking GPO settings with `-GPOScope Both`, the script provides detailed information about where Kerberos encryption GPOs are linked:
- **✅ OU Name [Order: X]**: GPO is enabled and linked to this OU
- **❌ OU Name [Order: X]**: GPO is linked but disabled
- **(Enforced)**: GPO link is enforced (cannot be blocked by child containers)

#### Link Status Indicators
- **Complete**: Linked to both Domain and Domain Controllers OU
- **Domain-wide**: Linked to Domain root (affects all objects)  
- **Domain Controllers**: Linked only to DC OU
- **Specific OUs**: Linked to selected organizational units only

#### Coverage Analysis
- **Lower numbers = Higher priority** (Order 1 processes before Order 2)
- **Conflicts resolved by precedence** (last applied wins)
- **Enforced links override** child container settings

#### Link Order Significance
1. **Phase 1**: Apply to Domain Controllers OU first (minimize risk)
2. **Phase 2**: Test with pilot groups using domain-level GPO
3. **Phase 3**: Roll out domain-level GPO organization-wide
4. **Phase 4**: Optionally maintain separate DC-specific settings

### Policy Location
**Path**: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`

**Policy**: `Network security: Configure encryption types allowed for Kerberos`

**Recommended Settings**:
- ✅ **AES128_HMAC_SHA1**
- ✅ **AES256_HMAC_SHA1** 
- ❌ **DES_CBC_CRC** (uncheck - deprecated)
- ❌ **DES_CBC_MD5** (uncheck - deprecated)
- ❌ **RC4_HMAC_MD5** (uncheck - weak)

### User Configuration
**Note**: The same policy also exists under User Configuration, but Computer Configuration takes precedence for computer accounts.

### GPO Application Timeline

**CRITICAL**: Understanding when GPO settings take effect is essential for planning:

#### For Computer Accounts
- **GPO Application**: Next computer startup or `gpupdate /force`
- **Kerberos Ticket Refresh**: New tickets issued use new encryption settings immediately after GPO application
- **Active Tickets**: Existing tickets continue with old encryption until they expire (typically 10 hours)
- **Full Effect**: Complete transition occurs after ticket expiration + GPO refresh

#### For User Accounts  
- **GPO Application**: Next user logon or `gpupdate /force`
- **Kerberos Ticket Refresh**: New tickets issued use new encryption settings immediately after GPO application
- **Active Tickets**: Existing tickets continue with old encryption until they expire (typically 10 hours)
- **Full Effect**: Complete transition occurs after ticket expiration + GPO refresh

#### Timeline Summary
1. **Immediate (0-15 minutes)**: GPO refresh on clients
2. **Short-term (15 minutes - 10 hours)**: Mixed encryption environment (new tickets AES, old tickets may still be RC4)
3. **Complete (10+ hours)**: All tickets using new encryption settings

#### Monitoring GPO Application
Use these commands to verify GPO application:
```cmd
# Check GPO application status
gpresult /h gpresult.html

# Force GPO refresh
gpupdate /force

# Check current Kerberos tickets after GPO refresh
klist
```

**Note**: This GPO setting affects the same underlying `msDS-SupportedEncryptionTypes` attribute that this script audits. Applying the recommended GPO settings will resolve the issues identified by this audit tool.

### GPO vs Direct Attribute Setting

| Method | Scope | Management | Recommendation |
|--------|-------|------------|----------------|
| **GPO** | Organization-wide, inherited | Centralized, version controlled | ✅ **Preferred for production** |
| **Direct Attribute** | Per-object, explicit | Manual, script-based | ⚠️ **Use for exceptions only** |

**Best Practice**: Use GPO for organization-wide policy, use direct attribute setting only for specific exceptions or emergency remediation.

### GPO Deployment Strategy
1. **Test first**: Deploy to a test OU before production
2. **Staged rollout**: Apply to different OUs in phases
3. **Monitor**: Check for authentication issues after deployment
4. **Verify**: Run this audit script after GPO application to confirm remediation

## Manual Monitoring with klist

After implementing RC4 remediation, you can manually monitor Kerberos tickets to verify that weak encryption ciphers are no longer being used. Use the `klist` command to inspect current Kerberos tickets:

### Check Current Tickets
```cmd
klist
```

### Detailed Ticket Information
```cmd
klist -li 0x3e7 tickets
```

### Look for Encryption Types
Pay attention to the **Encryption Type** field in the output:
- **RC4-HMAC (0x17)** - Weak encryption (should be eliminated)
- **AES128-CTS-HMAC-SHA1-96 (0x11)** - Strong encryption ✅
- **AES256-CTS-HMAC-SHA1-96 (0x12)** - Strong encryption ✅

### Example Output After Remediation
```
Current LogonId is 0:0x3e7

Cached Tickets: (2)

#0>	Client: user@CONTOSO.COM
	Server: krbtgt/CONTOSO.COM@CONTOSO.COM
	KerbTicket Encryption Type: AES256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
	Start Time: 10/28/2025 10:00:00 (local)
	End Time:   10/28/2025 20:00:00 (local)
	Renew Time: 11/4/2025 10:00:00 (local)
	Session Key Type: AES256-CTS-HMAC-SHA1-96
```

If you still see RC4-HMAC encryption types after remediation, it indicates that some objects may still need to be addressed.

## Impact on NTLM Authentication

**Important**: The RC4 encryption settings configured by this tool **only affect Kerberos authentication**, not NTLM authentication. Here's what you need to know:

### NTLM vs Kerberos
- **Kerberos**: Uses the `msDS-SupportedEncryptionTypes` attribute that this tool audits and remediates
- **NTLM**: Uses password hashes stored separately and is not affected by these encryption type settings

### NTLM Security Considerations
- NTLM authentication will continue to work normally after RC4 remediation
- NTLM inherently uses weaker security than Kerberos with AES
- Consider implementing NTLM restrictions through Group Policy for enhanced security:
  - `Network Security: Restrict NTLM: NTLM authentication in this domain`
  - `Network Security: Restrict NTLM: Incoming NTLM traffic`
  - `Network Security: Restrict NTLM: Outgoing NTLM traffic to remote servers`

### Recommended Security Strategy
1. **Phase 1**: Implement RC4 remediation for Kerberos (this tool)
2. **Phase 2**: Gradually restrict NTLM usage through Group Policy
3. **Phase 3**: Monitor authentication logs to ensure compatibility
4. **Phase 4**: Consider disabling NTLM entirely in highly secure environments

## Sample Output

### Sample Output with Cross-Forest Scanning

```
🌲 Targeting forest: target.com
🔍 Attempting to discover domain controller in target forest...
✅ Found target domain controller: dc01.target.com
✅ Successfully connected to target forest: target.com
📊 Forest contains domains: target.com, subdomain.target.com

🔍 Checking Group Policy settings...
Checking GPO settings for Kerberos encryption in domain: target.com
      🌲 Operating in target forest: target.com
Scope: Both
      🔍 Checking GPO: Target Forest Kerberos Policy
      ✅ Found Kerberos encryption configuration
    🔗 Linked to the following locations:
      ✅ Domain Root [Order: 1]
    📈 Coverage: Domain-wide (All objects + 0 additional OUs)
    ✅ Optimal settings (AES128+256 enabled, RC4+DES disabled)

🔍 Scanning for objects with weak encryption...
  🌲 Scanning in target forest context: target.com
Scanning domain: target.com

### Sample Output with Enhanced GPO Analysis

```
🔍 Checking Group Policy settings...
Checking GPO settings for Kerberos encryption in domain: contoso.com
Scope: Both
      🔍 Decoding value: DES-CBC-CRC
      📊 Settings analysis: AES128=False, AES256=False, RC4Disabled=True, DESDisabled=False
  📋 Found Kerberos encryption GPO: EncryptionTypes
    🔗 Linked to the following locations:
      ✅ Domain Controllers OU [Order: 1]
    📈 Coverage: Domain Controllers + 0 additional OUs
    ⚠️  Consider linking to Domain level for complete coverage
    ⚠️  Sub-optimal settings detected:
      - AES128 not enabled
      - AES256 not enabled
      - DES not disabled
        💡 Note: If your numeric value doesn't include DES bits (1,2), DES is already disabled
        💡 To explicitly disable DES: Ensure GPO unchecks 'DES-CBC-CRC' and 'DES-CBC-MD5'
  🔍 Checking GPO application status...
    📊 GPO Application Status (sample analysis):
    ℹ️  Legend:
      • GPO Applied (AES-only): Objects with msDS-SupportedEncryptionTypes = 24 (AES128+AES256)
      • Manual Settings (custom): Objects with non-standard encryption values (not 24)
      • Not Set (RC4 fallback): Objects without msDS-SupportedEncryptionTypes attribute

    🖥️  Domain Controllers (3 total):
      • GPO Applied (AES-only): 0
      • Manual Settings (custom values): 3
      • Not Set (RC4 fallback): 0
    💻 Regular Computers (sample of 4):
      • GPO Applied (AES-only): 1
      • Manual Settings (custom values): 3
      • Not Set (RC4 fallback): 0
    👤 Users (sample of 7):
      • GPO Applied (AES-only): 0
      • Manual Settings (custom values): 0
      • Not Set (RC4 fallback): 7
    💡 RECOMMENDATIONS:
      • Ensure GPO is linked to Domain level and refreshed
      • Run 'gpupdate /force' on affected systems
      • Objects with 'Not Set' status will be flagged in detailed scan below
  💡 GPO LINKING BEST PRACTICES:
     • Domain Level: Affects all users and computers (recommended for organization-wide policy)
     • Domain Controllers OU: Affects only DCs (recommended for DC-specific requirements)
     • Both Levels: Provides comprehensive coverage and allows for different settings if needed

🔍 Scanning for objects with weak encryption...
Scanning domain: contoso.com

✅ AUDIT COMPLETE: No objects with RC4 encryption or weak settings found!
All objects in the forest are using strong AES encryption.
```
```
🔍 Checking Group Policy settings...
Checking GPO settings for Kerberos encryption in domain: contoso.com
Scope: Both
  📋 Found Kerberos encryption GPO: Secure Kerberos Settings
    🔗 Linked to the following locations:
      ✅ Domain Root [Order: 1]
      ✅ Domain Controllers OU [Order: 1]
      ✅ IT Department OU [Order: 2]
      ✅ Servers OU [Order: 3] (Enforced)
    📈 Coverage: Complete (Domain + DCs + 2 additional OUs)
    ✅ Optimal settings (AES128+256 enabled, RC4+DES disabled)
  🔍 Checking GPO application status...
    📊 GPO Application Status (sample analysis):
    🖥️  Domain Controllers (3 total):
      • GPO Applied (AES-only): 3
      • Manual Settings: 0
      • Not Set (RC4 fallback): 0
      ✅ All DCs have optimal encryption settings!
    💻 Regular Computers (sample of 10):
      • GPO Applied (AES-only): 9
      • Manual Settings: 1
      • Not Set (RC4 fallback): 0
    👤 Users (sample of 10):
      • GPO Applied (AES-only): 10
      • Manual Settings: 0
      • Not Set (RC4 fallback): 0
  💡 GPO LINKING BEST PRACTICES:
     • Domain Level: Affects all users and computers (recommended for organization-wide policy)
     • Domain Controllers OU: Affects only DCs (recommended for DC-specific requirements)
     • Both Levels: Provides comprehensive coverage and allows for different settings if needed

🔍 Scanning for objects with weak encryption...
Scanning domain: contoso.com

✅ AUDIT COMPLETE: No objects with RC4 encryption or weak settings found!
All objects in the forest are using strong AES encryption.
```
```
🔍 Checking Group Policy settings...
Checking GPO settings for Kerberos encryption in domain: contoso.com
Scope: Both
  📋 Found Kerberos encryption GPO: Secure Kerberos Settings
    🔗 Linked to: Domain + Domain Controllers OU (Complete coverage)
    ✅ Optimal settings (AES128+256 enabled, RC4+DES disabled)
  � Checking GPO application status...
    📊 GPO Application Status (sample analysis):
    🖥️  Domain Controllers (3 total):
      • GPO Applied (AES-only): 3
      • Manual Settings: 0
      • Not Set (RC4 fallback): 0
      ✅ All DCs have optimal encryption settings!
    💻 Regular Computers (sample of 10):
      • GPO Applied (AES-only): 8
      • Manual Settings: 1
      • Not Set (RC4 fallback): 1
    👤 Users (sample of 10):
      • GPO Applied (AES-only): 9
      • Manual Settings: 0
      • Not Set (RC4 fallback): 1
    💡 RECOMMENDATIONS:
      • Ensure GPO is linked to Domain level and refreshed
      • Run 'gpupdate /force' on affected systems
      • Objects with 'Not Set' status will be flagged in detailed scan below
  �💡 GPO LINKING BEST PRACTICES:
     • Domain Level: Affects all users and computers (recommended for organization-wide policy)
     • Domain Controllers OU: Affects only DCs (recommended for DC-specific requirements)
     • Both Levels: Provides comprehensive coverage and allows for different settings if needed

🔍 Scanning for objects with weak encryption...
Scanning domain: contoso.com

✅ AUDIT COMPLETE: No objects with RC4 encryption or weak settings found!
All objects in the forest are using strong AES encryption.
```

### When Issues Are Detected
```
🔍 Checking Group Policy settings...
Checking GPO settings for Kerberos encryption in domain: contoso.com
Scope: Both
  ❌ No Kerberos encryption GPOs found in domain: contoso.com
  💡 RECOMMENDATION: Create and link GPO with 'Network security: Configure encryption types allowed for Kerberos'
     • For Domain Controllers: Link to 'Domain Controllers' OU (affects DC authentication)
     • For All Objects: Link to Domain root (affects all computers and users)
     • Best Practice: Use both for comprehensive coverage

🔍 Scanning for objects with weak encryption...
Scanning domain: contoso.com

⚠️  AUDIT RESULTS: Found 3 object(s) with weak encryption settings:

Domain      ObjectType Name           EncTypes
------      ---------- ----           --------
contoso.com User       john.doe       RC4-HMAC
contoso.com Computer   WORKSTATION1$  Not Set (RC4 fallback)
contoso.com Trust      subdomain      RC4-HMAC

🚨 CRITICAL WARNING - Windows Server 2025 Compatibility:
Found 1 object(s) with undefined encryption types (msDS-SupportedEncryptionTypes not set).
Windows Server 2025 disables the RC4 fallback mechanism by default.
These objects will experience authentication failures on Windows Server 2025 domain controllers!

RECOMMENDATION:
- Run this script with -ApplyFixes to set AES encryption (value 24)
- Or configure via Group Policy: 'Network security: Configure encryption types allowed for Kerberos'
- Test thoroughly before deploying to production environments

📄 Results exported to: .\RC4_Audit_Results_20251028_143025.csv
```

## Exporting Results

### Automatic Export with Switch
Use the `-ExportResults` parameter to automatically export results:

```powershell
.\RC4_AD_SCAN.ps1 -ExportResults
```

This creates a timestamped CSV file: `RC4_Audit_Results_YYYYMMDD_HHMMSS.csv`

### Manual Export (Legacy)
Alternatively, uncomment the last line in the script for manual export:

```powershell
$results | Export-Csv ".\RC4_Audit_Results.csv" -NoTypeInformation -Encoding UTF8
```

### CSV File Contents
The exported CSV includes:
- **Domain**: Domain name where the object is located
- **ObjectType**: Computer or Trust (User objects are not scanned)
- **Name**: Object name (SamAccountName or Trust name)
- **DN**: Distinguished Name of the object
- **EncTypes**: Current encryption types in human-readable format

## Security Considerations

- **Test first**: Run in audit mode before applying fixes
- **Backup**: Ensure you have AD backups before making changes
- **Compatibility**: Verify that all applications support AES encryption
- **Staged rollout**: Consider fixing objects in phases rather than all at once
- **Monitor authentication**: Use `klist` to verify that RC4 tickets are no longer issued
- **NTLM limitation**: Remember that this tool only addresses Kerberos encryption; NTLM authentication is not affected
- **Event monitoring**: Monitor Windows Security logs (Event IDs 4768, 4769) for authentication issues after remediation
- **Legacy applications**: Some older applications may require additional configuration to work with AES-only settings

## Troubleshooting

### Administrator Privileges Required
The script will automatically check for Administrator privileges and exit with an error if not running as Administrator:

```
❌ ERROR: This script must be run as Administrator!
Required privileges:
- Domain Administrator (for scanning and fixing users/computers)
- Enterprise Administrator (for fixing domain trusts)

Please restart PowerShell as Administrator and try again.
```

**Solution**: Right-click on PowerShell and select "Run as Administrator"

### Permission Issues
Ensure you're running as a user with appropriate AD permissions:
- Domain Admin for scanning and fixing users/computers
- Enterprise Admin for fixing domain trusts

### Module Not Found
Install the Active Directory PowerShell module:
```powershell
# On Windows Server
Add-WindowsFeature RSAT-AD-PowerShell

# On Windows 10/11
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools"
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool modifies Active Directory objects. Always test in a non-production environment first and ensure you have proper backups before running in production.