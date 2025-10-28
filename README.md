# RC4 Active Directory Security Audit Tool

**Version**: 1.0  
**Author**: Jan Tiedemann  
**Created**: October 2025

A PowerShell script to audit and remediate RC4 encryption usage in Active Directory forests. This tool helps identify security vulnerabilities related to weak RC4 encryption and provides options to upgrade to stronger AES encryption.

## Overview

RC4 is a deprecated encryption algorithm that is considered cryptographically weak. This tool scans your entire Active Directory forest to identify:
- Users with RC4 encryption enabled
- Computers with RC4 encryption enabled  
- Domain trusts with RC4 encryption enabled
- Objects with no encryption types specified (which fall back to RC4)

## Features

- **Forest-wide scanning**: Automatically discovers and scans all domains in the forest
- **Comprehensive object coverage**: Audits Users, Computers, and Domain Trusts
- **Detailed reporting**: Shows current encryption types for each flagged object
- **Clear success/failure feedback**: Displays appropriate messages when no issues are found vs. when problems are detected
- **Windows Server 2025 compatibility warnings**: Alerts for objects that will fail authentication on Server 2025 DCs
- **Optional remediation**: Interactive mode to fix issues by setting AES-only encryption
- **Export capability**: Results can be exported to CSV for further analysis

## Requirements

- **Administrator privileges**: Must run PowerShell as Administrator
- PowerShell 5.1 or later
- Active Directory PowerShell module
- Domain Administrator privileges (for scanning and fixing users/computers)
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

When using `-ApplyFixes`, the script will:
- Prompt for each object that needs remediation
- Allow you to choose whether to fix each individual object
- Apply AES-only encryption settings (value 24 = 0x18)

When using `-ExportResults`, the script will:
- Create a timestamped CSV file with all audit results
- Save the file in the current directory with format: `RC4_Audit_Results_YYYYMMDD_HHMMSS.csv`
- Display the export path upon completion

## Understanding the Output

The script displays encryption types for each flagged object:

- **Not Set (RC4 fallback)**: No encryption types specified, defaults to RC4
- **RC4-HMAC**: RC4 encryption is explicitly enabled
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

## Windows Server 2025 Compatibility

**Critical Update**: Windows Server 2025 introduces significant changes to Kerberos encryption handling:

### RC4 Fallback Mechanism Disabled
- Windows Server 2025 domain controllers **disable RC4 fallback by default**
- Objects with undefined `msDS-SupportedEncryptionTypes` will **fail authentication**
- This affects objects that previously relied on automatic RC4 fallback

### Migration Timeline
- **Immediate Action Required**: Audit all objects before upgrading to Server 2025
- **Test Environment**: Validate encryption settings in non-production first
- **Production Planning**: Set explicit AES encryption for all objects

### Identifying At-Risk Objects
This script specifically identifies objects showing **"Not Set (RC4 fallback)"** which will be affected by Server 2025 changes. These objects require immediate attention to prevent authentication failures.

## Group Policy Configuration

You can also configure encryption types through Group Policy instead of manually setting the `msDS-SupportedEncryptionTypes` attribute:

### Computer Configuration
**Path**: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`

**Policy**: `Network security: Configure encryption types allowed for Kerberos`

**Recommended Settings**:
- ✅ **AES128_HMAC_SHA1**
- ✅ **AES256_HMAC_SHA1** 
- ❌ **DES_CBC_CRC** (uncheck - deprecated)
- ❌ **DES_CBC_MD5** (uncheck - deprecated)
- ❌ **RC4_HMAC_MD5** (uncheck - weak)

### User Configuration
**Path**: `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`

**Policy**: `Network security: Configure encryption types allowed for Kerberos`

**Note**: This GPO setting affects the same underlying `msDS-SupportedEncryptionTypes` attribute that this script audits. Applying the recommended GPO settings will resolve the issues identified by this audit tool.

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

### When No Issues Are Found
```
Scanning domain: contoso.com

✅ AUDIT COMPLETE: No objects with RC4 encryption or weak settings found!
All objects in the forest are using strong AES encryption.
```

### When Issues Are Detected
```
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
- **ObjectType**: User, Computer, or Trust
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