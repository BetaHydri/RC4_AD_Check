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
- **Optional remediation**: Interactive mode to fix issues by setting AES-only encryption
- **Export capability**: Results can be exported to CSV for further analysis

## Requirements

- PowerShell 5.1 or later
- Active Directory PowerShell module
- Domain Administrator privileges (for scanning)
- Enterprise Administrator privileges (for remediation of trusts)

## Installation

1. Clone or download this repository
2. Ensure the Active Directory PowerShell module is installed:
   ```powershell
   Import-Module ActiveDirectory
   ```

## Usage

### Audit Mode (Read-Only)

Run a scan to identify RC4 usage without making any changes:

```powershell
.\RC4_AD_SCAN.ps1
```

### Remediation Mode

Run with interactive remediation prompts:

```powershell
.\RC4_AD_SCAN.ps1 -ApplyFixes
```

When using `-ApplyFixes`, the script will:
- Prompt for each object that needs remediation
- Allow you to choose whether to fix each individual object
- Apply AES-only encryption settings (value 24 = 0x18)

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

## Sample Output

```
Scanning domain: contoso.com
Domain      ObjectType Name           EncTypes
------      ---------- ----           --------
contoso.com User       john.doe       RC4-HMAC
contoso.com Computer   WORKSTATION1$  Not Set (RC4 fallback)
contoso.com Trust      subdomain      RC4-HMAC
```

## Exporting Results

Uncomment the last line in the script to export results to CSV:

```powershell
$results | Export-Csv ".\RC4_Audit_Results.csv" -NoTypeInformation -Encoding UTF8
```

## Security Considerations

- **Test first**: Run in audit mode before applying fixes
- **Backup**: Ensure you have AD backups before making changes
- **Compatibility**: Verify that all applications support AES encryption
- **Staged rollout**: Consider fixing objects in phases rather than all at once

## Troubleshooting

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