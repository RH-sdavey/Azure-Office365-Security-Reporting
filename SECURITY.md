# Security Policy

## Supported Versions

We actively support the following versions of the Azure & Office 365 Security Report:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 2.0.x   | ✅ | Current stable release |
| 1.1.x   | ✅ | Security fixes only |
| 1.0.x   | ❌ | No longer supported |

## Security Considerations

### Data Handling
- **Read-Only Operations**: This tool performs only read operations and never modifies Azure or Office 365 configurations
- **Local Data Processing**: All data processing occurs locally on the user's machine
- **No Data Transmission**: No sensitive data is transmitted to external services
- **Temporary Files**: CSV exports are created locally with user-specified file paths

### Authentication & Permissions
- **Modern Authentication**: Uses OAuth 2.0 and modern authentication flows
- **Principle of Least Privilege**: Requests only the minimum required permissions
- **Scoped Access**: Microsoft Graph scopes are explicitly defined and limited
- **Session Management**: Provides clear authentication status and logout capabilities

### Logging & Audit Trail
- **Comprehensive Logging**: All operations are logged with timestamps
- **Error Logging**: Security-relevant errors are logged for audit purposes
- **No Sensitive Data**: Logs do not contain passwords, tokens, or sensitive user data
- **Local Storage**: Log files are stored locally and not transmitted

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please follow these steps:

### 🚨 For Critical Security Issues

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. **Email**: Send details to `security@[domain]` (replace with actual contact)
2. **Subject Line**: Use "SECURITY: Azure-Office365-Security-Reporting - [Brief Description]"
3. **Encryption**: Use PGP encryption if possible (public key available on request)

### 📧 What to Include

Please provide as much information as possible:

```
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Affected versions
- Any proof-of-concept code (if applicable)
- Suggested mitigation or fix (if known)
```

### ⏱️ Response Timeline

We are committed to addressing security issues promptly:

| Severity | Initial Response | Status Update | Resolution Target |
|----------|------------------|---------------|-------------------|
| Critical | Within 24 hours | Every 48 hours | 7 days |
| High | Within 48 hours | Weekly | 14 days |
| Medium | Within 1 week | Bi-weekly | 30 days |
| Low | Within 2 weeks | Monthly | 60 days |

### 🔒 Vulnerability Severity Classification

#### Critical
- Remote code execution vulnerabilities
- Authentication bypass
- Privilege escalation
- Data exfiltration possibilities

#### High  
- Local privilege escalation
- Information disclosure of sensitive data
- Denial of service attacks
- Cross-site scripting (if web components added)

#### Medium
- Information disclosure of non-sensitive data
- Minor authentication issues
- Configuration vulnerabilities

#### Low
- Information disclosure with minimal impact
- Minor security improvements
- Best practice recommendations

## Security Best Practices for Users

### Deployment Security
- ✅ **Run from trusted locations** - Deploy scripts in secure, monitored directories
- ✅ **Verify script integrity** - Check file hashes before execution
- ✅ **Use dedicated accounts** - Consider using dedicated service accounts for auditing
- ✅ **Regular updates** - Keep the script and all dependencies updated

### Execution Environment
- ✅ **Secure workstation** - Run from hardened, up-to-date systems
- ✅ **Network security** - Ensure secure network connections (VPN if required)
- ✅ **Antivirus scanning** - Scan scripts with updated antivirus software
- ✅ **PowerShell execution policy** - Use appropriate execution policies

### Data Protection
- ✅ **Secure file storage** - Store CSV exports in secure, encrypted locations
- ✅ **Access controls** - Implement proper file system permissions
- ✅ **Data retention** - Follow organizational data retention policies
- ✅ **Secure disposal** - Securely delete temporary files and logs when no longer needed

### Monitoring & Auditing
- ✅ **Log monitoring** - Monitor script execution logs for anomalies
- ✅ **Access logging** - Log who runs the script and when
- ✅ **Change management** - Track script updates and modifications
- ✅ **Compliance** - Ensure usage aligns with organizational compliance requirements

## Security Features in This Project

### Code Security
- **Static Analysis**: Code is designed to avoid common security pitfalls
- **Input Validation**: All user inputs are validated and sanitized
- **Error Handling**: Comprehensive error handling prevents information leakage
- **No Hardcoded Secrets**: No credentials or sensitive data in source code

### Runtime Security
- **Execution Policy**: Requires appropriate PowerShell execution policies
- **Module Verification**: Validates required modules before execution
- **Permission Checks**: Verifies necessary permissions before proceeding
- **Secure Defaults**: Uses secure default configurations

### Network Security
- **TLS/SSL**: All API communications use encrypted connections
- **Certificate Validation**: Proper certificate validation for all connections
- **No Proxy Bypass**: Respects organizational proxy configurations
- **Timeout Controls**: Implements appropriate timeout controls for network requests

## Compliance Considerations

This tool is designed to support various compliance frameworks:

- **ISO 27001**: Information security management
- **SOC 2**: Service organization controls
- **NIST Cybersecurity Framework**: Security assessment capabilities
- **CIS Controls**: Implementation of security controls assessment
- **GDPR**: Privacy impact assessment support

## Third-Party Dependencies

We regularly monitor our dependencies for security vulnerabilities:

### PowerShell Modules
- `Az.*` modules - Microsoft-maintained Azure modules
- `Microsoft.Graph.*` - Microsoft Graph PowerShell SDK
- `ExchangeOnlineManagement` - Microsoft Exchange Online module
- `MicrosoftTeams` - Microsoft Teams PowerShell module

### Security Update Process
1. **Automated Scanning**: Dependencies are scanned for known vulnerabilities
2. **Update Testing**: Security updates are tested before release
3. **Release Notes**: Security-related updates are documented in release notes
4. **User Notification**: Users are notified of critical security updates

## Contact Information

For security-related questions or concerns:

- **Security Issues**: Use the vulnerability reporting process above
- **General Security Questions**: Create a GitHub Discussion
- **Security Documentation**: Contribute to security documentation via pull requests

---

**Last Updated**: June 26, 2025  
**Version**: 2.0  
**Next Review**: July 26, 2025
