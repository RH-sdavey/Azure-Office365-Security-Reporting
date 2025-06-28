# 🛡️ Azure & Office 365 Security Report

[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Azure](https://img.shields.io/badge/Azure-AD%20%7C%2```
Azure-Office365-Security-Reporting/
├── 📜 AzureSecurityReport-Modular.ps1      # Main entry point (v3.5)
├── 📁 Modules/
│   ├── AzureSecurityCore.psm1              # Core utilities & authentication
│   ├── AzureSecurityIAM.psm1               # Azure IAM security checks
│   ├── AzureSecurityDataProtection.psm1    # Azure data protection checks
│   ├── AzureSecurityOffice365.psm1         # Office 365 security checks
│   ├── AzureSecuritySettings.psm1          # Configuration & settings management
│   ├── AzureSecurityInfrastructure.psm1    # Azure infrastructure security
│   └── AzureSecuritySharePoint.psm1        # SharePoint & OneDrive security
├── 🚀 Start-AzureSecurityReport.ps1        # Launcher script (recommended)
├── 🔧 Build-SingleFile.ps1                 # Builds single-file deployment
├── 🎬 MenuLayout.gif                        # Visual menu overview
├── 📋 README.md                            # This file
├── 📝 MIGRATION_NOTES.md                   # Migration from v1.1 to v3.0
├── 📊 RELEASE_NOTES_v3.5.md               # Version 3.5 release notes
└── � AzureSecurityReport_*.log            # Generated log files
```ecurityReport-Modular.ps1      # Main entry point (v3.5)s-0078d4.svg)](https://azure.microsoft.com)
[![Office365](https://img.shields.io/badge/Office%20365-Exchange%20%7C%20Teams-orange.svg)](https://www.office.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Version](https://img.shields.io/badge/Version-3.5-brightgreen.svg)](https://github.com/SteffMet/Azure-Office365-Security-Reporting)

> **A comprehensive PowerShell 7 security auditing tool for Azure and Office 365 environments**

This project provides a modular, read-only security assessment script that helps organizations identify security gaps, compliance issues, and cost optimization opportunities across their Azure and Office 365 infrastructure.

![Menu Layout Demo](MenuLayout.gif)

## 🆕 What's New in Version 3.5

### 🎉 **Major New Features**

- **⚙️ Settings & Configuration Management** - Save Azure Service Principal credentials for automated authentication
- **🏗️ Azure Infrastructure Security Suite** - Comprehensive analysis of Azure storage, Key Vault, and network security
- **📁 SharePoint & OneDrive Security Assessment** - Deep dive into sharing settings and data protection
- **🔐 Service Principal Authentication** - Certificate-based auto-authentication for unattended operations
- **📊 Enhanced Security Coverage** - 10+ new security reports covering critical Azure resources

### 🛡️ **New Security Modules**

1. **Azure Storage Security Analysis**
   - Public blob container detection
   - Storage encryption validation
   - HTTPS enforcement checking
   - Network access rule analysis

2. **Azure Key Vault Security Assessment**
   - Certificate expiration monitoring (30-day alerts)
   - Access policy analysis
   - Network restriction validation
   - Soft delete and purge protection status

3. **Network Security Groups (NSG) Analysis**
   - Dangerous firewall rule detection
   - Internet-exposed services identification
   - SSH/RDP exposure alerts
   - Database port security validation

4. **SharePoint & OneDrive Security**
   - External sharing configuration analysis
   - OneDrive usage and security monitoring
   - Data Loss Prevention (DLP) policy guidance
   - Guest access assessment

5. **Advanced Configuration Management**
   - Encrypted credential storage
   - Auto-connect functionality
   - Customizable export paths
   - Configuration backup and restore

### 📈 **Enhanced Reporting**
- **5 new CSV reports** with timestamped exports
- **Risk-based scoring** (Critical/High/Medium/Low)
- **Security recommendations** for each finding
- **Executive summary** dashboards

---

## 🌟 Key Features

### 🔐 Azure Security Auditing
- **Identity & Access Management (IAM)**
  - Multi-Factor Authentication (MFA) status analysis
  - Guest user access review and reporting
  - Password expiry policy assessment
  - Conditional Access policy evaluation

- **🛡️ Data Protection**
  - Azure VM TLS configuration analysis (Azure Resource Graph)
  - Virtual Machine disk encryption status
  - Security compliance reporting

- **🏗️ Infrastructure Security**
  - Azure Storage Account security configuration
  - Public blob container detection
  - Azure Key Vault security assessment
  - Certificate expiration monitoring
  - Network Security Group (NSG) analysis
  - Dangerous firewall rules detection

### ☁️ Office 365 Security Auditing
- **📊 License Management**
  - Comprehensive license usage analysis
  - Cost optimization recommendations
  - Unassigned license detection and reporting

- **👤 User Account Security**
  - Inactive account detection (90+ days)
  - Licensed but inactive account identification
  - Security risk assessment

- **📧 Email Security**
  - Mailbox forwarding rule analysis
  - External email forwarding detection
  - Exchange Online security assessment

- **👥 Microsoft Teams Security**
  - External access configuration review
  - Teams with external users/guests reporting
  - Teams security posture assessment

- **📁 SharePoint & OneDrive Security**
  - SharePoint sharing settings analysis
  - OneDrive usage and security monitoring
  - Data Loss Prevention (DLP) policy guidance
  - External sharing detection

### ⚙️ Configuration Management
- **Settings & Credential Storage**
  - Azure Service Principal configuration
  - Secure credential storage for automation
  - Auto-connect functionality
  - Customizable export paths
  - Configuration management

## 🚀 Quick Start

### Prerequisites

Ensure you have PowerShell 7.0+ installed:
```powershell
# Check PowerShell version
$PSVersionTable.PSVersion
```

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SteffMet/Azure-Office365-Security-Reporting.git
   cd Azure-Office365-Security-Reporting
   ```

2. **Run the launcher script (Recommended):**
   ```powershell
   .\Start-AzureSecurityReport.ps1
   ```
   
   **Or run directly:**
   ```powershell
   # Modular version (recommended)
   .\AzureSecurityReport-Modular.ps1
   ```

3. **Follow the prompts:**
   - The script will automatically check for required modules
   - Install missing modules when prompted
   - Authenticate to Azure and Microsoft Graph
   - Navigate through the security audit menus

## 📋 Required Modules

The script will automatically prompt to install these modules if missing:

```powershell
# Azure modules
Az.Accounts
Az.Compute
Az.Security
Az.ResourceGraph
Az.KeyVault
Az.Network
Az.Storage

# Microsoft Graph modules
Microsoft.Graph.Users
Microsoft.Graph.Identity.SignIns
Microsoft.Graph.Reports
Microsoft.Graph.Sites

# Office 365 modules
ExchangeOnlineManagement
MicrosoftTeams
```

## 🔑 Required Permissions

### Azure AD Roles
- **Recommended**: Global Reader or Security Reader
- **Minimum**: Directory Readers + specific object permissions

### Azure Subscription Permissions
- **Storage Security**: Storage Account Contributor (read-only)
- **Key Vault Security**: Key Vault Reader
- **Network Security**: Network Contributor (read-only)
- **VM Security**: Virtual Machine Contributor (read-only)

### Microsoft Graph API Permissions
```
User.Read.All
Directory.Read.All
Policy.Read.ConditionalAccess
UserAuthenticationMethod.Read.All
Organization.Read.All
Reports.Read.All
AuditLog.Read.All
Sites.Read.All
```

### Office 365 Permissions
- **Exchange Online**: View-Only Organization Management
- **Microsoft Teams**: Teams Administrator (read-only operations)
- **SharePoint Online**: SharePoint Administrator (read-only operations)

## 🗂️ Project Structure

```
Azure-Office365-Security-Reporting/
├── 📜 AzureSecurityReport-Modular.ps1      # Main entry point (v3.0)
├── 📁 Modules/
│   ├── AzureSecurityCore.psm1              # Core utilities & authentication
│   ├── AzureSecurityIAM.psm1               # Azure IAM security checks
│   ├── AzureSecurityDataProtection.psm1    # Azure data protection checks
│   └── AzureSecurityOffice365.psm1         # Office 365 security checks
├── � Start-AzureSecurityReport.ps1        # Launcher script (recommended)
├── �🔧 Build-SingleFile.ps1                 # Builds single-file deployment
├── 🎬 MenuLayout.gif                        # Visual menu overview
├── 📋 README.md                            # This file
├── 📝 MIGRATION_NOTES.md                   # Migration from v1.1 to v3.0
└── � AzureSecurityReport_*.log            # Generated log files
```

## 🎯 Usage Examples

### Main Menu Navigation
```
Read-Only Azure & Office 365 Security Audit Menu
================================================
1. Identity and Access Management Report (Azure AD)
2. Data Protection Report (Azure)
3. Azure Infrastructure Security Report
4. Office 365 Security Report
5. SharePoint & OneDrive Security Report
6. Settings & Configuration
7. Exit
```

#### 1. Identity and Access Management (IAM) Submenu
```
IAM Security Checks
===================
1. Check MFA Status
2. Check Guest User Access
3. Check Password Expiry Settings
4. Check Conditional Access Policies
5. Return to Main Menu
```

#### 2. Data Protection Submenu
```
Data Protection Security Checks
===============================
1. Check TLS Configuration on VMs (Azure Resource Graph)
2. Check Virtual Machine Encryption
3. Return to Main Menu
```

#### 3. Azure Infrastructure Security Submenu
```
Azure Infrastructure Security Checks
====================================
1. Azure Storage Security Report
2. Azure Key Vault Security Report
3. Network Security Groups Report
4. Return to Main Menu
```

#### 4. Office 365 Security Submenu
```
Read-Only Office 365 Audit Menu
===============================
1. License Usage Report
2. Inactive Accounts Report
3. Check Mailbox Forwarding Rules
4. Microsoft Teams
5. Return to Main Menu
```

##### 4.4. Microsoft Teams Submenu
```
Microsoft Teams Security Checks
===============================
1. Check External Access Configuration
2. Report Teams with External Users or Guests
3. Return to Office 365 Menu
```

#### 5. SharePoint & OneDrive Security Submenu
```
SharePoint & OneDrive Security Checks
=====================================
1. SharePoint Sharing Settings Report
2. OneDrive Security & Usage Report
3. Data Loss Prevention (DLP) Policy Report
4. Return to Main Menu
```

#### 6. Settings & Configuration Submenu
```
Settings & Configuration
=======================
1. Configure Azure Service Principal
2. Set Export Path
3. Toggle Auto-Connect
4. View Current Configuration
5. Reset Configuration
6. Return to Main Menu
```

### Sample Output - License Analysis
```powershell
=== LICENSE USAGE SUMMARY ===
Total SKUs: 5
Total unassigned licenses: 25
Estimated monthly savings if optimized: $875

⚠ Microsoft 365 E3: 45 assigned, 15 unassigned (Potential savings: $540/month)
✓ Exchange Online Plan 1: 20 assigned, 0 unassigned

🚨 Critical: 8 inactive accounts have active licenses assigned!
💰 Potential monthly savings: $200 (estimated)
```

### Sample Output - Azure Storage Security
```powershell
=== AZURE STORAGE SECURITY ANALYSIS ===
[Critical] mystorage123 - Issues: Public containers detected: publiccontainer
[High] anotherstorage - Issues: Public blob access allowed, HTTPS not enforced
[Medium] corpstorage - Issues: Network access allows all
[Low] securestorage - No security issues detected

=== STORAGE SECURITY SUMMARY ===
Total Storage Accounts: 4
Critical Risk: 1
High Risk: 1
Medium Risk: 1
Low Risk: 1
```

### Sample Output - Network Security
```powershell
=== AZURE NETWORK SECURITY ANALYSIS ===
[Critical] web-nsg - Issues: SSH/RDP open to Internet, Database ports open to Internet
[Medium] app-nsg - Issues: Dangerous inbound rules detected
[Low] secure-nsg - No security issues detected

=== NETWORK SECURITY SUMMARY ===
Total NSGs: 3
Critical Risk: 1
High Risk: 0
Medium Risk: 1
Low Risk: 1
```

### Sample Output - Settings Configuration
```powershell
Settings & Configuration
=======================
Current Configuration:
  Tenant ID: 12345678-1234-1234-1234-123456789012
  Application ID: 87654321-4321-4321-4321-210987654321
  Service Principal: Enabled
  Auto Connect: Enabled
  Export Path: .\Reports
```

## 📊 Report Exports

All findings can be exported to timestamped CSV files:

| Report Type | Filename Format | Contents |
|-------------|----------------|----------|
| License Usage | `License_Usage_Report_YYYYMMDD_HHMMSS.csv` | SKU details, utilization, cost analysis |
| Inactive Accounts | `Inactive_Accounts_Report_YYYYMMDD_HHMMSS.csv` | User details, last sign-in, license status |
| MFA Status | `MFA_Report_YYYYMMDD_HHMMSS.csv` | User MFA configuration, admin accounts |
| Mailbox Forwarding | `Mailbox_Forwarding_Report_YYYYMMDD_HHMMSS.csv` | Forwarding rules, external destinations |
| Teams External Users | `Teams_External_Users_Report_YYYYMMDD_HHMMSS.csv` | Teams with external access |
| Storage Security | `Storage_Security_Report_YYYYMMDD_HHMMSS.csv` | Storage account security configuration |
| Key Vault Security | `KeyVault_Security_Report_YYYYMMDD_HHMMSS.csv` | Key vault security assessment |
| Network Security | `Network_Security_Report_YYYYMMDD_HHMMSS.csv` | NSG rules and network security |
| SharePoint Sharing | `SharePoint_Sharing_Report_YYYYMMDD_HHMMSS.csv` | SharePoint sharing settings |
| OneDrive Security | `OneDrive_Security_Report_YYYYMMDD_HHMMSS.csv` | OneDrive usage and security |

## 🔧 Advanced Configuration

### Single-File Deployment
Create a standalone script for easy distribution:
```powershell
.\Build-SingleFile.ps1 -OutputPath "AzureSecurityReport-Standalone.ps1"
```

### VSCode Integration
The project includes VSCode configuration for enhanced development:
- PowerShell 7 terminal integration
- Admin script execution tasks
- Debugging configurations

### Custom Module Development
Extend functionality by creating additional modules:
```powershell
# Example: Create a new security module
Import-Module .\Modules\AzureSecurityCore.psm1
# Add your custom security checks here
```

## 🛠️ Troubleshooting

### Microsoft Graph Assembly Conflicts
If you encounter "Assembly with same name is already loaded" errors:

**🔧 Quick Fix Options:**

1. **Use the launcher script (Recommended)**:
   ```powershell
   .\Start-AzureSecurityReport.ps1
   ```

2. **Use the fix script**:
   ```powershell
   .\Fix-GraphModules.ps1
   ```

3. **Manual session restart**:
   ```powershell
   # Exit PowerShell completely
   exit
   
   # Start fresh PowerShell 7 session
   pwsh
   cd "path\to\Azure-Office365-Security-Reporting"
   .\AzureSecurityReport-Modular.ps1
   ```

4. **Automatic restart helper**:
   ```powershell
   .\Restart-PowerShellSession.ps1
   ```

**🔍 Why This Happens:**
Microsoft Graph PowerShell modules use .NET assemblies that can conflict when loaded multiple times in the same session. This is a known limitation of the Microsoft Graph SDK.

### Common Issues

| Issue | Solution |
|-------|----------|
| Module import errors | Run `Install-Module` as Administrator |
| Authentication failures | Verify account permissions and retry |
| CSV export errors | Check file path permissions |
| Graph API rate limits | Wait and retry after a few minutes |

### Performance Optimization

For large tenants (1000+ users):
- Use `-PageSize` parameter where supported
- Run during off-peak hours
- Consider filtering results to reduce data volume

## 🛡️ Security & Compliance

### Read-Only Operations
- ✅ **No modifications** to any Azure or Office 365 configurations
- ✅ **Audit trail** - All actions logged with timestamps
- ✅ **Secure authentication** using modern authentication flows
- ✅ **Least privilege** - Only requires read permissions

### Data Privacy
- 🔒 No sensitive data stored or transmitted
- 🔒 Local CSV exports with configurable file paths
- 🔒 Comprehensive logging for compliance auditing

### Reporting Issues
- 🐛 [Report bugs](https://github.com/SteffMet/Azure-Office365-Security-Reporting/issues/new?template=bug_report.md)
- 💡 [Request features](https://github.com/SteffMet/Azure-Office365-Security-Reporting/issues/new?template=feature_request.md)
- 📖 [Improve documentation](https://github.com/SteffMet/Azure-Office365-Security-Reporting/issues/new?template=documentation.md)

## 📈 Roadmap

- [ ] **Azure Defender for Cloud** integration
- [ ] **Compliance framework** mapping (ISO 27001, SOC 2, etc.)
- [ ] **PowerBI dashboard** templates
- [ ] **Scheduled execution** with automated reporting
- [ ] **Multi-tenant** support
- [ ] **REST API** integration for third-party tools

## ⚠️ Known Limitations

| Component | Limitation | Workaround |
|-----------|------------|------------|
| VM TLS Checking | Uses Azure Resource Graph metadata analysis, not direct VM inspection | Azure Resource Graph provides VM metadata for intelligent TLS assessment |
| Large Teams Environments | May take time to scan all teams | Progress indicators implemented |
| Audit Log Retention | Limited by tenant audit log settings | Documented in prerequisites |
| Exchange Connection | Requires separate authentication | Automatic connection handling |

## 📞 Support

- 📧 **Issues**: [GitHub Issues](https://github.com/SteffMet/Azure-Office365-Security-Reporting/issues)
- 📖 **Documentation**: [Wiki](https://github.com/SteffMet/Azure-Office365-Security-Reporting/wiki)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/SteffMet/Azure-Office365-Security-Reporting/discussions)

---

<div align="center">

**⭐ If this project helps you, please consider giving it a star! ⭐**

Made with ❤️ by [SteffMet](https://github.com/SteffMet)

*Last Updated: June 28, 2025*

</div>
