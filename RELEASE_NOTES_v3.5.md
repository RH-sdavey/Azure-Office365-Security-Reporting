# 🚀 Release Notes - Azure & Office 365 Security Report v3.5

## Release Date: June 28, 2025

### 🎉 Major Version Release - v3.5

This is a significant feature release that introduces comprehensive Azure infrastructure security assessment capabilities, advanced configuration management, and SharePoint/OneDrive security analysis.

---

## 🆕 What's New

### ⚙️ **Settings & Configuration Management**
- **New Settings Module** (`AzureSecuritySettings.psm1`)
- **Service Principal Authentication** - Store Azure AD app registration details securely
- **Auto-Connect Functionality** - Automated authentication using saved credentials
- **Certificate-Based Authentication** - Support for unattended operations
- **Configurable Export Paths** - Customize where reports are saved
- **Configuration Backup/Restore** - Save and restore settings

### 🏗️ **Azure Infrastructure Security Suite**
- **New Infrastructure Module** (`AzureSecurityInfrastructure.psm1`)
- **Azure Storage Security Analysis**
  - Public blob container detection
  - Storage account encryption validation
  - HTTPS enforcement checking
  - Network access rule analysis
  - Risk-based scoring (Critical/High/Medium/Low)

- **Azure Key Vault Security Assessment**
  - Certificate expiration monitoring (30-day alerts)
  - Access policy analysis (detect excessive permissions)
  - Network access restriction validation
  - Soft delete and purge protection status
  - Security recommendation engine

- **Network Security Groups (NSG) Analysis**
  - Dangerous firewall rule detection
  - Internet-exposed SSH/RDP detection
  - Database port security validation
  - Wildcard rule identification
  - Critical security risk alerts

### 📁 **SharePoint & OneDrive Security**
- **New SharePoint Module** (`AzureSecuritySharePoint.psm1`)
- **SharePoint Sharing Settings Analysis**
  - External sharing configuration review
  - Site-level security assessment
  - Guest access detection
- **OneDrive Security & Usage Monitoring**
  - Storage usage analysis
  - Inactive OneDrive detection
  - Security posture assessment
- **Data Loss Prevention (DLP) Policy Guidance**
  - DLP policy recommendations
  - Security best practices

### 📊 **Enhanced Reporting & User Experience**
- **5 New CSV Reports** with timestamped exports
- **Updated Main Menu** - Now 7 options (was 4)
- **Risk-Based Scoring** - Critical/High/Medium/Low classifications
- **Security Recommendations** - Actionable advice for each finding
- **Progress Indicators** - Better user feedback during scans
- **Enhanced Error Handling** - More resilient to API failures

---

## 🔧 Technical Improvements

### 🏛️ **Architecture Enhancements**
- **3 New PowerShell Modules** added to the modular architecture
- **Improved Module Loading** - Better dependency management
- **Enhanced Error Handling** - Graceful degradation for missing permissions
- **Configuration System** - JSON-based settings storage

### 🔐 **Authentication Improvements**
- **Service Principal Support** - Automated authentication for CI/CD scenarios
- **Certificate-Based Auth** - More secure than password-based authentication
- **Auto-Connect Feature** - Streamlined user experience
- **Fallback Authentication** - Graceful fallback to interactive auth

### 📈 **Performance Optimizations**
- **Efficient Resource Enumeration** - Better handling of large tenants
- **Progress Tracking** - Real-time feedback during long operations
- **Memory Management** - Improved handling of large datasets
- **API Rate Limiting** - Better handling of Graph API throttling

---

## 📋 New PowerShell Modules Required

The following additional modules are now required:

```powershell
# New Azure modules for v3.5
Az.KeyVault          # Key Vault security analysis
Az.Network           # NSG and network security
Az.Storage           # Storage account security

# New Microsoft Graph module
Microsoft.Graph.Sites # SharePoint and OneDrive analysis
```

---

## 🎯 New Menu Structure

### Updated Main Menu (7 options):
```
1. Identity and Access Management Report (Azure AD)
2. Data Protection Report (Azure)
3. Azure Infrastructure Security Report          # 🆕 NEW
4. Office 365 Security Report
5. SharePoint & OneDrive Security Report         # 🆕 NEW
6. Settings & Configuration                      # 🆕 NEW
7. Exit
```

### New Submenus:
- **Azure Infrastructure Security** (Options 1-4)
- **SharePoint & OneDrive Security** (Options 1-4)
- **Settings & Configuration** (Options 1-6)

---

## 📊 New Reports Generated

| Report | File Format | Content |
|--------|-------------|---------|
| Storage Security | `Storage_Security_Report_YYYYMMDD_HHMMSS.csv` | Storage account security configuration |
| Key Vault Security | `KeyVault_Security_Report_YYYYMMDD_HHMMSS.csv` | Key vault security assessment |
| Network Security | `Network_Security_Report_YYYYMMDD_HHMMSS.csv` | NSG rules and network security |
| SharePoint Sharing | `SharePoint_Sharing_Report_YYYYMMDD_HHMMSS.csv` | SharePoint sharing settings |
| OneDrive Security | `OneDrive_Security_Report_YYYYMMDD_HHMMSS.csv` | OneDrive usage and security |

---

## 🔑 New Permissions Required

### Azure Subscription Permissions:
- **Storage Account Contributor** (read-only) - For storage security analysis
- **Key Vault Reader** - For Key Vault security assessment
- **Network Contributor** (read-only) - For NSG analysis

### Microsoft Graph API Permissions:
- **Sites.Read.All** - For SharePoint and OneDrive analysis

---

## 🚀 Getting Started with v3.5

### For New Users:
1. Clone the repository
2. Run `.\AzureSecurityReport-Modular.ps1`
3. Follow the module installation prompts
4. Configure authentication in Settings (Option 6)

### For Existing Users:
1. Pull the latest changes
2. Install new required modules when prompted
3. Explore the new Settings menu (Option 6)
4. Try the new Azure Infrastructure Security (Option 3)
5. Check out SharePoint & OneDrive Security (Option 5)

### For Automation Scenarios:
1. Set up Azure AD App Registration with certificate
2. Use Settings menu to configure Service Principal
3. Enable Auto-Connect for unattended operation

---

## 🛡️ Security Enhancements

- **Read-Only Operations** - All new features maintain read-only security posture
- **Encrypted Credential Storage** - Secure configuration file for automation
- **Least Privilege** - Only requests minimum required permissions
- **Audit Trail** - Enhanced logging for all operations

---

## 🔄 Upgrade Path

### From v3.0 to v3.5:
- ✅ **Fully Backward Compatible** - All existing functionality preserved
- ✅ **No Breaking Changes** - Existing reports continue to work
- ✅ **Automatic Module Detection** - Script will prompt for new modules
- ✅ **Settings Migration** - New configuration system auto-initializes

---

## 📞 Support & Feedback

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/SteffMet/Azure-Office365-Security-Reporting/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/SteffMet/Azure-Office365-Security-Reporting/discussions)
- 📖 **Documentation**: Updated README with comprehensive examples

---

## 🙏 Acknowledgments

Thank you to the community for feedback and suggestions that helped shape this release. Special thanks to contributors who requested:
- Azure Storage security analysis
- Service Principal authentication
- SharePoint security assessment
- Enhanced configuration management

---

**Happy Security Auditing! 🛡️**

*The Azure & Office 365 Security Report Team*
