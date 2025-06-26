# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Azure Defender for Cloud integration
- Compliance framework mapping (ISO 27001, SOC 2)
- PowerBI dashboard templates
- Multi-tenant support
- REST API integration

## [2.0.0] - 2025-06-26

### Added
- **Office 365 Security Module** - Comprehensive Office 365 security auditing
- **License Usage Report** - Analyze Office 365 license utilization and cost optimization
- **Inactive Accounts Detection** - Identify users inactive for 90+ days with license impact
- **Mailbox Forwarding Analysis** - Detect potentially risky email forwarding rules
- **Microsoft Teams Security** - External access and guest user reporting
- **Modular Architecture** - Separated functionality into reusable PowerShell modules
- **Enhanced Authentication** - Extended Microsoft Graph scopes for Office 365 data
- **Cost Optimization** - License cost analysis and savings recommendations
- **Security Scoring** - Basic security posture scoring for Teams configuration
- **Comprehensive Logging** - Enhanced logging with error categorization
- **CSV Export Enhancement** - Timestamped exports with validation
- **GitHub Repository Setup** - Complete project structure for open source collaboration

### Changed
- **Menu Structure** - Updated to include Office 365 options in main menu
- **Error Handling** - Improved error messages and recovery procedures
- **Output Formatting** - Enhanced color coding and progress indicators
- **Module Dependencies** - Added Office 365 PowerShell modules to requirements
- **Authentication Flow** - Streamlined connection process for multiple services

### Technical Improvements
- PowerShell 7.0+ requirement for modern features
- Modular design for better maintainability
- Comprehensive error handling and logging
- Progress indicators for long-running operations
- Input validation and sanitization

## [1.1.0] - 2025-06-25

### Added
- **Enhanced Error Handling** - Comprehensive try-catch blocks throughout
- **Detailed Logging** - Timestamped log files for audit trails
- **Progress Indicators** - Real-time feedback during security scans
- **Input Validation** - Robust file path and user input validation
- **Color-Coded Output** - Visual indicators for security status
- **PowerShell 7 Support** - Updated for modern PowerShell features

### Changed
- **Module Requirements** - More specific module dependencies
- **Authentication Scopes** - Enhanced Microsoft Graph permissions
- **CSV Export Logic** - Improved file handling and error recovery
- **Menu Navigation** - Better user experience with clear options

### Fixed
- **Module Installation** - Automatic handling of missing dependencies
- **File Path Validation** - Robust directory creation and permission checking
- **Authentication Errors** - Better error messages and recovery options

## [1.0.0] - 2025-06-20

### Added
- **Initial Release** - Core Azure security auditing functionality
- **Azure IAM Checks** - MFA status, guest users, password policies
- **Conditional Access Analysis** - Policy review and recommendations  
- **Data Protection** - VM encryption and TLS configuration checks
- **Interactive Menus** - User-friendly navigation system
- **CSV Export** - Report generation with customizable file paths
- **Authentication Integration** - Azure and Microsoft Graph connectivity

### Security Features
- Read-only operations ensuring no configuration changes
- Secure authentication with modern auth flows
- Comprehensive audit logging for compliance
- Error handling to prevent information disclosure

### Core Modules
- `AzureSecurityCore.psm1` - Shared utilities and authentication
- `AzureSecurityIAM.psm1` - Identity and access management checks
- `AzureSecurityDataProtection.psm1` - Data protection auditing

---

## Version History Summary

| Version | Release Date | Major Features |
|---------|--------------|----------------|
| 2.0.0 | 2025-06-26 | Office 365 integration, modular architecture |
| 1.1.0 | 2025-06-25 | Enhanced error handling, PowerShell 7 support |
| 1.0.0 | 2025-06-25 | Initial Azure security auditing release |

---

### Legend
- **Added** - New features
- **Changed** - Changes in existing functionality  
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security-related changes
