# Contributing to Azure & Office 365 Security Report

Thank you for your interest in contributing to this project! We welcome contributions from the community to help improve the security auditing capabilities.

## 🤝 Ways to Contribute

- 🐛 **Report bugs** and issues
- 💡 **Suggest new features** or improvements
- 📖 **Improve documentation**
- 🔧 **Submit code improvements**
- 🧪 **Add test coverage**
- 🌟 **Share feedback** and use cases

## 🚀 Getting Started

### Prerequisites
- PowerShell 7.0 or higher
- Access to Azure/Office 365 tenant for testing
- Git for version control
- VSCode (recommended for development)

### Development Setup
1. **Fork the repository**
   ```bash
   git clone https://github.com/YourUsername/Azure-Office365-Security-Reporting.git
   cd Azure-Office365-Security-Reporting
   ```

2. **Set up your development environment**
   ```powershell
   # Install required modules
   .\AzureSecurityReport-Modular.ps1
   # Follow prompts to install dependencies
   ```

3. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 📝 Development Guidelines

### Code Style
- Use **Pascal Case** for function names: `Get-SecurityReport`
- Use **Camel Case** for variables: `$userCount`
- Include **comprehensive comments** for complex logic
- Follow **PowerShell best practices** and coding standards
- Use **approved PowerShell verbs** where possible

### Module Structure
```powershell
# Each function should include:
function Get-ExampleReport {
    <#
    .SYNOPSIS
        Brief description of the function
    .DESCRIPTION
        Detailed description of what the function does
    .EXAMPLE
        Get-ExampleReport
        Example of how to use the function
    #>
    
    param(
        [Parameter(Mandatory=$false)]
        [string]$ExampleParameter
    )
    
    try {
        Write-ColorOutput "Starting example report..." "Yellow"
        
        # Function logic here
        
        Write-ColorOutput "✓ Example report completed successfully." "Green"
    } catch {
        Write-ColorOutput "Error in example report: $($_.Exception.Message)" "Red"
        Write-Log "Error in example report: $($_.Exception.Message)" "ERROR"
    }
}
```

### Error Handling
- Always use **try-catch blocks** for external API calls
- Log errors using the **Write-Log function**
- Provide **user-friendly error messages**
- Include **actionable recommendations** where possible

### Testing
- Test your changes with **different tenant configurations**
- Verify **read-only operations** - ensure no modifications are made
- Test **error scenarios** and edge cases
- Validate **CSV export functionality**

## 🐛 Reporting Bugs

When reporting bugs, please include:

### Bug Report Template
```markdown
**Bug Description**
A clear and concise description of the bug.

**Steps to Reproduce**
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- PowerShell Version: [e.g. 7.2.5]
- Module Versions: [e.g. Az.Accounts 2.9.1]
- Azure/Office 365 Environment: [e.g. Commercial, GCC, etc.]
- Error Messages: [Include full error messages and stack traces]

**Screenshots/Logs**
If applicable, add screenshots or log files to help explain the problem.
```

## 💡 Feature Requests

### Feature Request Template
```markdown
**Feature Description**
A clear and concise description of the feature you'd like to see.

**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
Describe the solution you'd like to see implemented.

**Alternative Solutions**
Describe any alternative solutions you've considered.

**Additional Context**
Add any other context, screenshots, or examples about the feature request.

**Security Considerations**
How does this feature impact security? Any permissions required?
```

## 🔧 Code Contributions

### Pull Request Process

1. **Update documentation** if your changes affect user-facing functionality
2. **Add or update comments** for any new complex logic
3. **Test thoroughly** in a development environment
4. **Follow the existing code style** and patterns
5. **Update the changelog** if applicable

### Pull Request Template
```markdown
**Description**
Brief description of changes made.

**Type of Change**
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to not work as expected)
- [ ] Documentation update

**Testing**
- [ ] I have tested my changes locally
- [ ] I have tested with different tenant configurations
- [ ] I have verified read-only operations
- [ ] I have tested error scenarios

**Checklist**
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] New and existing unit tests pass locally
```

## 📊 Adding New Security Checks

### Guidelines for New Checks
1. **Research the security requirement** thoroughly
2. **Identify the appropriate PowerShell module** and cmdlets
3. **Determine required permissions** and scopes
4. **Design the check logic** to be read-only
5. **Create meaningful output** with clear recommendations
6. **Add export functionality** for findings
7. **Include comprehensive error handling**

### Example: Adding a New Office 365 Check
```powershell
# Function to check SharePoint external sharing settings
function Get-SharePointExternalSharingReport {
    Write-ColorOutput "Checking SharePoint external sharing settings..." "Yellow"
    
    try {
        # Check if SharePoint module is available
        if (-not (Get-Module -ListAvailable -Name "Microsoft.Online.SharePoint.PowerShell")) {
            Write-ColorOutput "SharePoint Online Management Shell is required. Please install it." "Red"
            return
        }
        
        # Your implementation here
        
        # Display summary with color coding
        if ($hasSecurityIssues) {
            Write-ColorOutput "⚠ External sharing risks detected!" "Red"
        } else {
            Write-ColorOutput "✓ SharePoint external sharing properly configured." "Green"
        }
        
        # Prompt for export
        $Export = Read-Host "Would you like to export SharePoint sharing settings to CSV? (Y/N)"
        if ($Export -eq 'Y' -or $Export -eq 'y') {
            $FilePath = Get-ValidFilePath "SharePoint_External_Sharing_Report"
            $Report | Export-Csv -Path $FilePath -NoTypeInformation -ErrorAction Stop
            Write-ColorOutput "Results exported to: $FilePath" "Green"
        }
        
    } catch {
        Write-ColorOutput "Error checking SharePoint external sharing: $($_.Exception.Message)" "Red"
        Write-Log "Error checking SharePoint external sharing: $($_.Exception.Message)" "ERROR"
    }
}
```

## 📚 Documentation Contributions

### Areas for Documentation Improvement
- **Setup and installation guides**
- **Troubleshooting scenarios**
- **Security best practices**
- **Use case examples**
- **API reference documentation**

### Documentation Style Guide
- Use **clear, concise language**
- Include **practical examples**
- Add **screenshots** where helpful
- Provide **step-by-step instructions**
- Keep content **up to date** with latest features

## 🏆 Recognition

Contributors will be:
- **Listed in the README** acknowledgments section
- **Credited in release notes** for significant contributions
- **Given appropriate GitHub repository permissions** for ongoing contributors

## 📞 Questions?

- **GitHub Discussions**: For general questions and community support
- **GitHub Issues**: For bug reports and feature requests
- **Pull Request Comments**: For code-specific discussions

## 📜 Code of Conduct

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

---

**Thank you for contributing to make Azure and Office 365 environments more secure! 🛡️**
