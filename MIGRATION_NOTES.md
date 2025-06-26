# Migration Notes

## AzureSecurityReport.ps1 Deprecation

### Status: ⚠️ Deprecated (Version 1.1)

The single-file `AzureSecurityReport.ps1` has been superseded by the modular approach in `AzureSecurityReport-Modular.ps1` (Version 3.0).

### Why the change?

1. **Better Organization**: Modular architecture makes code more maintainable
2. **Enhanced Features**: Office 365 security checks added in modular version
3. **Improved Error Handling**: Better module conflict resolution
4. **Future-Proof**: Easier to add new security checks as separate modules

### Migration Path

**If you're currently using `AzureSecurityReport.ps1`:**
1. Switch to `AzureSecurityReport-Modular.ps1`
2. Use the launcher: `.\Start-AzureSecurityReport.ps1`
3. All functionality from the old script is available in the new modular version

### Can I delete AzureSecurityReport.ps1?

**Yes**, you can safely delete `AzureSecurityReport.ps1` if:
- ✅ You've tested the modular version works in your environment
- ✅ You don't have any custom modifications to the old script
- ✅ Your automation/scripts reference the modular version

### Key Improvements in Modular Version

| Feature | Old Version | New Version |
|---------|-------------|-------------|
| Office 365 Support | ❌ | ✅ |
| Teams Security Checks | ❌ | ✅ |
| License Management | ❌ | ✅ |
| TLS Configuration | Simulated | Azure Resource Graph |
| Code Organization | Single file | Modular |
| Maintainability | Difficult | Easy |
| Visual Documentation | ❌ | ✅ (MenuLayout.gif) |
| Version | 1.1 | 3.0 |

### Breaking Changes

- Menu structure has been updated (see README.md)
- Some function names have changed (prefixed with `Test-` in modules)
- Office 365 functionality requires additional modules

---

*Last Updated: June 26, 2025*
