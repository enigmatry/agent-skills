# Package Security Analysis

Scan the codebase for packages with known security vulnerabilities, deprecated packages, and significantly outdated dependencies that pose security, compatibility, or maintenance risks.

## Core Security Principle
**All third-party dependencies must be free of known security vulnerabilities. Vulnerable, deprecated, or significantly outdated packages must be updated or replaced.**

## 1. Package Management Systems Analysis
**Check all package files:**
- **NuGet packages**: `*.csproj`, `packages.config`, `Directory.Packages.props`, `Directory.Build.props`
- **npm packages**: `package.json`, `package-lock.json`, `yarn.lock`
- **Other package managers**: Any additional dependency files (pip, composer, etc.)

**Search for:**
- Package version specifications with explicit versions
- Floating version ranges (e.g., `^`, `~`, `>=`)
- Pre-release or beta package references
- Local or custom package sources

## 2. Vulnerability Assessment
**Critical Security Checks:**
- ✅ Packages with known CVEs (Common Vulnerabilities and Exposures)
- ✅ Packages flagged by security advisories
- ✅ Packages with critical or high severity vulnerabilities
- ✅ Transitive dependencies with security issues
- ❌ Packages from untrusted or unofficial sources

**Priority vulnerability types:**
- Authentication/authorization bypasses
- Remote code execution vulnerabilities
- SQL injection vulnerabilities
- Cross-site scripting (XSS) vulnerabilities
- Denial of service vulnerabilities

## 3. Deprecation and End-of-Life Analysis
**Check for:**
- Packages officially deprecated by maintainers
- Packages with no recent updates (>2 years)
- Packages targeting end-of-life frameworks (.NET Framework versions, Node.js versions)
- Packages with successor/replacement packages available
- Packages with maintenance mode warnings

## 4. Version Currency Assessment
**Analyze version gaps:**
- Current version vs latest stable version
- Major version differences (breaking changes)
- Security patch availability
- LTS (Long Term Support) vs current versions
- Framework compatibility requirements

## 5. Package Analysis Tools
**Recommended scanning methods:**
```bash
# .NET vulnerability scanning
dotnet list package --vulnerable
dotnet list package --deprecated
dotnet list package --outdated

# npm vulnerability scanning  
npm audit
npm audit --audit-level high
npm outdated

# Alternative tools
# - Snyk scan
# - OWASP Dependency Check
# - WhiteSource/Mend
# - GitHub Dependabot alerts
```

## 6. Risk Assessment Criteria
**Categorize findings by risk level:**

**CRITICAL (Immediate action required):**
- Known exploits in the wild
- Critical/High CVSS scores (>7.0)
- Authentication/RCE vulnerabilities
- No available patches/updates

**HIGH (Address soon):**
- Medium CVSS scores (4.0-7.0)
- Deprecated packages with security implications
- Significantly outdated packages (>2 major versions)
- Framework compatibility issues

**MEDIUM (Plan for update):**
- Low CVSS scores (<4.0)
- Minor version updates available
- Non-security deprecation warnings
- Performance/feature improvements available

**LOW (Monitor):**
- Pre-release updates available
- Documentation-only updates
- Non-critical feature additions

## 7. Compatibility and Breaking Changes
**Assess update impact:**
- API breaking changes between versions
- Framework requirement changes
- Dependency conflicts
- Configuration changes required
- Testing requirements for updates

## What to Report
For each package issue found, provide:
- **Package name** and current version
- **Latest available** version
- **Risk level** (Critical/High/Medium/Low)
- **Issue type** (Vulnerable/Deprecated/Outdated)
- **CVE numbers** or security advisory references
- **Impact assessment** (what could be exploited)
- **Update recommendation** (specific version to upgrade to)
- **Breaking changes** or compatibility concerns
- **Priority** for remediation


```
## Package Vulnerability Assessment

### Critical Issues (Immediate Action Required):
1. **PackageName v1.2.3** → Recommended: v2.1.0
   - CVE-2023-XXXX: Remote Code Execution
   - CVSS Score: 9.8 (Critical)
   - Affected: Authentication module
   - Action: Immediate upgrade required

### High Priority Issues:
[Similar format for high priority items]

### Update Recommendations Summary:
- Total packages analyzed: X
- Vulnerable packages: X
- Deprecated packages: X  
- Outdated packages: X
- Immediate action required: X packages
```

## Additional Considerations
1. **Supply chain security**: Check for typosquatting or suspicious packages
2. **License compliance**: Verify license compatibility of updates
3. **Update testing**: Identify packages requiring extensive testing
4. **Rollback planning**: Consider packages with complex rollback requirements
5. **Monitoring setup**: Ongoing vulnerability scanning automation

Focus on providing actionable intelligence with clear prioritization for remediation efforts.

