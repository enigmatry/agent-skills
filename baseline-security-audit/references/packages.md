# Package Security Analysis

Scan the codebase for packages with known security vulnerabilities, deprecated packages, and significantly outdated dependencies that pose security, compatibility, or maintenance risks.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A03 Software Supply Chain Failures · **ASVS 5.0:** V15 Secure Coding and Architecture

## Core Security Principle
**All third-party dependencies must be free of known security vulnerabilities. Vulnerable, deprecated, or significantly outdated packages must be updated or replaced.**

## 1. Package Management Systems Analysis
**Check all package files:**
- **NuGet packages**: `*.csproj`, `Directory.Packages.props`, `Directory.Build.props`, `nuget.config` (package sources); `packages.config` is legacy (.NET Framework), not expected on this stack
- **npm packages**: `package.json`, `package-lock.json`, `yarn.lock`, `.npmrc` (registry)

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

**Runtime end-of-life (verify against endoflife.date at audit time; status as of October 2026):**

| Runtime | Status | Where to check |
|---------|--------|----------------|
| .NET 6, .NET 7 | End of life | `<TargetFramework>` in `*.csproj`, `global.json`, `UseDotNet@2` in pipelines |
| .NET 8 (LTS) and .NET 9 (STS) | Both end support on **10 November 2026** — flag as High if no migration to .NET 10 is planned | same |
| .NET 10 (LTS) | Supported until November 2028 — target version | same |
| Node.js 18, 20 | End of life (Node 20 ended 30 April 2026) | `engines.node` in `package.json`, `.nvmrc`, `NodeTool@0` / `UseNode@1` in pipelines |
| Node.js 22 | Maintenance until April 2027 | same |
| Node.js 24 | Active LTS — target version | same |
| Angular ≤ 19 | End of life (Angular 19 ended 19 May 2026) | `@angular/core` in `package.json` |
| Angular 20 | LTS until 28 November 2026 | same |
| Angular 21, 22 | Supported | same |

Sources: https://dotnet.microsoft.com/platform/support/policy/dotnet-core , https://endoflife.date/nodejs , https://endoflife.date/angular
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
# .NET vulnerability scanning (.NET 10 SDK noun-first form; the verb-first `dotnet list package ...` still works as an alias)
# ⚠️ ALWAYS include --include-transitive — direct-package scans miss the majority of real-world CVEs
dotnet package list --vulnerable --include-transitive --format json
dotnet package list --deprecated --include-transitive --format json
dotnet package update --vulnerable   # NuGet 7 / .NET 10 SDK: moves every vulnerable package to a fixed version
dotnet nuget why <package>           # shows the transitive path that pulls a flagged package in
# Source: https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/sdk

# npm vulnerability scanning  
npm audit
npm audit --audit-level high
npm outdated

# Alternative tools
# - Snyk scan
# - OWASP Dependency Check
# - WhiteSource/Mend
# - GitHub Dependabot alerts
# - GitHub Code Security for Azure DevOps: AdvancedSecurity-Dependency-Scanning@1 pipeline task
#   (Advanced Security split into Code Security and Secret Protection in June 2025;
#   https://devblogs.microsoft.com/devops/github-secret-protection-and-github-code-security-for-azure-devops/)
```

### NuGetAudit configuration review

Restore-time auditing is what produces `NU1901`–`NU1904` in the first place. Check `*.csproj`, `Directory.Build.props` and `Directory.Packages.props` for:
- `<NuGetAudit>` — must not be `false`
- `<NuGetAuditMode>all</NuGetAuditMode>` — must be set explicitly on net8.0 and net9.0 projects; their default is `direct`, which skips transitive packages (`all` is the default only from net10.0)
- `<NuGetAuditLevel>` — `low` (default) or `moderate`; `high` or `critical` hides most advisories
- every `<NuGetAuditSuppress Include="https://github.com/advisories/..." />` — needs a comment stating why the advisory does not apply
- `<NoWarn>` must not list `NU1901`–`NU1904`

Findings: audit disabled, or transitive audit off (`direct` mode or no `NuGetAuditMode` on net8.0/net9.0) = Medium; a suppression without a justification comment = Low.
Sources: https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages , https://learn.microsoft.com/en-us/dotnet/core/compatibility/sdk/10.0/nugetaudit-transitive-packages

### Audit sources on private feeds

When `nuget.config` lists only an Azure Artifacts feed, restore has no vulnerability database and the audit silently does nothing (`NU1905` warning). Check for both blocks:
```xml
<auditSources>
  <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
</auditSources>
<packageSourceMapping>
  <clear />
  <packageSource key="nuget.org"><package pattern="*" /></packageSource>
  <packageSource key="azure-artifacts"><package pattern="Company.*" /></packageSource>
</packageSourceMapping>
```
Findings: private feed with no `<auditSources>` = Medium; private feed without `<packageSourceMapping>` (dependency confusion: a public package with the same name as an internal one can be resolved from the wrong feed) = Low.
Source: https://learn.microsoft.com/en-us/nuget/reference/errors-and-warnings/nu1905

### npm supply-chain controls

After the September 2025 chalk/debug compromise and the Shai-Hulud worm, npm revoked classic tokens (December 2025), introduced OIDC trusted publishing, added `min-release-age` (npm 11.10) and, with npm 12 (July 2026), blocks dependency lifecycle scripts by default. Check:
- lockfile (`package-lock.json`, `yarn.lock` or `pnpm-lock.yaml`) committed and the pipeline runs `npm ci`, never `npm install`
- `.npmrc` has `ignore-scripts=true`, or CI uses npm 12+ (`NodeTool@0`/`UseNode@1` version, `npm --version` in the build log)
- `.npmrc` has `min-release-age=<days>` (pnpm: `minimumReleaseAge` in `pnpm-workspace.yaml`)
- registry pinned: `registry=` or `@scope:registry=` lines for Azure Artifacts feeds
- `npm audit signatures` runs in CI
- no `git+`, tarball (`.tgz`) or `http://` entries in the lockfile `resolved` fields
- dependencies that declare `preinstall`/`postinstall` scripts reviewed (`npm query ":attr(scripts, [postinstall])"`)
- if the organisation publishes packages: trusted publishing (OIDC from the pipeline) instead of long-lived tokens

Findings: no lockfile or `npm install` in CI = High; lifecycle scripts not blocked = Medium; no `min-release-age` or no `npm audit signatures` = Low.
Sources: https://github.com/orgs/community/discussions/179562 , https://www.infoq.com/news/2026/08/npm-12-released/ , https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack

### SBOM (Low, informational)

Check that the pipeline produces a software bill of materials: `npm sbom --sbom-format cyclonedx`, `dotnet CycloneDX` or `Microsoft.Sbom.Tool` (`sbom-tool generate`). Under the EU Cyber Resilience Act the 24-hour vulnerability-reporting duties apply since 11 September 2026 and the SBOM and vulnerability-handling obligations from 11 December 2027 for products with digital elements; custom-built and SaaS software may be out of scope, so report a missing SBOM as Low and informational.
Source: https://www.jonesday.com/en/insights/2026/07/eu-cyber-resilience-act-24hour-reporting-duties-start-september-11-2026

## 6. Risk Assessment Criteria
**Categorize findings by risk level:**

Use the NVD CVSS severity bands as reported by the advisory; do not shift them up.

**Critical (immediate action required):**
- CVSS 9.0–10.0
- Known exploits in the wild (any CVSS)
- Unauthenticated RCE or authentication bypass (any CVSS)

**High (address soon):**
- CVSS 7.0–8.9
- Deprecated packages with security implications
- Packages targeting an end-of-life runtime (see section 3)
- A lockfile `resolved` URL or a `nuget.config` package source outside the configured registries (see Additional Considerations)
- No lockfile committed, or CI runs `npm install` instead of `npm ci` (section 5)

**Medium (plan for update):**
- CVSS 4.0–6.9
- Significantly outdated packages (>2 major versions behind)
- Non-security deprecation warnings
- NuGetAudit disabled or transitive audit off on net8.0/net9.0; a private-feed-only `nuget.config` without `<auditSources>`; npm lifecycle scripts not blocked (section 5)

**Low (monitor):**
- CVSS 0.1–3.9
- `NuGetAuditSuppress` without a justification comment; private feed without `<packageSourceMapping>`; no `min-release-age`; no `npm audit signatures`; no SBOM produced (section 5)

Not findings: minor or patch updates available, pre-release versions available, documentation-only or feature-only updates, `^`/`~` ranges in `package.json` when a lockfile is committed and CI uses `npm ci`.

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
1. **Supply chain security**: every `"resolved"` URL in `package-lock.json` (or `resolved` line in `yarn.lock`) and every `<add key=... value=...>` source in `nuget.config` must point at a configured registry (`https://registry.npmjs.org/`, `https://api.nuget.org/v3/index.json`, or the organisation's Azure Artifacts feed `https://pkgs.dev.azure.com/...`). Search with `"resolved": "(?!https://registry\.npmjs\.org/|https://pkgs\.dev\.azure\.com/)` and report each other host as High
2. **Update testing**: Identify packages requiring extensive testing
3. **Rollback planning**: Consider packages with complex rollback requirements
4. **Monitoring setup**: Ongoing vulnerability scanning automation

Focus on providing actionable intelligence with clear prioritization for remediation efforts.

