# Code Quality Analysis

Review the project's build pipeline output and SonarQube dashboard to identify security-related warnings and assess the overall code quality baseline.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A03 Software Supply Chain Failures, A06 Insecure Design · **ASVS 5.0:** V15 Secure Coding and Architecture

## Core Security Principle
**Security vulnerabilities and hotspots flagged by static analysis tools must be resolved before release. Build warnings related to security or known vulnerabilities are treated as security findings. Other quality issues (bugs, code coverage) are reported separately as technical debt.**

## 1. Locate SonarQube and Pipeline Configuration

Before checking results, identify how SonarQube is connected to the project.

**Files to examine:**
- `sonar-project.properties` or `.sonarcloud.properties` — project key, organisation, quality gate
- `azure-pipelines.yml` or `*.yml` pipeline files — SonarQube analysis steps and build warning configuration
- `*.csproj` — `<TreatWarningsAsErrors>` and `<WarningsAsErrors>` MSBuild properties

**Search for:**
```yaml
# Azure DevOps — SonarQube/SonarCloud tasks
- task: SonarQubePrepare
- task: SonarQubeAnalyze
- task: SonarQubePublish
- task: SonarCloudPrepare
```

```xml
<!-- MSBuild warning configuration -->
<TreatWarningsAsErrors>true</TreatWarningsAsErrors>
<WarningsAsErrors>CS8600;CS8602</WarningsAsErrors>
<NoWarn>...</NoWarn>
```

**Ask the user for:**
- SonarQube or SonarCloud project dashboard URL
- Access to the most recent Azure DevOps build log

**Note on MCP integration:** Some projects have Azure DevOps and/or SonarQube connected via MCP. If MCP tools for either service are available in the current session, use them to retrieve build results and SonarQube metrics directly instead of asking the user.

## 2. Azure DevOps Build Warnings

Review the most recent successful build log for warnings that relate to security or known vulnerabilities.

**Security-relevant warning categories to look for:**

- **Vulnerability advisories** — NuGet or npm packages with known CVEs flagged during restore or build
- **Nullable reference warnings** that indicate potential null-dereference paths in security-sensitive code (e.g. authentication, authorisation handlers)
- **Deprecated API warnings** — use of APIs marked obsolete due to security concerns
- **Analyzer warnings** — output from Roslyn security analysers (e.g. `CA2100` SQL injection risk, `CA5394` insecure random, `CA5350`/`CA5351` weak cryptography)
- **Secret scanning warnings** — any pipeline-level credential scanning output

**Common Roslyn security analyser rule IDs to flag:**
```
CA2100  — SQL queries built from user input
CA2109  — Review visible event handlers
CA5350  — Do not use weak cryptographic algorithms (3DES)
CA5351  — Do not use broken cryptographic algorithms (MD5, DES)
CA5359  — Do not disable certificate validation
CA5394  — Do not use insecure randomness
CA5397  — Do not use deprecated SslProtocols values
CA3001–CA3147 — Various injection and XSS risks
```

**The CA security rules above are OFF by default.** They only run when the project enables them. A clean build log proves nothing unless one of these is present in the `.csproj`, `Directory.Build.props` or `.editorconfig`:
- `<AnalysisMode>All</AnalysisMode>` or `<AnalysisModeSecurity>All</AnalysisModeSecurity>`
- `<AnalysisLevel>latest-All</AnalysisLevel>` (or `<version>-All`)
- Explicit per-rule severities in `.editorconfig`, e.g. `dotnet_diagnostic.CA2100.severity = warning`, `dotnet_diagnostic.CA5350.severity = warning`

Do **not** accept these as evidence; they do not turn on rules that are disabled by default:
- `dotnet_analyzer_diagnostic.category-Security.severity = warning` or `dotnet_analyzer_diagnostic.severity = warning` (bulk severity only changes rules that are already enabled)
- `<EnableNETAnalyzers>true</EnableNETAnalyzers>` on its own (it is already the default and only enables analyzer execution)

Report "security analyzers not enabled" as a Medium finding when none of the accepted settings is configured. Reference: https://learn.microsoft.com/dotnet/fundamentals/code-analysis/configuration-options

**RED FLAGS:**
- Build warnings suppressed in bulk via `<NoWarn>` without justification, or `<NoWarn>` containing `CA2100`, `CA5xxx` or `NU1901`–`NU1904` (Medium)
- Vulnerable packages do not fail CI (Medium). Compliant when either `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` is set (it promotes `NU1903`/`NU1904` with every other warning) or `<WarningsAsErrors>` lists `NU1903;NU1904`. Red flag when neither is set, or when `TreatWarningsAsErrors=true` is combined with `<WarningsNotAsErrors>` that lists `NU1903` or `NU1904` (Microsoft's documented pattern of excluding only `NU1901;NU1902` is fine). Reference: https://learn.microsoft.com/nuget/concepts/auditing-packages
- Vulnerability advisories present in restore output but not acted on (rate by the advisory's CVSS band as in check 2, packages.md)
- `NU1900` or `NU1905` in the restore output: the audit could not run (no vulnerability data source configured), which is itself a Medium finding

## 3. SonarQube — Security Ratings (Overall Code)

Navigate to the project in SonarQube or SonarCloud and check the **Overall Code** tab.

**Ratings to check and their meaning:**

| Metric | Target | Action if not met |
|--------|--------|-------------------|
| **Vulnerabilities** | **A** | Report as security finding |
| **Security Hotspots Reviewed** | **A** | Report as security finding |

**SonarQube rating scales** (SonarQube Server/Cloud, Multi-Quality Rule mode is the default):
- **Security rating** (`security_rating` / `software_quality_security_rating`): **A** = no open Security issues; **B** = at least one Low; **C** = at least one Medium; **D** = at least one High; **E** = at least one Blocker
- **Security Review rating** (`security_review_rating`, hotspots reviewed): **A** ≥ 80%; **B** ≥ 70%; **C** ≥ 50%; **D** ≥ 30%; **E** < 30%

> **Security Hotspots are deprecated.** SonarQube Server 2026.4 and later (and SonarQube Cloud) fold hotspots into Security issues. If `security_review_rating` or the hotspots endpoint is absent, rely on the Security rating and the Security issues list alone and do not report "hotspots not reviewed".

Use the MCP tools when available: `get_project_quality_gate_status`, `get_component_measures` (metrics `security_rating`, `new_security_rating`, `security_review_rating`, `vulnerabilities`), `search_sonar_issues_in_projects` (Security impact), `search_security_hotspots`. Resolve the project key from `.sonarlint/connectedMode.json`, `sonar.projectKey`, or the `projectKey` in the pipeline task.

**For each open Security issue (or unreviewed Security Hotspot on older servers), note:**
- Rule ID and description (e.g. `csharpsquid:S2076 — OS command injection`)
- Affected file and line number
- Severity as reported by SonarQube

**RED FLAGS:**
- Security rating below A on Overall Code (rate each open Security issue per the mapping under What to Report)
- Security Review rating below A (fewer than 80% of hotspots reviewed) on servers that still have hotspots (Medium)
- Quality gate without a security condition (Security rating on New Code or Overall Code), or a pipeline that does not wait for the gate (Medium; `SonarQubePublish` with `pollingTimeoutSec: 0`, no `SonarQubePublish`/`SonarCloudPublish` task at all, or Sonar tasks with `continueOnError: true`). A publish task without an explicit `pollingTimeoutSec` is compliant: it polls for 300 seconds by default

## 4. SonarQube — Code Quality (Technical Debt)

The following metrics are **not security findings** but should be reported as technical debt for the project team's awareness.

**Metrics to check on the Overall Code tab:**

| Metric | Threshold | Severity if breached |
|--------|-----------|----------------------|
| **Bugs** (Critical or Blocker) | 0 | Low — technical debt |
| **Code Coverage** | ≥ 70% | Low — technical debt |
| **Duplications** | ≤ 3% | Low — technical debt |
| **Maintainability rating** | A | Low — technical debt |

**Note:** These findings are informational. They do not indicate a direct security risk but reflect the overall health of the codebase and the team's ability to maintain and reason about it safely over time.
Do not create any Jira stories for these technical debt items, but include them in the final report for visibility.

## What to Report

### Security Findings

For each security-related build warning or SonarQube security finding, provide:
- **Source**: Azure DevOps build log / SonarQube
- **Rule or warning ID** (e.g. `CA2100`, `S3649`)
- **File** and line number where available
- **Description** of the issue
- **Severity**: High (Blocker or Critical/High Security issue, broken crypto, injection risk) / Medium (Major or Medium Security issue; an unreviewed Security Hotspot with review priority High) / Low (Minor or Low Security issue; an unreviewed Security Hotspot with review priority Medium or Low; a suppressed security warning). Use the hotspot's own review priority, never a flat Medium
- **Recommendation**: remediation step or link to SonarQube rule documentation

### Technical Debt (report separately, low priority)

For each code quality issue, provide:
- **Metric**: Bugs / Code Coverage / Duplications / Maintainability
- **Current value** vs. **threshold**
- **Note**: *Reported as technical debt — not a security finding*
