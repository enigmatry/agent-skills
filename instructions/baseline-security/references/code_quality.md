# Code Quality Analysis

Review the project's build pipeline output and SonarQube dashboard to identify security-related warnings and assess the overall code quality baseline.

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

**RED FLAGS:**
- Build warnings suppressed in bulk via `<NoWarn>` without justification
- `<TreatWarningsAsErrors>` set to `false` or absent, meaning security analyser warnings are silent
- Vulnerability advisories present in restore output but not acted on

## 3. SonarQube — Security Ratings (Overall Code)

Navigate to the project in SonarQube or SonarCloud and check the **Overall Code** tab.

**Ratings to check and their meaning:**

| Metric | Target | Action if not met |
|--------|--------|-------------------|
| **Vulnerabilities** | **A** | Report as security finding |
| **Security Hotspots Reviewed** | **A** | Report as security finding |

**SonarQube rating scale:**
- **A** — 0 vulnerabilities / 100% hotspots reviewed
- **B** — at least 1 minor vulnerability
- **C** — at least 1 major vulnerability
- **D** — at least 1 critical vulnerability
- **E** — at least 1 blocker vulnerability

**For each open Vulnerability or unreviewed Security Hotspot, note:**
- Rule ID and description (e.g. `java:S2076 — OS command injection`)
- Affected file and line number
- Severity as reported by SonarQube

**RED FLAGS:**
- Vulnerabilities rating below A on Overall Code
- Security Hotspots rating below A (unreviewed hotspots)
- Quality gate set to "None" or a custom gate that does not enforce security ratings

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
- **Risk**: HIGH (blocker or critical vulnerability, broken crypto, injection risk) / MEDIUM (major vulnerability or unreviewed security hotspot) / LOW (minor vulnerability or suppressed security warning)
- **Recommendation**: remediation step or link to SonarQube rule documentation

### Technical Debt (report separately, low priority)

For each code quality issue, provide:
- **Metric**: Bugs / Code Coverage / Duplications / Maintainability
- **Current value** vs. **threshold**
- **Note**: *Reported as technical debt — not a security finding*
