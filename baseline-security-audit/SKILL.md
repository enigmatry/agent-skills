---
name: baseline-security-audit
description: Use only when the user explicitly asks for a "Baseline Security" scan or audit of the codebase, or to create Jira stories from a Baseline Security audit. Do not use for a general security scan, vulnerability assessment, penetration test or code review that does not name Baseline Security.
compatibility: Designed for Claude Code or similar agents. Requires an Atlassian Jira MCP server for story creation, a SonarQube MCP server for the Code Quality check, and internet access for the Security Headers, SSL/TLS and Package Security checks.
metadata:
  author: enigmatry
  version: "2.0"
---

# Baseline Security Audit Skill

## Overview

This skill performs a comprehensive baseline security audit of the codebase by analyzing common security vulnerabilities and misconfigurations. It can create Jira stories for selected findings after user confirmation for tracking and remediation.

## What This Skill Does

This skill performs the following security checks (each with detailed guidance in the references folder):

1. **Secrets and Credentials** - Scans for hardcoded secrets, credentials and API keys, and verifies that credentials differ per environment
    - See [references/secrets.md](references/secrets.md)

2. **Package Security** - Checks for dependencies with known vulnerabilities, end-of-life runtimes and supply-chain controls
    - See [references/packages.md](references/packages.md)

3. **SQL Injection** - Identifies SQL injection vulnerabilities in database queries
    - See [references/sql_injection.md](references/sql_injection.md)

4. **Exception Handling** - Reviews error handling to keep exception details out of responses while logging them
    - See [references/exception_handling.md](references/exception_handling.md)

5. **Logging Security** - Validates log sinks, levels, audit separation and the absence of secrets and PII in logs
    - See [references/logging.md](references/logging.md)

6. **Sensitive Query Strings** - Checks for sensitive data in URL query parameters and in URL logging
    - See [references/sensitive_query_strings.md](references/sensitive_query_strings.md)

7. **IDOR (Insecure Direct Object References)** - Analyzes object-level and function-level authorization checks
    - See [references/idor.md](references/idor.md)

8. **Output Encoding** - Validates encoding and sanitization to prevent XSS
    - See [references/output_encoding.md](references/output_encoding.md)

9. **Input Validation** - Ensures user input is validated server-side, including mass assignment and path traversal
    - See [references/input_validation.md](references/input_validation.md)

10. **Code Minification** - Verifies production builds do not expose source maps or debug code
    - See [references/code_minification.md](references/code_minification.md)

11. **Data Minimization** - Identifies unnecessary exposure of data through APIs and the frontend, and unnecessary storage of sensitive data (GDPR)
    - See [references/data_minimization.md](references/data_minimization.md)

12. **Cookie and Storage Security** - Validates cookie flags and browser storage of sensitive data
    - See [references/cookie_storage_security.md](references/cookie_storage_security.md)

13. **Cryptography Security** - Ensures strong algorithms, key management and password hashing
    - See [references/cryptography_security.md](references/cryptography_security.md)

14. **Security Headers** - Checks response security headers (CSP, HSTS, Permissions-Policy and others) and removal of version-disclosing headers
    - See [references/security_headers.md](references/security_headers.md)

15. **HTTP Verb Whitelisting** - Ensures only the HTTP verbs the application uses are allowed
    - See [references/http_verb_whitelisting.md](references/http_verb_whitelisting.md)

16. **SSL/TLS Configuration** - Validates TLS protocols, cipher suites, certificates and code-level TLS settings
    - See [references/ssl_tls_configuration.md](references/ssl_tls_configuration.md)

17. **Database Field Encryption** - Verifies that sensitive columns are encrypted at the column or application level
    - See [references/database_field_encryption.md](references/database_field_encryption.md)

18. **Code Quality** - Reviews build warnings, security analyzers and SonarQube security ratings
    - See [references/code_quality.md](references/code_quality.md)

19. **Authentication Security** - Verifies OpenID Connect with Authorization Code + PKCE, authorization by default, Swagger restricted to Development, and token lifetime and password policy
    - See [references/authentication_security.md](references/authentication_security.md)

Each check provides:
- Specific patterns to search for
- RED FLAGS to identify
- Findings rated on the single severity scale below
- Remediation guidance
- Code examples

## Severity Scale

Every reference file rates findings on this one scale. Rate by **impact and exploitability**, never by who supplies the input or which environment is affected: admin-supplied input does not lower a finding below Medium, and any cross-tenant or cross-user impact is at least High.

| Severity | Definition | Typical examples |
|----------|------------|------------------|
| **Critical** | Exploitable now, from unauthenticated or low-privilege input, with severe impact | Secret or credential in source, config or logs; injection reachable from user input; authentication bypass; CVSS 9.0+; CVV or PAN stored in clear; broken or home-made crypto protecting secrets |
| **High** | Exploitable with authenticated input, or exposes sensitive data, or a core control is missing | Missing authorization on an endpoint; stack traces or exception details in HTTP responses; TLS 1.0/1.1 enabled; no HSTS; unauthenticated CBC data handed to clients; CVSS 7.0–8.9; PII or special-category data logged as payload; runtime past end of life |
| **Medium** | Defense-in-depth gap or misconfiguration that needs another weakness to exploit | Missing security header; security analyzers not enabled; unreviewed SonarQube security issues; CVSS 4.0–6.9; verbose logging in production; no automated certificate renewal |
| **Low** | Hygiene or informational; no realistic exploit path on its own | `SameSite` not explicit; HSTS `preload` absent; public identifiers shared across environments; post-quantum readiness; documentation gaps; CVSS below 4.0 |

Status words such as SECURE / PARTIALLY SECURE / INSECURE, IMPLEMENTED / PARTIAL / NOT, or EXCESSIVE / MODERATE / MINIMAL are **not** severities; when a reference file uses them for an assessment, every reported finding still carries one of the four severities above.

**Report every finding with:** Severity · Check number and name · Location (file:line, header, or live URL) · What was found · Remediation · OWASP Top 10:2025 category (from the mapping below).

## Standards Mapping

Tag each finding with the OWASP Top 10:2025 category and ASVS 5.0 chapter of its check.

| # | Check | OWASP Top 10:2025 | ASVS 5.0 |
|---|-------|-------------------|----------|
| 1 | Secrets and Credentials | A02 Security Misconfiguration | V13 Configuration |
| 2 | Package Security | A03 Software Supply Chain Failures | V15 Secure Coding and Architecture |
| 3 | SQL Injection | A05 Injection | V1 Encoding and Sanitization |
| 4 | Exception Handling | A10 Mishandling of Exceptional Conditions | V16 Security Logging and Error Handling |
| 5 | Logging Security | A09 Security Logging and Alerting Failures | V16 Security Logging and Error Handling, V14 Data Protection |
| 6 | Sensitive Query Strings | A04 Cryptographic Failures (data exposure) | V14 Data Protection |
| 7 | IDOR (Insecure Direct Object References) | A01 Broken Access Control | V8 Authorization |
| 8 | Output Encoding | A05 Injection | V1 Encoding and Sanitization, V3 Web Frontend Security |
| 9 | Input Validation | A05 Injection, A06 Insecure Design | V2 Validation and Business Logic |
| 10 | Code Minification | A02 Security Misconfiguration | V13 Configuration, V3 Web Frontend Security |
| 11 | Data Minimization | A04 Cryptographic Failures, A06 Insecure Design | V14 Data Protection |
| 12 | Cookie and Storage Security | A02 Security Misconfiguration, A07 Authentication Failures | V7 Session Management, V3 Web Frontend Security |
| 13 | Cryptography Security | A04 Cryptographic Failures | V11 Cryptography |
| 14 | Security Headers | A02 Security Misconfiguration | V3 Web Frontend Security, V13 Configuration |
| 15 | HTTP Verb Whitelisting | A02 Security Misconfiguration | V4 API and Web Service, V13 Configuration |
| 16 | SSL/TLS Configuration | A04 Cryptographic Failures, A02 Security Misconfiguration | V12 Secure Communication |
| 17 | Database Field Encryption | A04 Cryptographic Failures | V14 Data Protection, V11 Cryptography |
| 18 | Code Quality | A03 Software Supply Chain Failures, A06 Insecure Design | V15 Secure Coding and Architecture |
| 19 | Authentication Security | A07 Authentication Failures, A01 Broken Access Control | V6 Authentication, V8 Authorization, V10 OAuth and OIDC |

Sources: https://owasp.org/Top10/2025/ , https://github.com/OWASP/ASVS/tree/v5.0.0

## How to Use

Invoke this skill only by naming it:
- "Perform a Baseline Security audit"
- "Run the Baseline Security scan on this project"
- "Create Jira stories from the Baseline Security findings"

It is not the right skill for a general security scan, a vulnerability assessment, a penetration test or a code review; those requests should not trigger it.

## Execution Flow

### Step 0 — Select Checks and Collect the Production URL (one prompt, at the very start)

Before doing anything else, present the full list of available checks and ask one question that collects both the selection and the production URL:

> "Which security checks would you like to run, and what is the production URL?
>
> | # | Check |
> |---|-------|
> | 1 | Secrets and Credentials |
> | 2 | Package Security |
> | 3 | SQL Injection |
> | 4 | Exception Handling |
> | 5 | Logging Security |
> | 6 | Sensitive Query Strings |
> | 7 | IDOR (Insecure Direct Object References) |
> | 8 | Output Encoding |
> | 9 | Input Validation |
> | 10 | Code Minification |
> | 11 | Data Minimization |
> | 12 | Cookie and Storage Security |
> | 13 | Cryptography Security |
> | 14 | Security Headers |
> | 15 | HTTP Verb Whitelisting |
> | 16 | SSL/TLS Configuration |
> | 17 | Database Field Encryption |
> | 18 | Code Quality |
> | 19 | Authentication Security |
>
> Reply with **`all`** or a comma-separated list of numbers (e.g. `1, 3, 5`). Checks 14 (Security Headers) and 16 (SSL/TLS Configuration) inspect the live site: add the production URL on the same line (e.g. `all, https://app.example.com`) or leave it out to fall back to static analysis."

Store the selected check numbers as `SELECTED_CHECKS` and the URL as `PRODUCTION_URL` (empty when none was given). Only run, report on, and create Jira stories for the selected checks. Do **not** ask either question again during the audit; if the user gives no URL and checks 14 or 16 are selected, run their static analysis and say so in the findings.

### Step 0b — Determine the Hosting Model (once, before running checks)

Checks 10, 12, 14, 15 and 16 depend on where the application runs, because `web.config` is only honoured by IIS and Azure App Service on Windows. Determine `HOSTING_MODEL` from repository evidence before running them; ask the user once only if the evidence is contradictory or absent.

| `HOSTING_MODEL` | Evidence | Effect on checks |
|-----------------|----------|------------------|
| `iis` | `web.config` with `<aspNetCore>` or `<system.webServer>`, Bicep `Microsoft.Web/sites` without `linuxFxVersion`, pipeline deploying to IIS or Windows App Service | `web.config` sections (`customHeaders`, `requestFiltering`, `removeServerHeader`, `httpErrors`) apply |
| `linux` | `Dockerfile`, Bicep `linuxFxVersion`, `kind: 'app,linux'`, AKS or Container Apps manifests, Kestrel exposed directly | `web.config` is ignored; the equivalents are middleware (`UseHsts`, security-header middleware, method filtering) and container or platform settings. Do not report missing `web.config` entries |
| `edge` (modifier, combined with either) | Bicep `Microsoft.Cdn/profiles` (Front Door), `Microsoft.Network/applicationGateways`, or a reverse proxy in front of the app | Headers, TLS policy and verb filtering may be set or stripped at the edge; when `PRODUCTION_URL` is available, the live response is the ground truth, and `UseForwardedHeaders` must be configured |

Store the result as `HOSTING_MODEL` and do **not** ask again.

### Step 1 — Run the Selected Checks

**Scope once.** Before the first check, list what will be audited: every deployable project (`*.csproj` of web apps, APIs and workers; every `angular.json` project), the pipeline files (`azure-pipelines*.yml`, `**/*.yml` under a pipelines folder), infrastructure (`*.bicep`, `*.parameters.json`), and `nuget.config` / `package.json`. In a monorepo cover every deployable project; name any folder you deliberately leave out (samples, archived code, generated code). Reuse this list for every check.

**For each check in `SELECTED_CHECKS`, in numeric order:**

1. **Read the check's reference file in full** before searching. The file states what to look for, what counts as a finding, the severity of each finding and the remediation; do not work from the check's one-line description.
2. **Apply the audit context.** Follow the file's `Hosting model` line with `HOSTING_MODEL`, and use `PRODUCTION_URL` where the file calls for live inspection.
3. **Search, then confirm.** Run the file's `Files to examine` globs and `Search patterns` first, then read every hit in context before rating it. A pattern match is a candidate, not a finding; the file's "not a finding" rules apply.
4. **Rate and record** every confirmed finding in the format from the Severity Scale section: Severity · check number and name · location (`path:line`, header name, or URL) · what was found · remediation · OWASP Top 10:2025 category.
5. **Collect human-input questions.** Where the file marks an item as "ask the user" or "requires human input", gather those questions and ask them in one batch at the end of the check, never one at a time in the middle of it.
6. **Close the check with a result block**, even when nothing was found:

   > **Check N — <name>:** `<k> findings` or `No findings`.
   > Searched: <globs and patterns used, files or endpoints inspected, live URL or static analysis>.
   > Not verifiable from code: <human-input items still open, or "none">.

Checks may run in parallel (for example one subagent per check) when the environment supports it; every runner gets `SELECTED_CHECKS`, `HOSTING_MODEL`, `PRODUCTION_URL`, the scope list and the full reference file, and the audit report is assembled in numeric order regardless of completion order.

## Jira Integration

### Step 2 — Jira Priority Mapping

All findings already carry one of the four severities from the Severity Scale section. Map them to Jira priorities as follows (verify the priority names against the target Jira project's scheme; some schemes use `Medium` instead of `Normal`):

| Severity | Jira Priority |
|----------|---------------|
| Critical | `Highest`     |
| High     | `High`        |
| Medium   | `Normal`      |
| Low      | `Low`         |

### Step 3 — Present All Findings and Ask Which to Send to Jira

After **all selected checks** are complete, output a numbered consolidated table of every finding. Each check covers a distinct topic, so a configuration is reported under exactly one check; if the same file and line surfaces twice, keep the finding under the check whose topic it is and drop the other:

| # | Check | Finding | Location | Severity | OWASP 2025 |
|---|-------|---------|----------|----------|------------|
| 1 | 1 Secrets and Credentials | Hardcoded API key | src/Api/appsettings.json:14 | Critical | A02 |
| 2 | ... | ... | ... | ... | ... |

Then ask the user exactly once:

> "Which findings should be created as Jira stories, and in which Jira project?
> Reply with **`all`** or a comma-separated list of numbers (e.g. `1, 3, 5`) followed by the project code (e.g. `1, 3, 5 in SEC`), or **`none`** to skip Jira creation."

Store the project code as `JIRA_PROJECT_CODE`. If the user gives a selection without a project code, ask for the code once. If the answer is `none`, stop here: do not ask for a project code and skip Steps 4 and 5.

Do **not** create any Jira stories before receiving this answer.

### Step 4 — Create a Jira Story for Each Selected Finding

> **Package Security — special consolidation rule:**
> Instead of one story per package, consolidate all npm findings into a single story and all NuGet findings into a single story (at most 2 stories for this check). List every affected package, its current version, recommended version, CVE(s), and risk level in the description of the consolidated story. Apply the highest priority among the individual findings to the consolidated story. If a package ecosystem has no findings, omit its story entirely.

Before the first story, call `getAccessibleAtlassianResources` once and store the returned cloud id as `CLOUD_ID`; every Jira call below requires it.

For each finding selected by the user, create one Jira story using the `createJiraIssue` tool with the following fields:

| Field               | Value                                                                                  |
|---------------------|----------------------------------------------------------------------------------------|
| `cloudId`           | `CLOUD_ID`                                                                             |
| `projectKey`        | `JIRA_PROJECT_CODE` (collected in Step 3)                                              |
| `issueTypeName`     | `Story`                                                                                |
| `summary`           | `[Security Audit] <Check Name>: <short finding title>`                                 |
| `description`       | Finding location (file + line number), description of the issue, remediation steps, and the line `OWASP Top 10:2025: <category>` (Markdown) |
| `additional_fields` | `{"labels": ["BaselineSecurity"], "priority": {"name": "<mapped priority>"}}` — labels and priority are only accepted through this object |

**Example summary:** `[Security Audit] Secrets and Credentials: Hardcoded API key in appsettings.json`

After each `createJiraIssue` call succeeds:

1. Echo the created story key inline in the audit output as a link built from the site URL that `getAccessibleAtlassianResources` returned, e.g.: *(→ created [PROJ-42](<site URL>/browse/PROJ-42))*
2. Call `createIssueLink` to relate the new story to the ETL project story for this project:
   - `cloudId`: `CLOUD_ID`
   - `type`: `"Relates"`
   - `inwardIssue`: newly created story key (e.g. `YES-42`)
   - `outwardIssue`: ETL project story key (e.g. `ETL-2879`)

   Find the ETL story once, before creating the first link, with `searchJiraIssuesUsingJql` (`cloudId` = `CLOUD_ID`), for example `project = ETL AND summary ~ "<current project name>" AND summary ~ "Baseline security"`. If more than one issue matches or none does, show the candidates and ask the user for the key. Store it as `ETL_STORY_KEY` and do not search again.

> ⚠️ Do **not** use `customfield_10014` (Epic Link) for this — that field only accepts Epics.
> The ETL story is a *Story*, not an Epic. Use `createIssueLink` instead.

### Step 5 — Final Summary Table

After all selected stories are created, output a consolidated table:

| Story Key | Check | Summary | Priority |
|-----------|-------|---------|----------|
| PROJ-42   | Secrets and Credentials | Hardcoded API key in appsettings.json | Highest |
| ...       | ...   | ...     | ...      |

If the user replied `none`, skip story creation and omit this table.
