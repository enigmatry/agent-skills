---
name: baseline-security-audit
description: Ensures baseline security practices are followed in the project. Use this when asked to perform a security audit on the codebase. Can create Jira stories for selected security findings.
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

1. **Secrets Management** - Scans for hardcoded secrets, credentials, and API keys
   - See [references/secrets.md](references/secrets.md)

2. **Package Security** - Checks for insecure dependencies and outdated packages with known vulnerabilities
   - See [references/packages.md](references/packages.md)

3. **SQL Injection** - Identifies potential SQL injection vulnerabilities in database queries
   - See [references/sql_injection.md](references/sql_injection.md)

4. **Exception Handling** - Reviews error handling patterns to prevent information disclosure
   - See [references/exception_handling.md](references/exception_handling.md)

5. **Logging Security** - Validates logging practices and checks for sensitive data in logs
   - See [references/logging.md](references/logging.md)

6. **Sensitive Data in Logs** - Identifies logging of passwords, tokens, and other sensitive information
   - See [references/sensitive_data_logging.md](references/sensitive_data_logging.md)

7. **Sensitive Query Strings** - Checks for sensitive data exposure in URL query parameters
   - See [references/sensitive_query_strings.md](references/sensitive_query_strings.md)

8. **IDOR (Insecure Direct Object References)** - Analyzes authorization checks for object access
   - See [references/idor.md](references/idor.md)

9. **Output Encoding** - Validates proper encoding to prevent XSS attacks
   - See [references/output_encoding.md](references/output_encoding.md)

10. **Input Validation** - Ensures all user input is validated server-side and client-side
    - See [references/input_validation.md](references/input_validation.md)

11. **Code Minification** - Verifies production builds are minified and source maps are secured
    - See [references/code_minification.md](references/code_minification.md)

12. **Environment Credentials** - Ensures different credentials per environment (dev/test/staging/prod)
    - See [references/environment_credentials.md](references/environment_credentials.md)

13. **Data Minimization** - Identifies unnecessary storage of sensitive/personal data (GDPR compliance)
    - See [references/data_minimization.md](references/data_minimization.md)

14. **Data Storage Minimization** - Reviews database entities for minimal sensitive data storage
    - See [references/data_storage_minimization.md](references/data_storage_minimization.md)

15. **Cookie and Storage Security** - Validates secure cookie configuration and localStorage usage
    - See [references/cookie_storage_security.md](references/cookie_storage_security.md)

16. **Cryptography Security** - Ensures strong cryptographic algorithms for hashing and encryption
    - See [references/cryptography_security.md](references/cryptography_security.md)

17. **Security Headers** - Checks proper configuration of CSP, HSTS, X-Frame-Options, and other security headers
    - See [references/security_headers.md](references/security_headers.md)
    - **Note**: Uses `PRODUCTION_URL` collected at the start of the audit. If empty, skip live analysis and note it in the findings.

18. **Version Info Headers** - Prevents disclosure of platform/version information in HTTP headers
    - See [references/version_info_headers.md](references/version_info_headers.md)

19. **HTTP Verb Whitelisting** - Ensures only necessary HTTP verbs are allowed, blocks unused methods
    - See [references/http_verb_whitelisting.md](references/http_verb_whitelisting.md)

20. **SSL/TLS Configuration** - Validates SSL/TLS protocol versions and cipher suites using SSL Labs analysis
    - See [references/ssl_tls_configuration.md](references/ssl_tls_configuration.md)
    - **Note**: Uses `PRODUCTION_URL` collected at the start of the audit. If empty, skip live analysis and note it in the findings.

21. **Database Field Encryption** - Verifies that sensitive fields (SSN, credit card numbers, bank account details, etc.) are encrypted at the column or application level so they are unreadable with direct database access
    - See [references/database_field_encryption.md](references/database_field_encryption.md)

22. **Code Quality** - Reviews build pipeline warnings for security-related issues and checks SonarQube for vulnerability and security hotspot ratings
    - See [references/code_quality.md](references/code_quality.md)

23. **Authentication Security** - Verifies that a standard authentication protocol (OpenID Connect, Authorization Code + PKCE) is used, all API endpoints require authorization by default, Swagger is restricted to Development, and token lifetime and password policies meet minimum requirements
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
| 1 | Secrets Management | A02 Security Misconfiguration | V13 Configuration |
| 2 | Package Security | A03 Software Supply Chain Failures | V15 Secure Coding and Architecture |
| 3 | SQL Injection | A05 Injection | V1 Encoding and Sanitization |
| 4 | Exception Handling | A10 Mishandling of Exceptional Conditions | V16 Security Logging and Error Handling |
| 5 | Logging Security | A09 Security Logging and Alerting Failures | V16 Security Logging and Error Handling |
| 6 | Sensitive Data in Logs | A09 Security Logging and Alerting Failures | V16, V14 Data Protection |
| 7 | Sensitive Query Strings | A04 Cryptographic Failures (data exposure) | V14 Data Protection |
| 8 | IDOR | A01 Broken Access Control | V8 Authorization |
| 9 | Output Encoding | A05 Injection | V1 Encoding and Sanitization, V3 Web Frontend Security |
| 10 | Input Validation | A05 Injection, A06 Insecure Design | V2 Validation and Business Logic |
| 11 | Code Minification | A02 Security Misconfiguration | V13 Configuration, V3 Web Frontend Security |
| 12 | Environment Credentials | A02 Security Misconfiguration | V13 Configuration |
| 13 | Data Minimization | A04 Cryptographic Failures, A06 Insecure Design | V14 Data Protection |
| 14 | Data Storage Minimization | A04 Cryptographic Failures, A06 Insecure Design | V14 Data Protection |
| 15 | Cookie and Storage Security | A02 Security Misconfiguration, A07 Authentication Failures | V7 Session Management, V3 Web Frontend Security |
| 16 | Cryptography Security | A04 Cryptographic Failures | V11 Cryptography |
| 17 | Security Headers | A02 Security Misconfiguration | V3 Web Frontend Security, V13 Configuration |
| 18 | Version Info Headers | A02 Security Misconfiguration | V13 Configuration |
| 19 | HTTP Verb Whitelisting | A02 Security Misconfiguration | V4 API and Web Service, V13 Configuration |
| 20 | SSL/TLS Configuration | A04 Cryptographic Failures, A02 Security Misconfiguration | V12 Secure Communication |
| 21 | Database Field Encryption | A04 Cryptographic Failures | V14 Data Protection, V11 Cryptography |
| 22 | Code Quality | A03 Software Supply Chain Failures, A06 Insecure Design | V15 Secure Coding and Architecture |
| 23 | Authentication Security | A07 Authentication Failures, A01 Broken Access Control | V6 Authentication, V8 Authorization, V10 OAuth and OIDC |

Sources: https://owasp.org/Top10/2025/ , https://github.com/OWASP/ASVS/tree/v5.0.0

## Finding Ownership

Several checks look at the same code. A finding that matches a row below is reported **once**, under the owning check; the other checks only reference it ("see finding #n under check X") and never create a second finding or Jira story for it.

| Finding | Owner | Also encountered in |
|---------|-------|---------------------|
| Caller-supplied id used in a query without an ownership or tenant check | 8 IDOR | 3, 10 |
| Missing `[Authorize]` / no fallback authorization policy | 23 Authentication | 8 |
| Role check present but no resource-level check (BFLA) | 8 IDOR | 23 |
| Mass assignment / over-posting of `Id`, `OwnerId`, `TenantId`, `Role` (BOPLA) | 10 Input Validation | 8, 13 |
| Global exception handler present and logging | 4 Exception Handling | 5 |
| Exception details or stack traces in HTTP responses | 4 Exception Handling | 6 |
| Secrets, tokens or PII inside log messages or destructured objects | 6 Sensitive Data in Logs | 4, 5 |
| Log sinks, levels, console output, audit separation | 5 Logging | 6 |
| Query-string values written to access logs or telemetry | 7 Sensitive Query Strings | 6 |
| HSTS header | 17 Security Headers | 20 |
| CSP, `X-XSS-Protection` and other response headers | 17 Security Headers | 9 |
| CORS policy | 17 Security Headers | 19 |
| Frontend models or interfaces exposing sensitive fields | 13 Data Minimization | 14 |
| Encryption state of a sensitive database column | 21 Database Field Encryption | 14, 16 |
| Hard-coded, static or unrotated encryption key | 16 Cryptography | 21 |
| Public identifiers (client id, tenant id, instrumentation key) shared across environments | 12 Environment Credentials (Low, hygiene) | 1 |
| Credential-bearing value in an Angular environment file | 1 Secrets | 12 |
| Password hashing | 16 Cryptography | 10, 23 |
| Password policy | 23 Authentication | 10 |
| Code-level TLS settings (`SslProtocols`, `TrustServerCertificate`, certificate validation callbacks) | 20 SSL/TLS | 16 |
| Source maps served publicly | 11 Code Minification | 18 |
| Swagger or OpenAPI reachable outside Development | 23 Authentication | 18 |
| Path traversal in file access | 10 Input Validation | 8 |

## How to Use

Invoke this skill by asking for a security audit:
- "Perform a baseline security audit"
- "Check the codebase for security issues"
- "Run security checks on this project"

## Execution Flow

### Step 0 — Select Checks to Run (ask once, at the very start)

Before doing anything else, present the full list of available checks and ask the user which ones to run:

> "Which security checks would you like to run?
>
> | # | Check |
> |---|-------|
> | 1 | Secrets Management |
> | 2 | Package Security |
> | 3 | SQL Injection |
> | 4 | Exception Handling |
> | 5 | Logging Security |
> | 6 | Sensitive Data in Logs |
> | 7 | Sensitive Query Strings |
> | 8 | IDOR (Insecure Direct Object References) |
> | 9 | Output Encoding |
> | 10 | Input Validation |
> | 11 | Code Minification |
> | 12 | Environment Credentials |
> | 13 | Data Minimization |
> | 14 | Data Storage Minimization |
> | 15 | Cookie and Storage Security |
> | 16 | Cryptography Security |
> | 17 | Security Headers |
> | 18 | Version Info Headers |
> | 19 | HTTP Verb Whitelisting |
> | 20 | SSL/TLS Configuration |
> | 21 | Database Field Encryption |
> | 22 | Code Quality |
> | 23 | Authentication Security |
>
> Reply with **`all`** to run all checks, or provide a comma-separated list of numbers (e.g. `1, 3, 5`) to run a specific subset."

Store the selected check numbers as `SELECTED_CHECKS`. Only run, report on, and create Jira stories for the selected checks.
Do **not** ask again during the audit.

If `SELECTED_CHECKS` includes **17 (Security Headers)** or **20 (SSL/TLS Configuration)** — or if `all` was selected — ask the user for the production URL immediately after the check selection:

> "Checks 17 and/or 20 require a live URL. What is the production URL? (leave blank to skip live inspection and fall back to static analysis)"

Store the answer as `PRODUCTION_URL`. If the user leaves it blank, set `PRODUCTION_URL` to empty and proceed with static analysis for both checks.
Do **not** ask for this URL again during the audit.

### Step 0b — Determine the Hosting Model (once, before running checks)

Checks 11, 15, 17, 18, 19 and 20 depend on where the application runs, because `web.config` is only honoured by IIS and Azure App Service on Windows. Determine `HOSTING_MODEL` from repository evidence before running them; ask the user once only if the evidence is contradictory or absent.

| `HOSTING_MODEL` | Evidence | Effect on checks |
|-----------------|----------|------------------|
| `iis` | `web.config` with `<aspNetCore>` or `<system.webServer>`, Bicep `Microsoft.Web/sites` without `linuxFxVersion`, pipeline deploying to IIS or Windows App Service | `web.config` sections (`customHeaders`, `requestFiltering`, `removeServerHeader`, `httpErrors`) apply |
| `linux` | `Dockerfile`, Bicep `linuxFxVersion`, `kind: 'app,linux'`, AKS or Container Apps manifests, Kestrel exposed directly | `web.config` is ignored; the equivalents are middleware (`UseHsts`, security-header middleware, method filtering) and container or platform settings. Do not report missing `web.config` entries |
| `edge` (modifier, combined with either) | Bicep `Microsoft.Cdn/profiles` (Front Door), `Microsoft.Network/applicationGateways`, or a reverse proxy in front of the app | Headers, TLS policy and verb filtering may be set or stripped at the edge; when `PRODUCTION_URL` is available, the live response is the ground truth, and `UseForwardedHeaders` must be configured |

Store the result as `HOSTING_MODEL` and do **not** ask again.

## Jira Integration

### Step 1 — Collect the Jira Project Code (ask once, at the very start)

After confirming the selected checks, ask the user exactly once:

> "What is the Jira project code where security stories should be created? (e.g. `SEC`, `PROJ`)"

Store the answer as `JIRA_PROJECT_CODE` and reuse it for all subsequent story creation calls.
Do **not** ask again during the audit.

### Step 2 — Jira Priority Mapping

All findings already carry one of the four severities from the Severity Scale section. Map them to Jira priorities as follows (verify the priority names against the target Jira project's scheme; some schemes use `Medium` instead of `Normal`):

| Severity | Jira Priority |
|----------|---------------|
| Critical | `Highest`     |
| High     | `High`        |
| Medium   | `Normal`      |
| Low      | `Low`         |

### Step 3 — Present All Findings and Ask Which to Send to Jira

After **all selected checks** are complete, deduplicate first: any finding that matches a row of the Finding Ownership table is kept only under its owning check. Then output a numbered consolidated table of every finding:

| # | Check | Finding | Location | Severity | OWASP 2025 |
|---|-------|---------|----------|----------|------------|
| 1 | 1 Secrets Management | Hardcoded API key | src/Api/appsettings.json:14 | Critical | A02 |
| 2 | ... | ... | ... | ... | ... |

Then ask the user exactly once:

> "Which findings should be created as Jira stories?
> Reply with **`all`** to create stories for all findings, a comma-separated list of numbers (e.g. `1, 3, 5`), or **`none`** to skip Jira creation."

Do **not** create any Jira stories before receiving this answer.

### Step 4 — Create a Jira Story for Each Selected Finding

> **Package Security — special consolidation rule:**
> Instead of one story per package, consolidate all npm findings into a single story and all NuGet findings into a single story (at most 2 stories for this check). List every affected package, its current version, recommended version, CVE(s), and risk level in the description of the consolidated story. Apply the highest priority among the individual findings to the consolidated story. If a package ecosystem has no findings, omit its story entirely.

Before the first story, call `getAccessibleAtlassianResources` once and store the returned cloud id as `CLOUD_ID`; every Jira call below requires it.

For each finding selected by the user, create one Jira story using the `createJiraIssue` tool with the following fields:

| Field               | Value                                                                                  |
|---------------------|----------------------------------------------------------------------------------------|
| `cloudId`           | `CLOUD_ID`                                                                             |
| `projectKey`        | `JIRA_PROJECT_CODE` (collected above)                                                  |
| `issueTypeName`     | `Story`                                                                                |
| `summary`           | `[Security Audit] <Check Name>: <short finding title>`                                 |
| `description`       | Finding location (file + line number), description of the issue, remediation steps, and the line `OWASP Top 10:2025: <category>` (Markdown) |
| `additional_fields` | `{"labels": ["BaselineSecurity"], "priority": {"name": "<mapped priority>"}}` — labels and priority are only accepted through this object |

**Example summary:** `[Security Audit] Secrets Management: Hardcoded API key in appsettings.json`

After each `createJiraIssue` call succeeds:

1. Echo the created story key inline in the audit output, e.g.: *(→ created [PROJ-42](https://enigmatry.atlassian.net/browse/PROJ-42))*
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
| PROJ-42   | Secrets Management | Hardcoded API key in appsettings.json | High |
| ...       | ...   | ...     | ...      |

If the user replied `none`, skip story creation and omit this table.
