# Sensitive Data in Logs Analysis

Scan the codebase for sensitive data being written to logs, which could expose credentials, PII, or other confidential information through log files and aggregation systems.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A09 Security Logging and Alerting Failures · **ASVS 5.0:** V16 Security Logging and Error Handling, V14 Data Protection
> **Owns:** secrets, tokens or PII inside log messages or destructured objects (also encountered in 4, 5)
> **Defers to:** exception details or stack traces in HTTP responses → check 4 (exception_handling.md); log sinks, levels, console output, audit separation → check 5 (logging.md); query-string values written to access logs or telemetry → check 7 (sensitive_query_strings.md)

## Core Security Principle
**Sensitive data — including credentials, tokens, PII, and financial information — must never appear in log output. Log statements must record what happened without recording the sensitive values involved.**

## 1. Authentication and Credential Logging

Search for log statements that may capture:
- Passwords, PINs, or security codes
- API keys, tokens, or secrets
- Session IDs, authentication tokens, or bearer tokens
- JWT tokens, OAuth tokens, or refresh tokens
- Database credentials, connection strings, or certificates

## 2. Personal Identifiable Information (PII) Logging

Search for log statements that may capture:
- Social Security Numbers, tax IDs, or national identifiers
- Credit card numbers, bank account details, or payment information
- Email addresses, phone numbers, or personal contact details
- Names, addresses, or demographic data
- Medical records, health information, or biometric data

An actor identifier (user id, UPN, email or display name of the user performing the action) in an audit or application log is the required audit actor, not a finding. Flag name, email or phone only when logged as *payload* (the changed value, the full profile object, the request body).

## 3. Business Sensitive Data Logging

Search for log statements that may capture:
- Full customer records or transaction payloads (card data, bank details, amounts tied to a named person)
- Proprietary business logic or trade secrets
- Internal system configurations or infrastructure details (connection strings, credentials, internal hostnames)

Order ids, customer ids, counts and performance or usage metrics are not findings.

## 4. Common Logging Vulnerabilities

- Full object serialization including sensitive properties
- Exception messages that embed secrets or user input (e.g. `SqlException` carrying a connection string, an `ArgumentException` echoing a password) logged without redaction — full stack traces themselves are **required** in the log sink (see logging.md and exception_handling.md); the finding is sensitive values inside the message or `Exception.Data`, or stack traces reaching the HTTP response
- Request/response logging containing sensitive headers or bodies
- Debug logging left enabled in production
- Structured logging with sensitive data in log context or scope

## 5. Framework-Specific Checks

- **ASP.NET Core**: Request logging middleware exposing sensitive parameters
- **Serilog/NLog**: Structured logging with sensitive properties in log context
- **Entity Framework**: SQL query logging with sensitive parameter values (`EnableSensitiveDataLogging()` outside Development)
- **HTTP client logging**: Authorization headers or request bodies
- **Custom loggers**: Application-specific logging implementations

## 6. Logging Configuration Issues

- Log levels set too verbose in production (`Debug`, `Trace`) — owned by check 5 (logging.md); reference that finding instead of reporting it here
- Sensitive data not excluded via `[LogProperties]` / `[LogPropertyIgnore]` (`Microsoft.Extensions.Telemetry`), `Microsoft.Extensions.Compliance` redaction (`AddRedaction()`, `[DataClassification]` attributes) or Serilog `Destructurama.Attributed` `[NotLogged]`
- Global exception handlers writing exception details (message, stack trace, inner exceptions) into the HTTP response instead of only into the log — owned by check 4 (exception_handling.md); reference that finding instead of reporting it here
- Application Insights or APM tools capturing sensitive request data; query-string values captured in access logs or telemetry are owned by check 7 (sensitive_query_strings.md); reference that finding instead of reporting it here
- Log files stored in insecure locations

## 7. Data Masking and Redaction Gaps

- No masking for sensitive fields before logging
- Inconsistent redaction patterns across the application
- Sensitive data in plain text in log outputs
- Missing sanitization before logging user inputs

## 8. Compliance and Regulatory Concerns

- GDPR violations through excessive personal data logging
- PCI DSS violations with payment card data in logs
- HIPAA violations with health information in logs
- Financial regulation requirements not met through transaction logging

## 9. Files and Search Patterns

**Files to examine:**
- `appsettings*.json`, `Program.cs`, `Startup.cs` — logging, HTTP logging and EF configuration
- `*Behaviour.cs` / `*Behavior.cs`, `*Middleware.cs`, `*Interceptor.cs`, `*Filter.cs` — request/response and pipeline logging
- `azure-pipelines*.yml` — pipeline steps that echo secrets or set `System.Debug`
- `environment*.ts`, `*.interceptor.ts` — Angular `console.log` of tokens or responses

**Search patterns:**
```regex
Log(Information|Debug|Trace|Warning|Error|Critical)\(.*\b(password|pwd|secret|token|authorization|bearer|connectionstring|iban|bsn|ssn|creditcard|cvv)\b
\{@\w+\}                                           // Serilog destructuring of a whole object
EnableSensitiveDataLogging
ShowPII\s*=\s*true                                   // IdentityModelEventSource
HttpLoggingFields\.(All|RequestBody|ResponseBody|RequestQuery)
LogContext\.PushProperty\(                           // sensitive value pushed into the log scope
System\.Debug\s*[:=]\s*true                          // Azure DevOps diagnostic mode
console\.(log|debug|info)\([^)]*(token|password|Authorization)
```

## What to Report

For each finding, provide:
- **File** and line number
- **Log statement** or configuration entry
- **Data type** being logged (credential, PII, financial, etc.)
- **Severity**: Critical (credentials, tokens, session ids, BSN/SSN, PAN/CVV in logs) / High (special-category or financial payload; exception messages carrying connection strings or user secrets) / Medium (email, name or phone logged as payload rather than as the acting user; request or response bodies logged). Verbosity and sink configuration are owned by check 5 (logging.md) and are not rated here
- **Recommendation**: masking, redaction, or removal approach
