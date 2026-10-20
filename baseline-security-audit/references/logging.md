# Logging Security Analysis

Analyze the codebase to verify that logging practices meet security requirements: unhandled exceptions are captured with full stack traces, console output is gated behind a debug flag, security-relevant events are written to a dedicated audit log, and no credentials, tokens, PII or other confidential values are written to log output.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A09 Security Logging and Alerting Failures · **ASVS 5.0:** V16 Security Logging and Error Handling, V14 Data Protection

## Core Security Principle
**Logging must ensure all errors are captured for debugging while keeping sensitive details out of user-facing responses. Security events must be auditable and separated from general application logs. Sensitive data — including credentials, tokens, PII, and financial information — must never appear in log output: log statements must record what happened without recording the sensitive values involved.**

## 1. Unhandled Exception Logging

Verify that all unhandled exceptions are captured and logged with complete stack traces.

> Full stack traces in the **log sink** are required and are not a sensitive-data finding. What section 4 flags is sensitive values inside exception messages (connection strings, tokens, user input) and exception details that reach the **HTTP response**. Do not report the same handler under both sections.

See check 4 (exception_handling.md) for whether a global handler exists and for exception details in HTTP responses. This check reports only the sink side: exceptions that reach no configured sink, or `LogError(message)` calls that drop the exception object. Severity when exceptions are not logged at all = High.

**Search patterns:**
- `UseExceptionHandler`, `AddExceptionHandler<T>()`, `IExceptionHandler` (.NET 8+), `AddProblemDetails()`
- `ExceptionFilterAttribute`, `IExceptionFilter`, `OnException`, `HandleException`, `GlobalException`
- `logger.LogError` with exception parameters
- Middleware registration in `Configure` or `Program.cs`
- .NET 10 only: an `IExceptionHandler` that returns `true` without calling `LogError` and without `ExceptionHandlerOptions.SuppressDiagnosticsCallback` configured — the middleware no longer logs for it (see exception_handling.md, section 1); .NET 8 and 9 log automatically

## 2. Console Logging Configuration

Verify that application logs are only written to the console when the Debug log level is active.

**Check for:**
- Console logging sink configuration in appsettings files
- Minimum log level set appropriately for console output
- Separation between console and file or structured logging configurations
- Environment-specific settings (Development vs. Production)
- Serilog or built-in logging provider configuration

**Search patterns:**
- `Console` in logging configuration (`appsettings.json`, `appsettings.Development.json`)
- `"WriteTo"` with Console sink
- `"MinimumLevel"` settings for console logging
- `AddConsole()` method calls
- `"Microsoft"`, `"Microsoft.AspNetCore"`, `"Microsoft.EntityFrameworkCore"` or `"System"` categories left at `Information` or lower in `appsettings.json` / `appsettings.Production.json` (framework noise and SQL text in production logs)

Severity: console the only sink in production, or framework categories at `Information` or lower in production = Medium; no correlation id (`HttpContext.TraceIdentifier`, `Activity.Current.Id`, Serilog `{CorrelationId}` / `{TraceId}`) in the output template = Low.

## 3. Audit Log Separation

Verify that security-relevant events are written to a dedicated audit log, separate from general application logs. Events to cover:
- Logon attempts (successful and failed)
- Sign-out events
- Email address changes
- Role changes
- Organisation or tenant changes
- Permission modifications
- Password change and reset
- MFA enrolment and removal
- Token or API-key issuance and revocation
- Privileged or admin actions
- Access to, export or deletion of sensitive records
- Consent changes
- Failed authorization (403)
- Configuration changes
- When sign-in is delegated to Entra ID, sign-in and MFA events live in the Entra sign-in and audit logs; their absence in the app is not a finding

Audit records MUST contain the acting user's id, UPN or email as the actor, together with the timestamp, action, target and outcome (section 4 explains why the actor identifier is not a sensitive-data finding). Severity when authentication, authorization or privileged actions (role, permission, tenant changes) are not audited = High; audit events written only to the general application log with no separate sink or category = Medium.

**Check for:**
- Separate audit log file or logging provider configuration
- Dedicated audit logger instances or named categories
- Authentication event logging (`OnAuthenticationFailed`, `OnTokenValidated`, etc.)
- User modification event logging
- Role and permission change logging
- Filter expressions routing audit events away from the application log

**Search patterns:**
- Separate log file paths containing `audit`
- Authentication event handlers: `OnSignedIn`, `OnSigningIn`, `OnSigningOut` (`CookieAuthenticationEvents`); `OnTokenValidated`, `OnAuthenticationFailed` (`JwtBearerEvents` / `OpenIdConnectEvents`)
- User change events: email changes, role assignments, organisation updates
- Domain events or audit event handlers
- Dedicated audit logging categories or contexts
- Audit-sink patterns: Serilog `.Filter.ByIncludingOnly(Matching.FromSource("Audit"))` sub-logger or `AuditTo`, an `ILogger<AuditLogger>` category routed to its own sink, an EF `SaveChangesInterceptor` writing an `AuditLog` table

**Alerting (OWASP A09 is "Logging and Alerting Failures"):** look for Azure Monitor alert rules (`Microsoft.Insights/scheduledQueryRules` or `metricAlerts` in Bicep, `az monitor` in pipelines) or Sentinel analytics rules covering failed-login bursts, 5xx spikes and audit-log silence (no audit events for N hours), and for log-shipping health (diagnostic settings or agent heartbeat). No alerting on security events, found in code or confirmed by the user = High.

**Audit log integrity and retention:** the audit sink must be append-only or immutable (Log Analytics table retention, immutable/WORM blob container, a table the app identity can only `INSERT` into), access to logs restricted (RBAC on the workspace or storage account) and a retention period defined (Bicep `retentionInDays`, Serilog `retainedFileCountLimit`). Serilog audit events go through `AuditTo` (fails loudly) rather than `WriteTo`; a shared file sink the app identity can rewrite is not an audit log. Missing integrity or retention evidence = Medium; audit events writable or deletable by the application identity = High.

## 4. Sensitive Data in Logs

Scan the codebase for sensitive data being written to logs, which could expose credentials, PII, or other confidential information through log files and aggregation systems.

### 4.1 Authentication and Credential Logging

Search for log statements that may capture:
- Passwords, PINs, or security codes
- API keys, tokens, or secrets
- Session IDs, authentication tokens, or bearer tokens
- JWT tokens, OAuth tokens, or refresh tokens
- Database credentials, connection strings, or certificates

### 4.2 Personal Identifiable Information (PII) Logging

Search for log statements that may capture:
- Social Security Numbers, tax IDs, or national identifiers
- Credit card numbers, bank account details, or payment information
- Email addresses, phone numbers, or personal contact details
- Names, addresses, or demographic data
- Medical records, health information, or biometric data

An actor identifier (user id, UPN, email or display name of the user performing the action) in an audit or application log is the required audit actor (section 3), not a finding. Flag name, email or phone only when logged as *payload* (the changed value, the full profile object, the request body).

### 4.3 Business Sensitive Data Logging

Search for log statements that may capture:
- Full customer records or transaction payloads (card data, bank details, amounts tied to a named person)
- Proprietary business logic or trade secrets
- Internal system configurations or infrastructure details (connection strings, credentials, internal hostnames)

Order ids, customer ids, counts and performance or usage metrics are not findings.

### 4.4 Common Logging Vulnerabilities

- Full object serialization including sensitive properties
- Exception messages that embed secrets or user input (e.g. `SqlException` carrying a connection string, an `ArgumentException` echoing a password) logged without redaction — full stack traces themselves are **required** in the log sink (section 1); the finding is sensitive values inside the message or `Exception.Data`, or stack traces reaching the HTTP response
- Request/response logging containing sensitive headers or bodies
- Debug logging left enabled in production (section 2)
- Structured logging with sensitive data in log context or scope

### 4.5 Framework-Specific Checks

- **ASP.NET Core**: Request logging middleware exposing sensitive parameters
- **Serilog/NLog**: Structured logging with sensitive properties in log context
- **Entity Framework**: SQL query logging with sensitive parameter values (`EnableSensitiveDataLogging()` outside Development)
- **HTTP client logging**: Authorization headers or request bodies
- **Custom loggers**: Application-specific logging implementations

### 4.6 Logging Configuration Issues

- Sensitive data not excluded via `[LogProperties]` / `[LogPropertyIgnore]` (`Microsoft.Extensions.Telemetry`), `Microsoft.Extensions.Compliance` redaction (`AddRedaction()`, `[DataClassification]` attributes) or Serilog `Destructurama.Attributed` `[NotLogged]`
- Application Insights or APM tools capturing sensitive request data
- Log files stored in insecure locations

See check 6 (sensitive_query_strings.md) for query-string values in access logs and for the OpenTelemetry `url.query` redaction switch (`DISABLE_URL_QUERY_REDACTION` / `DisableUrlQueryRedaction`).

### 4.7 Data Masking and Redaction Gaps

- No masking for sensitive fields before logging
- Inconsistent redaction patterns across the application
- Sensitive data in plain text in log outputs
- Missing sanitization before logging user inputs
- Log injection: `LogInformation($"User {name} logged in")` — string interpolation instead of a message template lets user input forge log lines (CRLF) and breaks structured logging (Sonar S6670); interpolated user input in a log call = Low

## 5. Files and Search Patterns

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
scheduledQueryRules|metricAlerts|actionGroups|SecurityInsights   // alert rules (section 3); none = High
AuditTo\.|WriteTo\.File\([^)]*[Aa]udit|retentionInDays|immutab   // audit sink integrity and retention (section 3)
Log(Information|Warning|Error|Debug|Trace)\(\$"                   // log injection via interpolation (section 4.7); Low
```

## What to Report

For each of requirements 1–3, provide:
- ✅ **IMPLEMENTED** / ⚠️ **PARTIALLY IMPLEMENTED** / ❌ **NOT IMPLEMENTED**
- Specific file locations and line numbers where implementations are found (or absent)
- Gaps or missing components
- Security risks if the requirement is not met
- Concrete recommendations for implementation or improvement

For each sensitive-data finding (section 4), provide:
- **File** and line number
- **Log statement** or configuration entry
- **Data type** being logged (credential, PII, financial, etc.)
- **Recommendation**: masking, redaction, or removal approach

**Severity** for each gap or finding:
- **Critical**: credentials, tokens, session ids, BSN/SSN, PAN/CVV in logs
- **High**: no global exception logging (exceptions reach no sink, or are logged without the exception object); audit events not logged for authentication, authorization or privileged actions; no alerting on security events; audit events writable or deletable by the application identity; special-category or financial payload in logs; exception messages carrying connection strings or user secrets
- **Medium**: console the only sink in production, or `Microsoft.*` / `System.*` categories at `Information` or lower in production; audit events not separated from the application log; no evidence of audit-log integrity, access control or retention; email, name or phone logged as payload rather than as the acting user; request or response bodies logged
- **Low**: missing correlation ids; interpolated user input in a log call (log injection)
