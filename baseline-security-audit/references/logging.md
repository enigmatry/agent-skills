# Logging Security Analysis

Analyze the codebase to verify that logging practices meet security requirements: unhandled exceptions are captured with full stack traces, console output is gated behind a debug flag, and security-relevant events are written to a dedicated audit log.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A09 Security Logging and Alerting Failures · **ASVS 5.0:** V16 Security Logging and Error Handling
> **Owns:** log sinks, levels, console output, audit separation (also encountered in 6)
> **Defers to:** global exception handler present and logging → check 4 (exception_handling.md); secrets, tokens or PII inside log messages or destructured objects → check 6 (sensitive_data_logging.md)

## Core Security Principle
**Logging must ensure all errors are captured for debugging while keeping sensitive details out of user-facing responses. Security events must be auditable and separated from general application logs.**

## 1. Unhandled Exception Logging

Verify that all unhandled exceptions are captured and logged with complete stack traces.

> Full stack traces in the **log sink** are required and are not a sensitive-data finding. What sensitive_data_logging.md flags is sensitive values inside exception messages (connection strings, tokens, user input) and exception details that reach the **HTTP response**. Do not report the same handler under both checks.

Whether a global exception handler is present and logs is owned by check 4 (exception_handling.md); reference that finding instead of reporting it here. This check reports only the sink side: exceptions that reach no configured sink, or `LogError(message)` calls that drop the exception object. Severity when exceptions are not logged at all = High.

**Check for:**
- Global exception handling middleware (`UseExceptionHandler`, custom middleware)
- Exception filter attributes (`ExceptionFilterAttribute` implementations)
- Proper registration in `Startup.cs` or `Program.cs`
- `logger.LogError(exception, message)` calls that include the exception object
- Coverage for both API controllers and general application exceptions

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

Audit records MUST contain the acting user's id, UPN or email as the actor, together with the timestamp, action, target and outcome. An actor identifier in an audit record is not a sensitive-data finding under check 6 (sensitive_data_logging.md); what check 6 flags is sensitive values carried as payload (the new password, the token, the full request body). Severity when authentication, authorization or privileged actions (role, permission, tenant changes) are not audited = High; audit events written only to the general application log with no separate sink or category = Medium.

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

## What to Report

For each of the three requirements above, provide:
- ✅ **IMPLEMENTED** / ⚠️ **PARTIALLY IMPLEMENTED** / ❌ **NOT IMPLEMENTED**
- Specific file locations and line numbers where implementations are found (or absent)
- Gaps or missing components
- Security risks if the requirement is not met
- **Severity** for each gap behind a PARTIALLY IMPLEMENTED or NOT IMPLEMENTED status:
  - No global exception logging (exceptions reach no sink, or are logged without the exception object) = High
  - Audit events not logged for authentication, authorization or privileged actions = High
  - Console the only sink in production, or `Microsoft.*` / `System.*` categories at `Information` or lower in production = Medium
  - Audit events not separated from the application log = Medium
  - Missing correlation ids = Low
- Concrete recommendations for implementation or improvement
