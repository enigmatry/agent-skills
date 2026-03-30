# Logging Security Analysis

Analyze the codebase to verify that logging practices meet security requirements: unhandled exceptions are captured with full stack traces, console output is gated behind a debug flag, and security-relevant events are written to a dedicated audit log.

## Core Security Principle
**Logging must ensure all errors are captured for debugging while keeping sensitive details out of user-facing responses. Security events must be auditable and separated from general application logs.**

## 1. Unhandled Exception Logging

Verify that all unhandled exceptions are captured and logged with complete stack traces.

**Check for:**
- Global exception handling middleware (`UseExceptionHandler`, custom middleware)
- Exception filter attributes (`ExceptionFilterAttribute` implementations)
- Proper registration in `Startup.cs` or `Program.cs`
- `logger.LogError(exception, message)` calls that include the exception object
- Coverage for both API controllers and general application exceptions

**Search patterns:**
- `UseExceptionHandler`, `ExceptionFilterAttribute`, `IExceptionFilter`
- `OnException`, `HandleException`, `GlobalException`
- `logger.LogError` with exception parameters
- Middleware registration in `Configure` or `Program.cs`

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

## 3. Audit Log Separation

Verify that security-relevant events are written to a dedicated audit log, separate from general application logs. Events to cover:
- Logon attempts (successful and failed)
- Sign-out events
- Email address changes
- Role changes
- Organisation or tenant changes
- Permission modifications

**Check for:**
- Separate audit log file or logging provider configuration
- Dedicated audit logger instances or named categories
- Authentication event logging (`OnAuthenticationFailed`, `OnTokenValidated`, etc.)
- User modification event logging
- Role and permission change logging
- Filter expressions routing audit events away from the application log

**Search patterns:**
- Separate log file paths containing `audit`
- Authentication event handlers: `OnAuthenticationFailed`, `OnSignIn`, `OnSignOut`
- User change events: email changes, role assignments, organisation updates
- Domain events or audit event handlers
- Dedicated audit logging categories or contexts

## What to Report

For each of the three requirements above, provide:
- ✅ **IMPLEMENTED** / ⚠️ **PARTIALLY IMPLEMENTED** / ❌ **NOT IMPLEMENTED**
- Specific file locations and line numbers where implementations are found (or absent)
- Gaps or missing components
- Security risks if the requirement is not met
- Concrete recommendations for implementation or improvement
