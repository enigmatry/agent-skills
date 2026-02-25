Please perform a comprehensive analysis of the codebase to verify the following logging requirements are properly implemented:

### 1. Unhandled Exception Logging with Stack Traces
**Requirement**: All unhandled exceptions must be captured and logged with complete stack traces using ASP.NET middleware or a global exception handler.

**Check for:**
- Global exception handling middleware (e.g., `UseExceptionHandler`, custom middleware)
- Exception filter attributes (e.g., `ExceptionFilterAttribute` implementations)
- Proper registration in startup/program configuration
- Stack trace inclusion in exception logging
- Coverage for both API controllers and general application exceptions

**Search patterns:**
- `UseExceptionHandler`, `ExceptionFilterAttribute`, `IExceptionFilter`
- `OnException`, `HandleException`, `GlobalException`
- `logger.LogError` with exception parameters
- Middleware registration in `Configure` or `Program.cs`

### 2. Console Application Logging with Debug Level
**Requirement**: Application logs should only be written to the console when the Debug level flag is set.

**Check for:**
- Console logging sink configuration in appsettings files
- Debug log level configuration for console output specifically
- Separation between console and file logging configurations
- Environment-specific settings (Development vs Production)
- Proper Serilog or built-in logging provider configuration

**Search patterns:**
- `Console` in logging configuration (appsettings.json, appsettings.Development.json)
- `"WriteTo"` with Console sink
- `"MinimumLevel"` settings for console logging
- `AddConsole()` method calls
- Environment-specific console logging setup

### 3. Separate Auditing Logs for Security Events
**Requirement**: All auditing events must be logged to a separate log file/provider, including:
- Logon attempts (successful and failed)
- Sign-out events
- Email address changes
- Role changes
- Organization/tenant changes
- Permission modifications

**Check for:**
- Separate audit log file or logging provider configuration
- Dedicated audit logger instances or categories
- Authentication event logging (OnAuthenticationFailed, OnTokenValidated, etc.)
- User modification event logging
- Role/permission change logging
- Proper separation from application logs using filters or separate loggers

**Search patterns:**
- Separate log file paths containing "audit"
- Authentication event handlers: `OnAuthenticationFailed`, `OnSignIn`, `OnSignOut`
- User change events: email changes, role assignments, organization updates
- Domain events or audit event handlers
- Filter expressions separating audit logs from application logs
- Dedicated audit logging categories or contexts

### Analysis Approach:
1. **Configuration Analysis**: Examine appsettings.json files for logging configuration
2. **Middleware Analysis**: Check Program.cs/Startup.cs for exception handling middleware
3. **Event Handler Analysis**: Look for authentication and user change event handlers
4. **Domain Event Analysis**: Check for audit-related domain events and their handlers
5. **Logging Pattern Analysis**: Search for actual logging statements in critical areas

### Expected Deliverables:
For each requirement, provide:
- ✅ **IMPLEMENTED** / ⚠️ **PARTIALLY IMPLEMENTED** / ❌ **NOT IMPLEMENTED**
- Specific file locations and line numbers where implementations are found
- Any gaps or missing components
- Security risks if requirements are not met
- Concrete recommendations for implementation or improvement

Please analyze the codebase systematically and provide a detailed report on compliance with these logging requirements.