# Exception Handling Security Analysis

Analyze the codebase for secure exception handling that logs complete error details while protecting users from sensitive information exposure:

### Core Security Requirement:
**All unhandled exceptions must be logged with full stack traces, but actual error details and stack traces must NEVER be visible to users in non-development environments, including API responses.**

### 1. Exception Logging Check
**Verify:**
- Global exception handler captures ALL unhandled exceptions
- Full stack traces logged using `logger.LogError(exception, message)`
- Proper exception context (request details, user info, correlation IDs)

**Search for:** `UseExceptionHandler`, `AddExceptionHandler<T>()` / `IExceptionHandler` (.NET 8+), `AddProblemDetails()` / `IProblemDetailsService`, `UseStatusCodePages()`, `ExceptionFilterAttribute`, `OnException`, global middleware registration

> **.NET 10 behaviour change:** when an `IExceptionHandler.TryHandleAsync` returns `true`, `ExceptionHandlerMiddleware` no longer logs the exception or emits the `error.type` metric unless `ExceptionHandlerOptions.SuppressDiagnosticsCallback` returns `false`. On .NET 10 projects, any handler that returns `true` must itself call `logger.LogError(exception, ...)`, or the callback must be configured; otherwise report "unhandled exceptions not logged" as HIGH. On .NET 8 and 9 the middleware logs before invoking the handler, so a handler without its own `LogError` is not a gap. Determine the version from `<TargetFramework>`.

### 2. Secure Error Response Analysis
**Critical Security Check - In PRODUCTION:**
- ❌ No stack traces in API responses
- ❌ No internal error messages exposed
- ❌ No database/file paths visible
- ✅ Only generic, user-friendly messages returned
- ✅ Proper HTTP status codes (400, 401, 403, 404, 500)
- ✅ Structured responses (ProblemDetails format)

**Look for dangerous patterns:** `exception.ToString()`, `exception.Message`, `exception.StackTrace` in responses

### 3. Environment-Specific Behavior
**Verify:**
- Development: Detailed errors allowed for debugging
- Production/Staging: Generic messages only
- Configuration-driven: `UseDeveloperExceptionPage()` properly gated
- No hardcoded environment checks

### 4. Response Format Security
**Secure response example:**
```json
{
  "title": "An error occurred while processing your request",
  "status": 500,
  "instance": "/api/resource/123"
}
```

**Insecure response (avoid):**
```json
{
  "error": "SqlException: Cannot connect to 'internal-db-01'",
  "stackTrace": "at System.Data.SqlClient..."
}
```

### Expected Results:
For each area, provide:
- ✅ **SECURE** / ⚠️ **PARTIALLY SECURE** / ❌ **INSECURE**
- Specific vulnerabilities with file locations
- Examples of problematic error responses
- Concrete remediation steps

### Key Security Questions:
1. Can users see stack traces or internal details through API responses?
2. Do error messages reveal system architecture or database information?
3. Are all exceptions properly caught and logged without exposure?
4. Is environment-specific error handling correctly implemented?

Focus on preventing information disclosure while ensuring comprehensive logging for debugging.
