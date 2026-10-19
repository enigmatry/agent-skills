# Exception Handling Security Analysis

Analyze the codebase for secure exception handling that logs complete error details while protecting users from sensitive information exposure:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A10 Mishandling of Exceptional Conditions · **ASVS 5.0:** V16 Security Logging and Error Handling

## Core Security Requirement:
**All unhandled exceptions must be logged with full stack traces, but actual error details and stack traces must NEVER be visible to users in non-development environments, including API responses.**

## 1. Exception Logging Check
**Verify:**
- Global exception handler captures ALL unhandled exceptions
- Full stack traces logged using `logger.LogError(exception, message)`
- Proper exception context (request details, user info, correlation IDs)

Full stack traces go to the log sink; secrets, tokens or PII inside the logged message or a destructured exception object must be redacted (see check 5 (logging.md)).

**Search for:** `UseExceptionHandler`, `AddExceptionHandler<T>()` / `IExceptionHandler` (.NET 8+), `AddProblemDetails()` / `IProblemDetailsService`, `UseStatusCodePages()`, `ExceptionFilterAttribute`, `OnException`, global middleware registration

> **.NET 10 behaviour change:** when an `IExceptionHandler.TryHandleAsync` returns `true`, `ExceptionHandlerMiddleware` no longer logs the exception or emits the `error.type` metric unless `ExceptionHandlerOptions.SuppressDiagnosticsCallback` returns `false`. On .NET 10 projects, any handler that returns `true` must itself call `logger.LogError(exception, ...)`, or the callback must be configured; otherwise report "unhandled exceptions not logged" as High. On .NET 8 and 9 the middleware logs before invoking the handler, so a handler without its own `LogError` is not a gap. Determine the version from `<TargetFramework>`.

## 2. Secure Error Response Analysis
**Critical Security Check - in any environment other than Development:**
- ❌ No stack traces in API responses
- ❌ No internal error messages exposed
- ❌ No database/file paths visible
- ✅ Only generic, user-friendly messages returned
- ✅ Proper HTTP status codes (400, 401, 403, 404, 500)
- ✅ Structured responses (ProblemDetails format)

**Look for dangerous patterns:** `exception.ToString()`, `exception.Message`, `exception.StackTrace` in responses, including `Problem(detail: ex.Message)`, `Results.Problem(ex.Message)` and `ValidationProblem` writers that echo raw exception text (Medium). Domain exceptions such as `NotFoundException`/`ValidationException` whose message is written for the client are not findings; only `Message` from non-domain exceptions (`SqlException`, `IOException`, `HttpRequestException`, plain `Exception`) counts.

**Fail-open catch blocks (A10 covers fail-open as well as disclosure):** empty `catch { }`, `catch (Exception) { return true; }` or `return Ok()` inside authorization handlers (`AuthorizationHandler<T>`), validators or payment code. Search `catch\s*(\(\w*\))?\s*\{\s*\}` and `catch[^}]*return (true|Ok\()`. Fail-open in an authorization or validation path = High.

## 3. Environment-Specific Behavior
**Verify:**
- Development: Detailed errors allowed for debugging
- Any environment other than Development: generic messages only
- Configuration-driven: `UseDeveloperExceptionPage()` properly gated behind `app.Environment.IsDevelopment()` (on .NET 8+ the `WebApplication` template adds it automatically in Development)
- No `#if DEBUG` and no string compares against `"Development"`/`"Production"`; use `IHostEnvironment.IsDevelopment()`/`IsEnvironment(...)`
- IIS / App Service layer (`web.config`, `web.release.config`, release-pipeline variables): `<customErrors mode="Off">` (legacy), `<httpErrors errorMode="Detailed">` or `existingResponse="PassThrough"` while detailed errors are on, `ASPNETCORE_DETAILEDERRORS=true` or `ASPNETCORE_ENVIRONMENT=Development` in `<environmentVariables>` or pipeline variables = High (detailed errors reachable in production); `stdoutLogEnabled="true"` with `stdoutLogFile` under `wwwroot` or another served path = Medium
- ProblemDetails libraries: Hellang.Middleware.ProblemDetails `IncludeExceptionDetails = (ctx, ex) => true` (or not gated on `IsDevelopment()`), `ProblemDetailsOptions.CustomizeProblemDetails` copying `ex.ToString()`/`ex.Message` into `Detail` = High when unconditional in production

## 4. Response Format Security
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

## Expected Results:
For each area, provide:
- ✅ **SECURE** / ⚠️ **PARTIALLY SECURE** / ❌ **INSECURE** (assessment status, not a severity)
- For every ⚠️ or ❌ status, one finding per issue carrying a severity:
  - Stack trace or exception detail in an HTTP response in any environment other than Development — High
  - No global exception handler (`UseExceptionHandler`/`IExceptionHandler`/exception filter) — High
  - Unhandled exceptions not logged (including the .NET 10 `TryHandleAsync` case above) — High
  - Handler that swallows the exception without logging it — Medium
  - `exception.Message` from a non-domain exception in a response, including `Problem(detail: ex.Message)`/`Results.Problem(ex.Message)` — Medium
  - Fail-open catch block in an authorization or validation path — High
  - `UseDeveloperExceptionPage()` not gated, or environment detected via `#if DEBUG`/string compares — Medium
  - Detailed errors enabled at the IIS/App Service layer (`customErrors`/`httpErrors`/`ASPNETCORE_DETAILEDERRORS`/`ASPNETCORE_ENVIRONMENT=Development` in production) or an unconditional `IncludeExceptionDetails`/`CustomizeProblemDetails` copying exception text — High; `stdoutLogEnabled="true"` writing under `wwwroot` — Medium
  - Domain exceptions (`NotFoundException`, `ValidationException`, ...) surfacing their message — not a finding
- Specific vulnerabilities with file locations
- Examples of problematic error responses
- Concrete remediation steps

## Key Security Questions:
1. Can users see stack traces or internal details through API responses?
2. Do error messages reveal system architecture or database information?
3. Are all exceptions properly caught and logged without exposure?
4. Is environment-specific error handling correctly implemented?

Focus on preventing information disclosure while ensuring comprehensive logging for debugging.
