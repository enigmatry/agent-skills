# Sensitive Query Strings Analysis

Scan the codebase for sensitive data being transmitted in URL query parameters, which exposes that data in server logs, browser history, proxy logs, and referrer headers.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A04 Cryptographic Failures (data exposure) · **ASVS 5.0:** V14 Data Protection

## Core Security Principle
**Sensitive data must never be placed in URL query parameters. Authentication tokens, credentials, and PII must be transmitted in request headers or the request body using POST over HTTPS.**

## 1. Authentication and Authorization Data in URLs

Search for query parameters that carry:
- API keys, tokens, or secrets
- Session IDs or authentication tokens
- Passwords, PINs, or security codes
- JWT or bearer tokens
- OAuth access or refresh tokens

Not findings: opaque ids and REST path ids (`/users/{id}`). See check 7 (idor.md) for a sequential id that the server trusts for authorization without an ownership check. The OAuth `?code=` on the redirect URI is by design: flag only an authorization code written to logs. See check 19 (authentication_security.md) for a missing PKCE.

## 2. Personal Identifiable Information (PII) in URLs

Search for query parameters that carry:
- Social Security Numbers, tax IDs, or national identifiers
- Email addresses, phone numbers, or personal contact information
- Names, addresses, or demographic data
- Medical information or health records
- Financial information such as credit card numbers or account details

## 3. Business Sensitive Data in URLs

Search for query parameters that carry:
- Database connection strings or credentials
- Internal system identifiers that should not be exposed
- Proprietary or confidential business data
- Customer data, orders, or transaction details
- Internal file paths, server names, or infrastructure details

## 4. Vulnerable URL Construction Patterns

- URLs constructed with string concatenation including sensitive data
- Query parameters named `?password=`, `?token=`, `?secret=`, or `?key=`
  A password-reset link with `?token=` is the OWASP-recommended pattern; the finding there is a token that is not single-use or does not expire, or a reset page that loads third-party resources without `Referrer-Policy: no-referrer`
- Outbound credentials in URLs built by the application: `?apikey=`/`?key=` to third parties, webhook URLs that embed tokens, `UriBuilder` or string interpolation putting a secret into an `HttpClient` request URL, Azure DevOps URLs carrying a PAT. Secret in an outbound URL = High (it lands in the third party's and every proxy's logs); send it in an `Authorization` header instead
- Redirect URLs containing sensitive information
- Debug or diagnostic URLs exposing internal state
- Search parameters that leak private data

## 5. Framework-Specific Checks

- **ASP.NET Core**: `[FromQuery]` parameters on controller actions that bind tokens, passwords or PII
- **Redirect methods**: `Redirect()`, `LocalRedirect()` or `RedirectToAction()` with sensitive route values
- **Angular `HttpParams`**: `new HttpParams().set('token', ...)` or `{ params: { email } }` on `HttpClient.get`
- **Angular router**: `router.navigate([...], { queryParams: { token, email } })` and `[queryParams]` bindings in templates
- **Template-literal URLs**: `${baseUrl}/export?token=${token}` built in services
- **Downloads**: `window.open(url)` or `<a [href]>` with a token or SAS signature appended for file downloads instead of an authenticated `HttpClient` blob request
- **Legacy (.NET Framework MVC / Razor), not expected on this stack**: `Url.Action()`, `Html.ActionLink()`, `method="GET"` forms

## 6. HTTP Method and Exposure Risks

- GET requests that should use POST for sensitive operations
- Angular reactive forms submitted with `HttpClient.get` and form values as params (legacy Razor `method="GET"` forms are not expected on this stack)
- Links or redirects that expose sensitive data via referrer headers
- Token-bearing pages (reset, invitation, magic link): the token leaks through the `Referer` header to every third-party resource the page loads and through `window.opener` from links it opens. Require `Referrer-Policy: no-referrer` on such pages (the header itself is check 14 (security_headers.md)) and `rel="noopener noreferrer"` on outbound `target="_blank"` links; search `target="_blank"` without `rel=`. Token-bearing page loading third-party resources without `no-referrer` = Medium
- Bookmarkable or shareable URLs containing private information

## 7. Logging and Monitoring Risks

- URLs with sensitive query parameters being written to access logs
- Where the full URL is written on this stack: IIS W3C logs include `cs-uri-query` by default (`<logFile logExtFileFlags="...UriQuery...">`), App Service web-server logging (same W3C format), Application Insights `request.url` (`requests | project url`), `Microsoft.AspNetCore.Hosting.Diagnostics` "Request starting" at `Information` (full path and query), `HttpLoggingFields.RequestQuery` (pattern owned by check 5 (logging.md)), OpenTelemetry `url.query` (redacted by default)
- `OTEL_DOTNET_EXPERIMENTAL_ASPNETCORE_DISABLE_URL_QUERY_REDACTION=true` (or the `HTTPCLIENT` variant) switches that redaction off = Medium; otherwise rate the value in the URL per What to Report, not the sink
- Browser history exposure of sensitive URL parameters
- Analytics tools tracking URLs with private information
- CDN or proxy logs capturing sensitive query parameters

## 8. Files and Search Patterns

**Files to examine:**
- `*.service.ts`, `*.component.ts`, `*.interceptor.ts` — Angular URL and param construction
- `*Controller.cs`, `*Client.cs` — `[FromQuery]` binding and outbound URLs
- `*.http` — request files that document the real URLs

**Search patterns:**
```regex
[?&](token|access_token|api[_-]?key|apikey|secret|password|pwd|sig|sas)=
HttpParams\(\)[^;]*\.set\(['"](token|password|email|bsn|ssn)
queryParams:\s*\{[^}]*(token|email|password)
window\.open\([^)]*(token|access_token)
\$\{[^}]*(token|password)[^}]*\}                  // inside a URL template literal
\[FromQuery\][^,)]*(token|password|email|bsn|ssn)
logExtFileFlags|DISABLE_URL_QUERY_REDACTION|"Microsoft\.AspNetCore\.Hosting\.Diagnostics"\s*:\s*"(Information|Debug|Trace)"   // URL sinks (section 7)
```

## What to Report

For each finding, provide:
- **File** and line number
- **Code snippet** showing the URL or query string construction
- **Data type** being exposed (credential, PII, etc.)
- **Severity**: High (bearer or API tokens, passwords, session ids or SAS signatures in URLs built by the application, including outbound calls and webhook URLs) / Medium (PII such as email, BSN or date of birth in query strings; OpenTelemetry URL-query redaction switched off; token-bearing page loading third-party resources without `Referrer-Policy: no-referrer`) / Low (everything else, e.g. internal identifiers with limited exposure). Opaque or REST path ids are not findings
- **Recommendation**: use POST body, request headers, or server-side session storage instead
