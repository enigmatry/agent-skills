# Sensitive Query Strings Analysis

Scan the codebase for sensitive data being transmitted in URL query parameters, which exposes that data in server logs, browser history, proxy logs, and referrer headers.

## Core Security Principle
**Sensitive data must never be placed in URL query parameters. Authentication tokens, credentials, and PII must be transmitted in request headers or the request body using POST over HTTPS.**

## 1. Authentication and Authorization Data in URLs

Search for query parameters that carry:
- API keys, tokens, or secrets
- User IDs, session IDs, or authentication tokens
- Passwords, PINs, or security codes
- JWT or bearer tokens
- OAuth tokens, refresh tokens, or authorization codes

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
- Redirect URLs containing sensitive information
- Debug or diagnostic URLs exposing internal state
- Search parameters that leak private data

## 5. Framework-Specific Checks

- **ASP.NET Core**: Query string parameters in controller actions
- **URL generation**: `Url.Action()` or `Html.ActionLink()` passing sensitive data
- **Redirect methods**: `RedirectToAction()` with sensitive parameters
- **Forms**: `method="GET"` on forms that submit sensitive fields
- **AJAX**: JavaScript constructing GET requests with sensitive data

## 6. HTTP Method and Exposure Risks

- GET requests that should use POST for sensitive operations
- Form submissions with `method="GET"` containing sensitive fields
- Links or redirects that expose sensitive data via referrer headers
- Bookmarkable or shareable URLs containing private information

## 7. Logging and Monitoring Risks

- URLs with sensitive query parameters being written to access logs
- Browser history exposure of sensitive URL parameters
- Analytics tools tracking URLs with private information
- CDN or proxy logs capturing sensitive query parameters

## What to Report

For each finding, provide:
- **File** and line number
- **Code snippet** showing the URL or query string construction
- **Data type** being exposed (credential, PII, etc.)
- **Risk**: HIGH (passwords, tokens, SSN) / MEDIUM (email, user IDs, personal data) / LOW (internal identifiers with limited exposure)
- **Recommendation**: use POST body, request headers, or server-side session storage instead
