Please scan my codebase for sensitive data being passed through query strings. Check for:

**1. Authentication & Authorization Data**
- API keys, tokens, or secrets in URL parameters
- User IDs, session IDs, or authentication tokens as query parameters
- Passwords, PINs, or security codes in query strings
- JWT tokens or bearer tokens passed via URL parameters
- OAuth tokens, refresh tokens, or authorization codes in URLs

**2. Personal Identifiable Information (PII)**
- Social Security Numbers, tax IDs, or national identifiers
- Email addresses, phone numbers, or personal contact information
- Names, addresses, or demographic data in query parameters
- Medical information, health records, or sensitive personal data
- Financial information like credit card numbers or bank account details

**3. Business Sensitive Data**
- Database connection strings or credentials in URLs
- Internal system identifiers that shouldn't be exposed
- Proprietary business data, pricing, or confidential information
- Customer data, orders, or transaction details in query strings
- Internal file paths, server names, or infrastructure details

**4. Common Vulnerable Patterns**
- URLs constructed with string concatenation including sensitive data
- Query parameters like `?password=`, `?token=`, `?secret=`, `?key=`
- Redirect URLs containing sensitive information
- Search parameters that might leak private data
- Debug or diagnostic URLs exposing internal state

**5. Framework-Specific Checks**
- ASP.NET Core: Query string parameters in controllers and action methods
- URL generation: `Url.Action()` or `Html.ActionLink()` with sensitive data
- Redirect methods: `RedirectToAction()` with sensitive parameters
- Form submissions using GET method instead of POST for sensitive data
- AJAX requests: JavaScript making GET requests with sensitive data

**6. HTTP Methods & Data Exposure**
- GET requests that should use POST for sensitive operations
- Form submissions with `method="GET"` containing sensitive fields
- Links or redirects that expose sensitive data in referrer headers
- Bookmarkable URLs that contain private information
- Shareable URLs that inadvertently expose confidential data

**7. Logging & Monitoring Risks**
- URLs with sensitive data being logged in access logs
- Query parameters captured in error logs or monitoring systems
- Browser history exposure of sensitive URL parameters
- Server logs, CDN logs, or proxy logs capturing sensitive URLs
- Analytics tools tracking URLs with private information

**8. Input Sources to Examine**
- URL builders and query string construction code
- Redirect logic and URL forwarding mechanisms
- Form action attributes and HTTP method specifications
- JavaScript URL manipulation and AJAX request construction
- Link generation in templates, views, or email content

Please provide:
- Specific file locations and line numbers where sensitive data appears in URLs
- Risk level assessment (Critical/High/Medium/Low) based on data sensitivity
- Examples of vulnerable URL construction patterns
- Alternative secure methods (POST, request headers, session storage)
- Framework-specific recommendations for secure data transmission
- Code examples showing proper secure alternatives