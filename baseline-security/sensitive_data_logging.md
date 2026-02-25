Please scan my codebase for sensitive data being logged inappropriately. Check for:

**1. Authentication & Credential Logging**
- Passwords, PINs, or security codes in log statements
- API keys, tokens, or secrets being logged
- Session IDs, authentication tokens, or bearer tokens in logs
- JWT tokens, OAuth tokens, or refresh tokens being logged
- Database credentials, connection strings, or certificates in logs

**2. Personal Identifiable Information (PII) Logging**
- Social Security Numbers, tax IDs, or national identifiers
- Credit card numbers, bank account details, or payment information
- Email addresses, phone numbers, or personal contact details
- Names, addresses, or demographic data in logs
- Medical records, health information, or biometric data

**3. Business Sensitive Data Logging**
- Customer data, orders, or transaction details
- Proprietary algorithms, business logic, or trade secrets
- Internal system configurations, server details, or infrastructure info
- Pricing information, financial data, or revenue details
- User behavior patterns, analytics data, or usage statistics

**4. Common Logging Vulnerabilities**
- Full object serialization including sensitive properties
- Exception logging that exposes sensitive stack traces
- Request/response logging containing sensitive headers or bodies
- Debug logging left enabled in production environments
- Structured logging with sensitive data in log context

**5. Framework-Specific Checks**
- ASP.NET Core: Request logging middleware exposing sensitive data
- Serilog/NLog: Structured logging with sensitive properties
- Entity Framework: SQL query logging with sensitive parameters
- HTTP client logging: Authorization headers or request bodies
- Custom loggers: Application-specific logging implementations

**6. Logging Configuration Issues**
- Log levels set too verbose in production (Debug, Trace)
- Sensitive data not marked with [SkipLogging] or similar attributes
- Global exception handlers logging full exception details
- Application Insights or monitoring tools capturing sensitive data
- Log files stored in insecure locations or with weak permissions

**7. Data Masking & Redaction Gaps**
- Lack of data masking for sensitive fields
- Inconsistent redaction patterns across the application
- Sensitive data visible in plain text in log outputs
- Missing sanitization before logging user inputs
- No differentiation between sensitive and non-sensitive data logging

**8. Compliance & Regulatory Concerns**
- GDPR violations through excessive personal data logging
- PCI DSS violations with payment card data in logs
- HIPAA violations with health information logging
- Financial regulations breached through transaction logging
- Industry-specific compliance requirements not met

**9. Log Storage & Transmission Security**
- Logs transmitted over unencrypted channels
- Log aggregation systems without proper access controls
- Cloud logging services with inadequate security configurations
- Log retention policies that don't consider data sensitivity
- Third-party logging services receiving sensitive data

**10. Development vs Production Logging**
- Debug information with sensitive data in production logs
- Development logging configurations deployed to production
- Test data or mock credentials appearing in production logs
- Verbose logging enabled for troubleshooting and never disabled
- Different logging behaviors between environments

Please provide:
- Specific file locations and line numbers where sensitive data is logged
- Risk level assessment (Critical/High/Medium/Low) based on data sensitivity
- Examples of sensitive data patterns found in logging statements
- Recommended data masking or redaction techniques
- Configuration changes needed to secure logging
- Framework-specific logging security best practices
- Code examples showing secure logging alternatives