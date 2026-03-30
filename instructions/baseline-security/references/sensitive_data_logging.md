# Sensitive Data in Logs Analysis

Scan the codebase for sensitive data being written to logs, which could expose credentials, PII, or other confidential information through log files and aggregation systems.

## Core Security Principle
**Sensitive data — including credentials, tokens, PII, and financial information — must never appear in log output. Log statements must record what happened without recording the sensitive values involved.**

## 1. Authentication and Credential Logging

Search for log statements that may capture:
- Passwords, PINs, or security codes
- API keys, tokens, or secrets
- Session IDs, authentication tokens, or bearer tokens
- JWT tokens, OAuth tokens, or refresh tokens
- Database credentials, connection strings, or certificates

## 2. Personal Identifiable Information (PII) Logging

Search for log statements that may capture:
- Social Security Numbers, tax IDs, or national identifiers
- Credit card numbers, bank account details, or payment information
- Email addresses, phone numbers, or personal contact details
- Names, addresses, or demographic data
- Medical records, health information, or biometric data

## 3. Business Sensitive Data Logging

Search for log statements that may capture:
- Customer data, orders, or transaction details
- Proprietary business logic or trade secrets
- Internal system configurations or infrastructure details
- Pricing information or financial data
- Usage statistics or behavioural analytics

## 4. Common Logging Vulnerabilities

- Full object serialization including sensitive properties
- Exception logging that exposes sensitive stack traces or database internals
- Request/response logging containing sensitive headers or bodies
- Debug logging left enabled in production
- Structured logging with sensitive data in log context or scope

## 5. Framework-Specific Checks

- **ASP.NET Core**: Request logging middleware exposing sensitive parameters
- **Serilog/NLog**: Structured logging with sensitive properties in log context
- **Entity Framework**: SQL query logging with sensitive parameter values
- **HTTP client logging**: Authorization headers or request bodies
- **Custom loggers**: Application-specific logging implementations

## 6. Logging Configuration Issues

- Log levels set too verbose in production (`Debug`, `Trace`)
- Sensitive data not excluded via `[SkipLogging]` or destructuring policies
- Global exception handlers logging full exception details
- Application Insights or APM tools capturing sensitive request data
- Log files stored in insecure locations

## 7. Data Masking and Redaction Gaps

- No masking for sensitive fields before logging
- Inconsistent redaction patterns across the application
- Sensitive data in plain text in log outputs
- Missing sanitization before logging user inputs

## 8. Compliance and Regulatory Concerns

- GDPR violations through excessive personal data logging
- PCI DSS violations with payment card data in logs
- HIPAA violations with health information in logs
- Financial regulation requirements not met through transaction logging

## What to Report

For each finding, provide:
- **File** and line number
- **Log statement** or configuration entry
- **Data type** being logged (credential, PII, financial, etc.)
- **Risk**: CRITICAL (passwords, tokens, SSN, payment data) / HIGH (email, phone, PII) / MEDIUM (internal system details) / LOW (non-sensitive debug information left enabled in production)
- **Recommendation**: masking, redaction, or removal approach
