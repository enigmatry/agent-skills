Please scan my codebase for potential SQL injection vulnerabilities. Check for:

**1. Dynamic SQL Construction**
- String interpolation in SQL queries ($"SELECT * FROM Users WHERE Id = '{userId}'")
- String concatenation with user input ("SELECT * FROM " + tableName)
- StringBuilder used to build SQL with user data
- String.Format() with SQL and user parameters

**2. Raw SQL Execution**
- ExecuteSqlRaw() or ExecuteSqlInterpolated() calls
- FromSqlRaw() or FromSqlInterpolated() usage
- CommandText assignments with dynamic content
- Database.SqlQuery() or similar raw SQL methods

**3. Stored Procedure Calls**
- Dynamic stored procedure name construction
- Parameter values built through string manipulation
- CommandType.StoredProcedure with concatenated names

**4. ORM Vulnerabilities**
- Raw SQL in Entity Framework queries
- Dynamic LINQ expressions built from strings
- Unsafe Where() clauses with string operations
- HQL/native SQL in Hibernate (if applicable)

**5. Input Sources to Validate**
- User input from forms, APIs, query strings
- URL parameters used in queries
- File uploads that generate SQL
- Configuration values that might be tampered

**6. Common Patterns to Flag**
- Any SQL keyword (SELECT, INSERT, UPDATE, DELETE) followed by string operations
- WHERE clauses built dynamically
- ORDER BY with dynamic column names
- Table/column names from user input
- LIKE patterns with unescaped wildcards

**7. Framework-Specific Checks**
- Check if parameterized queries are used consistently
- Verify proper escaping mechanisms are in place
- Look for bypass of built-in protections
- Examine custom SQL builders or ORMs

Please provide:
- Specific file locations and line numbers
- Risk level assessment (High/Medium/Low)
- Code examples of vulnerabilities found
- Recommended fixes with secure code alternatives
- Overall security assessment and best practices