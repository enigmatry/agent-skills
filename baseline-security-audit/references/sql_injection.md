# SQL Injection Analysis

Scan the codebase for SQL injection vulnerabilities where user input is incorporated into SQL queries without proper parameterization or escaping.

## Core Security Principle
**All database queries must use parameterized queries or prepared statements. User input must never be concatenated or interpolated directly into SQL strings.**

## 1. Dynamic SQL Construction

Search for string interpolation, concatenation, or formatting used to build SQL queries:
- String interpolation in SQL queries (e.g. `$"SELECT * FROM Users WHERE Id = '{userId}'"`)
- String concatenation with user input (e.g. `"SELECT * FROM " + tableName`)
- `StringBuilder` used to build SQL with user-supplied data
- `String.Format()` with SQL and user parameters

## 2. Raw SQL Execution

**Unsafe unless every dynamic value is passed as a parameter** (these accept a plain `string`):
- `FromSqlRaw()`, `ExecuteSqlRaw()`, `ExecuteSqlRawAsync()`, `SqlQueryRaw<T>()`
- `CommandText` assignments with dynamic content (`SqlCommand`, Dapper `Query`/`Execute`)
- Flag when the SQL string is built with `+`, `$"..."` assigned to a `string` first, `string.Format`, `StringBuilder`, or `string.Concat`

**Safe by construction** (these take a `FormattableString` and EF Core parameterizes every `{value}`):
- `FromSql()`, `FromSqlInterpolated()`, `ExecuteSql()`, `ExecuteSqlInterpolated()`, `SqlQuery<T>()`
- Do **not** flag these. The only exception is when the argument is a pre-built string cast or converted to `FormattableString` (e.g. `FromSqlInterpolated($"{alreadyConcatenatedSql}")` or `FormattableStringFactory.Create(sql)`), which defeats the parameterization.

## 3. Stored Procedure Calls

Check for unsafe stored procedure invocation:
- Dynamic stored procedure name construction
- Parameter values built through string manipulation
- `CommandType.StoredProcedure` with concatenated names

## 4. ORM Vulnerabilities

Check for unsafe raw queries within ORMs:
- Raw SQL passed to Entity Framework methods
- Dynamic LINQ expressions built from user-supplied strings
- Unsafe `Where()` clauses with string operations
- HQL or native SQL queries (if applicable)

## 5. Input Sources to Validate

Identify all user-controlled input flowing into queries:
- Form fields, API request bodies, and query string parameters
- URL route parameters used in queries
- File-upload metadata that feeds into SQL
- Configuration values that might be tampered with

## 6. Common Patterns to Flag

- Any SQL keyword (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) followed by string operations
- `WHERE` clauses built dynamically at runtime
- `ORDER BY` with a dynamic column name from user input
- Table or column names sourced from user input
- `LIKE` patterns using unescaped wildcards from user input

## 7. Framework-Specific Checks

- Confirm parameterized queries or `IDbCommand` parameters are used consistently
- Verify proper escaping mechanisms are in place where raw SQL is unavoidable
- Look for bypasses of built-in ORM query protections
- Examine custom SQL builders or query helper utilities

## What to Report

For each finding, provide:
- **File** and line number
- **Code snippet** showing the vulnerable query construction
- **Input source**: where the user-controlled value originates
- **Risk**: HIGH (direct user input in query) / MEDIUM (indirect or partially controlled input) / LOW (admin-only or configuration-controlled input)
- **Recommendation** with a secure parameterized alternative
