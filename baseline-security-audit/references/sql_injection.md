# SQL Injection Analysis

Scan the codebase for SQL injection vulnerabilities where user input is incorporated into SQL queries without proper parameterization or escaping.

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A05 Injection · **ASVS 5.0:** V1 Encoding and Sanitization

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
- The legacy `System.Data.SqlClient` package is unsupported: flag its `PackageReference` as Medium and recommend `Microsoft.Data.SqlClient`

**Safe by construction** (these take a `FormattableString` and EF Core parameterizes every `{value}`):
- `FromSql()`, `FromSqlInterpolated()`, `ExecuteSql()`, `ExecuteSqlInterpolated()`, `SqlQuery<T>()`
- Do **not** flag these. The only exception is when the argument is a pre-built string cast or converted to `FormattableString` (e.g. `FromSqlInterpolated($"{alreadyConcatenatedSql}")` or `FormattableStringFactory.Create(sql)`), which defeats the parameterization.

## 3. Stored Procedure Calls

Check for unsafe stored procedure invocation:
- Dynamic stored procedure name construction
- Parameter values built through string manipulation
- `CommandType.StoredProcedure` with concatenated names
- T-SQL dynamic SQL in the database layer (`**/*.sql`, `*.sqlproj`/DACPAC projects, `migrationBuilder.Sql(...)`): `EXEC(@sql)`/`EXECUTE(` on a concatenated string, `sp_executesql` without a `@params` declaration (or with `@stmt` built by `+`), string-built SQL inside procedures, functions and triggers, and `migrationBuilder.Sql($"...")` interpolating a non-constant value. Rate with the same scale as C# injection (What to Report)

## 4. ORM Vulnerabilities

Check for unsafe raw queries within ORMs:
- Raw SQL passed to Entity Framework methods
- Dynamic LINQ expressions built from user-supplied strings
- `System.Linq.Dynamic.Core` string predicates built from user-supplied strings (e.g. `.Where("Name == \"" + input + "\"")`, `.OrderBy(sortExpression)`) and raw SQL inside `Where` (e.g. `EF.Functions.*` fed a concatenated string). Plain LINQ `Contains`/`StartsWith`/`EndsWith` on an `IQueryable` are parameterized by EF Core and are not findings. A user-supplied sort or filter string parsed by Dynamic LINQ (version 1.3.0 or later) into an EF Core expression is not a finding either, with or without an allow-list, because the generated SQL stays parameterized
- HQL or native SQL queries (if applicable)

## 5. Input Sources to Validate

Identify all user-controlled input flowing into queries:
- Form fields, API request bodies, and query string parameters
- URL route parameters used in queries
- File-upload metadata that feeds into SQL
- Configuration values that might be tampered with

## 6. Common Patterns to Flag

- A raw-SQL entry point whose argument is built from string operations:
  ```regex
  (FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw|CommandText\s*=|\.Query(Async|First|Single)?\(|\.Execute(Async)?\()\s*\(?\s*(\$"|"[^"]*"\s*\+|string\.(Format|Concat)|\w+Builder\.ToString\(\))
  ```
- `WHERE` clauses built dynamically at runtime
- `ORDER BY` with a dynamic column name from user input
- Table or column names sourced from user input
- `LIKE` patterns using unescaped wildcards from user input

## 7. Framework-Specific Checks

**Files to examine:**
- `**/*.cs` (repositories, `*DbContext*.cs`, `*Repository*.cs`, `*Query*.cs`, `*Handler*.cs`, Dapper helpers)
- `**/*.sql`, `**/*.sqlproj` (DACPAC) and `**/Migrations/**/*.cs` for dynamic SQL inside stored procedures, functions and `migrationBuilder.Sql(...)` (section 3)

**Search patterns:**
```regex
FromSqlRaw|ExecuteSqlRaw(Async)?|SqlQueryRaw
CommandText\s*=
new SqlCommand\(\s*(\$"|"[^"]*"\s*\+|\w+\s*\+)
\.(Query|QueryFirst|QuerySingle|Execute)(Async)?(<[^>]+>)?\(\s*(\$"|"[^"]*"\s*\+|string\.(Format|Concat))
string\.(Format|Concat)\([^)]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)\b
\$"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)\b[^"]*\{
\b(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)\b[^"]*"\s*\+\s*\w+
StringBuilder[\s\S]{0,200}\b(SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER BY)\b
FormattableStringFactory\.Create|FromSqlInterpolated\(\$"\{\w+\}"\)
CommandType\.StoredProcedure[\s\S]{0,120}\+
System\.Linq\.Dynamic|\.Where\(\s*\$?"|\.OrderBy\(\s*\$?"
new SqlDataAdapter\(\s*(\$"|"[^"]*"\s*\+|\w+\s*\+)
System\.Data\.SqlClient                                        // legacy package: Medium, migrate to Microsoft.Data.SqlClient
EXEC(UTE)?\s*\(\s*@\w+|sp_executesql\s+@\w+\s*(;|$)|sp_executesql\s+N?'[^']*'\s*\+   // T-SQL dynamic SQL (*.sql, *.sqlproj)
migrationBuilder\.Sql\(\s*\$"
```

## What to Report

For each finding, provide:
- **File** and line number
- **Code snippet** showing the vulnerable query construction
- **Input source**: where the user-controlled value originates
- **Risk**: Critical (unauthenticated user input reaches the query) / High (authenticated user input reaches the query) / Medium (indirect, partially controlled or admin-supplied input; admin-supplied input is never rated below Medium) / Low (only compile-time constants or allow-listed values reach the query)
- **Recommendation** with a secure parameterized alternative
