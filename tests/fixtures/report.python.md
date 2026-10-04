# Crux triage report

Triager: `mock`  |  Findings: 7  |  True positive: 5  |  Needs human: 1  |  Likely noise: 1

Nothing below has been closed or suppressed. This is a ranked queue for review.

## [TRUE POSITIVE] SQL query built by string concatenation with user input

- **Where:** `WebGoat/App_Code/DB/CustomerDAL.cs:64`
- **Rule / severity:** `csharp.lang.security.sqli.raw-sql-concat` (HIGH)  |  CWE: CWE-89
- **Confidence:** 1.00  |  **False-positive likelihood:** 0.00
- **Why:** Heuristic: a high-signal rule in application code with no strong false-positive indicator. Treat as real until proven otherwise.
- **Fix:** Use parameterised queries or an ORM; never concatenate user input into SQL.

```
string sql = "SELECT * FROM Customers WHERE Id = '" + Request["customerId"] + "'";
var cmd = new SqlCommand(sql, conn);
```

## [TRUE POSITIVE] Reflected XSS via Response.Write of unencoded input

- **Where:** `WebGoat/Content/Search.aspx.cs:37`
- **Rule / severity:** `csharp.lang.security.xss.raw-response-write` (HIGH)  |  CWE: CWE-79
- **Confidence:** 1.00  |  **False-positive likelihood:** 0.00
- **Why:** Heuristic: a high-signal rule in application code with no strong false-positive indicator. Treat as real until proven otherwise.
- **Fix:** Contextually encode output and avoid rendering raw user input into HTML.

```
Response.Write("You searched for: " + Request.QueryString["q"]);
```

## [TRUE POSITIVE] SQLi café

- **Where:** `https://a/login?q=é`
- **Rule / severity:** `dast/sqli` (HIGH)
- **Confidence:** 1.00  |  **False-positive likelihood:** 0.00
- **Why:** Heuristic: a high-signal rule in application code with no strong false-positive indicator. Treat as real until proven otherwise.
- **Fix:** Use parameterised queries or an ORM; never concatenate user input into SQL.

```
x
	"y"
```

## [TRUE POSITIVE] Weak hashing algorithm (MD5) used for passwords

- **Where:** `WebGoat/App_Code/Auth/PasswordHasher.cs:21`
- **Rule / severity:** `csharp.lang.security.crypto.weak-hash-md5` (MEDIUM)  |  CWE: CWE-327
- **Confidence:** 0.85  |  **False-positive likelihood:** 0.10
- **Why:** Heuristic: a high-signal rule in application code with no strong false-positive indicator. Treat as real until proven otherwise.
- **Fix:** Use a current, vetted algorithm and library defaults; drop the weak primitive.

```
using (var md5 = MD5.Create()) { return Convert.ToBase64String(md5.ComputeHash(bytes)); }
```

## [TRUE POSITIVE] Vulnerable dependency: Newtonsoft.Json (deserialization DoS)

- **Where:** `WebGoat/packages.config:5`
- **Rule / severity:** `sca.Newtonsoft.Json.CVE-2024-21907` (MEDIUM)  |  CWE: CWE-502
- **Confidence:** 0.85  |  **False-positive likelihood:** 0.10
- **Why:** Heuristic: a high-signal rule in application code with no strong false-positive indicator. Treat as real until proven otherwise.
- **Fix:** Confirm exploitability, then apply the standard control for this weakness class.

```
<package id="Newtonsoft.Json" version="12.0.1" targetFramework="net48" />
```

## [NEEDS HUMAN] SQL built by concatenation in a test fixture

- **Where:** `WebGoat.Tests/Fixtures/SeedData.cs:112`
- **Rule / severity:** `csharp.lang.security.sqli.raw-sql-concat` (HIGH)  |  CWE: CWE-89
- **Confidence:** 0.05  |  **False-positive likelihood:** 0.50
- **Why:** Confidence 0.05 below the 0.55 gate. Routed to a human. Original reasoning: Heuristic: mixed signals, no clear verdict. Triaged as real but with low confidence, so the gate will route it to a human.
- **Fix:** Use parameterised queries or an ORM; never concatenate user input into SQL.

```
var sql = "INSERT INTO Customers (Name) VALUES ('" + name + "')"; // test seed
```

## [LIKELY NOISE] Possible API key in sample config

- **Where:** `WebGoat/vendor/examples/appsettings.sample.json:9`
- **Rule / severity:** `generic.secrets.detected-generic-api-key` (INFO)  |  CWE: CWE-798
- **Confidence:** 0.65  |  **False-positive likelihood:** 0.80
- **Why:** Heuristic: fires in a low-risk path (test, vendor, generated) or is a low-severity rule, so it is more likely noise than an exploitable issue.
- **Fix:** Move the secret to a vault or environment config; rotate the exposed value.

```
"ApiKey": "EXAMPLE_PLACEHOLDER_DO_NOT_USE_0000"
```
