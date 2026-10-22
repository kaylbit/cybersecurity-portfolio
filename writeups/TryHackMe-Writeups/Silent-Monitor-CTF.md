# Silent Monitor — Penetration Testing Writeup

## 1. Overview

| Field | Details |
|---|---|
| Platform | TryHackMe |
| Target | Silent Monitor |
| Target IP | `10.48.128.171` |
| Difficulty | Medium |
| Category | Web Application / Linux Privilege Escalation |
| Assessment Date |  October 22, 2026 | 
| Methodology | PTES-inspired workflow |
| Status | Completed |

### Objective

Assess the target's exposed services and web application, identify exploitable vulnerabilities, obtain initial access, and evaluate whether privilege escalation is possible within the authorized TryHackMe lab.

### Executive Summary

The assessment identified two open TCP ports: `22` (SSH) and `5050` (web application). Directory enumeration discovered an internal NOC portal at `/internal`.

The login mechanism was vulnerable to SQL injection, allowing authentication bypass. The authenticated application exposed a host health-check function that was vulnerable to OS command injection. This enabled command execution as the `www-data` service account and disclosure of a configuration file containing credentials for the `sysadmin` account.

The discovered credentials provided SSH access. After obtaining the user flag, a KeePass database was recovered from the user's backup directory. Its master password was cracked using a password wordlist, revealing a root account password. The recovered credential enabled a switch to the root account, completing the privilege-escalation path.

**Confirmed outcomes:**
- Authentication bypass through SQL injection.
- OS command execution as `www-data`.
- SSH access as `sysadmin`.
- User flag retrieved.
- KeePass database password recovered.
- Root access obtained.
- Root flag retrieved.

## 2. Scope and Environment

- **Target IP:** `10.48.128.171`
- **Attacker environment:** Kali Linux
- **Tools used:** Metasploit Framework, Dirsearch, Burp Suite, SSH, SCP, `keepass4brute`, KeePassXC CLI, Linux shell utilities.
- **Scope:** The target services and application functionality exposed by the assigned TryHackMe machine.
- **Authorization:** Authorized training environment.

## 3. Reconnaissance

### 3.1 TCP port scanning

Metasploit's TCP port scanner was used to check the target.

```text
msf auxiliary(scanner/portscan/tcp) > set RHOSTS 10.48.128.171
msf auxiliary(scanner/portscan/tcp) > set THREADS 10
msf auxiliary(scanner/portscan/tcp) > run

[+] 10.48.128.171:22 - TCP OPEN
[+] 10.48.128.171:5050 - TCP OPEN
[*] Scanned 1 of 1 hosts (100% complete)
```

### Results

| Port | Status | Service interpretation |
|---|---|---|
| 22/TCP | Open | SSH |
| 5050/TCP | Open | Web application |

**Analysis:** Port 5050 was the primary application attack surface, while SSH provided a potential route for remote access if valid credentials could be obtained.

Service versions were not recorded in the supplied scan output and should not be inferred.

## 4. Enumeration

### 4.1 Directory discovery

Dirsearch was used to discover accessible web paths.

```bash
dirsearch -u http://10.48.128.171:5050/
```

**Confirmed discovery:**

| Path | HTTP status | Significance |
|---|---:|---|
| `/internal` | 200 | Returned an internal NOC portal login page |

The `/internal` page displayed a CorpNet NOC sign-in interface. Its page text stated that access was restricted to authorized personnel and that sessions were monitored and logged.

### 4.2 Internal NOC portal

The internal portal contained a login form and provided access to monitoring functionality after authentication.

The host health page included a connectivity probe that accepted a hostname or IP address and displayed the result of a ping operation.

**Attack surface identified:**
- Authentication logic on the login page.
- A user-controlled target field in the connectivity probe.
- Internal monitoring functionality accessible after login.

## 5. Vulnerability Analysis

### Finding 1 — SQL Injection in Authentication

**Affected component:** `/internal` login form

**Vulnerability class:** SQL Injection (CWE-89)

**Evidence:** The login was bypassed using the following username input:

```text
' OR 1=1;--
```

The application accepted the input and provided access to the authenticated portal.

**Technical explanation:**

The behavior is consistent with unsafe SQL query construction in which user-supplied input can alter the intended authentication query. The condition `OR 1=1` is always true, and the SQL comment syntax can cause the remaining portion of a query to be ignored, depending on the database and query structure.

The successful bypass confirms the authentication weakness in the lab. The exact SQL statement and database implementation were not independently established by the recorded evidence.

**Impact:** An unauthenticated attacker could bypass the intended login control and access functionality reserved for authenticated users.

**Recommended remediation:**
- Use parameterized queries or prepared statements.
- Avoid building SQL statements by concatenating user input.
- Return generic authentication errors.
- Apply least-privilege permissions to the application's database account.
- Add regression tests for SQL injection attempts.

### Finding 2 — OS Command Injection in Host Health Check

**Affected component:** Host Health Check connectivity probe

**Vulnerability class:** OS Command Injection (CWE-78)

**Evidence:** The host health-check field accepted a target such as `127.0.0.1`. Attempts to append commands using semicolons, pipes, and `&&` did not work as expected. Further investigation identified a newline-based injection using URL encoding.

The effective request value was:

```text
127.0.0.1%0A+whoami
```

Burp Suite was used to inspect and modify the request. The captured request contained `%250A`, which was changed to `%0A` to avoid the extra encoding layer.

The response displayed the normal ping output followed by:

```text
www-data
```

A subsequent command-listing test returned:

```text
app.py
netops.db
secret.config
templates
```

**Technical explanation:**

The application appears to have passed user-controlled input into a system command without safely separating data from executable command syntax. The URL-encoded newline changed how the input was interpreted after decoding, allowing an additional command to execute.

The observed `whoami` output confirmed command execution under the `www-data` service account.

**Impact:** An authenticated user able to exploit the probe could execute operating-system commands with the application's privileges. This can expose application files and secrets and may provide a path toward further compromise.

**Recommended remediation:**
- Avoid shell command construction for connectivity checks.
- Use a safe networking library or a subprocess API with an argument list and shell execution disabled.
- Validate hostnames and IP addresses against strict expected formats.
- Apply server-side allowlisting and reject control characters.
- Run the application with minimal operating-system privileges.
- Restrict access to application configuration and database files.

### Finding 3 — Credential Disclosure in Application Configuration

**Affected file:** `secret.config`

**Evidence:** After confirming command execution, the following command was used to inspect the configuration file:

```text
cat secret.config
```

The file contained database and application settings, along with a backup-agent account entry. That entry included credentials for the `sysadmin` account.

The discovered credentials successfully authenticated over SSH to the target.

**Technical explanation:**

A configuration file accessible to the web application's service account contained a reusable account password. The command-injection vulnerability therefore enabled a transition from limited web-service execution to access as a separate operating-system user.

**Impact:** Disclosure of the configuration file allowed remote SSH access as `sysadmin`, resulting in a more privileged foothold than the initial web-service account.

**Recommended remediation:**
- Store credentials in a secrets manager or protected configuration store.
- Ensure sensitive configuration files are readable only by the accounts that require them.
- Use separate credentials for application services and operating-system users.
- Rotate exposed credentials and review authentication logs.
- Prevent command injection to remove the initial route to the file.

## 6. Exploitation

### 6.1 Authentication bypass

1. Enumerated the web application on port 5050.
2. Discovered `/internal`.
3. Inspected the login page.
4. Submitted a SQL injection payload in the username field.
5. Obtained access to the internal portal.

**Outcome:** Authentication bypass confirmed.

### 6.2 Command injection

1. Opened the Host Health Check function.
2. Tested how the target input was handled.
3. Observed that common command separators did not work as expected.
4. Intercepted the request using Burp Suite.
5. Changed the double-encoded newline representation `%250A` to `%0A`.
6. Submitted the newline-based payload.
7. Observed `www-data` in the response, confirming command execution.
8. Listed the application directory and identified `secret.config`.
9. Read the configuration file and discovered credentials for `sysadmin`.

**Outcome:** OS command execution as `www-data` confirmed.

### 6.3 SSH access and user flag

The discovered credentials were used to authenticate over SSH.

```bash
ssh sysadmin@10.48.128.171
```

After logging in, the current identity was verified:

```bash
whoami
```

Observed output:

```text
sysadmin
```

The home directory contained `user.txt` and a `backups` directory. Reading the user flag produced:

```text
THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}
```

**Outcome:** SSH access as `sysadmin` and retrieval of the user flag confirmed.

## 7. Post-Exploitation and Privilege Escalation

### 7.1 KeePass database discovery

Inside `/home/sysadmin/backups`, the following files were discovered:

```text
README.txt
infrastructure.kdbx
```

The KeePass database was copied to the assessment machine for offline analysis.

```bash
scp sysadmin@10.48.128.171:/home/sysadmin/backups/infrastructure.kdbx ~/pentest/
```

### 7.2 KeePass master password recovery

The `keepass4brute` tool was used with the local `rockyou.txt` wordlist to test candidate master passwords against the database.

```bash
./keepass4brute.sh \
  ~/pentest/infrastructure.kdbx \
  /usr/share/wordlists/rockyou.txt
```

The tool reported a recovered master password:

```text
spring
```

This demonstrated that the database's master password was present in the tested wordlist and could be recovered through offline guessing.

**Security significance:** If an attacker obtains a password-protected KeePass database, a weak master password may allow offline password guessing without further interaction with the target.

### 7.3 Sensitive credential recovery

After unlocking the database, KeePassXC CLI was used to export its entries for inspection.

```bash
keepassxc-cli export ~/pentest/infrastructure.kdbx --format csv
```

The export contained an entry titled `Root User Password - Sensitive`, associated with the `root` username.

The recovered root credential was used to switch from `sysadmin` to `root`. Actual passwords are omitted from this public report.

**Recommended remediation:**
- Use a strong, unique KeePass master password that resists dictionary attacks.
- Protect backup databases with strict file permissions and encryption.
- Avoid storing privileged credentials in unnecessarily accessible backup files.
- Rotate exposed credentials and remove obsolete entries.
- Review backup retention and access controls.

### 7.4 Root access and root flag

After switching to the root account, the identity was verified:

```bash
whoami
```

Observed output:

```text
root
```

The root directory contained `root.txt`. Reading the file returned:

```text
THM{KDBx_V4ul7_H4s_b33n_cr4ck3d_0peN}
```

**Outcome:** Root access and retrieval of the root flag confirmed.

## 8. Attack Chain Summary

```text
1. Reconnaissance
2. TCP ports 22 and 5050 discovered
3. Dirsearch discovers /internal
4. SQL injection bypasses authentication
5. Host Health Check function accessed
6. Newline-based OS command injection
7. Command execution as www-data
8. secret.config exposes sysadmin credentials
9. SSH access as sysadmin
10. User flag retrieved
11. infrastructure.kdbx recovered from backups
12. KeePass master password cracked offline
13. Root password recovered from database
14. Switch to root
15. Root flag retrieved
```

## 9. Remediation Summary

| Finding | Suggested priority | Main remediation |
|---|---|---|
| SQL injection | High | Parameterized SQL queries |
| OS command injection | Critical | Remove unsafe shell execution and validate input |
| Credentials exposed in configuration | High | Restrict file access, rotate secrets, use secret management |
| Weak KeePass master password | High | Use a strong unique master password |
| Sensitive database stored in backups | High | Restrict backup access and protect privileged secrets |

These are preliminary, impact-based priorities rather than formal CVSS ratings. A production assessment should calculate severity using the complete application context, attack prerequisites, and business impact.

## 10. Lessons Learned

- Reconnaissance identifies the exposed services that form the initial attack surface.
- Directory enumeration can reveal application endpoints that are not obvious from the landing page.
- SQL injection can compromise authentication when queries are constructed unsafely.
- URL encoding and decoding behavior can affect how user input reaches the application.
- Command injection can turn an application-level weakness into operating-system command execution.
- Service-account permissions influence how far an attacker can progress after exploiting a web application.
- Sensitive configuration files can bridge the gap between web access and SSH access.
- Password-protected files are only as resistant to offline guessing as their master passwords and overall protection.
- A complete attack-chain report should document each transition with evidence rather than treating the final flag as the only proof.

## 11. References

- [Penetration Testing Execution Standard (PTES)](http://www.pentest-standard.org/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [KeePassXC Documentation](https://keepassxc.org/docs/)

## 12. Evidence Index

| Evidence ID | Description | Suggested filename |
|---|---|---|
| E-01 | TCP port scan | `E-01-port-scan.txt` |
| E-02 | Dirsearch results | `E-02-dirsearch.txt` |
| E-03 | SQL injection authentication bypass | `E-03-auth-bypass.png` |
| E-04 | Command injection request and response | `E-04-command-injection.png` |
| E-05 | Configuration file discovery (redacted) | `E-05-config-redacted.png` |
| E-06 | SSH session and user flag (redacted as needed) | `E-06-user-access.png` |
| E-07 | KeePass password recovery (redacted) | `E-07-kdbx-recovery.png` |
| E-08 | Root access and root flag | `E-08-root-access.png` |

---

**Disclaimer:** This report documents activities performed against an authorized TryHackMe training target. Credentials have been omitted from the public version. The findings should not be interpreted as evidence that unrelated systems are vulnerable.
