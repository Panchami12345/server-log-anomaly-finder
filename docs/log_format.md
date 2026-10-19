# Log Format & Theory

**Project 8: Server Log Anomaly Finder**
**Course:** Theory of Computation (BIS503)
**Week 1, Member 1:** Log Format & Theory (Research and Documentation)

---

## 1. Introduction

A web server such as Apache or Nginx writes one line to an **access log** every time a client (a browser, a script, or a bot) requests something from it. Each line is a small record of *who* asked, *when*, *for what*, and *what the server answered*.

These logs are valuable for security. A normal visitor leaves a short, predictable trail. An attacker scanning for weak spots, guessing passwords, or running automated tools leaves a very different trail. Our project reads these logs and flags the suspicious patterns using **regular expressions** and **DFAs**.

---

## 2. Apache and Nginx Log Formats

### 2.1 Common Log Format (CLF)

The basic Apache format:

```
%h %l %u %t "%r" %>s %b
```

### 2.2 Combined Log Format

The most widely used format. It is CLF plus two extra fields (referrer and user-agent). **Nginx uses the same layout by default** (its `combined` format), so one regex can handle both servers.

```
%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
```

**Our project uses the Combined Log Format.**

### 2.3 Annotated example

```
203.0.113.25 - alice [12/Oct/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36"
```

| Part | Value | Meaning |
|------|-------|---------|
| Client IP | `203.0.113.25` | Who sent the request |
| Identity | `-` | Almost always unused |
| User | `alice` | Authenticated user (or `-`) |
| Timestamp | `[12/Oct/2026:10:15:32 +0530]` | When the request arrived |
| Request line | `"GET /index.html HTTP/1.1"` | Method, path, protocol |
| Status code | `200` | Server's response result |
| Response size | `5120` | Bytes sent back |
| Referrer | `"https://example.com/"` | Page the user came from |
| User-agent | `"Mozilla/5.0 ..."` | Software making the request |

---

## 3. Field-by-Field Explanation

| # | Field | Example | Meaning | Why it matters for detection |
|---|-------|---------|---------|------------------------------|
| 1 | **IP address** (`%h`) | `203.0.113.25` | Address of the client that made the request. | Lets us group requests by source, e.g. count 404s or failed logins per IP. |
| 2 | **Identity** (`%l`) | `-` | Remote logname from the identd protocol. Almost always `-` (unused). | Ignored by our project. |
| 3 | **User** (`%u`) | `alice` or `-` | Username if HTTP authentication was used, otherwise `-`. | Useful context for login activity. |
| 4 | **Timestamp** (`%t`) | `[12/Oct/2026:10:15:32 +0530]` | Date, time, and timezone offset when the request was received. Format: `[day/Month/year:HH:MM:SS zone]`. | Used to detect **access outside business hours** and to measure how fast requests arrive. |
| 5 | **HTTP method** | `GET`, `POST` | The action requested. `GET` fetches a resource, `POST` submits data (e.g. a login form). | Failed logins are usually `POST` requests to a login URL. |
| 6 | **URL / path** | `/login`, `/admin`, `/.env` | The resource requested. | Probing for sensitive paths (`/admin`, `/.env`, `/backup.zip`) is a sign of scanning. |
| 7 | **Protocol** | `HTTP/1.1` | HTTP version used. | Rarely used for detection. |
| 8 | **Status code** (`%>s`) | `200`, `404`, `401` | The server's response result (see table below). | Core signal: many `404`s mean scanning, many `401`s mean password guessing. |
| 9 | **Response size** (`%b`) | `5120` | Bytes sent back (`-` or `0` if none). | Unusual sizes can hint at data leakage (not used in Week 1). |
| 10 | **Referrer** | `"https://example.com/"` | The page the user came from, or `"-"`. | Optional context. |
| 11 | **User-agent** | `"Mozilla/5.0 ..."` | Text the client uses to identify its software. | Hacking tools (`sqlmap`, `Nikto`) or empty values are suspicious. |

### Common HTTP status codes

| Code | Name | Meaning |
|------|------|---------|
| 200 | OK | Request succeeded. |
| 301 / 302 | Redirect | Resource moved, or redirect after a successful login. |
| 304 | Not Modified | Browser's cached copy is still valid. |
| 400 | Bad Request | Malformed request. |
| 401 | Unauthorized | Authentication required or failed (e.g. wrong password). |
| 403 | Forbidden | Server refuses access. |
| 404 | Not Found | The requested resource does not exist. |
| 500 | Internal Server Error | Server-side failure. |

---

## 4. Normal vs Suspicious Behaviour

| Aspect | Normal traffic | Suspicious traffic |
|--------|----------------|--------------------|
| Status codes | Mostly 200, 301, 302, 304; the odd stray 404 | Long runs of 404 or 401 from one IP |
| Paths | Real pages and assets (`/index.html`, `/images/logo.png`) | `/admin`, `/.env`, `/backup.zip`, `/wp-login.php` |
| Timing | Spread out, mostly during working hours | Many requests within seconds; activity late at night |
| User-agent | Real browsers (Chrome, Firefox, Safari) | Scanner/attack tools, scripting libraries, empty values |

---

## 5. Example Log Entries with Explanations

The IP addresses below come from ranges reserved for documentation (RFC 5737), so they are safe to use as examples.

### Normal entries

**Entry 1: Normal page view**
```
192.0.2.10 - - [12/Oct/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
```
*Normal.* Daytime request, valid page, status 200, genuine browser.

**Entry 2: Successful login**
```
192.0.2.22 - alice [12/Oct/2026:11:02:07 +0530] "POST /login HTTP/1.1" 302 0 "https://example.com/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
```
*Normal.* A `POST` to `/login` that redirects (302) means the login worked. A login by itself is not suspicious.

**Entry 3: Product page with a query string**
```
192.0.2.15 - - [12/Oct/2026:14:20:45 +0530] "GET /products?id=42 HTTP/1.1" 200 8734 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0"
```
*Normal.* Ordinary browsing during business hours.

**Entry 4: Cached image**
```
192.0.2.8 - - [12/Oct/2026:15:47:19 +0530] "GET /images/logo.png HTTP/1.1" 304 0 "https://example.com/about.html" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
```
*Normal.* Status 304 means the browser reused its cached copy.

**Entry 5: A single mistyped URL**
```
192.0.2.30 - - [12/Oct/2026:16:30:02 +0530] "GET /abuot.html HTTP/1.1" 404 196 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
```
*Normal, not an anomaly.* One 404 from a typo. It only becomes suspicious when the same IP produces many 404s quickly. This entry is useful for checking that our tool does not raise false alarms.

### Suspicious entries: repeated 404 errors (directory scanning)

**Entries 6, 7, 8: One IP probing hidden paths**
```
198.51.100.7 - - [12/Oct/2026:13:05:01 +0530] "GET /admin HTTP/1.1" 404 209 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
198.51.100.7 - - [12/Oct/2026:13:05:02 +0530] "GET /backup.zip HTTP/1.1" 404 209 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
198.51.100.7 - - [12/Oct/2026:13:05:02 +0530] "GET /.env HTTP/1.1" 404 209 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
```
*Suspicious: directory scanning.* The same IP requests several sensitive, non-existent paths within about a second, all returning 404. A human does not browse this way. Scanners try lists of common paths hoping one exists.

### Suspicious entries: failed-login flood (brute force)

**Entries 9, 10, 11: Repeated failed logins**
```
203.0.113.99 - - [12/Oct/2026:12:40:11 +0530] "POST /login HTTP/1.1" 401 287 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36"
203.0.113.99 - - [12/Oct/2026:12:40:12 +0530] "POST /login HTTP/1.1" 401 287 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36"
203.0.113.99 - - [12/Oct/2026:12:40:13 +0530] "POST /login HTTP/1.1" 401 287 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0 Safari/537.36"
```
*Suspicious: failed-login flood.* One IP sends a `POST` to `/login` every second and gets 401 (unauthorized) each time. This looks like automated password guessing (brute force). In a real log this would continue for many more lines.

### Suspicious entry: access outside business hours

**Entry 12: Admin access at 2:47 AM**
```
192.0.2.50 - bob [13/Oct/2026:02:47:55 +0530] "GET /admin/dashboard HTTP/1.1" 200 15320 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36"
```
*Suspicious: off-hours access.* The request itself is valid (status 200), but it touches a sensitive page at 02:47, far outside the assumed business hours of 09:00 to 18:00. It could be a stolen account or an insider acting unnoticed.

### Suspicious entries: unusual user-agent strings

**Entry 13: Attack tool `sqlmap`**
```
198.51.100.44 - - [12/Oct/2026:17:12:09 +0530] "GET /products?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 512 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
```
*Suspicious: attack tool.* `sqlmap` is an automated SQL-injection tool. The URL also carries an injection attempt (`' OR '1'='1`).

**Entry 14: Scanner `Nikto`**
```
198.51.100.45 - - [12/Oct/2026:17:20:31 +0530] "GET /cgi-bin/test.cgi HTTP/1.1" 404 209 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:001234)"
```
*Suspicious: vulnerability scanner.* `Nikto` is a web vulnerability scanner, and its name appears in the user-agent.

**Entry 15: Empty user-agent**
```
198.51.100.46 - - [12/Oct/2026:18:03:50 +0530] "GET / HTTP/1.1" 200 5120 "-" "-"
```
*Suspicious: no user-agent.* Real browsers always identify themselves. A missing value often means a crude script or bot.

---

## 6. Mapping Log Fields to Our Four Anomaly Types

| Anomaly | Fields used | Idea |
|---------|-------------|------|
| Repeated 404 errors | IP, status code, (timestamp) | Many `404` responses from the same IP in a short time. |
| Failed-login flood | IP, method, path, status code | Many `POST /login` lines with `401`/`403` from the same IP. |
| Access outside business hours | Timestamp | Time falls outside the assumed working window. |
| Unusual user-agent | User-agent | Matches known attack tools or is empty. |

> **Note:** Thresholds (e.g. "5 or more 404s within 60 seconds") and the business-hours window (assumed 09:00 to 18:00) are proposed values. See `thresholds.md` for the team's agreed values.

---

## 7. SIEM and Splunk

### 7.1 What is a SIEM?

**SIEM** stands for **Security Information and Event Management**. It is a system that:

1. **Collects** logs and events from many sources (web servers, firewalls, databases, applications) into one place.
2. **Normalizes and indexes** them so they can be searched quickly, regardless of source format.
3. **Correlates** events to find patterns (for example, many failed logins followed by a success).
4. **Alerts** security teams when something suspicious is detected.
5. **Visualizes** activity on dashboards and keeps records for investigations and compliance.

Without a SIEM, an analyst would have to read thousands of log files on many machines by hand.

### 7.2 What is Splunk?

**Splunk** is one of the most widely used log-analysis and SIEM platforms. It works roughly as follows:

- **Forwarders** send log data from servers to Splunk.
- **Indexers** parse and store the data, extracting fields (IP, status, URL, user-agent) automatically. Apache logs are recognized with the `access_combined` source type.
- **Search heads** let users query the data using Splunk's **Search Processing Language (SPL)**.
- **Dashboards and alerts** display results and notify the team when a condition is met.
- Splunk also offers a security-focused product (**Splunk Enterprise Security**) with ready-made detection rules.

**Example SPL query** to find IPs with many 404 errors:

```
index=web sourcetype=access_combined status=404
| stats count by clientip
| where count > 10
| sort - count
```

This counts 404 responses per IP and lists those with more than 10, which is exactly the "repeated 404s" anomaly in our project.

### 7.3 How this relates to our project

Our Server Log Anomaly Finder is a **simplified, small-scale version of what a SIEM does**:

| SIEM / Splunk step | Our project |
|--------------------|-------------|
| Ingest logs | Read `sample_logs.txt` |
| Parse fields | Extract IP, timestamp, method, path, status, user-agent |
| Detection rules | Regex patterns and DFAs for the four anomaly types |
| Alerts and reports | JSON report and visualization (Week 2) |

The key difference is that Splunk uses a full query language and a large indexing engine, whereas our tool applies **regular expressions and finite automata** directly. These are the Theory of Computation concepts at the core of this project.

---

## 8. References

- Apache HTTP Server documentation: *Log Files* and *Custom Log Formats* (httpd.apache.org)
- Nginx documentation: *Module ngx_http_log_module* (nginx.org)
- Splunk documentation: *Splunk Enterprise Search Reference* and *Splunk Enterprise Security* (docs.splunk.com)
- RFC 5737: *IPv4 Address Blocks Reserved for Documentation* (the example IPs used above)
- MDN Web Docs: *HTTP response status codes* (developer.mozilla.org)
