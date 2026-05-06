# Bagaholdin

> **Legal Notice:** This tool is intended **solely for educational purposes** and for use on networks you own or have **explicit written permission** to test. Unauthorised use against systems you do not own or have permission to access is illegal and unethical. The authors accept no liability for misuse.

A Metasploit Pro-style web interface for managing penetration test engagements. Bagaholdin is in a **workable state** — core features function as described, but it is under active development and not production-hardened. Treat it as a learning platform rather than a finished tool.

Each project groups target hosts into sessions, providing a live msfconsole terminal, automated scanning, CVE analysis, post-exploitation tooling, loot extraction, WiFi attack support, and structured report generation — all through a browser.

---

## Features

### Project Management
- **Projects and network scanning** — Group targets under a named project with a network range. Discover live hosts with an nmap ping sweep and add them as sessions with a single click. Select multiple hosts and add them in bulk.
- **Network Topology** — Visual SVG map of all hosts discovered within a project. Hosts are colour-coded by worst CVE severity (Critical/High/Medium/Low/Clean/Offline) with Bezier connectors from the inferred gateway node. Shows IP, hostname, OS, open port count, and CVE count per node.
- **Project Report** — Aggregated professional penetration test report across all sessions in a project. Covers cover page, table of contents, executive summary with KPI boxes and charts, host summaries, consolidated CVE findings with remediation advice, post-exploitation findings, and a legal disclaimer. Print-ready PDF output.

### Per-Session Workspace
- **Live msfconsole console** — Each session spawns a dedicated msfconsole process. Commands stream in real-time via WebSocket with command history and auto-reconnect. msfconsole auto-restarts on crash.
- **Vulnerability scanner** — Runs `nmap -sV -O --osscan-guess --script=vuln,vulners` against the target and parses results into a structured service list with OS detection. Results are persisted in the database and survive restarts.
- **Enumeration panel** — Parses nmap XML output and maps each open port to relevant Metasploit modules, filtered by OS and service type. Results are persisted.
- **CVE analysis** — Fetches CVEs from NVD, enriches with CVSS scores and GitHub public PoC repositories. Results are persisted in the database so they survive navigation and appear in project-level reports.
- **Searchsploit** — Search the local Exploit-DB copy for modules matching the target's services. Results are persisted per session.
- **Shells panel** — Lists active msfconsole sessions **filtered to the current target host** (sessions on other hosts are hidden). Supports interact, upgrade shell to Meterpreter, background, and kill. Upgrade creates a fresh meterpreter session, kills the original shell, then removes any spurious sessions created by multi-homed targets calling back from alternate NICs. Killed sessions are removed from the UI immediately (optimistic update). Auto-refreshes when a new session opens.
- **Post exploitation** — Quick-command buttons and recommended module lists filtered by session type (Meterpreter/shell) and OS (Linux/Windows). Session type is auto-detected when the Post Exploitation tab opens (quiet refresh that does not disturb an active session). Native meterpreter commands (`sysinfo`, `getuid`, `ps`, etc.) are sent directly. Commands of the form `shell <cmd>` use a 3-step channel-interact sequence to correctly capture subprocess output through msfconsole's non-TTY pipe. Output is automatically parsed for credentials, hashes, user accounts, system info, and other artefacts.
- **Active Directory panel** — Dedicated AD attack groups: Domain Enumeration, Credential Attacks, Lateral Movement, Privilege Escalation, BloodHound Collection, LDAP Enumeration, SMB/RPC Enumeration, and Certificate Attacks (ADCS). Includes **WinShare Sweep** — a multi-protocol credential test (SMB, LDAP, LDAPS, WinRM, RDP, SSH, MSSQL, FTP, WMI) that checks port availability before running, supports pass-the-hash and domain flags, and saves all `[+]` findings as structured loot.
- **Loot extraction** — Post-ex command output is parsed and saved to a per-session loot store (XML on disk + database). Visible in the session report and project report. Loot persists across restarts and logouts.
- **Session Report** — Structured engagement report covering scan summary, NSE findings, CVE analysis with remediation, post-exploitation output, and extracted loot. Print-ready PDF output.
- **Notes** — Free-text notes saved per session.
- **Directory busting** — Feroxbuster integration with real-time streaming output. Results are persisted per session until a fresh scan is run.
- **SQLMap** — SQL injection scanner with full option coverage from the man page: all injection techniques, enumeration flags (banner, current-user, databases, tables, columns, hostname, privileges, roles, count, schema, dump), OS access (os-shell, os-pwn), SQL query/shell execution, second-order injection, detection tuning (level, risk, true/false strings, HTTP code), tamper scripts, and all request options. Custom args use shell-aware quote splitting. Findings are saved to loot.

### Password Attacks
- **Hashcat** — GPU-accelerated WPA/WPA2 handshake cracking. Accepts `.cap` and `.22000` files. Select from 50+ ISP-derived mask presets grouped by router/SSID family (BT Hub, TALKTALK, Virgin Media, Orange, Sky, Plusnet, and more), or enter a custom mask. Supports custom charset arguments (`-1`) for restricted keyspaces. Cracked passwords are decoded from raw hashcat output (including hex-encoded results) and stamped onto the session's handshake loot entries.
- **WiFi handshake capture** — Monitor mode management, target AP scanning, and handshake capture via airodump-ng + aireplay-ng, all from the browser. Captured handshakes persist in `<baseDir>/handshakes/` until explicitly deleted and are restored on startup.
- **WPA3-Transition Downgrade** — Detects WPA3-Transition mode APs (SAE+PSK mixed) and deploys a rogue AP via hostapd-mana. Configured with `auth_algs=1` (WPA-PSK only) to force clients to downgrade from SAE to PSK for handshake capture.
- **Bruteforce** — Hydra-based credential brute-forcing against network services. Supports wordlists, combo files, and single credential mode. For HTTP form attacks:
  - WordPress, Generic, and Admin quick-fill presets
  - Form URL, POST params (`^USER^`/`^PASS^` placeholders), and success/failure condition fields
  - Target sanitisation: `http://host:port/path` is automatically split into host, port (`-s`), and URL path
  - Shell-safe displayed command (args containing `&` or `^` are single-quoted for safe copy-paste)
- **WPScan** — WordPress vulnerability scanner with password attack mode. Username lists populated from local SecLists/Usernames wordlists. Full finding blocks (header + detail lines) are saved to loot.

### Infrastructure
- **Authentication** — JWT-based login stored in an httpOnly cookie. Linux PAM authentication (uses your Linux system credentials). Bcrypt password hashing. Auth routes rate-limited to 10 req/min; all mutating routes rate-limited to 120 req/min.
- **Storage** — SQLite by default (file created next to the binary). PostgreSQL supported. In-memory store for zero-config use. All scan results, CVEs, loot, and enumeration data are persisted to the database and survive restarts.
- **Binary portability** — The binary resolves `.env`, the SQLite database, loot files, and handshake captures relative to its own location, so it can be run from any working directory.
- **Startup** — The browser opens automatically once the server is accepting connections (polled via TCP, no fixed delay). It opens to `/login` so the login page is always shown first, even when the browser has a cached session cookie.

---

## Quick Start

See [QUICKSTART.md](QUICKSTART.md).

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.20+, Chi router, Gorilla WebSocket |
| Frontend | React 18, TypeScript, React Router |
| Database | SQLite (default) or PostgreSQL or in-memory |
| Auth | JWT (httpOnly cookie, 24-hour expiry, Linux PAM) |
| Scanning | nmap |
| Console | msfconsole (one process per session, auto-restart) |
| Password attacks | hashcat, hydra, aircrack-ng suite, wpscan |
| Directory busting | feroxbuster |
| AD attacks | kerbrute, enum4linux-ng |
| WiFi | airodump-ng, aireplay-ng, hostapd-mana |

---

## Project Structure

```
.
├── backend/
│   ├── main.go          # Router, all HTTP handlers, server entry point
│   ├── db.go            # Database models, queries (SQLite + PostgreSQL + in-memory)
│   ├── auth.go          # JWT generation, validation, PAM auth, cookie helpers
│   ├── websocket.go     # WebSocket upgrade, session fan-out broadcaster
│   ├── executor.go      # msfconsole process lifecycle, stdin/stdout fan-out, auto-restart
│   ├── scanner.go       # nmap execution, XML parsing, OS/service/gateway detection
│   ├── loot.go          # Post-ex output parsing, loot persistence (XML + DB)
│   ├── bruteforce.go    # Hydra argument builder, job management, output parser
│   ├── hashcat.go       # Hashcat WPA cracking, hex password decode
│   ├── wifi.go          # Monitor mode, AP scan, handshake capture, rogue AP
│   ├── handshake.go     # Handshake file registry, disk persistence, startup restore
│   ├── wpscan.go        # WPScan execution, block-accumulation output parser
│   ├── feroxbuster.go   # Feroxbuster execution, result persistence
│   ├── helpers.go       # JSON utilities, shell argument quoting
│   ├── env.go           # .env loader
│   └── go.mod
├── frontend/
│   └── src/
│       └── components/
│           ├── LoginPage.tsx           # Login
│           ├── ProjectsPage.tsx        # Project list and creation
│           ├── Dashboard.tsx           # Network scanner, session list, topology/report buttons
│           ├── SessionDetail.tsx       # Main workspace (all action panels)
│           ├── Console.tsx             # Live msfconsole terminal
│           ├── ReportPage.tsx          # Per-session engagement report
│           ├── ProjectReportPage.tsx   # Aggregated project-level report
│           ├── TopographyPage.tsx      # Graphical network topology map
│           └── HandshakeCapturePanel.tsx # WiFi monitor mode, AP scan, handshake capture
├── docs/
│   └── DEVELOPMENT.md   # Architecture and developer guide
├── start.sh             # Start backend + frontend dev server together
├── install.sh           # Build frontend + binary for production
├── QUICKSTART.md
└── README.md
```

---

## Workflow

```
Login
  │
  ▼
Create Project  ──►  Scan Network  ──►  Add Hosts as Sessions
  │                       │
  │                       ├──► Network Topology  (graphical host map)
  │                       └──► Project Report    (aggregated PDF report)
  │
  ▼
Open Session
  │
  ├─► 1. Vulnerability Scan      nmap -sV -O --script=vuln,vulners
  │
  ├─► 2. Enumeration             Services + MSF modules from scan XML
  │
  ├─► 3. CVE Analysis            CVEs → NVD CVSS scores → GitHub PoCs → DB
  │
  ├─► 4. Shells                  Manage active MSF sessions
  │
  ├─► 5. Post Exploitation       Quick commands + recommended modules + loot
  │
  ├─► 6. Active Directory        Domain enum, cred attacks, lateral movement, ADCS
  │
  ├─► 7. Password Attacks        Hashcat (WiFi), Hydra (services), WPScan
  │
  ├─► 8. Directory Busting       Feroxbuster recursive content discovery
  │
  └─► 9. Report                  Per-session structured report (PDF)
```

The MSF Console is always visible alongside the action panels. Commands typed there go directly to the session's msfconsole process; output from any panel action also streams through the console.

---

## API Reference

### Auth (public)
| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Login, sets httpOnly JWT cookie |
| POST | `/api/auth/logout` | Clear cookie |

### Projects
| Method | Path | Description |
|---|---|---|
| GET | `/api/projects` | List user's projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/{id}` | Get project |
| PUT | `/api/projects/{id}` | Update project |
| DELETE | `/api/projects/{id}` | Delete project and all sessions |
| GET | `/api/projects/{id}/sessions` | List sessions in project |
| POST | `/api/projects/{id}/sessions` | Add session to project |
| GET | `/api/projects/{id}/hosts` | List discovered hosts |
| POST | `/api/projects/{id}/scan` | Run nmap ping sweep |

### Sessions
| Method | Path | Description |
|---|---|---|
| GET | `/api/sessions` | List all user sessions |
| POST | `/api/sessions` | Create standalone session |
| GET | `/api/sessions/{id}` | Get session |
| DELETE | `/api/sessions/{id}` | Delete session |

### Session Actions
| Method | Path | Description |
|---|---|---|
| POST | `/api/sessions/{id}/vuln-scan` | Start vulnerability scan (async) |
| GET | `/api/sessions/{id}/vuln-scan` | Poll scan status and results |
| POST | `/api/sessions/{id}/enumerate` | Parse scan XML into service list |
| POST | `/api/sessions/{id}/cve-analysis` | Run CVE analysis |
| GET | `/api/sessions/{id}/cve-results` | Retrieve stored CVE results |
| POST | `/api/sessions/{id}/cve-results` | Save CVE results to database |
| GET | `/api/sessions/{id}/searchsploit` | Search Exploit-DB (with DB fallback) |
| GET | `/api/sessions/{id}/searchsploit-results` | Retrieve stored searchsploit results |
| POST | `/api/sessions/{id}/shell` | Send command to msfconsole |
| GET | `/api/sessions/{id}/msf-sessions` | List active MSF sessions |
| POST | `/api/sessions/{id}/loot` | Save loot from post-ex output |
| GET | `/api/sessions/{id}/loot` | Retrieve session loot |
| GET | `/api/sessions/{id}/notes` | Retrieve session notes |
| POST | `/api/sessions/{id}/notes` | Save session notes |
| POST | `/api/sessions/{id}/bruteforce` | Start Hydra bruteforce |
| GET | `/api/sessions/{id}/bruteforce` | Poll bruteforce status |
| DELETE | `/api/sessions/{id}/bruteforce` | Stop bruteforce |
| POST | `/api/sessions/{id}/hashcat` | Start hashcat job |
| GET | `/api/sessions/{id}/hashcat` | Poll hashcat status |
| DELETE | `/api/sessions/{id}/hashcat` | Stop hashcat job |
| POST | `/api/sessions/{id}/ferox` | Start feroxbuster scan |
| GET | `/api/sessions/{id}/ferox` | Poll feroxbuster status |
| DELETE | `/api/sessions/{id}/ferox` | Stop feroxbuster |
| GET | `/api/sessions/{id}/ferox-results` | Retrieve stored ferox results |
| POST | `/api/sessions/{id}/wpscan` | Start WPScan |
| GET | `/api/sessions/{id}/wpscan` | Poll WPScan status |
| DELETE | `/api/sessions/{id}/wpscan` | Stop WPScan |
| POST | `/api/sessions/{id}/handshakes` | Upload or list handshake files |
| GET | `/api/sessions/{id}/handshakes` | List captured handshakes |
| DELETE | `/api/sessions/{id}/handshakes/{file}` | Delete a handshake file |

### Other
| Method | Path | Description |
|---|---|---|
| GET | `/api/ws?session={id}` | WebSocket — live msfconsole stream |
| GET | `/api/network` | Local network interfaces |
| GET | `/api/wordlists` | Available username and password wordlists |
| GET | `/api/health` | Health / auth check |

---

## Environment Variables

Create `backend/.env`:

```env
# Required
JWT_SECRET=change-this-to-a-long-random-string

# Database — omit for SQLite next to the binary, or set to memory:// for in-memory
DATABASE_URL=sqlite3://bagaholdin.db

# Optional
MSFCONSOLE_PATH=/usr/bin/msfconsole   # defaults to 'msfconsole' on PATH
COOKIE_SECURE=true                     # set in production (HTTPS only)
ALLOWED_ORIGIN=https://your-domain     # restrict WebSocket origin in production
```

---

## Building for Production

```bash
# 1. Build the React frontend
cd frontend
npm run build          # output → frontend/build/

# 2. Copy frontend build into backend/ui/ (required before go build)
rm -rf ../backend/ui && cp -r build ../backend/ui

# 3. Build the Go backend (serves API + static files on :8080)
cd ../backend
go build -o bagaholdin .
./bagaholdin
```

Or use the provided script:

```bash
chmod +x install.sh
./install.sh           # builds frontend then compiles backend/bagaholdin
```

The binary serves the React build as static files. Only port 8080 needs to be exposed. The `.env` file and SQLite database are resolved relative to the binary, so the binary can be run from any directory.

---

## Security Notes

- All protected routes require a valid JWT cookie set at login.
- Authentication uses Linux PAM — the same credentials as your Linux system login.
- Auth routes are rate-limited to 10 requests per minute per IP.
- All mutating session-action routes are rate-limited to 120 requests per minute per IP.
- The WebSocket endpoint validates the JWT before upgrading.
- Set `COOKIE_SECURE=true` and `ALLOWED_ORIGIN` when deploying over HTTPS.
- **Only use this tool on networks you own or have explicit written authorisation to test.**

---

## Legal

This software is provided for **educational purposes only**. Use it to learn about penetration testing concepts in a controlled lab environment, on your own systems, or on systems where you hold explicit written permission from the owner.

**Do not use this tool against systems you do not own or are not authorised to test.** Doing so is illegal in most jurisdictions and carries serious consequences. The authors and contributors accept no responsibility for any unlawful use.

---

## License

MIT
