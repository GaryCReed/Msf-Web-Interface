# Bagaholdin — Development Guide

## Architecture Overview

Bagaholdin is a single Go binary that embeds the compiled React frontend and serves everything on port 8080.

```
frontend/          React 18 + TypeScript source
frontend/build/    Production build (npm run build)
backend/ui/        Copy of frontend/build — embedded into binary at compile time
backend/           Go source (Chi router, Gorilla WebSocket, CGo SQLite)
backend/bagaholdin Compiled binary (gitignored)
```

### Build Pipeline

**Critical:** The binary embeds `backend/ui/` at compile time via `//go:embed all:ui` in `embed.go`. You must copy the frontend build into that directory before compiling or the binary will serve a stale UI.

```bash
# Full production build (use install.sh or do manually):
cd frontend && npm run build
rm -rf ../backend/ui && cp -r build ../backend/ui
cd ../backend && go build -o bagaholdin .
./bagaholdin        # serves on :8080, opens browser automatically
```

For development (hot reload):
```bash
# Terminal 1 — backend API
cd backend && go run .

# Terminal 2 — frontend dev server (proxies /api to :8080)
cd frontend && npm start     # opens :3000, hot reloads on save
```

---

## Backend

### Entry Point

`backend/main.go` — HTTP router setup, all handler registrations, server startup, browser launch.

Key functions:
- `baseDir()` — resolves the directory the binary lives in; used to anchor `.env`, SQLite path, and persistent data directories so the binary can be run from any working directory
- `init()` — loads `.env` from `baseDir()/.env`, re-reads `JWT_SECRET` after `.env` is loaded
- `main()` — mounts router, serves embedded static files, initialises handshake dir, starts `http.ListenAndServe(:8080)`, opens default browser after 500 ms

### Backend Source Files

| File | Purpose |
|---|---|
| `main.go` | Router, all HTTP handlers, server entry point |
| `db.go` | Database models, queries (SQLite + PostgreSQL + in-memory) |
| `auth.go` | JWT generation, validation, PAM authentication, cookie helpers |
| `websocket.go` | WebSocket upgrade, session fan-out broadcaster |
| `executor.go` | msfconsole process lifecycle, stdin/stdout fan-out, auto-restart |
| `scanner.go` | nmap execution, XML parsing, OS/service/gateway detection |
| `loot.go` | Post-ex output parsing, loot XML persistence, DB upsert |
| `bruteforce.go` | Hydra argument builder, job management, output parser |
| `hashcat.go` | Hashcat WPA cracking job management, hex password decode |
| `wifi.go` | Monitor mode, AP scan, handshake capture, WPA3-Transition rogue AP |
| `handshake.go` | Handshake file registry, disk persistence, restore on startup |
| `wpscan.go` | WPScan execution, block-accumulation output parser |
| `feroxbuster.go` | Feroxbuster execution, result persistence, DB save |
| `helpers.go` | JSON encode/decode, shell argument quoting |
| `env.go` | .env loader |

### Router

All protected routes sit under Chi middleware that validates the JWT cookie. Public routes: `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/ws` (WebSocket, validates JWT before upgrade).

Auth routes are rate-limited to 10 req/min per IP. All mutating session-action routes are rate-limited to 120 req/min per IP.

### Database

`backend/db.go` — supports three backends, selected via `DATABASE_URL`:

| Value | Backend |
|---|---|
| unset or `sqlite3://…` | SQLite (CGo, file next to binary) |
| `memory://` | In-memory (MemoryDB struct, no persistence) |
| `postgresql://…` | PostgreSQL (lib/pq driver) |

Default: SQLite file `bagaholdin.db` created next to the binary.

**Schema tables:**

| Table | Purpose |
|---|---|
| `users` | Account credentials (bcrypt) |
| `sessions` | Engagement sessions (host, project link) |
| `projects` | Project groups |
| `project_hosts` | Hosts discovered per project |
| `cve_results` | CVE analysis JSON blobs (one row per session) |
| `vuln_results` | Nmap vuln scan JSON blobs (one row per session) |
| `enum_results` | Service enumeration JSON blobs (one row per session) |
| `loot_data` | Serialised loot XML (one row per session) |
| `searchsploit_results` | Searchsploit output (one row per session) |
| `ferox_results` | Feroxbuster found URLs + output (one row per session) |

All result tables use `ON CONFLICT (session_id) DO UPDATE` (upsert). Results survive restarts and logouts.

### Authentication

`backend/auth.go` — Linux PAM authentication via `authenticateLinuxUser()`. JWT signed with `JWT_SECRET` (HS256, 24 h expiry), stored as an httpOnly cookie. `COOKIE_SECURE=true` enables the Secure flag for HTTPS deployments.

### WebSocket / MSF Console

`backend/websocket.go` — upgrades the connection, validates JWT, fans output from the session's msfconsole executor to all connected clients.

`backend/executor.go` — manages one `msfconsole -q` process per session. Commands sent via `ExecuteCommand(cmd)` write to msfconsole stdin; stdout/stderr are fanned out to a broadcaster. Auto-restarts on crash (up to 3 attempts with back-off). Handles transparent reconnect — subscriber channels stay alive across restarts.

### Scanner

`backend/scanner.go` — wraps nmap. Vuln scan runs asynchronously: nmap writes XML to `/tmp/msf-scans/<ip>.xml` then the handler parses services, OS info, and NSE script output. Results polled via `GET /api/sessions/{id}/vuln-scan` and persisted to `vuln_results` table.

**Gateway detection** (`systemGateway`):
1. Try `ip route show <network>` for a specific route with `via` inside the subnet
2. Fall back to `ip route show default` only if the default gateway is inside the subnet
3. Final fallback: `x.x.x.1` derived from the CIDR

The gateway is always force-added as a scan target even when it is also a local IP (e.g. Docker host bridge).

CVE analysis (`handleCVEAnalysis`) fetches from NVD API and greps the local MSF module tree. Results persisted to `cve_results` table with DB fallback on re-load.

### Loot System

`backend/loot.go` — all post-exploitation artefacts are stored as a structured XML document. The XML is saved to `<baseDir>/loot-<sessionID>.xml` on disk AND upserted into the `loot_data` database table on every write. On load, the DB is the primary source if the file is missing.

**Loot item types and their sources:**

| Type | Trigger |
|---|---|
| `credential` | hashdump, smart_hashdump, mimipenguin, lsa_secrets, cachedump output |
| `session_credential` | msfconsole session-opened event |
| `bruteforce_credential` | Hydra found line |
| `current_user` | getuid / whoami / id output |
| `system_info` | sysinfo / systeminfo / uname / ver output |
| `privileges` | getprivs / whoami /all |
| `groups` | group membership lines |
| `user_account` | /etc/passwd entries |
| `user_list` | net user output |
| `network_hosts` | arp output |
| `privilege_escalation` | getsystem result |
| `is_admin` | is_admin output |
| `environment` | env / set output (filtered for secret/key/pass/token) |
| `wifi_handshake` | Handshake capture; updated with cracked password by hashcat |
| `sqlmap_finding` | sqlmap scan findings |
| `wpscan_finding` | wpscan findings (full block including detail lines) |
| `ad_discovery` | nmap ldap-rootdse / smb-os-discovery output |
| `kerbrute_users` | kerbrute VALID USERNAME lines |
| `smb_enum` | enum4linux / enum4linux-ng output |
| `crackmapexec_finding` | crackmapexec [+] success lines (raw text blob) |
| `nxc_finding` | WinShare Sweep [+] lines (structured: protocol, host, port, machine, user, status) |

`AppendLoot(sessionID, target, cmd, output)` is the main entry point — it calls `extractLoot()` which dispatches to per-type parsers based on the `cmd` string.

`SetWifiHandshakePassword(sessionID, target, ssid, bssid, password)` — finds `wifi_handshake` loot entries matching the BSSID and stamps them with the cracked password. Called by hashcat after a successful crack.

`AppendNxcFinding(sessionID, target, finding)` — saves a single structured WinShare Sweep result as `nxc_finding`. Each field (protocol, host, port, machine, user, status, raw) is stored individually for table rendering in the loot tab.

### Async Job Pattern

Long-running tools (Hydra, hashcat, sqlmap, feroxbuster, wpscan) follow the same pattern:

1. `POST /sessions/{id}/tool` — start: create job struct with `cmd.Process`, store in `sync.Map`, begin goroutine that streams output to a buffer
2. `GET /sessions/{id}/tool` — poll: return current output + done flag
3. `DELETE /sessions/{id}/tool` — stop: call `Process.Kill()`, mark done

Job state is stored in package-level `sync.Map` (not the database). Output accumulated during the run is also saved to the database (feroxbuster, searchsploit) so results survive a restart.

### Meterpreter Post-Exploitation

`handleShellCommand` writes commands to msfconsole stdin via `ExecuteCommand` and collects output for up to 10 seconds (800 ms idle timeout).

**`shell <cmd>` channel issue:** In non-TTY mode (piped stdin/stdout), msfconsole's channel I/O for `shell <cmd>` only produces "Process N created. Channel N created." — the subprocess output does not reach the HTTP response. The frontend handles this with a 3-step sequence:

1. Send `shell` (standalone) — enters bash in channel-interact mode
2. Send `<cmd>` through the active channel — output flows back through channel stdout to msfconsole stdout to HTTP response
3. Send `exit` — closes bash, returns to meterpreter prompt

**Bash sub-shell tracking:** `inBashSubshellRef` tracks when the post-ex panel has entered an interactive bash sub-shell (via standalone `shell`). Before sending any native meterpreter command, if this flag is set, `exit` is sent first to return to the meterpreter prompt.

**Session type auto-detect:** `parseMsfSessions` is called both on the Shells tab (full load, backgrounds active session first) and silently when the Post Exploitation tab opens (`loadMsfSessionsQuiet`, no `ensureMsfPrompt`). The parser handles blank lines between the header and session rows (skipped, not treated as end-of-list) and the `*` prefix Metasploit adds to the currently-interacted session. `hostSessions` filters the global session list to only those whose connection string destination or info field matches `session.target_host`, so sessions on other hosts are not shown.

**Shell upgrade:** `post/multi/manage/shell_to_meterpreter` is run without `jobs -K` (which would kill needed infrastructure). After `run` completes, a 2-second pause allows callbacks to register. The session list is then reloaded: if at least one new meterpreter session was created, the original shell is killed and any spurious sessions with an empty `Information` field are also killed (these are callbacks from alternate NICs on a multi-homed target). If the upgrade failed, the original shell is left intact.

### Bruteforce (Hydra)

`backend/bruteforce.go` — `buildHydraArgs` constructs the hydra argv slice passed to `exec.Command` (no shell involved).

For `http-post-form` and `http-get-form`:
- `form_url` is required; any `http://host/` prefix is stripped to a bare path
- `form_params` must be non-empty (validated; error returned if missing)
- `form_condition` defaults to `F=incorrect` if empty
- Form arg format: `path:POST_data:condition` — passed as a single argv element, so `&` in params is safe

Target sanitisation: any `http(s)://` prefix is stripped and any embedded `host:port` is split — the port is promoted to the `-s PORT` flag so Hydra receives a bare IP, not `[IP:PORT]:80`.

The displayed command uses `shellQuoteArgs` — args containing `&`, `^`, spaces, or other shell-special characters are single-quoted so copying the command to a terminal works correctly.

### WiFi / Handshake

`backend/handshake.go` — handshake files (`.cap`, `.22000`) are stored in `<baseDir>/handshakes/` (persistent across restarts). On startup, `restoreHandshakesFromDisk()` walks the directory and re-populates the in-memory registry.

`backend/wifi.go` — rogue AP for WPA3-Transition downgrade uses hostapd-mana. The rogue interface is set to managed mode before configuring (`iw dev <iface> set type managed`). hostapd config uses `auth_algs=1` (WPA only, forces downgrade away from SAE) and `wpa_pairwise=TKIP CCMP`.

`backend/hashcat.go` — WPA cracking uses hashcat mode 22000. After cracking, the raw password token is decoded with `hexPlainDecode` (strips `$HEX[...]` wrapper; also tries raw hex decode guarded by `isPrintableASCII` to avoid corrupting numeric passwords). The cracked password is then stamped onto all matching `wifi_handshake` loot entries via `SetWifiHandshakePassword`.

### WPScan

`backend/wpscan.go` — output is processed with a block accumulator that buffers `[+]/[!]/[i]` header lines together with their following `| detail` lines. The full block (header + details) is saved as a single `wpscan_finding` loot entry. Single-line password/user finds are saved immediately without buffering.

### Feroxbuster

`backend/feroxbuster.go` — results are saved to both the `ferox_results` database table and an in-memory job buffer. On a new scan, `db.DeleteFeroxResults(sessionID)` clears the previous results. The output file is read as the authoritative source after the process exits (deduplication by URL).

### WinShare Sweep (nxcsweep.go)

`backend/nxcsweep.go` — multi-protocol credential sweep via NetExec (`nxc`). Nine protocols in a priority table (SMB/LDAP/LDAPS/WinRM/RDP/SSH/MSSQL/FTP/WMI), each with port, extra args, and a per-protocol flag strip list (`--local-auth` stripped from FTP). Port availability is checked with `net.DialTimeout` (2-second timeout) before running each protocol; skipped protocols log "closed/filtered". Supports password auth (`-p`) and pass-the-hash (`-H`). ANSI escape codes are stripped from output before storage. `[+]` lines are parsed by `reNxcFound` regex into `NxcFinding` structs (protocol, host, port, machine name, user+credential, status). Each finding is saved via `AppendNxcFinding` as a structured `nxc_finding` loot item. The loot tab renders these in a dedicated "NXC / CME Findings" table with `(Pwn3d!)` highlighted in red.

### SQLMap

`backend/sqlmap.go` — `buildSqlmapArgs` constructs the full argv slice from `SqlmapRequest`. All options from the man page are supported: injection techniques, `--time-sec`, `--second-url`, detection level/risk/strings/code, `--no-cast`, full enumeration suite (banner, current-user, current-db, is-dba, hostname, users, passwords, privileges, roles, databases, tables, columns, count, schema, dump/dump-all), SQL query/shell (`--sql-query`, `--sql-shell`), OS access (`--os-shell`, `--os-pwn`), request options (user-agent, proxy, Tor, SSL, ignore-code, delay, timeout, retries, threads), crawl, and custom args. Custom args are parsed by `shellSplitArgs()` (respects single/double quotes) rather than `strings.Fields`. The output parser detects: DBMS identification, injection parameter blocks (`Parameter: X (GET/POST)` + `Type: ...` lines), database list entries (`[*] name`), table/database label lines in dump output, dump rows, and OS access lines. `[*]` status lines (startup, target count) are excluded from database findings.

### File Paths

| Purpose | Path |
|---|---|
| Nmap scan XML | `/tmp/msf-scans/<ip>.xml` |
| Nmap raw output | `/tmp/msf-scans/<ip>-output.txt` |
| Hydra output | `/tmp/hydra-<sessionID>.txt` |
| SQLmap output | `/tmp/sqlmap-<sessionID>/` |
| Feroxbuster output | `/tmp/ferox-<sessionID>/results.txt` |
| Hashcat cracked | `/tmp/hashcat-<sessionID>-cracked.txt` |
| WiFi captures | `/tmp/wifi-cap-<sessionID>-*.cap` |
| WiFi hashes | `/tmp/wifi-cap-<sessionID>-*.22000` |
| Handshakes (persistent) | `<baseDir>/handshakes/` |
| Loot XML (persistent) | `<baseDir>/loot-<sessionID>.xml` |

On clean shutdown (`SIGINT`/`SIGTERM`) the `/tmp` directories are removed automatically. Handshakes and loot XML under `<baseDir>` are kept.

---

## Frontend

React 18 + TypeScript, bootstrapped with Create React App.

### Key Components

| Component | Purpose |
|---|---|
| `App.tsx` | Router, auth state, project fetch wrapper |
| `LoginPage.tsx` | PAM credential entry |
| `ProjectsPage.tsx` | Project CRUD, project-level tool panels |
| `Dashboard.tsx` | Per-project: network scan, session list, topology/report buttons |
| `SessionDetail.tsx` | 18-tab per-session workspace |
| `Console.tsx` | Live WebSocket msfconsole terminal with ANSI colour parsing |
| `ReportPage.tsx` | Per-session professional PDF report |
| `ProjectReportPage.tsx` | Aggregated project-level PDF report |
| `TopographyPage.tsx` | Draggable SVG network topology map |
| `HandshakeCapturePanel.tsx` | WiFi monitor mode, AP scan, handshake capture, WPA3-Transition detection |

### State Persistence

All significant result types are persisted to the database and survive restarts and logouts:

| Data | Storage |
|---|---|
| CVE results | `cve_results` table (JSON blob) |
| Vuln scan output | `vuln_results` table (JSON blob) |
| Enumeration results | `enum_results` table (JSON blob) |
| Loot | `loot_data` table (XML blob) + `<baseDir>/loot-<id>.xml` |
| Searchsploit results | `searchsploit_results` table |
| Feroxbuster results | `ferox_results` table (JSON blob) |
| Topology positions/labels | localStorage (`topology-{projectId}-pos/labels`) |
| OS info | localStorage (`session-{id}-os`) |

All DB tables use upsert (`ON CONFLICT DO UPDATE`) so re-running a scan always reflects the latest state.

### Routing / Login

`App.tsx` uses React Router. The `/login` route renders `LoginPage` unconditionally (regardless of auth state) so navigating to `/login` always shows the login form. After a successful login, the `isAuthenticated` state becomes `true` and the `/login` route renders `<Navigate to="/" replace />`, redirecting to the projects page. The binary opens the browser to `/login` (not `/`) once the server is accepting TCP connections.

### Post-Exploitation Panel

The post-ex panel has three layers of session state:
- `interactedSessionRef` / `interactedSession` — tracks which MSF session is currently entered (via `sessions -i <id>`)
- `inBashSubshellRef` — tracks whether a standalone `shell` command has been sent (dropping into an interactive bash sub-shell)
- `hostSessions` — derived from `msfSessions` filtered to the current `session.target_host` IP; used for the Shells panel display and `activeMsfSession` selection

Commands of the form `shell <cmd>` (with arguments) use the 3-step channel-interact sequence rather than sending `shell <cmd>` directly, because non-TTY msfconsole does not stream channel stdout back to the HTTP response for combined `shell cmd` calls.

The Shells panel kill button optimistically removes the session from `msfSessions` state immediately, clears `interactedSessionRef` if the killed session was the active one, then awaits `sessions -k N` followed by an 800ms settle and a full `loadMsfSessions` reload.

### CSS Variables

Dark theme defined in `frontend/src/index.css` as CSS custom properties. Report pages use explicit hex values — no CSS variables — so they print correctly.

### API Proxy (dev only)

`frontend/package.json` has `"proxy": "http://localhost:8080"` — all `/api/*` requests are forwarded to the backend during `npm start`. In production the Go binary serves both the API and the static files.

---

## Environment Variables (`backend/.env`)

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | (required) | HS256 signing key — use a long random string |
| `DATABASE_URL` | SQLite next to binary | `sqlite3://path.db`, `memory://`, or `postgresql://…` |
| `MSFCONSOLE_PATH` | `msfconsole` | Full path if not on PATH |
| `COOKIE_SECURE` | `false` | Set `true` in production (HTTPS) |
| `ALLOWED_ORIGIN` | (any) | Restrict WebSocket origin in production |

---

## Adding a New Tool Integration

1. **Backend handler** (`backend/main.go` or a new `backend/<tool>.go`):
   - Follow the async start/poll/stop pattern for long-running tools
   - For short tools, a synchronous handler with `context.WithTimeout` is sufficient
   - Parse output and call `AppendLoot` or a new `Append*` function in `loot.go`

2. **Loot parser** (`backend/loot.go`):
   - Add a new loot type string
   - Add an `Append<Tool>` function that parses raw output into `[]LootField`
   - Append a `LootItem` with the appropriate `Type`, `Source`, `Timestamp`, and `Fields`

3. **Persistence** (if results should survive restart):
   - Add a `Save<Tool>Results` / `Get<Tool>Results` method pair to `db.go`
   - Add the table to the schema in both `Migrate()` and the idempotent `CREATE TABLE IF NOT EXISTS` block
   - Call save after the run completes and load in the GET handler with DB fallback

4. **Route** (`backend/main.go`):
   - Register under the authenticated group: `r.Post("/sessions/{id}/tool", handleStartTool(db))`

5. **Frontend panel** (`frontend/src/components/SessionDetail.tsx`):
   - Add a new tab ID and label to `ACTIONS`
   - Add `{activeAction === N && <ToolPanel ... />}` in the render
   - Update the console-hide condition if the panel should be full-width

6. **Rebuild**: `npm run build` → `rm -rf backend/ui && cp -r frontend/build backend/ui` → `go build -o bagaholdin .`
