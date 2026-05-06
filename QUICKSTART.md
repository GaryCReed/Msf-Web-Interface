# Quick Start

> **Legal Notice:** Bagaholdin is for **educational purposes only** and must only be used on networks you own or have **explicit written permission** to test. Unauthorised use is illegal.

> **Status:** This project is in a **workable state** — it functions, but is not production-hardened. Treat it as a learning platform.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.20+ | `go version` |
| Node.js | 18+ | `node --version` |
| msfconsole | any | `which msfconsole` |
| nmap | any | `which nmap` |
| hashcat | any | `which hashcat` — for WiFi cracking |
| hydra | any | `which hydra` — for bruteforce |
| nxc | any | `which nxc` — for WinShare Sweep (NetExec) |
| sqlmap | any | `which sqlmap` — for SQL injection |
| feroxbuster | any | `which feroxbuster` — for directory busting |
| wpscan | any | `which wpscan` — for WordPress scanning |
| aircrack-ng suite | any | `which airodump-ng` — for WiFi capture |
| hostapd-mana | any | `which hostapd-mana` — for WPA3 downgrade |

---

## Starting the App

**1. Configure the backend**

```bash
cat > backend/.env <<'EOF'
JWT_SECRET=change-this-to-a-long-random-string
EOF
```

**2. Start everything**

```bash
chmod +x start.sh
./start.sh
```

Backend starts on `http://localhost:8080`, frontend dev server on `http://localhost:3000`.

**3. Open the app**

Navigate to `http://localhost:3000` and log in using your Linux system credentials.

---

## First Use

### Create a project

1. Log in and click **New Project**.
2. Enter a name and your target network range (e.g. `192.168.1.0/24`).
3. Click **Scan Network** to run an nmap ping sweep and discover live hosts.
4. Tick the hosts you want and click **+ Add Selected**, or click **+ Add** next to individual hosts.

### Project-level views (right column of the Dashboard)

| Button | What it does |
|---|---|
| **View Topology** | Opens a graphical network map of all discovered hosts. Hosts are colour-coded by worst CVE severity and connected to the inferred gateway node. |
| **Generate Report** | Opens an aggregated professional penetration test report covering all sessions in the project — executive summary, host summaries, consolidated CVE findings with remediation advice, and post-exploitation findings. |

### Work a session

Open a session to reach the main workspace. The MSF Console is always visible on the right. The left panel has action tabs:

| Tab | What it does |
|---|---|
| **Vulnerability Scan** | Runs `nmap -sV -O --script=vuln,vulners` against the target. Runs in the background — navigate away freely. Results persist to the database. |
| **Enumeration** | Parses scan XML into a structured service list and suggests Metasploit modules per service. Results persist. |
| **CVE Analysis** | Fetches CVEs from NVD, enriches with CVSS scores and GitHub PoC repositories. Results are saved to the database and feed into the project report. |
| **Shells** | Lists active MSF sessions **for the current target host only** (sessions on other hosts are hidden). Interact, upgrade to Meterpreter, background, or kill. Killed sessions are removed immediately. Upgrade automatically removes the original shell and any spurious sessions from multi-homed targets. |
| **Post Exploitation** | Quick-command buttons and recommended modules filtered by session type and OS. Session type is auto-detected when the tab opens. `shell <cmd>` buttons use a 3-step sequence to correctly capture output through msfconsole's non-TTY pipe. |
| **Active Directory** | Grouped AD attack commands: domain enum, credential attacks (Kerberoast, AS-REP, DCSync), lateral movement, privilege escalation, BloodHound, LDAP enum, SMB/RPC enum, ADCS certificate attacks. Includes WinShare Sweep for multi-protocol credential testing. |
| **Password Attacks** | WiFi handshake capture and hashcat cracking with 50+ ISP mask presets; Hydra bruteforce against network services with HTTP form presets; WPScan WordPress scanner. |
| **Directory Busting** | Feroxbuster recursive content discovery. Results persist per host until a fresh scan is run. |
| **SQLMap** | SQL injection scanner with full option coverage: all techniques, enumeration, OS shell access, tamper scripts, and detection tuning. Findings saved to loot. |
| **Report** | Structured per-session engagement report. Print or save as PDF. |

### MSF Console tips

- Type commands directly in the console input at the bottom of the screen.
- Arrow keys cycle through command history.
- The console auto-reconnects if the connection drops.
- msfconsole auto-restarts if it crashes (up to 3 attempts).
- When you **Interact** with a shell or Meterpreter session, the console enters that session. Panel actions that need the MSF prompt (e.g. running modules, listing sessions) will automatically background the active session first.

---

## Network Topology

Click **View Topology** on the project dashboard to open the topology map in a new tab.

- The **gateway node** (top-centre, blue) is inferred from the project network range (e.g. `192.168.1.1` for `192.168.1.0/24`). The actual system gateway is detected and force-added to scans.
- **Host nodes** below are colour-coded by worst CVE severity. Solid connectors indicate hosts with active sessions; dashed connectors indicate discovered-but-unsessioned hosts.
- Each node shows IP, hostname (if resolved), session name, detected OS, open port count, and CVE count.
- Click **Print / Save as PDF** in the toolbar to export.

---

## Password Attacks

### WiFi Handshake Cracking

1. In a session, go to the **Password Attacks** tab.
2. Upload a `.cap` or `.22000` file, **or** capture one live using the WiFi Capture sub-panel.
3. Select a mask from the **ISP / WiFi mask presets** dropdown. Presets are grouped by router family and reflect the correct keyspace, length, and character exclusions for each SSID type.
4. Optionally enter a custom mask or wordlist.
5. Click **Start**. Cracked passwords appear in the output and are automatically stamped onto the session's handshake loot entry.

Captured handshakes are stored in `<install-dir>/handshakes/` and persist until explicitly deleted.

### WPA3-Transition Downgrade

Vulnerable APs (those advertising both SAE and PSK) are highlighted in the WiFi Capture panel with an amber **WPA3-T** badge. Selecting one and starting a rogue AP attack:

- Spawns a hostapd-mana rogue AP configured for WPA-PSK only (`auth_algs=1`)
- Forces clients to downgrade from SAE to PSK
- Captures the resulting WPA2 handshake for offline cracking

### Service Bruteforce (Hydra)

1. Select a protocol from the service dropdown (ssh, ftp, http-post-form, etc.)
2. For **HTTP form attacks** (`http-post-form` / `http-get-form`):
   - Use the **WordPress**, **Generic**, or **Admin** preset buttons to auto-fill the URL path, POST params, and success/failure condition.
   - WordPress preset: `log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1` with `S=Dashboard` (detects the wp-admin dashboard on successful login).
   - Enter the target's IP or leave blank to use the session host. If the target is on a non-standard port (e.g. `:8181`), enter it in the **Port override** field — or include it in the target IP field as `192.168.1.1:8181` and it will be extracted automatically.
3. Choose credential mode: wordlists, combo file, or a single username/password pair.
4. Click **Start**.

### WinShare Sweep (Active Directory panel)

Tests credentials across up to nine protocols in one run. Found in the **Active Directory** tab.

1. Tick the protocols to test (SMB, LDAP, LDAPS, WinRM, RDP, SSH, MSSQL, FTP, WMI — all on by default).
2. Enter the target IP (defaults to the session host), domain, and either a password or an NT hash for pass-the-hash.
3. Toggle **--local-auth** if testing local accounts rather than domain accounts.
4. Click **▶ Run WinShare Sweep**.

Each protocol port is checked before running — closed ports are skipped. All `[+]` successes appear in the live output and are saved to the **NXC / CME Findings** section of the Loot tab. `(Pwn3d!)` is highlighted in red.

---

## Stopping

Press `Ctrl+C` in the terminal running `start.sh`. Both the backend and frontend are stopped cleanly.

---

## Production Build

Build a single self-contained binary that serves the React app on port 8080.

> **Important — two-step build:** The binary embeds the React UI at compile time from `backend/ui/`. You must copy the frontend build into that directory **before** running `go build`, otherwise the binary will serve a stale or empty UI.

```bash
# Option 1 — use the install script (handles both steps automatically)
chmod +x install.sh
./install.sh

# Option 2 — manual (both steps required)
cd frontend && npm run build
rm -rf ../backend/ui && cp -r build ../backend/ui   # ← required before go build
cd ../backend && go build -o bagaholdin .
```

Run the binary:

```bash
cd backend
./bagaholdin
```

The binary resolves `.env`, the SQLite database, loot files, and handshake captures relative to itself, so it can be placed and run from any directory. Only port 8080 needs to be exposed.

Set additional environment variables in `backend/.env` for production:

```env
COOKIE_SECURE=true
ALLOWED_ORIGIN=https://your-domain.example.com
```

---

## Troubleshooting

**`msfconsole` not found**
Add `MSFCONSOLE_PATH=/full/path/to/msfconsole` to `backend/.env`.

**`hashcat` or `hydra` not found**
Install them via your package manager (`sudo apt install hashcat hydra`) or add their full paths to `backend/.env`.

**Hydra http-post-form returns "Wrong syntax"**
Ensure the **POST params** field is filled in. The form argument requires three colon-separated parts: `path:params:condition`. Use the **WordPress**, **Generic**, or **Admin** preset buttons to auto-fill correct values.

**Hydra resolving wrong address (`[IP:PORT]:80`)**
Hydra is receiving the port as part of the hostname. Enter the IP and port separately — use the **Port override** field for the port number, or enter `IP:PORT` in the target IP field and it will be split automatically.

**WebSocket disconnects immediately**
Check that `JWT_SECRET` is set in `backend/.env`. A missing or empty secret causes token validation to fail and the WebSocket connection to close.

**Scan never completes**
Scan output is written to `/tmp/msf-scans/`. Check that directory for `.txt` and `.xml` files. Errors are written to `<ip>-output.txt.err`.

**CVEs not appearing in the project report**
Open each session, go to **CVE Analysis**, and run the analysis if it has not been run yet. Results are saved to the database automatically once loaded.

**Post-ex `shell <cmd>` commands show only "Process N created. Channel N created."**
This is a known limitation of non-TTY msfconsole. Use the post-ex panel buttons — they handle this automatically by entering bash first, sending the command through the active channel, then exiting. Avoid sending `shell cmd` directly via the console input for commands where you need to capture output.

**Meterpreter commands fail with "command not found"**
The console may be in a bash sub-shell from a previous `shell` command. The post-ex panel tracks this state and sends `exit` before the next meterpreter command, but if you sent `shell` via the console input manually, type `exit` in the console to return to the meterpreter prompt.

**WPA3 rogue AP not capturing handshakes**
Ensure `hostapd-mana` is installed and the wireless interface supports AP mode. The interface is automatically switched to managed mode before AP configuration. Check that the `wpa_pairwise=TKIP CCMP` line is present in the generated hostapd config — mixed TKIP/CCMP is required to accept both old and new client cipher suites.

**Handshake cracked password shows as hex**
If hashcat outputs the password in hex-encoded form, the backend automatically decodes it — provided the decoded bytes are printable ASCII. If the cracked password contains non-ASCII characters it will remain in the raw hashcat format.

**Port 3000 already in use**
`npm start` will offer to use a different port. The frontend dev proxy is configured for port 8080, so the backend port must not change.

**Database file in the wrong location**
The binary creates `bagaholdin.db` in the same directory as itself. If running with `go run .`, the database is created in the current working directory. Set `DATABASE_URL=sqlite3:///absolute/path/to/bagaholdin.db` in `.env` to fix the location explicitly.

**Upgrade to Meterpreter creates two sessions or zero sessions**
Two sessions: the target is multi-homed and meterpreter called back from multiple NICs. The upgrade button automatically kills any new sessions that have an empty Information field (spurious NICs) and keeps the real session. Zero sessions: the upgrade failed (wrong payload arch, firewall blocking port 4433, etc.) — the original shell is left alive so you can retry or use a different approach.

**Shells panel shows sessions from other hosts**
Each session page filters the MSF session list to only sessions whose connection destination or Info field matches the session's target host. If a session is missing, check that the target IP in Bagaholdin matches the IP in the msfconsole connection string.

**WinShare Sweep: `nxc` not found**
Install NetExec: `sudo apt install netexec` or `pipx install netexec`. The binary must be on PATH as `nxc`.

**Killed session still shows in the Shells panel**
The UI removes the session immediately on click (optimistic update). If it reappears after the reload, msfconsole did not fully process the kill — check the console output for errors and try `sessions -k N` manually.
