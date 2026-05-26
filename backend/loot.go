package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// lootMu serialises all loot file reads+writes to prevent concurrent goroutines
// from overwriting each other (e.g. multiple hydra creds found simultaneously).
var lootMu sync.Mutex

// lootDB is set at startup so saveLootDocument can persist to the database.
var lootDB *DB

// ── XML / JSON structures ────────────────────────────────────────────────────

type LootField struct {
	Name  string `xml:"name,attr" json:"name"`
	Value string `xml:",chardata" json:"value"`
}

type LootItem struct {
	Type      string      `xml:"type"       json:"type"`
	Source    string      `xml:"source"     json:"source"`
	Timestamp string      `xml:"timestamp"  json:"timestamp"`
	Fields    []LootField `xml:"data>field" json:"fields"`
}

type LootDocument struct {
	XMLName   xml.Name   `xml:"loot"`
	SessionID int        `xml:"session_id,attr"`
	Target    string     `xml:"target,attr"`
	Items     []LootItem `xml:"items>item"`
}

// ── File path ────────────────────────────────────────────────────────────────

func lootXMLPath(sessionID int) string {
	return fmt.Sprintf("/tmp/loot-%d.xml", sessionID)
}

// ── Load / Save ──────────────────────────────────────────────────────────────

func loadLootDocument(sessionID int) *LootDocument {
	data, err := os.ReadFile(lootXMLPath(sessionID))
	if err != nil && lootDB != nil {
		// /tmp file missing — try DB fallback
		if dbData, dbErr := lootDB.GetLootData(sessionID); dbErr == nil && len(dbData) > 0 {
			data = dbData
			err = nil
		}
	}
	if err != nil || len(data) == 0 {
		return nil
	}
	var doc LootDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return &doc
}

func saveLootDocument(doc *LootDocument) error {
	data, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	xmlBytes := append([]byte(xml.Header), data...)
	if lootDB != nil {
		lootDB.SaveLootData(doc.SessionID, xmlBytes) //nolint:errcheck
	}
	return os.WriteFile(lootXMLPath(doc.SessionID), xmlBytes, 0644)
}

// appendCredential is the shared implementation for credential loot entries.
// lootMu must NOT be held by the caller — this function acquires it.
func appendCredential(sessionID int, target, lootType, source, username, password string) error {
	if username == "" && password == "" {
		return nil
	}
	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	// Dedup: skip if an identical (type, username, password) entry already exists.
	for _, item := range doc.Items {
		if item.Type != lootType {
			continue
		}
		uMatch, pMatch := false, false
		for _, f := range item.Fields {
			if f.Name == "username" && f.Value == username {
				uMatch = true
			}
			if f.Name == "password" && f.Value == password {
				pMatch = true
			}
		}
		if uMatch && pMatch {
			return nil
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      lootType,
		Source:    source,
		Timestamp: ts,
		Fields:    lootFields("username", username, "password", password),
	})
	return saveLootDocument(doc)
}

// AppendSessionCredential saves credentials captured when an MSF session opens.
func AppendSessionCredential(sessionID int, target, username, password string) error {
	return appendCredential(sessionID, target, "session_credential", "msf_session_open", username, password)
}

// AppendBruteforceCredential saves a credential pair found by Hydra.
func AppendBruteforceCredential(sessionID int, target, username, password, service string) error {
	if username == "" && password == "" {
		return nil
	}
	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	for _, item := range doc.Items {
		if item.Type != "bruteforce_credential" {
			continue
		}
		uMatch, pMatch, sMatch := false, false, false
		for _, f := range item.Fields {
			if f.Name == "username" && f.Value == username {
				uMatch = true
			}
			if f.Name == "password" && f.Value == password {
				pMatch = true
			}
			if f.Name == "service" && f.Value == service {
				sMatch = true
			}
		}
		// Treat as duplicate only when username, password AND service all match
		if uMatch && pMatch && sMatch {
			return nil
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      "bruteforce_credential",
		Source:    "hydra/" + service,
		Timestamp: ts,
		Fields:    lootFields("username", username, "password", password, "service", service),
	})
	return saveLootDocument(doc)
}

// AppendWifiHandshakeLoot records a captured WPA handshake directly as a loot item.
func AppendWifiHandshakeLoot(sessionID int, target, ssid, bssid, capFile, hashFile string, hashCount int) error {
	lootMu.Lock()
	defer lootMu.Unlock()
	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      "wifi_handshake",
		Source:    "handshake_capture",
		Timestamp: ts,
		Fields: lootFields(
			"ssid", ssid,
			"bssid", bssid,
			"cap_file", capFile,
			"hash_file", hashFile,
			"hashes", fmt.Sprintf("%d", hashCount),
		),
	})
	return saveLootDocument(doc)
}

// SetWifiHandshakePassword adds or updates the "password" field on every
// wifi_handshake loot entry whose "bssid" matches.  If no matching entry
// exists a minimal new entry is created so the password is always recorded.
func SetWifiHandshakePassword(sessionID int, target, ssid, bssid, password string) error {
	if password == "" {
		return nil
	}
	lootMu.Lock()
	defer lootMu.Unlock()
	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	updated := false
	for i, item := range doc.Items {
		if item.Type != "wifi_handshake" {
			continue
		}
		for _, f := range item.Fields {
			if f.Name == "bssid" && strings.EqualFold(f.Value, bssid) {
				// Replace existing password field or append a new one.
				replaced := false
				for j, fld := range doc.Items[i].Fields {
					if fld.Name == "password" {
						doc.Items[i].Fields[j].Value = password
						replaced = true
						break
					}
				}
				if !replaced {
					doc.Items[i].Fields = append(doc.Items[i].Fields,
						LootField{Name: "password", Value: password})
				}
				updated = true
				break
			}
		}
	}
	if !updated {
		// No existing handshake entry — create a minimal one with the password.
		ts := time.Now().UTC().Format(time.RFC3339)
		doc.Items = append(doc.Items, LootItem{
			Type:      "wifi_handshake",
			Source:    "hashcat",
			Timestamp: ts,
			Fields:    lootFields("ssid", ssid, "bssid", bssid, "password", password),
		})
	}
	return saveLootDocument(doc)
}

// AppendSqlmapFinding saves a single sqlmap finding to the session's loot.
// Duplicate findings (same type+value) are silently skipped.
func AppendSqlmapFinding(sessionID int, target, findingType, value string) error {
	lootMu.Lock()
	defer lootMu.Unlock()
	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	for _, item := range doc.Items {
		if item.Type != "sqlmap_finding" {
			continue
		}
		var tMatch, vMatch bool
		for _, f := range item.Fields {
			if f.Name == "type" && f.Value == findingType {
				tMatch = true
			}
			if f.Name == "value" && f.Value == value {
				vMatch = true
			}
		}
		if tMatch && vMatch {
			return nil
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      "sqlmap_finding",
		Source:    "sqlmap",
		Timestamp: ts,
		Fields:    lootFields("type", findingType, "value", value),
	})
	return saveLootDocument(doc)
}

// AppendWpscanFinding saves a single wpscan finding to the session's loot.
// Duplicate findings (same type+value) are silently skipped.
func AppendWpscanFinding(sessionID int, target, findingType, value string) error {
	lootMu.Lock()
	defer lootMu.Unlock()
	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	for _, item := range doc.Items {
		if item.Type != "wpscan_finding" {
			continue
		}
		var tMatch, vMatch bool
		for _, f := range item.Fields {
			if f.Name == "type" && f.Value == findingType {
				tMatch = true
			}
			if f.Name == "value" && f.Value == value {
				vMatch = true
			}
		}
		if tMatch && vMatch {
			return nil
		}
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	doc.Items = append(doc.Items, LootItem{
		Type:      "wpscan_finding",
		Source:    "wpscan",
		Timestamp: ts,
		Fields:    lootFields("type", findingType, "value", value),
	})
	return saveLootDocument(doc)
}

// AppendLoot parses cmd+output for useful loot and appends to the session's loot.xml.
func AppendLoot(sessionID int, target, cmd, output string) error {
	items := extractLoot(cmd, output)
	if len(items) == 0 {
		return nil
	}
	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, items...)
	return saveLootDocument(doc)
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

func extractLoot(cmd, output string) []LootItem {
	c := strings.ToLower(strings.TrimSpace(cmd))
	ts := time.Now().UTC().Format(time.RFC3339)

	switch {
	case c == "sysinfo":
		return parseSysinfo(output, ts)
	case c == "getuid":
		return parseGetuid(output, ts)
	case c == "getsystem":
		return parseGetsystem(output, ts)
	case c == "getprivs":
		return parseGetprivs(output, ts)
	case c == "is_admin":
		return parseIsAdmin(output, ts)
	case c == "hashdump", c == "run post/linux/gather/hashdump":
		return parseHashdump(output, ts)
	case c == "shell id", c == "id":
		return parseLinuxID(output, ts)
	case c == "whoami", c == "shell whoami":
		return parseWhoami(output, ts)
	case c == "shell whoami /all", c == "whoami /all":
		return parseWhoamiAll(output, ts)
	case c == "shell uname -a", c == "uname -a":
		return parseUname(output, ts)
	case c == "shell ver":
		return parseWindowsVer(output, ts)
	case c == "shell net user", c == "net user":
		return parseNetUser(output, ts)
	case c == "shell cat /etc/passwd", c == "cat /etc/passwd":
		return parseEtcPasswd(output, ts)
	case c == "shell systeminfo", c == "systeminfo":
		return parseSysteminfo(output, ts)
	case c == "env", c == "shell env":
		return parseEnv(output, ts)
	case c == "arp", c == "shell arp":
		return parseArp(output, ts)
	case c == "run post/linux/gather/mimipenguin":
		return parseMimipenguin(output, ts)
	case c == "run post/windows/gather/lsa_secrets":
		return parseLsaSecrets(output, ts)
	case c == "run post/windows/gather/cachedump":
		return parseCachedump(output, ts)
	default:
		return nil
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func lootFields(pairs ...string) []LootField {
	out := make([]LootField, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			out = append(out, LootField{Name: pairs[i], Value: pairs[i+1]})
		}
	}
	return out
}

func singleLootItem(lootType, source, ts string, f []LootField) []LootItem {
	if len(f) == 0 {
		return nil
	}
	return []LootItem{{Type: lootType, Source: source, Timestamp: ts, Fields: f}}
}

// extractLineValue returns the value after "prefix:" from multi-line output (case-insensitive).
func extractLineValue(output, prefix string) string {
	pLower := strings.ToLower(prefix)
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), pLower) {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// ── Parsers ──────────────────────────────────────────────────────────────────

func parseSysinfo(output, ts string) []LootItem {
	return singleLootItem("system_info", "sysinfo", ts, lootFields(
		"hostname",     extractLineValue(output, "Computer"),
		"os",           extractLineValue(output, "OS"),
		"arch",         extractLineValue(output, "Architecture"),
		"language",     extractLineValue(output, "System Language"),
		"session_type", extractLineValue(output, "Meterpreter"),
	))
}

func parseGetuid(output, ts string) []LootItem {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(strings.ToLower(line), "server username") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return singleLootItem("current_user", "getuid", ts,
					lootFields("username", strings.TrimSpace(parts[1])))
			}
		}
	}
	return nil
}

func parseGetsystem(output, ts string) []LootItem {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "got system") || strings.Contains(lower, "already running as system") {
			return singleLootItem("privilege_escalation", "getsystem", ts,
				lootFields("result", strings.TrimSpace(line)))
		}
	}
	return nil
}

func parseGetprivs(output, ts string) []LootItem {
	var privs []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Se") {
			privs = append(privs, line)
		}
	}
	return singleLootItem("privileges", "getprivs", ts,
		lootFields("privileges", strings.Join(privs, ", ")))
}

func parseIsAdmin(output, ts string) []LootItem {
	lower := strings.ToLower(output)
	result := "false"
	if strings.Contains(lower, "admin") &&
		(strings.Contains(lower, "yes") || strings.Contains(lower, "true") ||
			strings.Contains(lower, "has admin") || strings.Contains(lower, "is admin")) {
		result = "true"
	}
	return singleLootItem("is_admin", "is_admin", ts, lootFields("admin", result))
}

var hashdumpRe = regexp.MustCompile(`^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::`)

func parseHashdump(output, ts string) []LootItem {
	var items []LootItem
	for _, line := range strings.Split(output, "\n") {
		m := hashdumpRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		items = append(items, LootItem{
			Type: "credential", Source: "hashdump", Timestamp: ts,
			Fields: lootFields("username", m[1], "rid", m[2], "lm_hash", m[3], "nt_hash", m[4]),
		})
	}
	return items
}

var linuxIDRe = regexp.MustCompile(`uid=(\d+)\(([^)]+)\)`)

func parseLinuxID(output, ts string) []LootItem {
	m := linuxIDRe.FindStringSubmatch(output)
	if m == nil {
		return nil
	}
	return singleLootItem("current_user", "id", ts, lootFields("uid", m[1], "username", m[2]))
}

func parseWhoami(output, ts string) []LootItem {
	val := strings.TrimSpace(output)
	if val == "" {
		return nil
	}
	return singleLootItem("current_user", "whoami", ts, lootFields("username", val))
}

func parseWhoamiAll(output, ts string) []LootItem {
	var groups, privs []string
	inGroup, inPriv := false, false
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "group name") {
			inGroup, inPriv = true, false
			continue
		}
		if strings.Contains(lower, "privilege name") {
			inGroup, inPriv = false, true
			continue
		}
		if lower == "" || strings.HasPrefix(lower, "---") || strings.HasPrefix(lower, "user name") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if inGroup && strings.ContainsAny(parts[0], `\`) {
			groups = append(groups, parts[0])
		}
		if inPriv && strings.HasPrefix(parts[0], "Se") {
			privs = append(privs, parts[0])
		}
	}
	var items []LootItem
	if len(groups) > 0 {
		items = append(items, LootItem{Type: "groups", Source: "whoami /all", Timestamp: ts,
			Fields: []LootField{{Name: "groups", Value: strings.Join(groups, ", ")}}})
	}
	if len(privs) > 0 {
		items = append(items, LootItem{Type: "privileges", Source: "whoami /all", Timestamp: ts,
			Fields: []LootField{{Name: "privileges", Value: strings.Join(privs, ", ")}}})
	}
	return items
}

func parseUname(output, ts string) []LootItem {
	val := strings.TrimSpace(output)
	if val == "" {
		return nil
	}
	return singleLootItem("system_info", "uname -a", ts, lootFields("kernel", val))
}

func parseWindowsVer(output, ts string) []LootItem {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "windows") || strings.Contains(line, "Version") {
			if line != "" {
				return singleLootItem("system_info", "ver", ts, lootFields("os_version", line))
			}
		}
	}
	return nil
}

var netUserWordRe = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9_\-\.]{2,19}\b`)

func parseNetUser(output, ts string) []LootItem {
	var users []string
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "---") {
			inList = true
			continue
		}
		if !inList || line == "" || strings.HasPrefix(strings.ToLower(line), "the command") {
			continue
		}
		for _, u := range netUserWordRe.FindAllString(line, -1) {
			users = append(users, u)
		}
	}
	return singleLootItem("user_list", "net user", ts,
		lootFields("users", strings.Join(users, ", ")))
}

var passwdLineRe = regexp.MustCompile(`^([^:]+):[^:]*:(\d+):(\d+):[^:]*:([^:]+):([^:\n]+)`)

func parseEtcPasswd(output, ts string) []LootItem {
	var items []LootItem
	for _, line := range strings.Split(output, "\n") {
		m := passwdLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		uid := 0
		fmt.Sscanf(m[2], "%d", &uid)
		if uid != 0 && uid < 1000 {
			continue // skip system accounts except root
		}
		items = append(items, LootItem{
			Type: "user_account", Source: "cat /etc/passwd", Timestamp: ts,
			Fields: lootFields("username", m[1], "uid", m[2], "gid", m[3],
				"home", m[4], "shell", strings.TrimSpace(m[5])),
		})
	}
	return items
}

func parseSysteminfo(output, ts string) []LootItem {
	return singleLootItem("system_info", "systeminfo", ts, lootFields(
		"hostname",   extractLineValue(output, "Host Name"),
		"os",         extractLineValue(output, "OS Name"),
		"os_version", extractLineValue(output, "OS Version"),
		"arch",       extractLineValue(output, "System Type"),
		"domain",     extractLineValue(output, "Domain"),
		"patches",    extractLineValue(output, "Hotfix(es)"),
	))
}

var envCredRe = regexp.MustCompile(`(?i)(pass|password|secret|key|token|api|credential)`)

func parseEnv(output, ts string) []LootItem {
	var interesting []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && envCredRe.MatchString(line) {
			interesting = append(interesting, line)
		}
	}
	return singleLootItem("environment", "env", ts,
		lootFields("interesting_vars", strings.Join(interesting, "\n")))
}

var arpEntryRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})`)

func parseArp(output, ts string) []LootItem {
	var hosts []string
	for _, line := range strings.Split(output, "\n") {
		m := arpEntryRe.FindStringSubmatch(line)
		if m != nil {
			hosts = append(hosts, fmt.Sprintf("%s (%s)", m[1], m[2]))
		}
	}
	return singleLootItem("network_hosts", "arp", ts,
		lootFields("hosts", strings.Join(hosts, ", ")))
}

func parseMimipenguin(output, ts string) []LootItem {
	var creds []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, ":") && !strings.HasPrefix(line, "[") {
			creds = append(creds, line)
		}
	}
	return singleLootItem("credential", "mimipenguin", ts,
		lootFields("credentials", strings.Join(creds, "\n")))
}

func parseLsaSecrets(output, ts string) []LootItem {
	var secrets []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "[-]") {
			secrets = append(secrets, line)
		}
	}
	return singleLootItem("credential", "lsa_secrets", ts,
		lootFields("secrets", strings.Join(secrets, "\n")))
}

func parseCachedump(output, ts string) []LootItem {
	var creds []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":$DCC2$") || strings.Contains(line, "Username:") {
			creds = append(creds, line)
		}
	}
	return singleLootItem("credential", "cachedump", ts,
		lootFields("cached_credentials", strings.Join(creds, "\n")))
}

// AppendKerbruteUsers parses kerbrute userenum output and saves valid usernames as loot.
func AppendKerbruteUsers(sessionID int, target, domain, wordlist, output string) error {
	var users []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "VALID USERNAME") {
			parts := strings.SplitN(line, "VALID USERNAME:", 2)
			if len(parts) == 2 {
				u := strings.Trim(parts[1], " \t\r")
				if u != "" {
					users = append(users, u)
				}
			}
		}
	}
	if len(users) == 0 {
		return nil
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}

	fields := []LootField{
		{Name: "Domain", Value: domain},
		{Name: "Wordlist", Value: wordlist},
	}
	for _, u := range users {
		fields = append(fields, LootField{Name: "Valid User", Value: u})
	}

	doc.Items = append(doc.Items, LootItem{
		Type:      "kerbrute_users",
		Source:    fmt.Sprintf("kerbrute userenum -d %s --dc %s %s", domain, target, wordlist),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendADDiscovery parses nmap ldap-rootdse / smb-os-discovery output and
// saves discovered domain information as a structured loot item.
func AppendADDiscovery(sessionID int, target, output string) error {
	extract := func(pattern string) string {
		m := regexp.MustCompile(pattern).FindStringSubmatch(output)
		if len(m) > 1 {
			return strings.TrimSpace(strings.TrimRight(m[1], "\x00\\"))
		}
		return ""
	}

	var fields []LootField
	add := func(name, val string) {
		if val != "" {
			fields = append(fields, LootField{Name: name, Value: val})
		}
	}

	add("DNS Domain Name",       extract(`(?i)DNS domain name: (.+)`))
	add("DNS Forest Name",       extract(`(?i)DNS forest name: (.+)`))
	add("DNS Computer Name",     extract(`(?i)DNS computer name: (.+)`))
	add("NetBIOS Domain Name",   extract(`(?i)NetBIOS domain name: ([^\\\x00\n]+)`))
	add("NetBIOS Computer Name", extract(`(?i)NetBIOS computer name: ([^\\\x00\n]+)`))
	add("Domain SID",            extract(`(?i)Domain SID: (.+)`))
	add("OS",                    extract(`(?i)^\s*OS: (.+)`))
	add("Naming Context",        extract(`defaultNamingContext: (.+)`))
	add("LDAP Service",          extract(`ldapServiceName: (.+)`))
	add("DC DNS Hostname",       extract(`dnsHostName: (.+)`))

	if len(fields) == 0 {
		return nil
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "ad_discovery",
		Source:    fmt.Sprintf("nmap -p 88,389 --script=ldap-rootdse,smb-os-discovery %s", target),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendSMBEnum parses enum4linux / enum4linux-ng output and saves users,
// groups, shares, password policy, and OS/domain info as a structured loot item.
// Handles both the old enum4linux bracket format (user:[x]) and the
// enum4linux-ng pipe format (| username: x).
func AppendSMBEnum(sessionID int, target, output string) error {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	seen := func(m map[string]bool, v string) bool {
		if m[v] { return true }
		m[v] = true
		return false
	}

	userSeen, groupSeen, shareSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var users, groups, shares []string

	// Regexes covering both tool formats.
	// enum4linux-ng:  | username: Administrator
	// enum4linux:     user:[Administrator] rid:[0x1f4]
	userNGRE  := regexp.MustCompile(`^\|\s+username:\s+(.+)`)
	userOldRE := regexp.MustCompile(`user:\[([^\]]+)\]`)
	groupNGRE  := regexp.MustCompile(`^\|\s+groupname:\s+(.+)`)
	groupOldRE := regexp.MustCompile(`group:\[([^\]]+)\]`)
	shareNGRE  := regexp.MustCompile(`^\|\s+sharename:\s+(.+)`)

	for _, line := range strings.Split(output, "\n") {
		if m := userNGRE.FindStringSubmatch(line); len(m) > 1 {
			if u := strings.TrimSpace(m[1]); u != "" && !seen(userSeen, u) { users = append(users, u) }
		} else if m := userOldRE.FindStringSubmatch(line); len(m) > 1 {
			if u := m[1]; !seen(userSeen, u) { users = append(users, u) }
		}
		if m := groupNGRE.FindStringSubmatch(line); len(m) > 1 {
			if g := strings.TrimSpace(m[1]); g != "" && !seen(groupSeen, g) { groups = append(groups, g) }
		} else if m := groupOldRE.FindStringSubmatch(line); len(m) > 1 {
			if g := m[1]; !seen(groupSeen, g) { groups = append(groups, g) }
		}
		if m := shareNGRE.FindStringSubmatch(line); len(m) > 1 {
			if s := strings.TrimSpace(m[1]); s != "" && !seen(shareSeen, s) { shares = append(shares, s) }
		}
	}

	// Old enum4linux share table (Sharename  Type  Comment header).
	inShares := false
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Sharename") && strings.Contains(line, "Type") { inShares = true; continue }
		if inShares {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "---") { if len(shares) > 0 { break }; continue }
			if parts := strings.Fields(line); len(parts) > 0 && !strings.HasPrefix(parts[0], "-") {
				if !seen(shareSeen, parts[0]) { shares = append(shares, parts[0]) }
			}
		}
	}

	// Password policy — both formats use similar keywords.
	minPwRE := regexp.MustCompile(`(?i)minimum.password.length[:\s]+(\d+)`)
	minPw := ""
	if m := minPwRE.FindStringSubmatch(output); len(m) > 1 { minPw = m[1] }

	// OS / domain info from enum4linux-ng.
	osRE     := regexp.MustCompile(`(?i)^\s+OS:\s+(.+)`)
	domainRE := regexp.MustCompile(`(?i)(?:Domain name|NetBIOS computer name|Domain)[:\s]+([A-Za-z0-9._-]+)`)
	osInfo, domain := "", ""
	for _, line := range strings.Split(output, "\n") {
		if osInfo == "" {
			if m := osRE.FindStringSubmatch(line); len(m) > 1 { osInfo = strings.TrimSpace(m[1]) }
		}
		if domain == "" {
			if m := domainRE.FindStringSubmatch(line); len(m) > 1 {
				if v := strings.TrimSpace(m[1]); v != "" && v != "0" { domain = v }
			}
		}
	}

	var fields []LootField
	if osInfo != ""  { fields = append(fields, LootField{Name: "OS", Value: osInfo}) }
	if domain != ""  { fields = append(fields, LootField{Name: "Domain", Value: domain}) }
	if len(users) > 0  { fields = append(fields, LootField{Name: "Users", Value: strings.Join(users, ", ")}) }
	if len(groups) > 0 { fields = append(fields, LootField{Name: "Groups", Value: strings.Join(groups, ", ")}) }
	if len(shares) > 0 { fields = append(fields, LootField{Name: "Shares", Value: strings.Join(shares, ", ")}) }
	if minPw != ""      { fields = append(fields, LootField{Name: "Min Password Length", Value: minPw}) }

	// Always persist the raw output so nothing is silently dropped when
	// structured parsing finds nothing (e.g. unauthenticated scan with no results).
	if len(fields) == 0 {
		fields = append(fields, LootField{Name: "Raw Output", Value: strings.TrimSpace(output)})
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "smb_enum",
		Source:    fmt.Sprintf("enum4linux-ng -A %s", target),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendNxcFinding saves a single structured NXC sweep [+] finding to loot.
// Each field is stored individually so the loot tab can render a proper table row.
func AppendNxcFinding(sessionID int, target string, f struct {
	Protocol string
	Host     string
	Port     int
	Name     string
	User     string
	Detail   string
	Raw      string
}) error {
	fields := []LootField{
		{Name: "protocol", Value: strings.ToUpper(f.Protocol)},
		{Name: "host", Value: f.Host},
		{Name: "port", Value: fmt.Sprintf("%d", f.Port)},
		{Name: "machine", Value: f.Name},
		{Name: "user", Value: f.User},
	}
	if f.Detail != "" {
		fields = append(fields, LootField{Name: "status", Value: f.Detail})
	}
	fields = append(fields, LootField{Name: "raw", Value: f.Raw})

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "nxc_finding",
		Source:    fmt.Sprintf("nxcsweep %s %s", strings.ToLower(f.Protocol), target),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendCMEFindings parses crackmapexec / nxc output and saves findings as loot.
// [*] lines are parsed for host info (OS, hostname, domain, signing).
// [+] lines are saved as auth successes.
// Falls back to saving the raw output when neither is found so nothing is silently dropped.
func AppendCMEFindings(sessionID int, target, proto, output string) error {
	// Strip residual ANSI codes in case --no-color was not honoured.
	output = stripANSI(output)

	var fields []LootField

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "[+]") {
			fields = append(fields, LootField{Name: "Auth Success", Value: line})
		} else if strings.Contains(line, "[*]") {
			// Host banner line — extract useful parts.
			// e.g. "SMB  192.168.1.1  445  DC01  [*] Windows Server 2019 x64 (name:DC01) (domain:corp.local) (signing:True)"
			fields = append(fields, LootField{Name: "Host Info", Value: line})
		}
	}

	// Always persist something so the user can see the scan ran.
	if len(fields) == 0 {
		trimmed := strings.TrimSpace(output)
		if trimmed == "" {
			return nil
		}
		fields = append(fields, LootField{Name: "Raw Output", Value: trimmed})
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "crackmapexec_finding",
		Source:    fmt.Sprintf("crackmapexec %s %s", proto, target),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendVulnScanLoot saves the already-parsed vuln scan results (services + OS)
// as a structured loot item, reusing the ServiceEnumResult and OSInfo types
// that the vuln scan goroutine already produces.
func AppendVulnScanLoot(sessionID int, target string, services []ServiceEnumResult, osInfo *OSInfo) error {
	if len(services) == 0 && osInfo == nil {
		return nil
	}

	var fields []LootField

	if osInfo != nil && osInfo.Name != "" {
		osLabel := osInfo.Name
		if osInfo.Accuracy > 0 {
			osLabel += fmt.Sprintf(" (%d%% confidence)", osInfo.Accuracy)
		}
		fields = append(fields, LootField{Name: "OS", Value: osLabel})
	}

	for _, svc := range services {
		portLabel := fmt.Sprintf("%d/%s", svc.Port, svc.Protocol)
		value := svc.Name
		if svc.Product != "" {
			value += " — " + svc.Product
			if svc.Version != "" {
				value += " " + svc.Version
			}
		}
		fields = append(fields, LootField{Name: portLabel, Value: value})
	}

	if len(fields) == 0 {
		return nil
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "nmap_scan",
		Source:    fmt.Sprintf("nmap -sV -O --script=vuln,vulners %s", target),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendNmapLoot parses nmap text output and saves open ports, services,
// versions, and OS detection as a structured loot item.
func AppendNmapLoot(sessionID int, target, args, output string) error {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	// port line: "22/tcp   open  ssh     OpenSSH 8.4p1 Debian ..."
	portRE := regexp.MustCompile(`^(\d+/\w+)\s+open\s+(\S+)\s*(.*)$`)
	// OS details line
	osRE := regexp.MustCompile(`(?i)^OS details?:\s+(.+)$`)
	// Running / aggressive OS guess
	runningRE := regexp.MustCompile(`(?i)^Running:\s+(.+)$`)

	var fields []LootField
	var ports []string

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if m := portRE.FindStringSubmatch(line); len(m) == 4 {
			port := m[1]
			svc := m[2]
			ver := strings.TrimSpace(m[3])
			label := svc
			if ver != "" {
				label = svc + " — " + ver
			}
			fields = append(fields, LootField{Name: port, Value: label})
			ports = append(ports, port)
		} else if m := osRE.FindStringSubmatch(line); len(m) == 2 {
			fields = append(fields, LootField{Name: "OS", Value: strings.TrimSpace(m[1])})
		} else if m := runningRE.FindStringSubmatch(line); len(m) == 2 {
			if len(fields) == 0 || fields[len(fields)-1].Name != "OS" {
				fields = append(fields, LootField{Name: "OS (guess)", Value: strings.TrimSpace(m[1])})
			}
		}
	}

	if len(fields) == 0 {
		return nil // no open ports or OS info found — nothing worth saving
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "nmap_scan",
		Source:    "nmap " + args + " " + target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}

// AppendFeroxLoot saves feroxbuster results to loot.
// Only 200-status URLs and URLs that look like files (have an extension in
// the final path segment) are recorded.
func AppendFeroxLoot(sessionID int, target string, found []FeroxResult) error {
	hasExt := regexp.MustCompile(`\.[a-zA-Z0-9]{1,10}$`)

	var fields []LootField
	seen := map[string]bool{}
	for _, r := range found {
		if seen[r.URL] {
			continue
		}
		seen[r.URL] = true

		isOK := r.Status == 200
		isFile := hasExt.MatchString(strings.Split(r.URL, "?")[0]) // strip query string before checking

		if !isOK && !isFile {
			continue
		}

		label := fmt.Sprintf("%d %s", r.Status, r.Method)
		if r.Size > 0 {
			label += fmt.Sprintf(" (%d bytes)", r.Size)
		}
		fields = append(fields, LootField{Name: r.URL, Value: label})
	}

	if len(fields) == 0 {
		return nil
	}

	lootMu.Lock()
	defer lootMu.Unlock()

	doc := loadLootDocument(sessionID)
	if doc == nil {
		doc = &LootDocument{SessionID: sessionID, Target: target}
	}
	doc.Items = append(doc.Items, LootItem{
		Type:      "web_enum",
		Source:    "feroxbuster → " + target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Fields:    fields,
	})
	return saveLootDocument(doc)
}
