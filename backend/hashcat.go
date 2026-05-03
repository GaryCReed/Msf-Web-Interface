package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// ── Job management ────────────────────────────────────────────────────────────

type HashcatJob struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	output  []string
	cracked []CrackedEntry
	done    bool
	err     string
}

var hashcatJobs sync.Map // sessionID → *HashcatJob

func getHashcatJob(sessionID int) *HashcatJob {
	v, _ := hashcatJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*HashcatJob)
}

// ── Handshake structures ──────────────────────────────────────────────────────

type HandshakeFile struct {
	CapPath    string `json:"cap_path"`
	HashPath   string `json:"hash_path"`   // .22000 file (empty if invalid)
	Status     string `json:"status"`      // "converted" | "invalid" | "already_converted"
	HashCount  int    `json:"hash_count"`  // lines in .22000 file
	ESSIDs     string `json:"essids"`      // comma-separated ESSIDs extracted
}

// ── Catalogue helpers ─────────────────────────────────────────────────────────

// hashcatRulesDir returns the hashcat rules directory.
func hashcatRulesDir() string {
	return "/usr/share/hashcat/rules"
}

// listHashcatRules returns all .rule files in the hashcat rules directory.
func listHashcatRules() []string {
	entries, err := os.ReadDir(hashcatRulesDir())
	if err != nil {
		return nil
	}
	var rules []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".rule") {
			rules = append(rules, filepath.Join(hashcatRulesDir(), name))
		}
	}
	return rules
}

// ── Handshake validation and conversion ───────────────────────────────────────

// capFilesForSession returns all .cap files captured for a session.
func capFilesForSession(sessionID int) []string {
	pattern := fmt.Sprintf("/tmp/wifi-cap-%d-*.cap", sessionID)
	matches, _ := filepath.Glob(pattern)
	// Also include -01.cap suffix that airodump-ng appends
	pattern2 := fmt.Sprintf("/tmp/wifi-cap-%d-*-01.cap", sessionID)
	m2, _ := filepath.Glob(pattern2)
	seen := map[string]bool{}
	var all []string
	for _, f := range append(matches, m2...) {
		if !seen[f] {
			seen[f] = true
			all = append(all, f)
		}
	}
	return all
}

// hash22Path returns the .22000 output path for a .cap file.
func hash22Path(capPath string) string {
	return strings.TrimSuffix(capPath, filepath.Ext(capPath)) + ".22000"
}

// validateAndConvert attempts to convert capPath to .22000 using hcxpcapngtool.
// Returns the HandshakeFile describing the result.
func validateAndConvert(capPath string) HandshakeFile {
	hashPath := hash22Path(capPath)

	// Already converted?
	if info, err := os.Stat(hashPath); err == nil && info.Size() > 0 {
		count := countLines(hashPath)
		return HandshakeFile{
			CapPath:   capPath,
			HashPath:  hashPath,
			Status:    "already_converted",
			HashCount: count,
		}
	}

	// Run hcxpcapngtool
	out, err := exec.Command("hcxpcapngtool", "-o", hashPath, capPath).CombinedOutput()
	_ = out // conversion output is verbose but not user-facing

	if err != nil {
		// Tool error — treat as invalid
		os.Remove(hashPath)
		os.Remove(capPath)
		return HandshakeFile{CapPath: capPath, Status: "invalid"}
	}

	// Check if the output file has content
	info, statErr := os.Stat(hashPath)
	if statErr != nil || info.Size() == 0 {
		// No valid hashes — delete both files
		os.Remove(hashPath)
		os.Remove(capPath)
		return HandshakeFile{CapPath: capPath, Status: "invalid"}
	}

	count := countLines(hashPath)
	return HandshakeFile{
		CapPath:   capPath,
		HashPath:  hashPath,
		Status:    "converted",
		HashCount: count,
	}
}

// countLines returns the number of non-empty lines in a file.
func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// ── Hashcat request / arg builder ─────────────────────────────────────────────

type HashcatRequest struct {
	HashFile      string `json:"hash_file"`
	HashType      int    `json:"hash_type"`   // default 22000
	AttackMode    int    `json:"attack_mode"` // 0=dict 3=mask 6=hybrid_wl+mask 7=hybrid_mask+wl
	Wordlist      string `json:"wordlist"`
	RulesFile     string `json:"rules_file"`
	Mask          string `json:"mask"`
	WorkloadProfile int  `json:"workload_profile"` // 1-4
	DeviceTypes   string `json:"device_types"`     // "1" CPU "2" GPU "1,2" both
	Optimized      bool   `json:"optimized"`
	Force          bool   `json:"force"`
	PotfileDisable bool   `json:"potfile_disable"`
	ShowPotfile    bool   `json:"show_potfile"`
	CustomArgs     string `json:"custom_args"`
}

func buildHashcatArgs(req HashcatRequest, outFile string) ([]string, error) {
	if req.HashFile == "" {
		return nil, fmt.Errorf("hash file required")
	}

	hashType := req.HashType
	if hashType == 0 {
		hashType = 22000
	}

	args := []string{
		"-m", strconv.Itoa(hashType),
		"-a", strconv.Itoa(req.AttackMode),
		req.HashFile,
	}

	switch req.AttackMode {
	case 0: // dictionary
		if req.Wordlist == "" {
			return nil, fmt.Errorf("wordlist required for dictionary attack")
		}
		args = append(args, req.Wordlist)
		if req.RulesFile != "" {
			args = append(args, "-r", req.RulesFile)
		}
	case 3: // mask
		if req.Mask == "" {
			return nil, fmt.Errorf("mask required for mask attack")
		}
		args = append(args, req.Mask)
	case 6: // hybrid wordlist + mask
		if req.Wordlist == "" || req.Mask == "" {
			return nil, fmt.Errorf("wordlist and mask required for hybrid attack")
		}
		args = append(args, req.Wordlist, req.Mask)
	case 7: // hybrid mask + wordlist
		if req.Wordlist == "" || req.Mask == "" {
			return nil, fmt.Errorf("mask and wordlist required for hybrid attack")
		}
		args = append(args, req.Mask, req.Wordlist)
	}

	w := req.WorkloadProfile
	if w < 1 || w > 4 {
		w = 3
	}
	args = append(args, "-w", strconv.Itoa(w))

	// Default to "1,2" (CPU + GPU) so hashcat works in VM environments that
	// have no supported GPU — without this, hashcat exits silently with
	// "No devices found" when GPU OpenCL is unavailable.
	dt := req.DeviceTypes
	if dt == "" {
		dt = "1,2"
	}
	args = append(args, "-D", dt)
	if req.Optimized {
		args = append(args, "-O")
	}
	if req.Force {
		args = append(args, "--force")
	}
	if req.PotfileDisable {
		args = append(args, "--potfile-disable")
	}
	if req.ShowPotfile {
		args = append(args, "--show")
	}

	// --hex-plain: passwords are always written as hex in the outfile, making
	// parsing unambiguous — plaintext "12345678" and hex string "12345678" are
	// otherwise indistinguishable, corrupting the displayed password.
	// Format 3 = hash:hex_plain; we decode in parseOutfileLine / hexPlainDecode.
	args = append(args,
		"--hex-plain",
		"--status", "--status-timer=10",
		"--outfile", outFile,
		"--outfile-format", "3",
	)

	if req.CustomArgs != "" {
		args = append(args, strings.Fields(req.CustomArgs)...)
	}

	return args, nil
}

// ── Output parsing ────────────────────────────────────────────────────────────

// extractWPANetworkInfo reads a .22000 hash file and returns the BSSID and ESSID
// from the first valid WPA* line. Used when the outfile only contains the bare plain.
func extractWPANetworkInfo(hashFile string) (bssid, essid string) {
	data, err := os.ReadFile(hashFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "WPA*") {
			continue
		}
		// Strip trailing :password if present (raw hash file won't have it, but be safe)
		hashPart := line
		if idx := strings.LastIndex(line, ":"); idx > 0 {
			hashPart = line[:idx]
		}
		fields := strings.Split(hashPart, "*")
		if len(fields) >= 6 {
			bssid = hexToMAC(strings.ToLower(fields[3]))
			essid = hexToASCII(fields[5])
			return
		}
	}
	return
}

// CrackedEntry holds a single cracked result from the hashcat outfile.
type CrackedEntry struct {
	Raw      string `json:"raw"`       // full hash:password line
	Display  string `json:"display"`   // human-friendly e.g. "MyWifi (aa:bb:cc:dd:ee:ff): password"
	BSSID    string `json:"bssid"`     // AP MAC (WPA only)
	ESSID    string `json:"essid"`     // network name (WPA only)
	Password string `json:"password"`  // plaintext password
}

// hexToMAC converts "aabbccddeeff" → "aa:bb:cc:dd:ee:ff"
func hexToMAC(h string) string {
	if len(h) != 12 {
		return h
	}
	return h[0:2] + ":" + h[2:4] + ":" + h[4:6] + ":" + h[6:8] + ":" + h[8:10] + ":" + h[10:12]
}

// hexToASCII decodes a hex string to a UTF-8 string, stopping at the first null
// byte (ESSID fields in .22000 are null-padded to 32 bytes). Falls back to the
// raw hex string if decoding fails entirely.
func hexToASCII(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	// Trim null padding
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	if len(b) == 0 {
		return h
	}
	return string(b)
}

// hexPlainDecode decodes a hashcat plain-text field. With --hex-plain the field
// is always a raw hex string. It also handles the legacy $HEX[...] wrapper.
func hexPlainDecode(s string) string {
	// $HEX[...] wrapper (older hashcat behaviour)
	if strings.HasPrefix(s, "$HEX[") && strings.HasSuffix(s, "]") {
		if b, err := hex.DecodeString(s[5 : len(s)-1]); err == nil {
			return string(b)
		}
	}
	// Raw hex string (--hex-plain output)
	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		return string(b)
	}
	return s
}

// parseOutfileLine parses a single line from hashcat outfile format 3 (hash:plain).
// For WPA*01/02 hashes it extracts BSSID, ESSID, and password.
func parseOutfileLine(line string) CrackedEntry {
	line = strings.TrimSpace(line)
	if line == "" {
		return CrackedEntry{}
	}

	// Find the last colon to split hash from password.
	// WPA lines look like WPA*02*...*aabbccddeeff*...:hex_password (--hex-plain)
	// Some hashcat versions write only the hex plain with no hash prefix.
	lastColon := strings.LastIndex(line, ":")
	var hashPart, password string
	if lastColon < 0 {
		// Bare hex plain — the entire line is the hex-encoded password
		hashPart = ""
		password = hexPlainDecode(line)
	} else {
		hashPart = line[:lastColon]
		password = hexPlainDecode(line[lastColon+1:])
	}

	entry := CrackedEntry{
		Raw:      line,
		Password: password,
	}

	// Try to parse WPA hash fields: WPA*01*pmkid*ap_mac*client_mac*essid_hex*...
	if strings.HasPrefix(hashPart, "WPA*") {
		fields := strings.Split(hashPart, "*")
		if len(fields) >= 6 {
			bssid := hexToMAC(strings.ToLower(fields[3]))
			essid := hexToASCII(fields[5])
			entry.BSSID = bssid
			entry.ESSID = essid
			entry.Display = fmt.Sprintf("%s (%s): %s", essid, bssid, password)
			return entry
		}
	}

	// Non-WPA: show hash truncated + password
	truncated := hashPart
	if len(truncated) > 40 {
		truncated = truncated[:40] + "…"
	}
	entry.Display = fmt.Sprintf("%s : %s", truncated, password)
	return entry
}

func parseHashcatCracked(outFile string) []CrackedEntry {
	data, err := os.ReadFile(outFile)
	if err != nil {
		return nil
	}
	var results []CrackedEntry
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		entry := parseOutfileLine(line)
		if entry.Raw != "" {
			results = append(results, entry)
		}
	}
	return results
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleGetHashcatHandshakes(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		caps := capFilesForSession(sessionID)
		var handshakes []HandshakeFile

		// Also include already-converted .22000 files that have no corresponding .cap
		seen22 := map[string]bool{}
		for _, cap := range caps {
			hs := validateAndConvert(cap)
			handshakes = append(handshakes, hs)
			if hs.HashPath != "" {
				seen22[hs.HashPath] = true
			}
		}

		// Standalone .22000 files (e.g. user-provided)
		existing22, _ := filepath.Glob(fmt.Sprintf("/tmp/wifi-cap-%d-*.22000", sessionID))
		for _, p := range existing22 {
			if !seen22[p] && countLines(p) > 0 {
				handshakes = append(handshakes, HandshakeFile{
					HashPath:  p,
					Status:    "already_converted",
					HashCount: countLines(p),
				})
			}
		}

		if handshakes == nil {
			handshakes = []HandshakeFile{}
		}

		// Also return available rules
		rules := listHashcatRules()
		if rules == nil {
			rules = []string{}
		}

		hsData, _ := encodeJSON(handshakes)
		rulesData, _ := encodeJSON(rules)
		fmt.Fprintf(w, `{"handshakes":%s,"rules":%s}`, hsData, rulesData)
	}
}

func handleStartHashcat(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		userID := claims.UserID
		// Reject if already running
		if j := getHashcatJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"hashcat already running"}`)
				return
			}
		}

		var req HashcatRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid request"}`)
			return
		}

		outFile := fmt.Sprintf("/tmp/hashcat-%d-cracked.txt", sessionID)
		os.Remove(outFile)

		args, err := buildHashcatArgs(req, outFile)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		job := &HashcatJob{}
		hashcatJobs.Store(sessionID, job)

		go func() {
			cmd := exec.Command("hashcat", args...)
			stdout, _ := cmd.StdoutPipe()
			stderr, _ := cmd.StderrPipe()

			job.mu.Lock()
			job.cmd = cmd
			job.output = append(job.output, fmt.Sprintf("[*] hashcat %s", strings.Join(args, " ")))
			job.mu.Unlock()

			if err := cmd.Start(); err != nil {
				job.mu.Lock()
				job.err = fmt.Sprintf("failed to start hashcat: %v", err)
				job.done = true
				job.mu.Unlock()
				return
			}

			readStream := func(sc *bufio.Scanner) {
				for sc.Scan() {
					line := sc.Text()
					job.mu.Lock()
					job.output = append(job.output, line)
					job.mu.Unlock()
				}
			}
			go readStream(bufio.NewScanner(stdout))
			go readStream(bufio.NewScanner(stderr))

			cmd.Wait()

			// Read cracked passwords from outfile and save to loot.
			// When the outfile only contains a bare plain (no WPA* prefix),
			// fall back to extracting BSSID/ESSID from the original hash file.
			cracked := parseHashcatCracked(outFile)
			fallbackBSSID, fallbackESSID := extractWPANetworkInfo(req.HashFile)
			for _, entry := range cracked {
				if entry.Password == "" {
					continue
				}
				bssid := entry.BSSID
				essid := entry.ESSID
				if bssid == "" {
					bssid = fallbackBSSID
				}
				if essid == "" {
					essid = fallbackESSID
				}
				AppendBruteforceCredential(sessionID, bssid, essid, entry.Password, "WPA")
				upsertWifiCrackedProject(db, userID, sessionID, essid, bssid, entry.Password)
			}
			job.mu.Lock()
			job.cracked = cracked
			if len(cracked) > 0 {
				job.output = append(job.output, fmt.Sprintf("[+] %d password(s) cracked", len(cracked)))
			}
			job.done = true
			job.mu.Unlock()
		}()

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetHashcat(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		// Also poll the outfile for live cracked passwords
		outFile := fmt.Sprintf("/tmp/hashcat-%d-cracked.txt", sessionID)

		job := getHashcatJob(sessionID)
		if job == nil {
			// Check for cracked results from a previous run
			cracked := parseHashcatCracked(outFile)
			crackedData, _ := encodeJSON(cracked)
			fmt.Fprintf(w, `{"status":"idle","output":[],"cracked":%s,"error":""}`, crackedData)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		cracked := make([]CrackedEntry, len(job.cracked))
		copy(cracked, job.cracked)
		done := job.done
		jobErr := job.err
		job.mu.Unlock()

		// Merge with live outfile reads (dedup by raw line)
		liveCracked := parseHashcatCracked(outFile)
		crackedSet := map[string]bool{}
		for _, c := range cracked {
			crackedSet[c.Raw] = true
		}
		for _, c := range liveCracked {
			if !crackedSet[c.Raw] {
				cracked = append(cracked, c)
			}
		}

		outData, _ := encodeJSON(output)
		crackedData, _ := encodeJSON(cracked)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"output":%s,"cracked":%s,"error":%q}`,
			status, outData, crackedData, jobErr)
	}
}

func handleStopHashcat(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		job := getHashcatJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job.mu.Lock()
		cmd := job.cmd
		job.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}
