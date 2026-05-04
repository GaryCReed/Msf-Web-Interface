package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// ── Job management ────────────────────────────────────────────────────────────

type BruteforceJob struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	output []string
	found  []FoundCred
	done   bool
	err    string
}

type FoundCred struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
}

// bruteJobs maps sessionID → *BruteforceJob.
var bruteJobs sync.Map

func getBruteJob(sessionID int) *BruteforceJob {
	v, _ := bruteJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*BruteforceJob)
}

// ── Request / response structs ────────────────────────────────────────────────

type BruteforceRequest struct {
	TargetIP string `json:"target_ip"`
	Service  string `json:"service"`

	// Credential mode: "wordlist" | "combo" | "single"
	Mode string `json:"mode"`

	// wordlist mode
	UserFile string `json:"user_file"`
	PassFile string `json:"pass_file"`

	// combo mode
	ComboFile string `json:"combo_file"`

	// single mode
	Login    string `json:"login"`
	Password string `json:"password"`

	// -e flags
	TryNull    bool `json:"try_null"`
	TryAsLogin bool `json:"try_as_login"`
	TryReverse bool `json:"try_reverse"`

	// options
	StopFirst  bool `json:"stop_first"`
	UseSSL     bool `json:"use_ssl"`
	LoopUsers  bool `json:"loop_users"`
	Verbose    bool `json:"verbose"`
	Tasks      int  `json:"tasks"`
	Timeout    int  `json:"timeout"`
	Port       int  `json:"port"`

	// HTTP form options (http-post-form / http-get-form)
	FormURL       string `json:"form_url"`
	FormParams    string `json:"form_params"`
	FormCondition string `json:"form_condition"`
}

// ── Hydra arg builder ─────────────────────────────────────────────────────────

func buildHydraArgs(target string, req BruteforceRequest, outFile string) ([]string, error) {
	var args []string

	// Credential flags
	switch req.Mode {
	case "combo":
		if req.ComboFile == "" {
			return nil, fmt.Errorf("combo file required")
		}
		args = append(args, "-C", req.ComboFile)
	case "single":
		if req.Login != "" {
			args = append(args, "-l", req.Login)
		}
		if req.Password != "" {
			args = append(args, "-p", req.Password)
		} else if req.PassFile != "" {
			args = append(args, "-P", req.PassFile)
		}
	default: // wordlist
		if req.UserFile != "" {
			args = append(args, "-L", req.UserFile)
		}
		if req.PassFile != "" {
			args = append(args, "-P", req.PassFile)
		}
	}

	// -e flags
	var eflags []string
	if req.TryNull {
		eflags = append(eflags, "n")
	}
	if req.TryAsLogin {
		eflags = append(eflags, "s")
	}
	if req.TryReverse {
		eflags = append(eflags, "r")
	}
	if len(eflags) > 0 {
		args = append(args, "-e", strings.Join(eflags, ""))
	}

	// Misc flags
	if req.StopFirst {
		args = append(args, "-f")
	}
	if req.UseSSL {
		args = append(args, "-S")
	}
	if req.LoopUsers {
		args = append(args, "-u")
	}
	if req.Verbose {
		args = append(args, "-V", "-v")
	}

	tasks := req.Tasks
	if tasks <= 0 {
		tasks = 1
	}
	args = append(args, "-t", strconv.Itoa(tasks))

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 32
	}
	args = append(args, "-w", strconv.Itoa(timeout))

	if req.Port > 0 {
		args = append(args, "-s", strconv.Itoa(req.Port))
	}

	// Output file
	args = append(args, "-o", outFile, "-b", "text")

	// Ignore existing restore file so re-runs start fresh
	args = append(args, "-I")

	// Target
	args = append(args, target)

	// Service + optional module params
	svc := req.Service
	if svc == "http-post-form" || svc == "http-get-form" {
		formURL := strings.TrimSpace(req.FormURL)
		if formURL == "" {
			formURL = "/"
		}
		// Strip full URL prefix if the user pasted a URL instead of a path
		if idx := strings.Index(formURL, "://"); idx != -1 {
			rest := formURL[idx+3:]
			if slash := strings.Index(rest, "/"); slash != -1 {
				formURL = rest[slash:]
			} else {
				formURL = "/"
			}
		}
		params := strings.TrimSpace(req.FormParams)
		if params == "" {
			return nil, fmt.Errorf("POST params required for %s (e.g. user=^USER^&pass=^PASS^)", svc)
		}
		cond := strings.TrimSpace(req.FormCondition)
		if cond == "" {
			cond = "F=incorrect"
		}
		formArg := fmt.Sprintf("%s:%s:%s", formURL, params, cond)
		args = append(args, svc, formArg)
	} else {
		args = append(args, svc)
	}

	return args, nil
}

// ── Output parser ─────────────────────────────────────────────────────────────

// hydraFoundRe matches lines like:
// [22][ssh] host: 192.168.0.1   login: admin   password: password123
// [22][ssh] host: 192.168.0.1   misc: (null)   login: admin   password: password123
var hydraFoundRe = regexp.MustCompile(
	`\[(\d+)\]\[([^\]]+)\] host: (\S+).*?login: (\S+)\s+password: (.+)`)

func parseHydraLine(line string) *FoundCred {
	m := hydraFoundRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	port, _ := strconv.Atoi(m[1])
	return &FoundCred{
		Port:     port,
		Service:  m[2],
		Host:     m[3],
		Login:    m[4],
		Password: strings.TrimSpace(m[5]),
	}
}

// ── Background runner ─────────────────────────────────────────────────────────

// upsertHostBruteforceLoot saves a cracked credential to the correct project loot.
// If the attacking session already belongs to a project, that project is used.
// Otherwise a project named after the target IP is found or created.
// A "Bruteforce Credentials" session within that project is found or created,
// and the credential is appended (deduplication handled by AppendBruteforceCredential).
func upsertHostBruteforceLoot(db *DB, userID, attackSessionID int, target, service, username, password string) {
	if target == "" {
		return
	}

	// Prefer the project the attacking session already belongs to.
	var projID int
	if attackSessionID > 0 {
		if sess, err := db.GetSession(attackSessionID, userID); err == nil && sess.ProjectID != nil {
			projID = *sess.ProjectID
		}
	}

	var proj *Project
	if projID != 0 {
		proj, _ = db.GetProject(projID, userID)
	}

	// Fall back: find or create a project named after the target IP.
	if proj == nil {
		projects, err := db.GetUserProjects(userID)
		if err == nil {
			for _, p := range projects {
				if strings.EqualFold(p.Name, target) {
					proj = p
					break
				}
			}
		}
		if proj == nil {
			var err error
			proj, err = db.CreateProject(userID, target, "")
			if err != nil {
				return
			}
		}
	}

	const sessName = "Bruteforce Credentials"
	var sessID int
	sessions, err := db.GetProjectSessions(proj.ID, userID)
	if err == nil {
		for _, s := range sessions {
			if s.SessionName == sessName {
				sessID = s.ID
				break
			}
		}
	}
	if sessID == 0 {
		sess, err := db.CreateProjectSession(userID, proj.ID, sessName, target)
		if err != nil {
			return
		}
		sessID = sess.ID
	}

	AppendBruteforceCredential(sessID, target, username, password, service)

	// Also store directly in the attacking session so credentials appear
	// in that session's Loot tab (action 8).
	if attackSessionID > 0 && attackSessionID != sessID {
		AppendBruteforceCredential(attackSessionID, target, username, password, service)
	}
}

func runHydra(sessionID int, target string, req BruteforceRequest, db *DB, userID int) {
	outFile := fmt.Sprintf("/tmp/hydra-%d.txt", sessionID)
	os.Remove(outFile)

	// Strip any http(s):// prefix and extract the host and port.
	// Hydra requires the host as a plain IP/hostname; port must come from -s.
	if idx := strings.Index(target, "://"); idx != -1 {
		rest := target[idx+3:]
		if slash := strings.Index(rest, "/"); slash != -1 {
			rest = rest[:slash]
		}
		target = rest
	}
	// If target is host:port, split and promote the port to req.Port (when not already set).
	if colonIdx := strings.LastIndex(target, ":"); colonIdx != -1 {
		if p, err2 := strconv.Atoi(target[colonIdx+1:]); err2 == nil && p > 0 && p <= 65535 {
			if req.Port == 0 {
				req.Port = p
			}
			target = target[:colonIdx]
		}
	}

	args, err := buildHydraArgs(target, req, outFile)
	job := getBruteJob(sessionID)
	if err != nil {
		job.mu.Lock()
		job.err = err.Error()
		job.done = true
		job.mu.Unlock()
		return
	}

	cmd := exec.Command("hydra", args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	job.mu.Lock()
	job.cmd = cmd
	job.output = append(job.output, fmt.Sprintf("[*] hydra %s", shellQuoteArgs(args)))
	job.mu.Unlock()

	if err := cmd.Start(); err != nil {
		job.mu.Lock()
		job.err = fmt.Sprintf("failed to start hydra: %v", err)
		job.done = true
		job.mu.Unlock()
		return
	}

	readStream := func(r interface{ Scan() bool; Text() string }) {
		for r.Scan() {
			line := r.Text()
			var newCred *FoundCred
			job.mu.Lock()
			job.output = append(job.output, line)
			if fc := parseHydraLine(line); fc != nil {
				job.found = append(job.found, *fc)
				cp := *fc
				newCred = &cp
			}
			job.mu.Unlock()
			// Save synchronously outside the job mutex so lootMu is always acquired.
			if newCred != nil {
				upsertHostBruteforceLoot(db, userID, sessionID, target, newCred.Service, newCred.Login, newCred.Password)
			}
		}
	}

	go readStream(bufio.NewScanner(stdout))
	go readStream(bufio.NewScanner(stderr))

	_ = cmd.Wait()

	job.mu.Lock()
	job.done = true
	job.mu.Unlock()
}

// ── Wordlist catalogue ────────────────────────────────────────────────────────

type WordlistEntry struct {
	Label string `json:"label"`
	Path  string `json:"path"`
	Group string `json:"group"`
}

// seclistsBase returns the first existing SecLists root directory.
func seclistsBase() string {
	for _, p := range []string{
		"/usr/share/wordlists/seclists",
		"/usr/share/seclists",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// walkWordlistDir walks a directory (max 2 levels deep) and returns .txt / .lst
// entries, skipping README files and directories.
func walkWordlistDir(root, group string) []WordlistEntry {
	var out []WordlistEntry
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(strings.ToLower(name), "readme") {
			continue
		}
		path := root + "/" + name
		if e.IsDir() {
			// one level of recursion — group name = parent/subdir
			sub := walkWordlistDir(path, group+"/"+name)
			out = append(out, sub...)
			continue
		}
		ext := strings.ToLower(name[max(0, len(name)-4):])
		if ext != ".txt" && ext != ".lst" && ext != ".csv" {
			continue
		}
		label := strings.TrimSuffix(name, ".txt")
		label = strings.TrimSuffix(label, ".lst")
		out = append(out, WordlistEntry{Label: label, Path: path, Group: group})
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func catalogueWordlists() (users []WordlistEntry, passwords []WordlistEntry) {
	base := seclistsBase()

	// ── Username lists ── SecLists first, then fallbacks ──────────────────────
	if base != "" {
		users = append(users, walkWordlistDir(base+"/Usernames", "SecLists/Usernames")...)
	}
	// Fallback fixed entries (only added if SecLists absent or file exists)
	type staticEntry struct{ label, path, group string }
	userFallbacks := []staticEntry{
		{"unix_users", "/usr/share/metasploit-framework/data/wordlists/unix_users.txt", "Metasploit"},
		{"http_default_users", "/usr/share/metasploit-framework/data/wordlists/http_default_users.txt", "Metasploit"},
		{"default_users_services", "/usr/share/metasploit-framework/data/wordlists/default_users_for_services_unhash.txt", "Metasploit"},
		{"postgres_default_user", "/usr/share/metasploit-framework/data/wordlists/postgres_default_user.txt", "Metasploit"},
		{"db2_default_user", "/usr/share/metasploit-framework/data/wordlists/db2_default_user.txt", "Metasploit"},
		{"ipmi_users", "/usr/share/metasploit-framework/data/wordlists/ipmi_users.txt", "Metasploit"},
		{"usernames (nmap)", "/usr/share/nmap/nselib/data/usernames.lst", "Nmap"},
		{"usernames (commix)", "/usr/share/commix/src/txt/default_usernames.txt", "Commix"},
	}
	for _, c := range userFallbacks {
		if _, err := os.Stat(c.path); err == nil {
			users = append(users, WordlistEntry{Label: c.label, Path: c.path, Group: c.group})
		}
	}

	// ── Password lists ── SecLists first, then fallbacks ──────────────────────
	if base != "" {
		passwords = append(passwords, walkWordlistDir(base+"/Passwords", "SecLists/Passwords")...)
	}
	passFallbacks := []staticEntry{
		{"rockyou", "/usr/share/wordlists/rockyou.txt", "Wordlists"},
		{"fasttrack", "/usr/share/wordlists/fasttrack.txt", "Wordlists"},
		{"john", "/usr/share/wordlists/john.lst", "Wordlists"},
		{"nmap.lst", "/usr/share/wordlists/nmap.lst", "Wordlists"},
		{"password.lst (msf)", "/usr/share/metasploit-framework/data/wordlists/password.lst", "Metasploit"},
		{"ipmi_passwords", "/usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt", "Metasploit"},
		{"default_pass_services", "/usr/share/metasploit-framework/data/wordlists/default_pass_for_services_unhash.txt", "Metasploit"},
	}
	for _, c := range passFallbacks {
		if _, err := os.Stat(c.path); err == nil {
			passwords = append(passwords, WordlistEntry{Label: c.label, Path: c.path, Group: c.group})
		}
	}

	// ── Combo files (appended to passwords with distinct group) ───────────────
	combos := []staticEntry{
		{"default_userpass_services", "/usr/share/metasploit-framework/data/wordlists/default_userpass_for_services_unhash.txt", "Metasploit Combo"},
		{"http_default_userpass", "/usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt", "Metasploit Combo"},
		{"db2_default_userpass", "/usr/share/metasploit-framework/data/wordlists/db2_default_userpass.txt", "Metasploit Combo"},
		{"postgres_default_userpass", "/usr/share/metasploit-framework/data/wordlists/postgres_default_userpass.txt", "Metasploit Combo"},
		{"oracle_default_userpass", "/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt", "Metasploit Combo"},
		{"scada_default_userpass", "/usr/share/metasploit-framework/data/wordlists/scada_default_userpass.txt", "Metasploit Combo"},
		{"routers_userpass", "/usr/share/metasploit-framework/data/wordlists/routers_userpass.txt", "Metasploit Combo"},
	}
	if base != "" {
		passwords = append(passwords, walkWordlistDir(base+"/Passwords/Default-Credentials", "SecLists Combo")...)
	}
	for _, c := range combos {
		if _, err := os.Stat(c.path); err == nil {
			passwords = append(passwords, WordlistEntry{Label: c.label, Path: c.path, Group: c.group})
		}
	}

	return users, passwords
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleGetWordlists() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		users, passwords := catalogueWordlists()
		data, _ := encodeJSON(map[string]interface{}{
			"users":     users,
			"passwords": passwords,
		})
		fmt.Fprint(w, data)
	}
}

func handleStartBruteforce(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}

		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		// Reject if already running
		if j := getBruteJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"attack already running"}`)
				return
			}
		}

		var req BruteforceRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid request: %v"}`, err)
			return
		}

		if req.Service == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"service required"}`)
			return
		}

		// Resolve target: explicit IP takes priority; otherwise fall back to session's host
		target := req.TargetIP
		if target == "" {
			session, err := db.GetSession(sessionID, claims.UserID)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":"session not found — enter a target IP"}`)
				return
			}
			target = session.TargetHost
		}

		job := &BruteforceJob{}
		bruteJobs.Store(sessionID, job)

		go runHydra(sessionID, target, req, db, claims.UserID)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetBruteforce(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}

		token := extractToken(r)
		_, err = validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		job := getBruteJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[]}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]FoundCred, len(job.found))
		copy(found, job.found)
		done := job.done
		jobErr := job.err
		job.mu.Unlock()

		outData, _ := encodeJSON(output)
		foundData, _ := encodeJSON(found)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"output":%s,"found":%s,"error":%q}`,
			status, outData, foundData, jobErr)
	}
}

func handleStopBruteforce(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		sessionID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid session id"}`)
			return
		}

		token := extractToken(r)
		_, err = validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		job := getBruteJob(sessionID)
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
