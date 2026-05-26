package main

import (
	"bufio"
	"fmt"
	"log"
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

type FeroxJob struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	output []string
	found  []FeroxResult
	done   bool
	err    string
}

// FeroxResult represents a single discovered URL from feroxbuster output.
type FeroxResult struct {
	Status int    `json:"status"`
	Method string `json:"method"`
	Size   int    `json:"size"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
	URL    string `json:"url"`
}

var feroxJobs sync.Map // sessionID → *FeroxJob

func getFeroxJob(sessionID int) *FeroxJob {
	v, _ := feroxJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*FeroxJob)
}

// ── Web wordlist catalogue ────────────────────────────────────────────────────

type FeroxWordlist struct {
	Label string `json:"label"`
	Path  string `json:"path"`
}

func listFeroxWordlists() []FeroxWordlist {
	candidates := []FeroxWordlist{
		// SecLists web-content (preferred)
		{Label: "SecLists — common.txt", Path: "/usr/share/seclists/Discovery/Web-Content/common.txt"},
		{Label: "SecLists — big.txt", Path: "/usr/share/seclists/Discovery/Web-Content/big.txt"},
		{Label: "SecLists — directory-list-2.3-medium.txt", Path: "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"},
		{Label: "SecLists — directory-list-2.3-small.txt", Path: "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"},
		{Label: "SecLists — raft-medium-directories.txt", Path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"},
		{Label: "SecLists — raft-large-directories.txt", Path: "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"},
		{Label: "SecLists — raft-medium-files.txt", Path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"},
		{Label: "SecLists — raft-medium-words.txt", Path: "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"},
		{Label: "SecLists — combined_words.txt", Path: "/usr/share/seclists/Discovery/Web-Content/combined_words.txt"},
		{Label: "SecLists — api/api-endpoints.txt", Path: "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"},
		// DirBuster
		{Label: "DirBuster — directory-list-2.3-medium.txt", Path: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"},
		{Label: "DirBuster — directory-list-2.3-small.txt", Path: "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"},
		// Dirb
		{Label: "Dirb — common.txt", Path: "/usr/share/wordlists/dirb/common.txt"},
		{Label: "Dirb — big.txt", Path: "/usr/share/wordlists/dirb/big.txt"},
		{Label: "Dirb — small.txt", Path: "/usr/share/wordlists/dirb/small.txt"},
	}

	var available []FeroxWordlist
	for _, wl := range candidates {
		if _, err := os.Stat(wl.Path); err == nil {
			available = append(available, wl)
		}
	}
	return available
}

// ── Request struct ─────────────────────────────────────────────────────────────

type FeroxRequest struct {
	// Target
	URL      string `json:"url"`
	Protocol string `json:"protocol"` // "http" | "https"

	// Wordlist
	Wordlist string `json:"wordlist"`

	// Request
	Extensions  string `json:"extensions"`   // comma-separated, e.g. "php,html,txt"
	Methods     string `json:"methods"`       // comma-separated, e.g. "GET,POST"
	Headers     string `json:"headers"`       // newline-separated "Key:Value"
	Cookies     string `json:"cookies"`       // semicolon-separated
	UserAgent   string `json:"user_agent"`
	RandomAgent bool   `json:"random_agent"`
	AddSlash    bool   `json:"add_slash"`
	Data        string `json:"data"`
	DataJSON    bool   `json:"data_json"`
	DataForm    bool   `json:"data_form"`

	// Proxy
	Proxy      string `json:"proxy"`
	BurpMode   bool   `json:"burp_mode"`
	BurpReplay bool   `json:"burp_replay"`

	// Composite
	Smart    bool `json:"smart"`
	Thorough bool `json:"thorough"`

	// Scan settings
	Threads        int    `json:"threads"`         // default 50
	Depth          int    `json:"depth"`           // default 4
	NoRecursion    bool   `json:"no_recursion"`
	ForceRecursion bool   `json:"force_recursion"`
	ScanLimit      int    `json:"scan_limit"`      // 0 = unlimited
	RateLimit      int    `json:"rate_limit"`      // 0 = unlimited
	TimeLimit      string `json:"time_limit"`      // e.g. "10m"
	DontExtract    bool   `json:"dont_extract"`

	// Response filters
	StatusCodes  string `json:"status_codes"`   // allow list, space/comma-separated
	FilterStatus string `json:"filter_status"`  // deny list
	FilterSize   string `json:"filter_size"`
	FilterWords  string `json:"filter_words"`
	FilterLines  string `json:"filter_lines"`
	FilterRegex  string `json:"filter_regex"`
	Unique       bool   `json:"unique"`
	DontFilter   bool   `json:"dont_filter"`

	// Client
	Timeout     int  `json:"timeout"`    // default 7
	Redirects   bool `json:"redirects"`
	Insecure    bool `json:"insecure"`

	// Dynamic collection
	CollectExtensions bool `json:"collect_extensions"`
	CollectBackups    bool `json:"collect_backups"`
	CollectWords      bool `json:"collect_words"`

	// Behaviour
	AutoTune bool `json:"auto_tune"`
	AutoBail bool `json:"auto_bail"`

	// Output
	Verbosity int  `json:"verbosity"` // 0-4; maps to that many -v flags
	Quiet     bool `json:"quiet"`

	// Extra
	CustomArgs string `json:"custom_args"`
}

// ── Arg builder ───────────────────────────────────────────────────────────────

func buildFeroxArgs(req FeroxRequest, outputFile string) ([]string, error) {
	if req.URL == "" {
		return nil, fmt.Errorf("target URL required")
	}
	if req.Wordlist == "" {
		return nil, fmt.Errorf("wordlist required")
	}

	args := []string{
		"-u", req.URL,
		"-w", req.Wordlist,
		"--no-state",           // don't litter .state files
		"-q",                   // suppress progress bars (clean output for streaming)
		"-o", outputFile,
	}

	// Composite presets first (they override individual flags)
	if req.BurpMode {
		args = append(args, "--burp")
	} else if req.BurpReplay {
		args = append(args, "--burp-replay")
	}
	if req.Thorough {
		args = append(args, "--thorough")
	} else if req.Smart {
		args = append(args, "--smart")
	}

	// Request
	if req.Extensions != "" {
		for _, ext := range splitCSV(req.Extensions) {
			args = append(args, "-x", strings.TrimPrefix(ext, "."))
		}
	}
	if req.Methods != "" {
		for _, m := range splitCSV(req.Methods) {
			args = append(args, "-m", m)
		}
	}
	if req.Data != "" {
		if req.DataJSON {
			args = append(args, "--data-json", req.Data)
		} else if req.DataForm {
			args = append(args, "--data-urlencoded", req.Data)
		} else {
			args = append(args, "--data", req.Data)
		}
	}
	if req.Headers != "" {
		for _, h := range strings.Split(req.Headers, "\n") {
			h = strings.TrimSpace(h)
			if h != "" {
				args = append(args, "-H", h)
			}
		}
	}
	if req.Cookies != "" {
		for _, c := range splitCSV(req.Cookies) {
			args = append(args, "-b", c)
		}
	}
	if req.RandomAgent {
		args = append(args, "-A")
	} else if req.UserAgent != "" {
		args = append(args, "-a", req.UserAgent)
	}
	if req.AddSlash {
		args = append(args, "-f")
	}
	if req.Protocol != "" && req.Protocol != "https" {
		args = append(args, "--protocol", req.Protocol)
	}

	// Proxy
	if !req.BurpMode && req.Proxy != "" {
		args = append(args, "-p", req.Proxy)
	}

	// Scan settings
	t := req.Threads
	if t <= 0 {
		t = 50
	}
	args = append(args, "-t", strconv.Itoa(t))

	if req.NoRecursion {
		args = append(args, "-n")
	} else {
		d := req.Depth
		if d <= 0 {
			d = 4
		}
		args = append(args, "-d", strconv.Itoa(d))
		if req.ForceRecursion {
			args = append(args, "--force-recursion")
		}
	}

	if req.ScanLimit > 0 {
		args = append(args, "--scan-limit", strconv.Itoa(req.ScanLimit))
	}
	if req.RateLimit > 0 {
		args = append(args, "--rate-limit", strconv.Itoa(req.RateLimit))
	}
	if req.TimeLimit != "" {
		args = append(args, "--time-limit", req.TimeLimit)
	}
	if req.DontExtract {
		args = append(args, "--dont-extract-links")
	}

	// Response filters
	if req.StatusCodes != "" {
		args = append(args, "-s")
		for _, s := range splitCSV(req.StatusCodes) {
			args = append(args, s)
		}
	}
	if req.FilterStatus != "" {
		for _, s := range splitCSV(req.FilterStatus) {
			args = append(args, "-C", s)
		}
	}
	if req.FilterSize != "" {
		args = append(args, "-S", req.FilterSize)
	}
	if req.FilterWords != "" {
		args = append(args, "-W", req.FilterWords)
	}
	if req.FilterLines != "" {
		args = append(args, "-N", req.FilterLines)
	}
	if req.FilterRegex != "" {
		args = append(args, "-X", req.FilterRegex)
	}
	if req.Unique {
		args = append(args, "--unique")
	}
	if req.DontFilter {
		args = append(args, "-D")
	}

	// Client
	to := req.Timeout
	if to <= 0 {
		to = 7
	}
	args = append(args, "-T", strconv.Itoa(to))
	if req.Redirects {
		args = append(args, "-r")
	}
	if req.Insecure || req.BurpMode {
		args = append(args, "-k")
	}

	// Dynamic collection
	if req.CollectExtensions {
		args = append(args, "-E")
	}
	if req.CollectBackups {
		args = append(args, "-B")
	}
	if req.CollectWords {
		args = append(args, "-g")
	}

	// Behaviour
	if req.AutoTune {
		args = append(args, "--auto-tune")
	}
	if req.AutoBail {
		args = append(args, "--auto-bail")
	}

	// Verbosity
	for i := 0; i < req.Verbosity && i < 4; i++ {
		args = append(args, "-v")
	}

	// Custom
	if req.CustomArgs != "" {
		args = append(args, strings.Fields(req.CustomArgs)...)
	}

	return args, nil
}

// splitCSV splits on commas and spaces, trimming each element.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ── Output parsing ────────────────────────────────────────────────────────────

// feroxbuster default text line: "200      GET       50l      144w     1234c http://target/page"
var reFeroxLine = regexp.MustCompile(`^(\d{3})\s+(\w+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?://\S+)`)

func parseFeroxLine(line string) *FeroxResult {
	m := reFeroxLine.FindStringSubmatch(line)
	if len(m) < 7 {
		return nil
	}
	status, _ := strconv.Atoi(m[1])
	lines, _ := strconv.Atoi(m[3])
	words, _ := strconv.Atoi(m[4])
	size, _ := strconv.Atoi(m[5])
	return &FeroxResult{
		Status: status,
		Method: m[2],
		Lines:  lines,
		Words:  words,
		Size:   size,
		URL:    m[6],
	}
}

// ── Runner ────────────────────────────────────────────────────────────────────

func saveFeroxToDB(db *DB, sessionID int, job *FeroxJob) {
	job.mu.Lock()
	found := make([]FeroxResult, len(job.found))
	copy(found, job.found)
	output := make([]string, len(job.output))
	copy(output, job.output)
	job.mu.Unlock()

	foundData, _ := encodeJSON(found)
	outputData, _ := encodeJSON(output)
	blob := fmt.Sprintf(`{"found":%s,"output":%s}`, foundData, outputData)
	if err := db.SaveFeroxResults(sessionID, blob); err != nil {
		log.Printf("ferox results save: %v", err)
	}

	if len(found) > 0 {
		// Derive origin (scheme + host) from the first found URL.
		target := found[0].URL
		for _, pfx := range []string{"https://", "http://"} {
			if strings.HasPrefix(target, pfx) {
				rest := target[len(pfx):]
				if i := strings.IndexByte(rest, '/'); i >= 0 {
					target = pfx + rest[:i]
				}
				break
			}
		}
		if err := AppendFeroxLoot(sessionID, target, found); err != nil {
			log.Printf("ferox loot save: %v", err)
		}
	}
}

func runFerox(job *FeroxJob, args []string, sessionID int, db *DB) {
	// Output file written by feroxbuster — same path as handleStartFerox.
	outputFile := fmt.Sprintf("/tmp/ferox-%d/results.txt", sessionID)

	cmd := exec.Command("feroxbuster", args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	job.mu.Lock()
	job.cmd = cmd
	job.output = append(job.output, fmt.Sprintf("[*] feroxbuster %s", strings.Join(args, " ")))
	job.mu.Unlock()

	if err := cmd.Start(); err != nil {
		job.mu.Lock()
		job.err = fmt.Sprintf("failed to start feroxbuster: %v", err)
		job.done = true
		job.mu.Unlock()
		return
	}

	readStream := func(sc *bufio.Scanner) {
		for sc.Scan() {
			line := sc.Text()
			job.mu.Lock()
			job.output = append(job.output, line)
			if r := parseFeroxLine(line); r != nil {
				job.found = append(job.found, *r)
			}
			job.mu.Unlock()
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); readStream(bufio.NewScanner(stdout)) }()
	go func() { defer wg.Done(); readStream(bufio.NewScanner(stderr)) }()

	cmd.Wait() // closes pipes once the process exits
	wg.Wait()  // drain any remaining buffered lines before reading job.found

	// The output file is the authoritative source: feroxbuster flushes it
	// completely before exiting, so it captures results the pipe may have
	// missed (e.g. the last batch before EOF).
	if raw, err := os.ReadFile(outputFile); err == nil {
		seen := map[string]bool{}
		job.mu.Lock()
		for _, r := range job.found {
			seen[r.URL] = true
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if r := parseFeroxLine(line); r != nil && !seen[r.URL] {
				job.found = append(job.found, *r)
				seen[r.URL] = true
			}
		}
		job.mu.Unlock()
	}

	job.mu.Lock()
	job.done = true
	job.mu.Unlock()

	saveFeroxToDB(db, sessionID, job)
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleGetFeroxWordlists() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		lists := listFeroxWordlists()
		if lists == nil {
			lists = []FeroxWordlist{}
		}
		data, _ := encodeJSON(lists)
		fmt.Fprintf(w, `{"wordlists":%s}`, data)
	}
}

func handleStartFerox(db *DB) http.HandlerFunc {
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

		if j := getFeroxJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"feroxbuster already running"}`)
				return
			}
		}

		var req FeroxRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid request"}`)
			return
		}

		outputDir := fmt.Sprintf("/tmp/ferox-%d", sessionID)
		os.MkdirAll(outputDir, 0o755)
		outputFile := fmt.Sprintf("%s/results.txt", outputDir)
		os.Remove(outputFile)

		args, err := buildFeroxArgs(req, outputFile)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		// Clear previous results — a fresh scan replaces the old ones.
		db.DeleteFeroxResults(sessionID) //nolint:errcheck

		job := &FeroxJob{}
		feroxJobs.Store(sessionID, job)
		go runFerox(job, args, sessionID, db)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetFerox(db *DB) http.HandlerFunc {
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

		job := getFeroxJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[],"error":""}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]FeroxResult, len(job.found))
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

func handleStopFerox(db *DB) http.HandlerFunc {
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

		job := getFeroxJob(sessionID)
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
		// Persist whatever was found before the kill.
		saveFeroxToDB(db, sessionID, job)
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}

// handleGetFeroxResults returns the last persisted scan results without
// requiring an active job — used to restore results on panel mount.
func handleGetFeroxResults(db *DB) http.HandlerFunc {
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
		data, err := db.GetFeroxResults(sessionID)
		if err != nil {
			fmt.Fprint(w, `{"found":null,"output":null}`)
			return
		}
		fmt.Fprint(w, data)
	}
}
