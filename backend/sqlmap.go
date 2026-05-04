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
	"unicode"

	"github.com/go-chi/chi/v5"
)

// ── Job management ────────────────────────────────────────────────────────────

type SqlmapJob struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	output []string
	found  []SqlmapFinding
	done   bool
	err    string
}

type SqlmapFinding struct {
	Type  string `json:"type"`  // "injection" | "database" | "table" | "hash" | "dump" | "os"
	Value string `json:"value"`
}

var sqlmapJobs sync.Map // sessionID → *SqlmapJob

func getSqlmapJob(sessionID int) *SqlmapJob {
	v, _ := sqlmapJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*SqlmapJob)
}

// ── Request struct ─────────────────────────────────────────────────────────────

type SqlmapRequest struct {
	// Target
	URL         string `json:"url"`
	Data        string `json:"data"`
	Cookie      string `json:"cookie"`
	Method      string `json:"method"`
	Headers     string `json:"headers"`
	RequestFile string `json:"request_file"`
	DirectConn  string `json:"direct_conn"`
	SecondURL   string `json:"second_url"` // for second-order injection

	// Injection
	TestParam string `json:"test_param"`
	DBMS      string `json:"dbms"`
	Prefix    string `json:"prefix"`
	Suffix    string `json:"suffix"`
	Tamper    string `json:"tamper"`
	Technique string `json:"technique"`
	TimeSec   int    `json:"time_sec"` // time-based blind delay (default 5)

	// Detection
	Level     int    `json:"level"`
	Risk      int    `json:"risk"`
	Smart     bool   `json:"smart"`
	Forms     bool   `json:"forms"`
	String_   string `json:"string"`     // string that indicates True response
	NotString string `json:"not_string"` // string that indicates False response
	Code      int    `json:"code"`       // HTTP code for True response

	// Enumeration
	GetBanner      bool `json:"get_banner"`
	GetCurrentUser bool `json:"get_current_user"`
	GetCurrentDB   bool `json:"get_current_db"`
	GetIsDBA       bool `json:"get_is_dba"`
	GetHostname    bool `json:"get_hostname"`
	GetUsers       bool `json:"get_users"`
	GetPasswords   bool `json:"get_passwords"`
	GetPrivileges  bool `json:"get_privileges"`
	GetRoles       bool `json:"get_roles"`
	GetDatabases   bool `json:"get_databases"`
	GetTables      bool `json:"get_tables"`
	GetColumns     bool `json:"get_columns"`
	GetCount       bool `json:"get_count"`
	DumpTable      bool `json:"dump_table"`
	DumpAll        bool `json:"dump_all"`
	Schema         bool `json:"schema"`

	// Enum filters
	Database string `json:"database"`
	Table    string `json:"table"`
	Column   string `json:"column"`

	// SQL / OS access (man page: --sql-query, --sql-shell, --os-shell, --os-pwn)
	SQLQuery string `json:"sql_query"`
	SQLShell bool   `json:"sql_shell"`
	OSShell  bool   `json:"os_shell"`
	OSPwn    bool   `json:"os_pwn"`

	// Request options
	RandomAgent bool    `json:"random_agent"`
	UserAgent   string  `json:"user_agent"`
	Proxy       string  `json:"proxy"`
	UseTor      bool    `json:"use_tor"`
	Delay       float64 `json:"delay"`
	Timeout     int     `json:"timeout"`
	Retries     int     `json:"retries"`
	Threads     int     `json:"threads"`
	ForceSSL    bool    `json:"force_ssl"`
	IgnoreCode  string  `json:"ignore_code"` // HTTP codes to ignore, e.g. "401,403"

	// General
	Verbosity    int    `json:"verbosity"`
	FlushSession bool   `json:"flush_session"`
	ParseErrors  bool   `json:"parse_errors"`
	NoCast       bool   `json:"no_cast"`
	CrawlDepth   int    `json:"crawl_depth"`
	CustomArgs   string `json:"custom_args"`
}

// ── Arg builder ───────────────────────────────────────────────────────────────

func buildSqlmapArgs(req SqlmapRequest, outputDir string) ([]string, error) {
	if req.URL == "" && req.RequestFile == "" && req.DirectConn == "" {
		return nil, fmt.Errorf("target URL, request file, or direct connection string required")
	}

	args := []string{"--batch", "--disable-coloring", "--output-dir=" + outputDir}

	// Target
	if req.URL != "" {
		args = append(args, "-u", req.URL)
	}
	if req.RequestFile != "" {
		args = append(args, "-r", req.RequestFile)
	}
	if req.DirectConn != "" {
		args = append(args, "-d", req.DirectConn)
	}
	if req.SecondURL != "" {
		args = append(args, "--second-url="+req.SecondURL)
	}

	// Request
	if req.Data != "" {
		args = append(args, "--data="+req.Data)
	}
	if req.Cookie != "" {
		args = append(args, "--cookie="+req.Cookie)
	}
	if req.Method != "" {
		args = append(args, "--method="+req.Method)
	}
	if req.Headers != "" {
		args = append(args, "--headers="+req.Headers)
	}
	if req.UserAgent != "" {
		args = append(args, "--user-agent="+req.UserAgent)
	}
	if req.RandomAgent {
		args = append(args, "--random-agent")
	}
	if req.Proxy != "" {
		args = append(args, "--proxy="+req.Proxy)
	}
	if req.UseTor {
		args = append(args, "--tor")
	}
	if req.ForceSSL {
		args = append(args, "--force-ssl")
	}
	if req.IgnoreCode != "" {
		args = append(args, "--ignore-code="+req.IgnoreCode)
	}
	if req.Delay > 0 {
		args = append(args, fmt.Sprintf("--delay=%.1f", req.Delay))
	}
	if req.Timeout > 0 {
		args = append(args, "--timeout="+strconv.Itoa(req.Timeout))
	}
	if req.Retries > 0 {
		args = append(args, "--retries="+strconv.Itoa(req.Retries))
	}
	if req.Threads > 1 {
		args = append(args, "--threads="+strconv.Itoa(req.Threads))
	}

	// Injection
	if req.TestParam != "" {
		args = append(args, "-p", req.TestParam)
	}
	if req.DBMS != "" {
		args = append(args, "--dbms="+req.DBMS)
	}
	if req.Prefix != "" {
		args = append(args, "--prefix="+req.Prefix)
	}
	if req.Suffix != "" {
		args = append(args, "--suffix="+req.Suffix)
	}
	if req.Tamper != "" {
		args = append(args, "--tamper="+req.Tamper)
	}
	tech := req.Technique
	if tech == "" {
		tech = "BEUSTQ"
	}
	args = append(args, "--technique="+tech)

	if req.TimeSec > 0 && req.TimeSec != 5 {
		args = append(args, "--time-sec="+strconv.Itoa(req.TimeSec))
	}

	// Detection
	level := req.Level
	if level < 1 || level > 5 {
		level = 1
	}
	args = append(args, "--level="+strconv.Itoa(level))

	risk := req.Risk
	if risk < 1 || risk > 3 {
		risk = 1
	}
	args = append(args, "--risk="+strconv.Itoa(risk))

	if req.Smart {
		args = append(args, "--smart")
	}
	if req.Forms {
		args = append(args, "--forms")
	}
	if req.ParseErrors {
		args = append(args, "--parse-errors")
	}
	if req.NoCast {
		args = append(args, "--no-cast")
	}
	if req.String_ != "" {
		args = append(args, "--string="+req.String_)
	}
	if req.NotString != "" {
		args = append(args, "--not-string="+req.NotString)
	}
	if req.Code > 0 {
		args = append(args, "--code="+strconv.Itoa(req.Code))
	}

	// Enumeration
	if req.GetBanner {
		args = append(args, "-b")
	}
	if req.GetCurrentUser {
		args = append(args, "--current-user")
	}
	if req.GetCurrentDB {
		args = append(args, "--current-db")
	}
	if req.GetIsDBA {
		args = append(args, "--is-dba")
	}
	if req.GetHostname {
		args = append(args, "--hostname")
	}
	if req.GetUsers {
		args = append(args, "--users")
	}
	if req.GetPasswords {
		args = append(args, "--passwords")
	}
	if req.GetPrivileges {
		args = append(args, "--privileges")
	}
	if req.GetRoles {
		args = append(args, "--roles")
	}
	if req.GetDatabases {
		args = append(args, "--dbs")
	}
	if req.GetTables {
		args = append(args, "--tables")
	}
	if req.GetColumns {
		args = append(args, "--columns")
	}
	if req.GetCount {
		args = append(args, "--count")
	}
	if req.Schema {
		args = append(args, "--schema")
	}
	if req.DumpTable {
		args = append(args, "--dump")
	}
	if req.DumpAll {
		args = append(args, "--dump-all")
	}

	// Enum filters
	if req.Database != "" {
		args = append(args, "-D", req.Database)
	}
	if req.Table != "" {
		args = append(args, "-T", req.Table)
	}
	if req.Column != "" {
		args = append(args, "-C", req.Column)
	}

	// SQL / OS access
	if req.SQLQuery != "" {
		args = append(args, "--sql-query="+req.SQLQuery)
	}
	if req.SQLShell {
		args = append(args, "--sql-shell")
	}
	if req.OSShell {
		args = append(args, "--os-shell")
	}
	if req.OSPwn {
		args = append(args, "--os-pwn")
	}

	// General
	v := req.Verbosity
	if v < 0 || v > 6 {
		v = 1
	}
	args = append(args, "-v", strconv.Itoa(v))

	if req.FlushSession {
		args = append(args, "--flush-session")
	}
	if req.CrawlDepth > 0 {
		args = append(args, "--crawl="+strconv.Itoa(req.CrawlDepth))
	}

	if req.CustomArgs != "" {
		extra, err := shellSplitArgs(req.CustomArgs)
		if err != nil {
			return nil, fmt.Errorf("custom args: %v", err)
		}
		args = append(args, extra...)
	}

	return args, nil
}

// shellSplitArgs splits a shell-like argument string respecting single and
// double quotes. It does not support backslash escaping outside quotes.
func shellSplitArgs(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	for i, r := range s {
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(r)
			}
		case inDouble:
			if r == '"' {
				inDouble = false
			} else {
				cur.WriteRune(r)
			}
		case r == '\'':
			inSingle = true
		case r == '"':
			inDouble = true
		case unicode.IsSpace(r):
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
		_ = i
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in custom args")
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args, nil
}

// ── Output parsing ────────────────────────────────────────────────────────────

var (
	reDBMS = regexp.MustCompile(`(?i)the back-end DBMS is ([^\n\r]+)`)

	// Matches the parameter injection block header: "Parameter: id (GET)"
	reParamHeader = regexp.MustCompile(`(?i)^Parameter:\s+(\S+)\s+\((\w+)\)`)

	// Matches injection type line inside a parameter block: "    Type: boolean-based blind"
	reInjType = regexp.MustCompile(`(?i)^\s+Type:\s+(.+)`)

	// Matches "... is vulnerable" or "SQL injection" confirmed lines
	reInjectable = regexp.MustCompile(`(?i)(is vulnerable|SQL injection (vulnerability|point)|parameter .+ is (injectable|vulnerable))`)

	// Database list item: "[*] dbname" — but only when it's a bare name, not a status line.
	// sqlmap prints [*] items for database names after "available databases [N]:"
	reDBItem = regexp.MustCompile(`^\[\*\]\s+(\S+)\s*$`)

	// Database/Table label lines in dump output
	reDBLine  = regexp.MustCompile(`(?i)^Database:\s+(\S+)`)
	reTblLine = regexp.MustCompile(`(?i)^Table:\s+(\S+)`)

	// Dump row (table border lines contain |)
	reDumpRow = regexp.MustCompile(`^\|\s+.+\s+\|`)

	// OS command execution result
	reOSCmd = regexp.MustCompile(`(?i)(command standard output|os-shell>|os_shell|command execution)`)
)

// parseSqlmapLine inspects a single output line and returns a finding if one is detected.
func parseSqlmapLine(line string) *SqlmapFinding {
	trimmed := strings.TrimSpace(line)

	// DBMS identification
	if m := reDBMS.FindStringSubmatch(line); len(m) > 1 {
		return &SqlmapFinding{Type: "injection", Value: "DBMS: " + strings.TrimSpace(m[1])}
	}

	// Injectable parameter block header
	if m := reParamHeader.FindStringSubmatch(trimmed); len(m) > 2 {
		return &SqlmapFinding{Type: "injection", Value: fmt.Sprintf("Parameter: %s (%s)", m[1], m[2])}
	}

	// Injection type line (inside a parameter block)
	if m := reInjType.FindStringSubmatch(line); len(m) > 1 {
		return &SqlmapFinding{Type: "injection", Value: "  Type: " + strings.TrimSpace(m[1])}
	}

	// Generic "is vulnerable / injectable" lines
	if reInjectable.MatchString(line) {
		return &SqlmapFinding{Type: "injection", Value: trimmed}
	}

	// [*] database_name — exclude status lines (contain spaces, "starting", digits only, etc.)
	if m := reDBItem.FindStringSubmatch(trimmed); len(m) > 1 {
		name := m[1]
		if !strings.EqualFold(name, "starting") &&
			!strings.EqualFold(name, "shutting") &&
			!strings.Contains(name, "target") &&
			!isAllDigits(name) {
			return &SqlmapFinding{Type: "database", Value: name}
		}
	}

	// "available databases" / "database schemas" header
	if strings.Contains(line, "available databases") || strings.Contains(line, "database schemas") {
		return &SqlmapFinding{Type: "database", Value: trimmed}
	}

	// Database: label line in dump/enumeration output
	if m := reDBLine.FindStringSubmatch(trimmed); len(m) > 1 {
		return &SqlmapFinding{Type: "database", Value: m[1]}
	}

	// Table: label line
	if m := reTblLine.FindStringSubmatch(trimmed); len(m) > 1 {
		return &SqlmapFinding{Type: "table", Value: m[1]}
	}

	// Password hash lines
	if strings.Contains(line, "password hash") || strings.Contains(line, "Password hash") {
		return &SqlmapFinding{Type: "hash", Value: trimmed}
	}

	// Dump row (table data)
	if reDumpRow.MatchString(trimmed) {
		return &SqlmapFinding{Type: "dump", Value: trimmed}
	}

	// OS access lines
	if reOSCmd.MatchString(line) {
		return &SqlmapFinding{Type: "os", Value: trimmed}
	}

	// Generic [+] found lines
	if strings.HasPrefix(trimmed, "[+]") {
		return &SqlmapFinding{Type: "injection", Value: trimmed}
	}

	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ── Runner ────────────────────────────────────────────────────────────────────

func runSqlmap(job *SqlmapJob, args []string, sessionID int, target string) {
	cmd := exec.Command("sqlmap", args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	job.mu.Lock()
	job.cmd = cmd
	job.output = append(job.output, fmt.Sprintf("[*] sqlmap %s", shellQuoteArgs(args)))
	job.mu.Unlock()

	if err := cmd.Start(); err != nil {
		job.mu.Lock()
		job.err = fmt.Sprintf("failed to start sqlmap: %v", err)
		job.done = true
		job.mu.Unlock()
		return
	}

	readStream := func(sc *bufio.Scanner) {
		for sc.Scan() {
			line := sc.Text()
			var newFinding *SqlmapFinding
			job.mu.Lock()
			job.output = append(job.output, line)
			if f := parseSqlmapLine(line); f != nil {
				job.found = append(job.found, *f)
				cp := *f
				newFinding = &cp
			}
			job.mu.Unlock()
			if newFinding != nil {
				AppendSqlmapFinding(sessionID, target, newFinding.Type, newFinding.Value)
			}
		}
	}
	go readStream(bufio.NewScanner(stdout))
	go readStream(bufio.NewScanner(stderr))

	cmd.Wait()

	job.mu.Lock()
	job.done = true
	job.mu.Unlock()
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleStartSqlmap(db *DB) http.HandlerFunc {
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

		if j := getSqlmapJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"sqlmap already running"}`)
				return
			}
		}

		var req SqlmapRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid request"}`)
			return
		}

		outputDir := fmt.Sprintf("/tmp/sqlmap-%d", sessionID)
		os.MkdirAll(outputDir, 0o755)

		args, err := buildSqlmapArgs(req, outputDir)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		job := &SqlmapJob{}
		sqlmapJobs.Store(sessionID, job)
		target := req.URL
		if target == "" {
			target = req.DirectConn
		}
		go runSqlmap(job, args, sessionID, target)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetSqlmap(db *DB) http.HandlerFunc {
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

		job := getSqlmapJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[],"error":""}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]SqlmapFinding, len(job.found))
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

func handleStopSqlmap(db *DB) http.HandlerFunc {
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

		job := getSqlmapJob(sessionID)
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
