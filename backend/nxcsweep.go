package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Job ───────────────────────────────────────────────────────────────────────

type NxcSweepJob struct {
	mu      sync.Mutex
	output  []string
	found   []NxcFinding
	done    bool
	err     string
	cmd     *exec.Cmd // current running nxc process
	stopped bool
}

type NxcFinding struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Detail   string `json:"detail"` // "(Pwn3d!)", share list, etc.
	Raw      string `json:"raw"`
}

var nxcSweepJobs sync.Map // sessionID → *NxcSweepJob

func getNxcSweepJob(sessionID int) *NxcSweepJob {
	v, _ := nxcSweepJobs.Load(sessionID)
	if v == nil {
		return nil
	}
	return v.(*NxcSweepJob)
}

// ── Protocol table ────────────────────────────────────────────────────────────

type nxcProto struct {
	name      string
	port      int
	extraArgs []string
	// flags to strip for this protocol (e.g. --local-auth breaks FTP)
	stripFlags []string
}

var nxcProtocols = []nxcProto{
	{name: "smb",   port: 445,  extraArgs: []string{"--shares"}},
	{name: "ldap",  port: 389,  extraArgs: []string{"--users"}},
	{name: "winrm", port: 5985, extraArgs: nil},
	{name: "rdp",   port: 3389, extraArgs: nil},
	{name: "ssh",   port: 22,   extraArgs: nil},
	{name: "mssql", port: 1433, extraArgs: []string{"-q", "SELECT name FROM master.sys.databases;"}},
	{name: "ftp",   port: 21,   extraArgs: []string{"--ls"}, stripFlags: []string{"--local-auth"}},
	{name: "wmi",   port: 135,  extraArgs: nil},
	{name: "ldaps", port: 636,  extraArgs: []string{"--users"}},
}

// ── Request struct ────────────────────────────────────────────────────────────

type NxcSweepRequest struct {
	Target    string   `json:"target"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Hash      string   `json:"hash"`       // NT hash for pass-the-hash
	Domain    string   `json:"domain"`
	LocalAuth bool     `json:"local_auth"`
	Protocols []string `json:"protocols"`  // subset to run; empty = all
	Timeout   int      `json:"timeout"`    // port-check timeout seconds (default 2)
}

// ── Output parser ─────────────────────────────────────────────────────────────

// nxc success line: "SMB   192.168.1.1  445  DC01  [+] CORP\admin:pass (Pwn3d!)"
// nxc share line:   "SMB   192.168.1.1  445  DC01  [+] ...  ADMIN$ READ,WRITE"
var reNxcFound = regexp.MustCompile(
	`(?i)^(\S+)\s+(\S+)\s+(\d+)\s+(\S*)\s+\[\+\]\s+(.+)`)

func parseNxcLine(line, proto string) *NxcFinding {
	m := reNxcFound.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil
	}
	port, _ := strconv.Atoi(m[3])
	rest := strings.TrimSpace(m[5])
	// Split off trailing (Pwn3d!) or similar annotations
	detail := ""
	if idx := strings.Index(rest, "("); idx != -1 {
		detail = strings.TrimSpace(rest[idx:])
		rest = strings.TrimSpace(rest[:idx])
	}
	// rest is now "DOMAIN\user:pass" or a share name etc.
	user := rest
	return &NxcFinding{
		Protocol: strings.ToLower(m[1]),
		Host:     m[2],
		Port:     port,
		Name:     m[4],
		User:     user,
		Detail:   detail,
		Raw:      strings.TrimSpace(line),
	}
}

// ── Port check ────────────────────────────────────────────────────────────────

func portOpen(host string, port, timeoutSec int) bool {
	timeout := time.Duration(timeoutSec) * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ── Runner ────────────────────────────────────────────────────────────────────

func runNxcSweep(job *NxcSweepJob, req NxcSweepRequest, sessionID int) {
	portTimeout := req.Timeout
	if portTimeout <= 0 {
		portTimeout = 2
	}

	// Determine which protocols to sweep
	enabled := map[string]bool{}
	if len(req.Protocols) == 0 {
		for _, p := range nxcProtocols {
			enabled[p.name] = true
		}
	} else {
		for _, p := range req.Protocols {
			enabled[strings.ToLower(p)] = true
		}
	}

	// Build global flags shared across protocols
	globalFlags := []string{}
	if req.Domain != "" {
		globalFlags = append(globalFlags, "-d", req.Domain)
	}
	if req.LocalAuth {
		globalFlags = append(globalFlags, "--local-auth")
	}

	for _, proto := range nxcProtocols {
		if !enabled[proto.name] {
			continue
		}

		job.mu.Lock()
		stopped := job.stopped
		job.mu.Unlock()
		if stopped {
			break
		}

		// Port check
		open := portOpen(req.Target, proto.port, portTimeout)
		status := fmt.Sprintf("[*] Port %d (%s): ", proto.port, proto.name)
		if !open {
			job.mu.Lock()
			job.output = append(job.output, status+"closed/filtered — skipping")
			job.mu.Unlock()
			continue
		}
		job.mu.Lock()
		job.output = append(job.output, status+"open")
		job.mu.Unlock()

		// Build args: nxc <proto> <target> -u <user> -p/-H <pass> [global] [extra]
		args := []string{proto.name, req.Target}
		if req.Username != "" {
			args = append(args, "-u", req.Username)
		}
		if req.Hash != "" {
			args = append(args, "-H", req.Hash)
		} else if req.Password != "" {
			args = append(args, "-p", req.Password)
		}

		// Apply global flags, stripping any that this protocol rejects
		stripSet := map[string]bool{}
		for _, f := range proto.stripFlags {
			stripSet[f] = true
		}
		for _, f := range globalFlags {
			if !stripSet[f] {
				args = append(args, f)
			}
		}

		args = append(args, proto.extraArgs...)

		cmd := exec.Command("nxc", args...)
		job.mu.Lock()
		job.cmd = cmd
		job.output = append(job.output, fmt.Sprintf("[>] nxc %s", strings.Join(args, " ")))
		job.mu.Unlock()

		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			job.mu.Lock()
			job.output = append(job.output, fmt.Sprintf("[!] Failed to start nxc %s: %v", proto.name, err))
			job.mu.Unlock()
			continue
		}

		readLines := func(sc *bufio.Scanner) {
			for sc.Scan() {
				line := sc.Text()
				// Strip ANSI escape sequences for clean storage
				clean := stripANSI(line)
				if strings.TrimSpace(clean) == "" {
					continue
				}
				var finding *NxcFinding
				job.mu.Lock()
				job.output = append(job.output, clean)
				if f := parseNxcLine(clean, proto.name); f != nil {
					job.found = append(job.found, *f)
					cp := *f
					finding = &cp
				}
				job.mu.Unlock()
				if finding != nil {
					AppendNxcFinding(sessionID, req.Target, struct {
						Protocol string
						Host     string
						Port     int
						Name     string
						User     string
						Detail   string
						Raw      string
					}{
						Protocol: finding.Protocol,
						Host:     finding.Host,
						Port:     finding.Port,
						Name:     finding.Name,
						User:     finding.User,
						Detail:   finding.Detail,
						Raw:      finding.Raw,
					})
				}
			}
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); readLines(bufio.NewScanner(stdout)) }()
		go func() { defer wg.Done(); readLines(bufio.NewScanner(stderr)) }()
		cmd.Wait()
		wg.Wait()
	}

	job.mu.Lock()
	job.output = append(job.output, "[*] Sweep complete.")
	job.done = true
	job.mu.Unlock()
}

// stripANSI removes ANSI escape sequences from s.
var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*[mKGABCDEFHJSTsu]`)

func stripANSI(s string) string {
	return reANSI.ReplaceAllString(s, "")
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleStartNxcSweep(db *DB) http.HandlerFunc {
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

		if j := getNxcSweepJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"sweep already running"}`)
				return
			}
		}

		var req NxcSweepRequest
		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid request"}`)
			return
		}

		// Fall back to session host if no target given
		if req.Target == "" {
			sess, err := db.GetSession(sessionID, claims.UserID)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":"session not found"}`)
				return
			}
			req.Target = sess.TargetHost
		}
		if req.Target == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"target required"}`)
			return
		}

		job := &NxcSweepJob{}
		nxcSweepJobs.Store(sessionID, job)
		go runNxcSweep(job, req, sessionID)

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetNxcSweep(db *DB) http.HandlerFunc {
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

		job := getNxcSweepJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle","output":[],"found":[],"error":""}`)
			return
		}

		job.mu.Lock()
		output := make([]string, len(job.output))
		copy(output, job.output)
		found := make([]NxcFinding, len(job.found))
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

func handleStopNxcSweep(db *DB) http.HandlerFunc {
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

		job := getNxcSweepJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job.mu.Lock()
		job.stopped = true
		cmd := job.cmd
		job.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}
