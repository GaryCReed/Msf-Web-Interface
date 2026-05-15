package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
)

// baseDir returns the directory the binary lives in, falling back to CWD when
// running under "go run" (where os.Args[0] is a temp path).
func baseDir() string {
	bin := os.Args[0]
	dir := filepath.Dir(bin)
	if strings.HasPrefix(dir, os.TempDir()) || dir == "." {
		if wd, err := os.Getwd(); err == nil {
			return wd
		}
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

func init() {
	// Load .env from the same directory as the binary so it is found regardless
	// of which directory the process is started from.
	envPath := filepath.Join(baseDir(), ".env")
	if err := loadEnv(envPath); err != nil {
		// Fallback: try CWD (covers the common `go run .` case)
		_ = loadEnv(".env")
	}
	// auth.go's init() ran before this (alphabetical order), so jwtSecret may
	// have been set before .env was loaded.  Re-read now that .env is in the env.
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		jwtSecret = []byte(secret)
	}
}

func main() {
	base := baseDir()

	// Determine database URL. Relative sqlite3:// paths are anchored to baseDir
	// so the DB file always lands next to the binary regardless of CWD.
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "sqlite3://bagaholdin.db"
	}
	if strings.HasPrefix(dbURL, "sqlite3://") {
		rel := strings.TrimPrefix(dbURL, "sqlite3://")
		if !filepath.IsAbs(rel) {
			dbURL = "sqlite3://" + filepath.Join(base, rel)
		}
	}

	log.Printf("Using DATABASE_URL: %s", dbURL)

	// Initialize database.
	db, err := NewDB(dbURL)
	if err != nil {
		fallback := "sqlite3://" + filepath.Join(base, "bagaholdin.db")
		log.Printf("Warning: could not open %s: %v — falling back to %s", dbURL, err, fallback)
		db, err = NewDB(fallback)
		if err != nil {
			log.Fatalf("Failed to open SQLite fallback: %v", err)
		}
	}
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	if db.isMemory {
		log.Println("Running with in-memory store (data will not persist across restarts)")
	} else {
		log.Println("Database connected and migrated successfully")
	}

	// Give the loot subsystem a DB reference so every saveLootDocument call
	// also persists to the database (survives /tmp clears and server restarts).
	lootDB = db

	// Store captured handshakes next to the binary so they survive reboots.
	// The directory is created on first run and existing files are restored
	// into the in-memory registry automatically.
	initHandshakeDir(filepath.Join(base, "handshakes"))

	// Start FTP server for remote handshake uploads.
	// Default port 2121; override with FTP_PORT env var (set to 21 for standard FTP).
	ftpPort := 2121
	if p, err := strconv.Atoi(os.Getenv("FTP_PORT")); err == nil && p > 0 {
		ftpPort = p
	}
	go startFTPServer(ftpPort)

	// Initialize router
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Rate-limited auth routes (10 requests/minute per IP)
	authLimiter := httprate.LimitByIP(10, time.Minute)
	router.With(authLimiter).Post("/api/auth/login", handleLogin(db))
	router.Post("/api/auth/logout", handleLogout)
	router.Get("/api/ws", handleWebSocket(db))

	// Protected routes
	// Broad rate limit on all mutating session-action routes (120 req/min per IP)
	actionLimiter := httprate.LimitByIP(120, time.Minute)

	router.Route("/api", func(r chi.Router) {
		r.Use(authMiddleware)
		r.Use(actionLimiter)

		r.Get("/health", handleHealth)
		r.Get("/network", handleNetwork)
		r.Get("/config", handleConfig)

		// Projects
		r.Get("/projects", handleGetProjects(db))
		r.Post("/projects", handleCreateProject(db))
		r.Get("/projects/{id}", handleGetProject(db))
		r.Put("/projects/{id}", handleUpdateProject(db))
		r.Delete("/projects/{id}", handleDeleteProject(db))
		r.Get("/projects/{id}/sessions", handleGetProjectSessions(db))
		r.Post("/projects/{id}/sessions", handleCreateProjectSession(db))
		r.Get("/projects/{id}/hosts", handleGetProjectHosts(db))
		r.Post("/projects/{id}/scan", handleProjectScan(db))

		r.Get("/sessions", handleGetSessions(db))
		r.Post("/sessions", handleCreateSession(db))
		r.Get("/sessions/{id}", handleGetSession(db))
		r.Delete("/sessions/{id}", handleDeleteSession(db))
		r.Post("/exploits/run", handleRunExploit(db))
		r.Post("/scan", handleScan)
		r.Post("/sessions/{id}/vuln-scan", handleVulnScan(db))
		r.Get("/sessions/{id}/vuln-scan", handleGetVulnScan(db))
		r.Post("/sessions/{id}/enumerate", handleEnumerate(db))
		r.Post("/sessions/{id}/cve-analysis", handleCVEAnalysis(db))
		r.Get("/sessions/{id}/cve-results", handleGetCVEResults(db))
		r.Post("/sessions/{id}/cve-results", handleSaveCVEResults(db))
		r.Get("/sessions/{id}/enum-results", handleGetEnumResults(db))
		r.Post("/sessions/{id}/enum-results", handleSaveEnumResults(db))
		r.Post("/sessions/{id}/shell", handleShellCommand(db))
		r.Get("/sessions/{id}/msf-sessions", handleListMsfSessions(db))
		r.Post("/sessions/{id}/loot", handleSaveLoot(db))
		r.Get("/sessions/{id}/loot", handleGetLoot(db))
		r.Post("/sessions/{id}/ad-scan", handleADScan(db))
		r.Post("/sessions/{id}/kerbrute", handleRunKerbrute(db))
		r.Post("/sessions/{id}/enum4linux", handleEnum4Linux(db))
		registerCMERoutes(r, db)
		r.Post("/sessions/{id}/nxcsweep", handleStartNxcSweep(db))
		r.Get("/sessions/{id}/nxcsweep", handleGetNxcSweep(db))
		r.Delete("/sessions/{id}/nxcsweep", handleStopNxcSweep(db))
		registerNmapRoutes(r, db)
		r.Get("/sessions/{id}/notes", handleGetNotes(db))
		r.Post("/sessions/{id}/notes", handleSaveNotes(db))
		r.Get("/sessions/{id}/searchsploit", handleSearchsploit(db))
		r.Get("/sessions/{id}/searchsploit-results", handleGetSearchsploitResults(db))
		r.Post("/sessions/{id}/bruteforce", handleStartBruteforce(db))
		r.Get("/sessions/{id}/bruteforce", handleGetBruteforce(db))
		r.Delete("/sessions/{id}/bruteforce", handleStopBruteforce(db))
		r.Get("/wordlists", handleGetWordlists())
		// Hashcat
		r.Get("/sessions/{id}/hashcat/handshakes", handleGetHashcatHandshakes(db))
		r.Post("/sessions/{id}/hashcat", handleStartHashcat(db))
		r.Get("/sessions/{id}/hashcat", handleGetHashcat(db))
		r.Delete("/sessions/{id}/hashcat", handleStopHashcat(db))
		// SqlMap
		r.Post("/sessions/{id}/sqlmap", handleStartSqlmap(db))
		r.Get("/sessions/{id}/sqlmap", handleGetSqlmap(db))
		r.Delete("/sessions/{id}/sqlmap", handleStopSqlmap(db))
		// FeroxBuster
		r.Get("/ferox/wordlists", handleGetFeroxWordlists())
		r.Post("/sessions/{id}/ferox", handleStartFerox(db))
		r.Get("/sessions/{id}/ferox", handleGetFerox(db))
		r.Delete("/sessions/{id}/ferox", handleStopFerox(db))
		r.Get("/sessions/{id}/ferox-results", handleGetFeroxResults(db))
			// WPScan
			r.Post("/sessions/{id}/wpscan", handleStartWpscan(db))
			r.Get("/sessions/{id}/wpscan", handleGetWpscan(db))
			r.Delete("/sessions/{id}/wpscan", handleStopWpscan(db))
			// Handshake upload
		r.Post("/wifi/handshakes/upload", handleUploadHandshake())
		r.Get("/wifi/handshakes", handleListHandshakes())
		r.Get("/wifi/handshakes/{name}/download", handleDownloadHandshake())
		r.Delete("/wifi/handshakes/{name}", handleDeleteHandshake())
		// WiFi capture workflow
		r.Get("/wifi/interfaces", handleGetWifiInterfaces())
		r.Post("/wifi/monitor", handleEnableMonitor())
		r.Delete("/wifi/monitor", handleDisableMonitor())
		r.Post("/wifi/managed", handleEnableManaged())
		r.Post("/sessions/{id}/wifi/scan", handleStartWifiScan(db))
		r.Get("/sessions/{id}/wifi/scan", handleGetWifiScan(db))
		r.Delete("/sessions/{id}/wifi/scan", handleStopWifiScan(db))
		r.Post("/sessions/{id}/wifi/capture", handleStartWifiCapture(db))
		r.Get("/sessions/{id}/wifi/capture", handleGetWifiCapture(db))
		r.Delete("/sessions/{id}/wifi/capture", handleStopWifiCapture(db))
		// Msfvenom payload generator
		r.Post("/sessions/{id}/msfvenom", handleMsfvenomGenerate(db))
		r.Post("/sessions/{id}/msfvenom/upload", handleMsfvenomUpload(db))
		r.Post("/sessions/{id}/msfvenom/winusername", handleMsfvenomGetWinUsername(db))
		// Tools
		r.Post("/wifi/reset", handleResetWifiAdapters())
	})

	// Serve React SPA from the embedded filesystem (backend/ui/ at compile time).
	sub, _ := fs.Sub(staticFiles, "ui")
	fileServer := http.FileServer(http.FS(sub))
	router.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(sub, path); err != nil {
			// SPA fallback: unknown routes get index.html so React Router handles them
			data, _ := fs.ReadFile(sub, "index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		fileServer.ServeHTTP(w, r)
	}))

	port := ":8080"
	fmt.Printf("Server starting on http://localhost%s\n", port)

	setupCleanup()

	go func() {
		// Wait until the HTTP server is actually accepting connections before
		// opening the browser, so the user never lands on a connection-refused page.
		addr := "localhost" + port
		for i := 0; i < 60; i++ {
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			if err == nil {
				conn.Close()
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		// Open to /login so the login page is always shown first, regardless of
		// whether the browser has a cached JWT cookie from a previous session.
		url := "http://localhost" + port + "/login"
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("open", url)
		case "windows":
			cmd = exec.Command("cmd", "/c", "start", url)
		default:
			cmd = exec.Command("xdg-open", url)
		}
		_ = cmd.Start()
	}()
	log.Fatal(http.ListenAndServe(port, router))
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token := os.Getenv("WPSCAN_API_TOKEN")
	tokenJSON, _ := encodeJSON(token)
	fmt.Fprintf(w, `{"wpscan_api_token":%s}`, tokenJSON)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func handleLogin(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"Invalid request"}`)
			return
		}

		if req.Username == "" || req.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"username and password are required"}`)
			return
		}

		if err := authenticateLinuxUser(req.Username, req.Password); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		user, err := db.GetOrCreateUser(req.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"Failed to initialise user"}`)
			return
		}

		SetSudoPassword(user.ID, req.Password)

		token, err := generateToken(user.ID, user.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"Failed to generate token"}`)
			return
		}

		setAuthCookie(w, token)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"user":{"id":%d,"username":"%s"}}`, user.ID, user.Username)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	clearAuthCookie(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"logged out"}`)
}

// cleanupSessionData removes all server-side artifacts for a session.
func cleanupSessionData(targetHost string) {
	os.Remove(scanXMLPath(targetHost))
}

func cleanupLoot(sessionID int) {
	os.Remove(lootXMLPath(sessionID))
}

func handleDeleteSession(db *DB) http.HandlerFunc {
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

		// Fetch session before deleting so we have the target host for file cleanup.
		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		// Kill the running msfconsole process if one exists.
		CloseExecutor(sessionID)

		if err := db.DeleteSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		// Remove nmap XML, loot, and any other scan artifacts.
		cleanupSessionData(session.TargetHost)
		cleanupLoot(sessionID)

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"message":"session deleted"}`)
	}
}

func handleRunExploit(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var req struct {
			SessionID int                    `json:"session_id"`
			Exploit   string                 `json:"exploit"`
			Options   map[string]interface{} `json:"options"`
		}

		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"Invalid request"}`)
			return
		}

		if req.Exploit == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"exploit is required"}`)
			return
		}

		executor := GetExecutor(req.SessionID)
		if executor == nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"no active console for this session - open the console tab first"}`)
			return
		}

		commands := []string{fmt.Sprintf("use %s", req.Exploit)}
		for k, v := range req.Options {
			commands = append(commands, fmt.Sprintf("set %s %v", k, v))
		}
		commands = append(commands, "run")

		for _, cmd := range commands {
			if err := executor.ExecuteCommand(cmd); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"error":"failed to send command: %s"}`, err.Error())
				return
			}
		}

		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"message":"Exploit launched","session_id":%d}`, req.SessionID)
	}
}

type SessionWithStatus struct {
	Session
	IsRunning bool `json:"is_running"`
}

func handleGetSessions(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		token := extractToken(r)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Missing token"}`)
			return
		}

		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		sessions, err := db.GetUserSessions(claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"Failed to fetch sessions"}`)
			return
		}

		result := make([]SessionWithStatus, len(sessions))
		for i, s := range sessions {
			result[i] = SessionWithStatus{Session: s, IsRunning: GetExecutor(s.ID) != nil}
		}

		w.WriteHeader(http.StatusOK)
		data, _ := encodeJSON(result)
		fmt.Fprintf(w, `{"sessions":%s}`, data)
	}
}

func handleCreateSession(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		var req struct {
			SessionName string `json:"session_name"`
			TargetHost  string `json:"target_host"`
		}

		if err := parseJSON(r, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"Invalid request"}`)
			return
		}

		if req.SessionName == "" || req.TargetHost == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"session_name and target_host are required"}`)
			return
		}

		session, err := db.CreateSession(claims.UserID, req.SessionName, req.TargetHost)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		w.WriteHeader(http.StatusCreated)
		data, _ := encodeJSON(session)
		fmt.Fprintf(w, `{"session":%s}`, data)
	}
}

func handleWebSocket(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleCommandWebSocket(w, r, db)
	}
}

func handleGetSession(db *DB) http.HandlerFunc {
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

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		result := SessionWithStatus{Session: *session, IsRunning: GetExecutor(sessionID) != nil}
		data, _ := encodeJSON(result)
		fmt.Fprintf(w, `{"session":%s}`, data)
	}
}

// handleVulnScan starts a background nmap scan decoupled from the HTTP request.
// The scan survives client disconnection; results are polled via handleGetVulnScan.
func handleVulnScan(db *DB) http.HandlerFunc {
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

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		targetHost := session.TargetHost

		// Reject if already running for this host.
		if _, running := activeScan.Load(targetHost); running {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"status":"running"}`)
			return
		}

		// Remove all previous scan artefacts so the poller doesn't return stale results.
		os.Remove(scanOutputPath(targetHost))
		os.Remove(scanOutputPath(targetHost) + ".err")
		os.Remove(scanXMLPath(targetHost))

		activeScan.Store(targetHost, struct{}{})

		// Run nmap detached from the request context so navigation doesn't kill it.
		go func() {
			defer activeScan.Delete(targetHost)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			xmlPath := scanXMLPath(targetHost)
			output, err := vulnScan(ctx, targetHost, xmlPath)
			if err != nil {
				os.WriteFile(scanOutputPath(targetHost)+".err", []byte(err.Error()), 0o644)
				return
			}
			os.WriteFile(scanOutputPath(targetHost), []byte(output), 0o644)

			// Persist results to DB so they survive server restarts.
			osInfo := parseNmapOS(xmlPath)
			osFamily := ""
			if osInfo != nil {
				osFamily = strings.ToLower(osInfo.Family)
			}
			services, _ := parseNmapServices(xmlPath, osFamily)
			outputData, _ := encodeJSON(output)
			osData, _ := encodeJSON(osInfo)
			servicesData, _ := encodeJSON(services)
			blob := fmt.Sprintf(`{"output":%s,"services":%s,"os_info":%s}`,
				outputData, servicesData, osData)
			if saveErr := db.SaveVulnResults(sessionID, blob); saveErr != nil {
				log.Printf("vuln results save: %v", saveErr)
			}
		}()

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

// handleGetVulnScan lets the frontend poll for a scan's status and results.
func handleGetVulnScan(db *DB) http.HandlerFunc {
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

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		targetHost := session.TargetHost

		// Still running — no results yet.
		if _, running := activeScan.Load(targetHost); running {
			fmt.Fprint(w, `{"status":"running"}`)
			return
		}

		// Check for error marker.
		errPath := scanOutputPath(targetHost) + ".err"
		if errBytes, err2 := os.ReadFile(errPath); err2 == nil {
			os.Remove(errPath)
			errData, _ := encodeJSON(string(errBytes))
			fmt.Fprintf(w, `{"status":"error","error":%s}`, errData)
			return
		}

		// Return completed results — prefer /tmp files, fall back to DB.
		outputBytes, fileErr := os.ReadFile(scanOutputPath(targetHost))
		if fileErr != nil {
			// /tmp file missing — try DB (survives server restarts).
			if blob, dbErr := db.GetVulnResults(sessionID); dbErr == nil && len(blob) > 2 {
				// blob = {"output":...,"services":...,"os_info":...}
				// Strip outer braces and merge into the status envelope.
				inner := blob[1 : len(blob)-1]
				fmt.Fprintf(w, `{"status":"done","target":%q,%s}`, targetHost, inner)
				return
			}
			fmt.Fprint(w, `{"status":"none"}`)
			return
		}

		output := string(outputBytes)
		xmlPath := scanXMLPath(targetHost)
		osInfo := parseNmapOS(xmlPath)
		osFamily := ""
		if osInfo != nil {
			osFamily = strings.ToLower(osInfo.Family)
		}
		services, _ := parseNmapServices(xmlPath, osFamily)

		outputData, _ := encodeJSON(output)
		osData, _ := encodeJSON(osInfo)
		servicesData, _ := encodeJSON(services)
		fmt.Fprintf(w, `{"status":"done","output":%s,"target":%q,"xml_path":%q,"services":%s,"os_info":%s}`,
			outputData, targetHost, xmlPath, servicesData, osData)
	}
}

func handleCVEAnalysis(db *DB) http.HandlerFunc {
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

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		// Only analyse CVEs from this session's own scan.
		target := session.TargetHost
		cves, err := parseNmapXML(scanXMLPath(target))
		if err != nil {
			// XML missing — return the CVE results that were stored after the last analysis.
			if stored, dbErr := db.GetCVEResults(sessionID); dbErr == nil && stored != "" {
				fmt.Fprintf(w, `{"cves":%s,"target":%q}`, stored, target)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"No scan results found — run Vulnerability Scan first"}`)
			return
		}

		type cveInfo struct {
			modules map[string]struct{}
		}
		cveMap := map[string]*cveInfo{}
		for _, cve := range cves {
			if _, ok := cveMap[cve]; !ok {
				cveMap[cve] = &cveInfo{modules: map[string]struct{}{}}
			}
			for _, mod := range findMsfModules(cve) {
				cveMap[cve].modules[mod] = struct{}{}
			}
		}

		results := make([]CVEResult, 0, len(cveMap))
		for cve, info := range cveMap {
			mods := make([]string, 0, len(info.modules))
			for mod := range info.modules {
				mods = append(mods, mod)
			}
			sort.Strings(mods)
			results = append(results, CVEResult{CVE: cve, Modules: mods, Targets: []string{target}})
		}
		sort.Slice(results, func(i, j int) bool { return results[i].CVE < results[j].CVE })

		data, _ := encodeJSON(results)
		fmt.Fprintf(w, `{"cves":%s,"target":%q}`, data, target)
	}
}

func handleGetEnumResults(db *DB) http.HandlerFunc {
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
		data, err := db.GetEnumResults(sessionID)
		if err != nil {
			fmt.Fprint(w, `{"results":null}`)
			return
		}
		fmt.Fprintf(w, `{"results":%s}`, data)
	}
}

func handleSaveEnumResults(db *DB) http.HandlerFunc {
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
		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"failed to read body"}`)
			return
		}
		if err := db.SaveEnumResults(sessionID, string(body)); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"failed to save: %s"}`, err.Error())
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

func handleGetCVEResults(db *DB) http.HandlerFunc {
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
		data, err := db.GetCVEResults(sessionID)
		if err != nil {
			// No stored results yet — return empty payload
			fmt.Fprint(w, `{"results":null}`)
			return
		}
		fmt.Fprintf(w, `{"results":%s}`, data)
	}
}

func handleSaveCVEResults(db *DB) http.HandlerFunc {
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
		// Verify the session belongs to this user
		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}
		// Read raw body — it's already a JSON array of CVE results
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"failed to read body"}`)
			return
		}
		if err := db.SaveCVEResults(sessionID, string(body)); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"failed to save: %s"}`, err.Error())
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

// getDomainFromLoot reads the ad_discovery loot item and returns the DNS Domain Name.
func getDomainFromLoot(sessionID int) string {
	doc := loadLootDocument(sessionID)
	if doc == nil {
		return ""
	}
	for _, item := range doc.Items {
		if item.Type == "ad_discovery" {
			for _, f := range item.Fields {
				if f.Name == "DNS Domain Name" {
					return f.Value
				}
			}
		}
	}
	return ""
}

func handleRunKerbrute(db *DB) http.HandlerFunc {
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
		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		var body struct {
			Wordlist string `json:"wordlist"`
			Domain   string `json:"domain"`
		}
		parseJSON(r, &body)

		if body.Wordlist == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"wordlist required"}`)
			return
		}

		domain := strings.TrimSpace(body.Domain)
		if domain == "" {
			domain = getDomainFromLoot(sessionID)
		}
		if domain == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"domain not found — run AD Discovery Scan first or enter domain manually"}`)
			return
		}

		target := session.TargetHost
		ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
		defer cancel()

		out, _ := exec.CommandContext(ctx, "kerbrute", "userenum",
			"-d", domain, "--dc", target, body.Wordlist).CombinedOutput()
		output := string(out)

		lootSaved := false
		if err := AppendKerbruteUsers(sessionID, target, domain, body.Wordlist, output); err != nil {
			log.Printf("kerbrute loot save: %v", err)
		} else {
			lootSaved = true
		}

		outJSON, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"output":%s,"domain":%q,"saved":%v}`, outJSON, domain, lootSaved)
	}
}

func handleEnum4Linux(db *DB) http.HandlerFunc {
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
		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		target := session.TargetHost
		ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
		defer cancel()

		// Prefer enum4linux-ng, fall back to enum4linux
		tool := "enum4linux-ng"
		args := []string{"-A", target}
		if _, lookErr := exec.LookPath(tool); lookErr != nil {
			tool = "enum4linux"
			args = []string{"-a", target}
		}

		out, _ := exec.CommandContext(ctx, tool, args...).CombinedOutput()
		output := string(out)

		saved := false
		if err := AppendSMBEnum(sessionID, target, output); err != nil {
			log.Printf("enum4linux loot save: %v", err)
		} else {
			saved = true
		}

		outJSON, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"output":%s,"saved":%v}`, outJSON, saved)
	}
}

func handleADScan(db *DB) http.HandlerFunc {
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
		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		target := session.TargetHost
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()

		out, _ := exec.CommandContext(ctx, "nmap", "-p", "88,389",
			"--script=ldap-rootdse,smb-os-discovery", target).CombinedOutput()
		output := string(out)

		saved := false
		if err := AppendADDiscovery(sessionID, target, output); err != nil {
			log.Printf("AD loot save: %v", err)
		} else {
			saved = true
		}

		outJSON, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"output":%s,"target":%q,"saved":%v}`, outJSON, target, saved)
	}
}

func handleEnumerate(db *DB) http.HandlerFunc {
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

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		var body struct {
			OSFamily string `json:"os_family"`
		}
		parseJSON(r, &body) // os_family is optional

		xmlPath := scanXMLPath(session.TargetHost)
		services, err := parseNmapServices(xmlPath, body.OSFamily)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"No scan results found — run Vulnerability Scan first"}`)
			return
		}

		data, _ := encodeJSON(services)
		fmt.Fprintf(w, `{"services":%s,"target":%q}`, data, session.TargetHost)
	}
}

func handleShellCommand(db *DB) http.HandlerFunc {
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

		_, err = db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		var body struct {
			Command string `json:"command"`
		}
		if err := parseJSON(r, &body); err != nil || strings.TrimSpace(body.Command) == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"command required"}`)
			return
		}

		executor := GetExecutor(sessionID)
		if executor == nil {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"error":"Console not initialised — open the Console tab first"}`)
			return
		}

		// Subscribe to output fan-out, send the command, collect output until
		// 800 ms of silence or the 10 s hard deadline, then return.
		connID, subChan := executor.Subscribe()
		defer executor.Unsubscribe(connID)

		if err := executor.ExecuteCommand(body.Command); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		var lines []string
		deadline := time.After(10 * time.Second)
		idle := time.NewTimer(800 * time.Millisecond)
		defer idle.Stop()

	collect:
		for {
			select {
			case line, ok := <-subChan:
				if !ok {
					break collect
				}
				lines = append(lines, line)
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(800 * time.Millisecond)
			case <-idle.C:
				break collect
			case <-deadline:
				break collect
			}
		}

		output := strings.Join(lines, "\n")
		data, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"output":%s}`, data)
	}
}

func handleListMsfSessions(db *DB) http.HandlerFunc {
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

		_, err = db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		executor := GetExecutor(sessionID)
		if executor == nil {
			fmt.Fprint(w, `{"sessions":[]}`)
			return
		}

		connID, subChan := executor.Subscribe()
		defer executor.Unsubscribe(connID)

		if err := executor.ExecuteCommand("sessions -l"); err != nil {
			fmt.Fprint(w, `{"sessions":[]}`)
			return
		}

		var lines []string
		deadline := time.After(5 * time.Second)
		idle := time.NewTimer(1500 * time.Millisecond)
		defer idle.Stop()

	collect:
		for {
			select {
			case line, ok := <-subChan:
				if !ok {
					break collect
				}
				lines = append(lines, line)
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(1500 * time.Millisecond)
			case <-idle.C:
				break collect
			case <-deadline:
				break collect
			}
		}

		output := strings.TrimSpace(strings.Join(lines, "\n"))
		data, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"output":%s}`, data)
	}
}

func handleSaveLoot(db *DB) http.HandlerFunc {
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

		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		var body struct {
			Cmd    string `json:"cmd"`
			Output string `json:"output"`
		}
		parseJSON(r, &body)

		if err := AppendLoot(sessionID, session.TargetHost, body.Cmd, body.Output); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

func handleGetLoot(db *DB) http.HandlerFunc {
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

		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		doc := loadLootDocument(sessionID)
		if doc == nil {
			fmt.Fprint(w, `{"items":[]}`)
			return
		}
		data, _ := encodeJSON(doc.Items)
		fmt.Fprintf(w, `{"items":%s}`, data)
	}
}

func notesPath(sessionID int) string {
	return fmt.Sprintf("/tmp/msf-notes-%d.txt", sessionID)
}

func handleGetNotes(db *DB) http.HandlerFunc {
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
		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}
		content, _ := os.ReadFile(notesPath(sessionID))
		data, _ := encodeJSON(string(content))
		fmt.Fprintf(w, `{"notes":%s}`, data)
	}
}

func handleSaveNotes(db *DB) http.HandlerFunc {
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
		if _, err := db.GetSession(sessionID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}
		var body struct {
			Notes string `json:"notes"`
		}
		parseJSON(r, &body)
		if err := os.WriteFile(notesPath(sessionID), []byte(body.Notes), 0o644); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

// SearchsploitHit represents a single searchsploit result row.
type SearchsploitHit struct {
	Title    string `json:"title"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Platform string `json:"platform"`
	EdbID    string `json:"edb_id"`
	Query    string `json:"query"`
}

// handleSearchsploit reads the nmap XML for the session's target host, builds one
// searchsploit query per discovered service, runs them, and returns deduplicated results.
func handleSearchsploit(db *DB) http.HandlerFunc {
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
		session, err := db.GetSession(sessionID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"session not found"}`)
			return
		}

		services, err := parseNmapServices(scanXMLPath(session.TargetHost), "")
		if err != nil {
			// XML missing — try DB-persisted services from the last vuln scan.
			if blob, dbErr := db.GetVulnResults(sessionID); dbErr == nil && blob != "" {
				var stored struct {
					Services []ServiceEnumResult `json:"services"`
				}
				if decodeJSON(blob, &stored) == nil && len(stored.Services) > 0 {
					services = stored.Services
					err = nil
				}
			}
		}
		if err != nil || len(services) == 0 {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"No scan results found — run Vulnerability Scan first"}`)
			return
		}

		// Build deduplicated queries from open-port services.
		seen := map[string]bool{}
		type queryEntry struct{ term string }
		var queries []queryEntry
		for _, svc := range services {
			if svc.State != "open" {
				continue
			}
			var term string
			switch {
			case svc.Product != "" && svc.Version != "":
				term = svc.Product + " " + svc.Version
			case svc.Product != "":
				term = svc.Product
			case svc.Name != "":
				term = svc.Name
			}
			if term == "" || seen[term] {
				continue
			}
			seen[term] = true
			queries = append(queries, queryEntry{term})
		}

		if len(queries) == 0 {
			fmt.Fprint(w, `{"results":[],"queries":[]}`)
			return
		}

		hitSeen := map[string]bool{}
		var hits []SearchsploitHit
		var ranQueries []string

		for _, q := range queries {
			ranQueries = append(ranQueries, q.term)
			out, _ := exec.Command("searchsploit", "--disable-colour", q.term).Output()
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.Contains(line, "|") ||
					strings.HasPrefix(strings.TrimSpace(line), "-") ||
					strings.Contains(strings.ToLower(line), "title") {
					continue
				}
				pipeIdx := strings.LastIndex(line, "|")
				if pipeIdx == -1 {
					continue
				}
				title := strings.TrimSpace(line[:pipeIdx])
				path := strings.TrimSpace(line[pipeIdx+1:])
				if title == "" || path == "" || hitSeen[path] {
					continue
				}
				hitSeen[path] = true

				parts := strings.Split(path, "/")
				hitType, platform := "", ""
				if len(parts) >= 1 {
					hitType = parts[0]
				}
				if len(parts) >= 2 {
					platform = parts[1]
				}
				file := parts[len(parts)-1]
				edbID := strings.TrimSuffix(file, filepath.Ext(file))

				hits = append(hits, SearchsploitHit{
					Title: title, Path: path, Type: hitType,
					Platform: platform, EdbID: edbID, Query: q.term,
				})
			}
		}

		if hits == nil {
			hits = []SearchsploitHit{}
		}
		queriesData, _ := encodeJSON(ranQueries)
		hitsData, _ := encodeJSON(hits)
		blob := fmt.Sprintf(`{"results":%s,"queries":%s}`, hitsData, queriesData)

		// Persist so results survive restarts and don't require re-running searchsploit.
		if err := db.SaveSearchsploitResults(sessionID, blob); err != nil {
			log.Printf("searchsploit results save: %v", err)
		}

		fmt.Fprint(w, blob)
	}
}

// handleGetSearchsploitResults returns the last saved searchsploit results without re-running.
func handleGetSearchsploitResults(db *DB) http.HandlerFunc {
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
		data, err := db.GetSearchsploitResults(sessionID)
		if err != nil {
			fmt.Fprint(w, `{"results":null}`)
			return
		}
		fmt.Fprint(w, data)
	}
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		CIDR string `json:"cidr"`
	}
	parseJSON(r, &req)

	cidr := req.CIDR
	if cidr == "" {
		nets := getLocalNetworks()
		if len(nets) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"no local networks detected"}`)
			return
		}
		cidr = nets[0]
	}

	results, err := scanNetwork(cidr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"scan failed: %s"}`, err.Error())
		return
	}

	data, _ := encodeJSON(results)
	fmt.Fprintf(w, `{"hosts":%s,"cidr":%q}`, data, cidr)
}

func handleNetwork(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ifaces := getLocalInterfaces()
	// Also expose flat network list for backwards-compat (used for LHOST selection).
	networks := getLocalNetworks()
	ifaceData, _ := encodeJSON(ifaces)
	netData, _ := encodeJSON(networks)
	fmt.Fprintf(w, `{"interfaces":%s,"networks":%s}`, ifaceData, netData)
}

func handleGetProjectHosts(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		hosts, err := db.GetProjectHosts(projectID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"project not found"}`)
			return
		}
		data, _ := encodeJSON(hosts)
		fmt.Fprintf(w, `{"hosts":%s}`, data)
	}
}

func handleProjectScan(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		project, err := db.GetProject(projectID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"project not found"}`)
			return
		}

		// Determine CIDR: use project's network_range if set, else auto-detect
		var req struct {
			CIDR string `json:"cidr"`
		}
		parseJSON(r, &req)
		cidr := req.CIDR
		if cidr == "" {
			cidr = project.NetworkRange
		}
		if cidr == "" {
			nets := getLocalNetworks()
			if len(nets) == 0 {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"error":"no local networks detected"}`)
				return
			}
			cidr = nets[0]
		}

		results, err := scanNetwork(cidr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"scan failed: %s"}`, err.Error())
			return
		}

		if err := db.UpsertScanResults(projectID, results); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"failed to save results: %s"}`, err.Error())
			return
		}

		hosts, err := db.GetProjectHosts(projectID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"failed to fetch hosts"}`)
			return
		}
		data, _ := encodeJSON(hosts)
		fmt.Fprintf(w, `{"hosts":%s,"cidr":%q}`, data, cidr)
	}
}

func handleGetProjects(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		projects, err := db.GetUserProjects(claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"Failed to fetch projects"}`)
			return
		}
		data, _ := encodeJSON(projects)
		fmt.Fprintf(w, `{"projects":%s}`, data)
	}
}

func handleCreateProject(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			Name         string `json:"name"`
			NetworkRange string `json:"network_range"`
		}
		if err := parseJSON(r, &req); err != nil || req.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"name is required"}`)
			return
		}
		p, err := db.CreateProject(claims.UserID, req.Name, req.NetworkRange)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}
		w.WriteHeader(http.StatusCreated)
		data, _ := encodeJSON(p)
		fmt.Fprintf(w, `{"project":%s}`, data)
	}
}

func handleGetProject(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		p, err := db.GetProject(projectID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"project not found"}`)
			return
		}
		data, _ := encodeJSON(p)
		fmt.Fprintf(w, `{"project":%s}`, data)
	}
}

func handleUpdateProject(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var body struct {
			Name         string `json:"name"`
			NetworkRange string `json:"network_range"`
		}
		parseJSON(r, &body)
		if strings.TrimSpace(body.Name) == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"name required"}`)
			return
		}
		proj, err := db.UpdateProject(projectID, claims.UserID, strings.TrimSpace(body.Name), strings.TrimSpace(body.NetworkRange))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		data, _ := encodeJSON(proj)
		fmt.Fprintf(w, `{"project":%s}`, data)
	}
}

func handleDeleteProject(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		// Collect child sessions before deletion for cleanup.
		childSessions, _ := db.GetProjectSessions(projectID, claims.UserID)

		// Close any running consoles and delete scan/loot files for each child session.
		for _, s := range childSessions {
			CloseExecutor(s.ID)
			cleanupSessionData(s.TargetHost)
			cleanupLoot(s.ID)
		}

		// Delete sessions explicitly so they are fully removed (not just orphaned).
		for _, s := range childSessions {
			db.DeleteSession(s.ID, claims.UserID) //nolint:errcheck
		}

		if err := db.DeleteProject(projectID, claims.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"project not found"}`)
			return
		}

		// Return deleted session IDs so the frontend can purge localStorage.
		ids := make([]int, len(childSessions))
		for i, s := range childSessions {
			ids[i] = s.ID
		}
		idsData, _ := encodeJSON(ids)
		fmt.Fprintf(w, `{"message":"project deleted","deleted_session_ids":%s}`, idsData)
	}
}

func handleGetProjectSessions(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		sessions, err := db.GetProjectSessions(projectID, claims.UserID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"project not found"}`)
			return
		}
		result := make([]SessionWithStatus, len(sessions))
		for i, s := range sessions {
			result[i] = SessionWithStatus{Session: s, IsRunning: GetExecutor(s.ID) != nil}
		}
		data, _ := encodeJSON(result)
		fmt.Fprintf(w, `{"sessions":%s}`, data)
	}
}

func handleCreateProjectSession(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		projectID, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid project id"}`)
			return
		}
		token := extractToken(r)
		claims, err := validateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			SessionName string `json:"session_name"`
			TargetHost  string `json:"target_host"`
		}
		if err := parseJSON(r, &req); err != nil || req.SessionName == "" || req.TargetHost == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"session_name and target_host are required"}`)
			return
		}
		session, err := db.CreateProjectSession(claims.UserID, projectID, req.SessionName, req.TargetHost)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}
		w.WriteHeader(http.StatusCreated)
		data, _ := encodeJSON(session)
		fmt.Fprintf(w, `{"session":%s}`, data)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Missing authorization token"}`)
			return
		}

		claims, err := validateToken(token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid authorization token"}`)
			return
		}

		// Store user ID in context for use in handlers
		r.Header.Set("X-User-ID", fmt.Sprintf("%d", claims.UserID))
		r.Header.Set("X-Username", claims.Username)

		next.ServeHTTP(w, r)
	})
}
