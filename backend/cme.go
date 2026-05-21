package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── CME job ───────────────────────────────────────────────────────────────────

type CMEJob struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	done   bool
	saved  bool
	err    string
	cancel context.CancelFunc
}

var cmeJobs sync.Map // sessionID → *CMEJob

func getCMEJob(sessionID int) *CMEJob {
	v, ok := cmeJobs.Load(sessionID)
	if !ok {
		return nil
	}
	return v.(*CMEJob)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleStartCME(db *DB) http.HandlerFunc {
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

		// Reject if already running
		if j := getCMEJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"cme already running"}`)
				return
			}
		}

		var body struct {
			Protocol string `json:"protocol"` // smb | ldap | winrm | ssh
			Username string `json:"username"`
			Password string `json:"password"`
			Action   string `json:"action"` // shares | users | groups | sessions | (empty=auth)
		}
		parseJSON(r, &body)

		proto := body.Protocol
		if proto == "" {
			proto = "smb"
		}
		target := session.TargetHost

		// Build args
		args := []string{proto, target}
		if body.Username != "" {
			args = append(args, "-u", body.Username)
		}
		if body.Password != "" {
			args = append(args, "-p", body.Password)
		}
		switch body.Action {
		case "shares":
			args = append(args, "--shares")
		case "users":
			args = append(args, "--users")
		case "groups":
			args = append(args, "--groups")
		case "sessions":
			args = append(args, "--sessions")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		job := &CMEJob{cancel: cancel}
		cmeJobs.Store(sessionID, job)

		go func() {
			cmd := exec.CommandContext(ctx, "crackmapexec", args...)
			cmd.Stdout = &job.buf
			cmd.Stderr = &job.buf
			runErr := cmd.Run()

			job.mu.Lock()
			job.done = true
			if runErr != nil && ctx.Err() == nil {
				job.err = runErr.Error()
			}
			// Strip any residual ANSI codes before storing/parsing.
			output := stripANSI(job.buf.String())
			job.buf.Reset()
			job.buf.WriteString(output)
			job.mu.Unlock()

			if saveErr := AppendCMEFindings(sessionID, target, proto, output); saveErr != nil {
				log.Printf("cme loot save: %v", saveErr)
			} else {
				job.mu.Lock()
				job.saved = true
				job.mu.Unlock()
			}
			cancel()
		}()

		fmt.Fprint(w, `{"ok":true}`)
	}
}

func handleGetCME(db *DB) http.HandlerFunc {
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

		job := getCMEJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"output":"","done":true}`)
			return
		}

		job.mu.Lock()
		output := job.buf.String()
		done := job.done
		saved := job.saved
		jobErr := job.err
		job.mu.Unlock()

		outJSON, _ := encodeJSON(output)
		errJSON, _ := encodeJSON(jobErr)
		fmt.Fprintf(w, `{"output":%s,"done":%v,"saved":%v,"error":%s}`, outJSON, done, saved, errJSON)
	}
}

func handleStopCME(db *DB) http.HandlerFunc {
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

		job := getCMEJob(sessionID)
		if job != nil {
			job.cancel()
			job.mu.Lock()
			job.done = true
			job.mu.Unlock()
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

// registerCMERoutes registers CrackMapExec routes on r (already auth-gated).
func registerCMERoutes(r chi.Router, db *DB) {
	r.Post("/sessions/{id}/cme", handleStartCME(db))
	r.Get("/sessions/{id}/cme", handleGetCME(db))
	r.Delete("/sessions/{id}/cme", handleStopCME(db))
}

// Ensure time import is used (already referenced above via time.Second).
var _ = time.Second
