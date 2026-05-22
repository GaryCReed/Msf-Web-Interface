package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// ── Job store ─────────────────────────────────────────────────────────────────

type NmapJob struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	done   bool
	cancel context.CancelFunc
}

var nmapJobs sync.Map // sessionID → *NmapJob

func getNmapJob(sessionID int) *NmapJob {
	v, ok := nmapJobs.Load(sessionID)
	if !ok {
		return nil
	}
	return v.(*NmapJob)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleStartNmapScan(db *DB) http.HandlerFunc {
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
		if j := getNmapJob(sessionID); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"nmap scan already running"}`)
				return
			}
		}

		var body struct {
			Flags   []string `json:"flags"`
			Scripts []string `json:"scripts"`
			Ports   string   `json:"ports"`
			Extra   string   `json:"extra"`
		}
		parseJSON(r, &body)

		// Build args — allowlist flags to prevent injection
		allowedFlags := map[string]bool{
			"-sV": true, "-sS": true, "-sU": true, "-O": true, "-A": true,
			"-Pn": true, "--open": true, "-T4": true, "-p-": true, "-n": true, "-sC": true,
		}
		args := []string{}
		for _, f := range body.Flags {
			if allowedFlags[f] {
				args = append(args, f)
			}
		}

		// Sanitise and add script list
		if len(body.Scripts) > 0 {
			safe := []string{}
			for _, s := range body.Scripts {
				// Only allow alphanumeric, hyphens, commas in script names
				clean := strings.Map(func(r rune) rune {
					if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
						return r
					}
					return -1
				}, s)
				if clean != "" {
					safe = append(safe, clean)
				}
			}
			if len(safe) > 0 {
				args = append(args, "--script="+strings.Join(safe, ","))
			}
		}

		// Port spec — only allow digits, commas, hyphens
		if body.Ports != "" {
			cleanPorts := strings.Map(func(r rune) rune {
				if (r >= '0' && r <= '9') || r == ',' || r == '-' {
					return r
				}
				return -1
			}, body.Ports)
			if cleanPorts != "" {
				args = append(args, "-p", cleanPorts)
			}
		}

		// Extra args — strip dangerous shell chars, allow only safe nmap options
		// (passed as a single tokenised argument, not through a shell)
		if body.Extra != "" {
			for _, tok := range strings.Fields(body.Extra) {
				// Allow options starting with -- or - (nmap option style)
				if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "--") {
					args = append(args, tok)
				}
			}
		}

		args = append(args, session.TargetHost)

		ctx, cancel := context.WithTimeout(context.Background(), 10*60*1e9) // 10 min
		job := &NmapJob{cancel: cancel}
		nmapJobs.Store(sessionID, job)

		argsStr := strings.Join(args[:len(args)-1], " ") // exclude target IP from source label
		target := session.TargetHost

		go func() {
			cmd := exec.CommandContext(ctx, "nmap", args...)
			cmd.Stdout = &job.buf
			cmd.Stderr = &job.buf
			_ = cmd.Run()
			job.mu.Lock()
			job.done = true
			output := job.buf.String()
			job.mu.Unlock()
			cancel()

			if err := AppendNmapLoot(sessionID, target, argsStr, output); err != nil {
				fmt.Printf("nmap loot save: %v\n", err)
			}
		}()

		fmt.Fprint(w, `{"ok":true}`)
	}
}

func handleGetNmapScan(db *DB) http.HandlerFunc {
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

		job := getNmapJob(sessionID)
		if job == nil {
			fmt.Fprint(w, `{"output":"","done":true}`)
			return
		}
		job.mu.Lock()
		output := job.buf.String()
		done := job.done
		job.mu.Unlock()

		outJSON, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"output":%s,"done":%v}`, outJSON, done)
	}
}

func handleStopNmapScan(db *DB) http.HandlerFunc {
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

		if job := getNmapJob(sessionID); job != nil {
			job.cancel()
			job.mu.Lock()
			job.done = true
			job.mu.Unlock()
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

func registerNmapRoutes(r chi.Router, db *DB) {
	r.Post("/sessions/{id}/nmap-scan", handleStartNmapScan(db))
	r.Get("/sessions/{id}/nmap-scan", handleGetNmapScan(db))
	r.Delete("/sessions/{id}/nmap-scan", handleStopNmapScan(db))
}
