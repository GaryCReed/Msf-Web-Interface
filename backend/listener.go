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

type ListenerJob struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	done   bool
	port   string
	cancel context.CancelFunc
}

var listenerJobs sync.Map // port string → *ListenerJob

func getListenerJob(port string) *ListenerJob {
	v, ok := listenerJobs.Load(port)
	if !ok {
		return nil
	}
	return v.(*ListenerJob)
}

// POST /api/listeners  — start nc -lvnp <port>
func handleStartListener() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		var body struct {
			Port string `json:"port"`
		}
		parseJSON(r, &body)

		port := strings.TrimSpace(body.Port)
		if port == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"port required"}`)
			return
		}
		// validate: digits only, 1–65535
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid port"}`)
			return
		}

		if j := getListenerJob(port); j != nil {
			j.mu.Lock()
			running := !j.done
			j.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"listener already running on that port"}`)
				return
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*60*1e9) // 1 h max
		job := &ListenerJob{cancel: cancel, port: port}
		listenerJobs.Store(port, job)

		go func() {
			cmd := exec.CommandContext(ctx, "nc", "-lvnp", port)
			cmd.Stdout = &job.buf
			cmd.Stderr = &job.buf
			_ = cmd.Run()
			job.mu.Lock()
			job.done = true
			job.mu.Unlock()
			cancel()
		}()

		fmt.Fprint(w, `{"ok":true}`)
	}
}

// GET /api/listeners/{port}
func handleGetListener() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		port := chi.URLParam(r, "port")
		job := getListenerJob(port)
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

// DELETE /api/listeners/{port}
func handleStopListener() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		port := chi.URLParam(r, "port")
		if j := getListenerJob(port); j != nil {
			j.cancel()
			j.mu.Lock()
			j.done = true
			j.mu.Unlock()
		}
		fmt.Fprint(w, `{"ok":true}`)
	}
}

// GET /api/listeners — list all known listeners with their status
func handleListListeners() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		type entry struct {
			Port string `json:"port"`
			Done bool   `json:"done"`
		}
		var list []entry
		listenerJobs.Range(func(k, v any) bool {
			j := v.(*ListenerJob)
			j.mu.Lock()
			done := j.done
			j.mu.Unlock()
			list = append(list, entry{Port: k.(string), Done: done})
			return true
		})

		data, _ := encodeJSON(list)
		fmt.Fprintf(w, `{"listeners":%s}`, data)
	}
}
