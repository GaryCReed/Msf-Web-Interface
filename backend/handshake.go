package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// handshakeDir is set by initHandshakeDir() during startup.
// It is placed next to the binary (via baseDir) so it survives reboots
// and app restarts — files are only removed when the user explicitly deletes them.
var handshakeDir string

type HandshakeEntry struct {
	mu         sync.Mutex
	Name       string    `json:"name"`        // sanitised stored name
	OrigName   string    `json:"orig_name"`   // original filename from upload
	Size       int64     `json:"size"`
	Status     string    `json:"status"`      // "processing"|"valid"|"invalid"
	HashFile   string    `json:"hash_file"`   // .22000 filename (when valid)
	Networks   int       `json:"networks"`    // number of WPA hashes extracted
	UploadedAt time.Time `json:"uploaded_at"`
	ErrMsg     string    `json:"error,omitempty"`
}

var (
	handshakesMu   sync.RWMutex
	handshakesLog  []*HandshakeEntry // ordered for listing
	handshakesIdx  = map[string]*HandshakeEntry{} // name → entry
)

// initHandshakeDir sets the persistent storage directory and restores the
// in-memory registry from any files already on disk (e.g. after a restart).
func initHandshakeDir(dir string) {
	handshakeDir = dir
	os.MkdirAll(handshakeDir, 0o755)
	restoreHandshakesFromDisk()
}

func restoreHandshakesFromDisk() {
	entries, err := os.ReadDir(handshakeDir)
	if err != nil {
		return
	}
	handshakesMu.Lock()
	defer handshakesMu.Unlock()

	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		// Only restore .cap files; .22000 files are linked from their cap entry.
		if !strings.HasSuffix(name, ".cap") {
			continue
		}
		if _, exists := handshakesIdx[name]; exists {
			continue // already registered (shouldn't happen on fresh start)
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		entry := &HandshakeEntry{
			Name:       name,
			OrigName:   name,
			Size:       info.Size(),
			UploadedAt: info.ModTime(),
		}
		hashName := name + ".22000"
		hashPath := filepath.Join(handshakeDir, hashName)
		if hashInfo, statErr := os.Stat(hashPath); statErr == nil && hashInfo.Size() > 0 {
			data, _ := os.ReadFile(hashPath)
			count := 0
			for _, line := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
			entry.Status = "valid"
			entry.HashFile = hashName
			entry.Networks = count
		} else {
			// No hash file yet — attempt conversion in the background.
			entry.Status = "processing"
			go processHandshake(entry)
		}
		handshakesLog = append(handshakesLog, entry)
		handshakesIdx[name] = entry
	}
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// registerCapturedHandshake copies a live-captured .cap file into the handshake
// library and runs hcxpcapngtool on it, making it immediately available in the
// Wifi Handshakes tab without the user having to re-upload it manually.
func registerCapturedHandshake(capPath, label string) {
	name := sanitiseName(label + ".cap")

	handshakesMu.Lock()
	name = uniqueName(name)
	dst := filepath.Join(handshakeDir, name)
	if err := copyFile(capPath, dst); err != nil {
		handshakesMu.Unlock()
		return
	}
	info, _ := os.Stat(dst)
	var size int64
	if info != nil {
		size = info.Size()
	}
	entry := &HandshakeEntry{
		Name:       name,
		OrigName:   label + ".cap",
		Size:       size,
		Status:     "processing",
		UploadedAt: time.Now(),
	}
	handshakesLog = append(handshakesLog, entry)
	handshakesIdx[name] = entry
	handshakesMu.Unlock()

	go processHandshake(entry)
}

// processHandshake runs hcxpcapngtool on the uploaded capture file.
// It updates the entry in place and is designed to be called in a goroutine.
func processHandshake(entry *HandshakeEntry) {
	capPath := filepath.Join(handshakeDir, entry.Name)
	hashName := entry.Name + ".22000"
	hashPath := filepath.Join(handshakeDir, hashName)

	out, err := exec.Command("hcxpcapngtool", "-o", hashPath, capPath).CombinedOutput()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if err != nil {
		// hcxpcapngtool returns non-zero when no networks found — check file first
		_ = out
	}

	info, statErr := os.Stat(hashPath)
	if statErr != nil || info.Size() == 0 {
		// No output file or empty → no valid handshake
		os.Remove(hashPath)
		entry.Status = "invalid"
		if err != nil {
			entry.ErrMsg = strings.TrimSpace(string(out))
		}
		return
	}

	// Count networks: each non-empty line is one WPA hash
	data, _ := os.ReadFile(hashPath)
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	entry.Status = "valid"
	entry.HashFile = hashName
	entry.Networks = count
}

// sanitiseName strips directory components and replaces unsafe chars.
func sanitiseName(orig string) string {
	base := filepath.Base(orig)
	// Keep only safe chars
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, base)
	if safe == "" || safe == "." {
		safe = "upload"
	}
	return safe
}

// uniqueName returns a name that doesn't collide with existing files.
func uniqueName(name string) string {
	candidate := name
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		if _, exists := handshakesIdx[candidate]; !exists {
			if _, err := os.Stat(filepath.Join(handshakeDir, candidate)); os.IsNotExist(err) {
				return candidate
			}
		}
		candidate = fmt.Sprintf("%s_%d%s", stem, i, ext)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleUploadHandshake() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		// 512 MB max total upload
		if err := r.ParseMultipartForm(512 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"failed to parse upload: %s"}`, err.Error())
			return
		}

		files := r.MultipartForm.File["files"]
		if len(files) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"no files provided"}`)
			return
		}

		var names []string

		handshakesMu.Lock()
		for _, fh := range files {
			name := sanitiseName(fh.Filename)
			name = uniqueName(name)

			f, err := fh.Open()
			if err != nil {
				continue
			}

			dst, err := os.Create(filepath.Join(handshakeDir, name))
			if err != nil {
				f.Close()
				continue
			}
			size, _ := io.Copy(dst, f)
			f.Close()
			dst.Close()

			entry := &HandshakeEntry{
				Name:       name,
				OrigName:   fh.Filename,
				Size:       size,
				Status:     "processing",
				UploadedAt: time.Now(),
			}
			handshakesLog = append(handshakesLog, entry)
			handshakesIdx[name] = entry
			names = append(names, name)

			go processHandshake(entry)
		}
		handshakesMu.Unlock()

		namesData, _ := encodeJSON(names)
		fmt.Fprintf(w, `{"uploaded":%s}`, namesData)
	}
}

func handleListHandshakes() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		type outEntry struct {
			Name       string    `json:"name"`
			OrigName   string    `json:"orig_name"`
			Size       int64     `json:"size"`
			Status     string    `json:"status"`
			HashFile   string    `json:"hash_file"`
			Networks   int       `json:"networks"`
			UploadedAt time.Time `json:"uploaded_at"`
			ErrMsg     string    `json:"error,omitempty"`
		}

		handshakesMu.RLock()
		out := make([]outEntry, len(handshakesLog))
		for i, e := range handshakesLog {
			e.mu.Lock()
			out[i] = outEntry{
				Name:       e.Name,
				OrigName:   e.OrigName,
				Size:       e.Size,
				Status:     e.Status,
				HashFile:   e.HashFile,
				Networks:   e.Networks,
				UploadedAt: e.UploadedAt,
				ErrMsg:     e.ErrMsg,
			}
			e.mu.Unlock()
		}
		handshakesMu.RUnlock()

		data, _ := encodeJSON(out)
		dirJSON, _ := encodeJSON(handshakeDir)
		fmt.Fprintf(w, `{"files":%s,"dir":%s}`, data, dirJSON)
	}
}

func handleDownloadHandshake() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		name := chi.URLParam(r, "name")
		// Accept either the stored .22000 name or the original cap name
		if !strings.HasSuffix(name, ".22000") {
			name = name + ".22000"
		}
		// Sanitise to prevent directory traversal
		name = filepath.Base(name)
		path := filepath.Join(handshakeDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"file not found"}`)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, path)
	}
}

func handleDeleteHandshake() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		name := filepath.Base(chi.URLParam(r, "name"))

		handshakesMu.Lock()
		entry, ok := handshakesIdx[name]
		if ok {
			delete(handshakesIdx, name)
			for i, e := range handshakesLog {
				if e.Name == name {
					handshakesLog = append(handshakesLog[:i], handshakesLog[i+1:]...)
					break
				}
			}
		}
		handshakesMu.Unlock()

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}

		os.Remove(filepath.Join(handshakeDir, name))
		if entry.HashFile != "" {
			os.Remove(filepath.Join(handshakeDir, entry.HashFile))
		}
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}
