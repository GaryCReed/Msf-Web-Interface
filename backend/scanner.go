package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ScanResult represents a discovered host on the network.
type ScanResult struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

// CVEResult pairs a CVE ID with the Metasploit modules that reference it
// and the list of target hosts where the CVE was found.
type CVEResult struct {
	CVE     string   `json:"cve"`
	Modules []string `json:"modules"`
	Targets []string `json:"targets,omitempty"`
}

// scanXMLPath returns the path where an nmap XML report for a target IP is stored.
func scanXMLPath(ip string) string {
	safe := strings.NewReplacer(":", "-", "/", "-", " ", "_").Replace(ip)
	return filepath.Join("/tmp/msf-scans", safe+".xml")
}

// scanOutputPath returns the path where the nmap text output is persisted.
func scanOutputPath(ip string) string {
	safe := strings.NewReplacer(":", "-", "/", "-", " ", "_").Replace(ip)
	return filepath.Join("/tmp/msf-scans", safe+"-output.txt")
}

// activeScan tracks hosts that have a scan currently in progress.
var activeScan sync.Map // key: targetHost (string), value: struct{}

// LocalInterface describes an active IPv4 network adapter.
type LocalInterface struct {
	Name string `json:"name"` // e.g. "eth0", "wlan0"
	CIDR string `json:"cidr"` // e.g. "192.168.1.5/24"
	IP   string `json:"ip"`   // e.g. "192.168.1.5"
}

// getLocalInterfaces returns all active non-loopback IPv4 adapters with name, CIDR, and IP.
func getLocalInterfaces() []LocalInterface {
	var ifaces []LocalInterface
	netIfaces, err := net.Interfaces()
	if err != nil {
		return ifaces
	}
	for _, iface := range netIfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				ifaces = append(ifaces, LocalInterface{
					Name: iface.Name,
					CIDR: ipNet.String(),
					IP:   ipNet.IP.String(),
				})
			}
		}
	}
	return ifaces
}

// getLocalNetworks returns CIDR strings for all active non-loopback IPv4 interfaces.
func getLocalNetworks() []string {
	ifaces := getLocalInterfaces()
	cidrs := make([]string, len(ifaces))
	for i, iface := range ifaces {
		cidrs[i] = iface.CIDR
	}
	return cidrs
}

// getLocalIPs returns the host IPs (without prefix length) of all active non-loopback IPv4 interfaces.
func getLocalIPs() map[string]bool {
	ips := map[string]bool{}
	for _, iface := range getLocalInterfaces() {
		ips[iface.IP] = true
	}
	return ips
}

// systemGateway returns the gateway IP for the network being scanned.
// On multi-homed machines (physical NIC + Docker + VPN) the default route
// belongs to a different subnet, so we only accept a routing-table result
// when the gateway IP actually falls inside the CIDR we are scanning.
func systemGateway(cidr string) string {
	_, network, _ := net.ParseCIDR(cidr)

	// Returns true when gw is a valid IPv4 address inside our target subnet.
	inSubnet := func(gw string) bool {
		ip := net.ParseIP(gw)
		return ip != nil && network != nil && network.Contains(ip)
	}

	reVia := regexp.MustCompile(`via (\d+\.\d+\.\d+\.\d+)`)

	// 1. Ask the kernel for the specific route to this network.
	//    e.g. "ip route show 172.19.0.0/16" — matches the exact interface route.
	if network != nil {
		if out, err := exec.Command("ip", "route", "show", network.String()).Output(); err == nil {
			if m := reVia.FindSubmatch(out); m != nil {
				if gw := string(m[1]); inSubnet(gw) {
					return gw
				}
			}
		}
	}

	// 2. Default route — only use it when the gateway is inside our subnet.
	//    Ignored on multi-homed machines where the default points elsewhere.
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		re := regexp.MustCompile(`default via (\d+\.\d+\.\d+\.\d+)`)
		if m := re.FindSubmatch(out); m != nil {
			if gw := string(m[1]); inSubnet(gw) {
				return gw
			}
		}
	}

	// 3. Fallback: derive x.x.x.1 from the host IP in the CIDR.
	//    Works for Docker bridges, VLANs, and any network where the gateway
	//    is conventionally the first host address.
	base := strings.SplitN(cidr, "/", 2)[0]
	octets := strings.Split(base, ".")
	if len(octets) == 4 {
		octets[3] = "1"
		return strings.Join(octets, ".")
	}
	return ""
}

// parseNmapHosts parses nmap text output and returns discovered hosts,
// skipping any IPs in the localIPs set.
func parseNmapHosts(out []byte, localIPs map[string]bool) []ScanResult {
	re := regexp.MustCompile(`Nmap scan report for (.+)`)
	var results []ScanResult
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := re.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		host := strings.TrimSpace(m[1])
		r := ScanResult{}
		if idx := strings.Index(host, " ("); idx != -1 {
			r.Hostname = host[:idx]
			r.IP = strings.TrimSuffix(host[idx+2:], ")")
		} else {
			r.IP = host
		}
		if localIPs[r.IP] {
			continue
		}
		results = append(results, r)
	}
	return results
}

func scanNetwork(cidr string) ([]ScanResult, error) {
	cmd := exec.Command("nmap", "-sn",
		"-PE", "-PP",
		"-PS21,22,23,25,53,80,110,443,445,3389,8080,8443",
		"-PA80,443",
		"-T4",
		cidr,
	)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, err
	}

	localIPs := getLocalIPs()
	results := parseNmapHosts(out, localIPs)

	// Always ensure the gateway/first-host appears in results.
	// The !localIPs[gw] guard is intentionally absent: on Docker-host setups
	// the bridge IP (e.g. 172.19.0.1) is a local interface but is also a
	// valid scan target running services.  We want it visible regardless.
	gw := systemGateway(cidr)
	if gw != "" {
		alreadyFound := false
		for _, r := range results {
			if r.IP == gw {
				alreadyFound = true
				break
			}
		}
		if !alreadyFound {
			// Use -Pn so nmap reports the host regardless of ICMP filtering.
			gwCmd := exec.Command("nmap", "-sn", "-Pn",
				"-PS22,23,80,443,8080,8443,8888",
				"-PA80,443",
				"--max-retries", "1", "-T4", gw,
			)
			gwOut, _ := gwCmd.Output()
			// parseNmapHosts filters localIPs, so if gw is local it returns
			// empty — fall through to the unconditional force-add below.
			gwHosts := parseNmapHosts(gwOut, localIPs)
			if len(gwHosts) > 0 {
				results = append(gwHosts, results...)
			} else {
				// Force-add: gateway must exist for the network to function,
				// even when it is the scanning machine's own bridge/VPN IP.
				results = append([]ScanResult{{IP: gw, Hostname: "gateway"}}, results...)
			}
		}
	}

	if results == nil {
		results = []ScanResult{}
	}
	return results, nil
}

// vulnScan runs a verbose nmap service/OS/vuln scan and saves XML output to xmlPath.
// -O --osscan-guess enables OS detection (requires raw socket privileges on Linux).
// Verbose text output is returned; the XML file is written alongside it for later analysis.
func vulnScan(ctx context.Context, targetHost, xmlPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(xmlPath), 0o755); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx,
		"nmap", "-v", "-sV", "-O", "--osscan-guess", "--script=vuln,vulners", "-T4", "--max-retries", "2",
		"-p-",
		"-oX", xmlPath,
		targetHost,
	)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}

// parseNmapXML reads a saved nmap XML report and extracts all unique CVE IDs.
func parseNmapXML(xmlPath string) ([]string, error) {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, err
	}

	cveRe := regexp.MustCompile(`CVE-\d{4}-\d+`)
	seen := map[string]bool{}
	var cves []string
	for _, match := range cveRe.FindAllString(string(data), -1) {
		upper := strings.ToUpper(match)
		if !seen[upper] {
			seen[upper] = true
			cves = append(cves, upper)
		}
	}
	return cves, nil
}

// ServiceEnumResult pairs a discovered service with the MSF modules that target it.
type ServiceEnumResult struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	State    string   `json:"state"` // "open" or "filtered"
	Name     string   `json:"name"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Modules  []string `json:"modules"`
}

// nmapXML structs used for service enumeration and OS detection parsing.
type nmapRunXML struct {
	Hosts []nmapHostXML `xml:"host"`
}
type nmapHostXML struct {
	Ports []nmapPortXML `xml:"ports>port"`
	OS    nmapOSXML     `xml:"os"`
}
type nmapPortXML struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   int            `xml:"portid,attr"`
	State    nmapStateXML   `xml:"state"`
	Service  nmapServiceXML `xml:"service"`
}
type nmapStateXML struct {
	State string `xml:"state,attr"`
}
type nmapCPEXML struct {
	Value string `xml:",chardata"`
}
type nmapServiceXML struct {
	Name    string       `xml:"name,attr"`
	Product string       `xml:"product,attr"`
	Version string       `xml:"version,attr"`
	OSType  string       `xml:"ostype,attr"` // e.g. "Windows", "Linux"
	CPEs    []nmapCPEXML `xml:"cpe"`
}
type nmapOSXML struct {
	Matches []nmapOSMatchXML `xml:"osmatch"`
}
type nmapOSMatchXML struct {
	Name     string           `xml:"name,attr"`
	Accuracy int              `xml:"accuracy,attr"`
	Classes  []nmapOSClassXML `xml:"osclass"`
}
type nmapOSClassXML struct {
	OSFamily string       `xml:"osfamily,attr"`
	OSGen    string       `xml:"osgen,attr"`
	CPEs     []nmapCPEXML `xml:"cpe"`
}

// OSInfo holds the best OS match identified by nmap.
type OSInfo struct {
	Name     string `json:"name"`
	Family   string `json:"family"`   // e.g. "Linux", "Windows"
	OSGen    string `json:"os_gen"`   // e.g. "10", "2019", "3.X"
	Accuracy int    `json:"accuracy"` // 0–100
}

// osGenFromName extracts a Windows version token from a free-form nmap OS match name.
// e.g. "Microsoft Windows XP SP2 or SP3" → "XP", "Microsoft Windows 7 SP1" → "7"
func osGenFromName(name string) string {
	tokens := []string{
		"XP", "Vista",
		"2000", "2003", "2008", "2012", "2016", "2019", "2022",
		"11", "10", "8.1", "8", "7",
	}
	upper := strings.ToUpper(name)
	for _, tok := range tokens {
		pattern := `\b` + regexp.QuoteMeta(strings.ToUpper(tok)) + `\b`
		if matched, _ := regexp.MatchString(pattern, upper); matched {
			return tok
		}
	}
	return ""
}

// normalizeOSFamily maps nmap ostype/osfamily strings to canonical family names.
func normalizeOSFamily(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "mac os x", "macos":
		return "macOS"
	case "freebsd", "netbsd", "openbsd":
		return "BSD"
	default:
		if s != "" {
			return s
		}
		return ""
	}
}

// parseCPEOS extracts OS family and version from a CPE string.
// e.g. "cpe:/o:microsoft:windows_7" → ("Windows","7")
//      "cpe:/o:linux:linux_kernel:3" → ("Linux","3")
func parseCPEOS(cpe string) (family, gen string) {
	if !strings.HasPrefix(cpe, "cpe:/o:") {
		return "", ""
	}
	parts := strings.Split(cpe[7:], ":")
	if len(parts) == 0 {
		return "", ""
	}
	vendor := parts[0]
	switch vendor {
	case "microsoft":
		family = "Windows"
		if len(parts) >= 2 {
			gen = winGenFromCPEProduct(parts[1])
		}
	case "linux", "canonical", "debian", "redhat", "centos", "suse":
		family = "Linux"
		if len(parts) >= 3 {
			gen = parts[2]
		}
	case "apple":
		family = "macOS"
	case "freebsd", "netbsd", "openbsd":
		family = "BSD"
	}
	return
}

// winGenFromCPEProduct extracts a human-readable Windows version from a CPE product token.
// e.g. "windows_7" → "7", "windows_server_2019" → "2019", "windows_10" → "10"
func winGenFromCPEProduct(prod string) string {
	parts := strings.Split(prod, "_")
	// Walk tokens from the end; first numeric token (≥2 digits) wins.
	for i := len(parts) - 1; i >= 0; i-- {
		tok := parts[i]
		if strings.EqualFold(tok, "xp") {
			return "XP"
		}
		if strings.EqualFold(tok, "vista") {
			return "Vista"
		}
		if len(tok) >= 2 {
			if _, err := strconv.Atoi(tok); err == nil {
				return tok
			}
		}
	}
	return ""
}

// inferOSFromServices votes on OS family using service ostype attributes and CPE strings.
// Returns nil when no evidence is found.
func inferOSFromServices(run nmapRunXML) *OSInfo {
	votes := map[string]int{}
	genByFamily := map[string]string{}

	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			svc := port.Service
			if svc.OSType != "" {
				f := normalizeOSFamily(svc.OSType)
				if f != "" {
					votes[f]++
				}
			}
			for _, cpe := range svc.CPEs {
				f, g := parseCPEOS(cpe.Value)
				if f != "" {
					votes[f]++
					if g != "" && genByFamily[f] == "" {
						genByFamily[f] = g
					}
				}
			}
		}
	}

	if len(votes) == 0 {
		return nil
	}

	bestFamily, bestCount, total := "", 0, 0
	for f, c := range votes {
		total += c
		if c > bestCount {
			bestFamily, bestCount = f, c
		}
	}

	// Scale accuracy: unanimous → 90, majority → 70–89
	acc := 70
	if total > 0 {
		pct := bestCount * 100 / total
		acc = 70 + pct/10
		if acc > 90 {
			acc = 90
		}
	}

	return &OSInfo{
		Name:     "Inferred from services",
		Family:   bestFamily,
		OSGen:    genByFamily[bestFamily],
		Accuracy: acc,
	}
}

// parseNmapOS reads a saved nmap XML report and returns the best OS identification.
// Uses three sources in order of preference:
//  1. <osmatch> entries (highest detail, requires -O privilege)
//  2. service ostype attributes (very reliable, present without -O)
//  3. service CPE strings with cpe:/o: prefix
//
// Returns nil only when all three sources yield no data.
func parseNmapOS(xmlPath string) *OSInfo {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil
	}
	var run nmapRunXML
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}

	// --- Source 1: osmatch ---
	var best *OSInfo
	for _, host := range run.Hosts {
		for _, match := range host.OS.Matches {
			if best != nil && match.Accuracy <= best.Accuracy {
				continue
			}
			family, osgen := "", ""
			for _, cls := range match.Classes {
				if family == "" && cls.OSFamily != "" {
					family = normalizeOSFamily(cls.OSFamily)
				}
				if osgen == "" && cls.OSGen != "" {
					osgen = cls.OSGen
				}
				// Pull osgen from CPE if still empty
				if osgen == "" {
					for _, cpe := range cls.CPEs {
						_, g := parseCPEOS(cpe.Value)
						if g != "" {
							osgen = g
							break
						}
					}
				}
				if family != "" && osgen != "" {
					break
				}
			}
			if osgen == "" && match.Name != "" {
				osgen = osGenFromName(match.Name)
			}
			best = &OSInfo{
				Name:     match.Name,
				Family:   family,
				OSGen:    osgen,
				Accuracy: match.Accuracy,
			}
		}
	}

	// --- Sources 2 & 3: service ostype + CPE ---
	svcBased := inferOSFromServices(run)

	switch {
	case best == nil:
		// No osmatch data at all — rely entirely on service inference.
		return svcBased

	case svcBased == nil:
		// No service evidence — osmatch only.
		return best

	default:
		// Both sources available: combine them.
		if best.Family == "" {
			best.Family = svcBased.Family
		}
		if best.OSGen == "" {
			best.OSGen = svcBased.OSGen
		}
		// Boost osmatch accuracy when service evidence agrees.
		if strings.EqualFold(best.Family, svcBased.Family) && best.Accuracy < 95 {
			boosted := best.Accuracy + 5
			if boosted > 95 {
				boosted = 95
			}
			best.Accuracy = boosted
		}
		// Override osmatch when it's low-confidence but service evidence strongly disagrees.
		if best.Accuracy < 70 && svcBased.Accuracy >= 80 &&
			!strings.EqualFold(best.Family, svcBased.Family) {
			return svcBased
		}
		return best
	}
}

// parseNmapServices reads a saved nmap XML report and returns each unique open/filtered port
// along with MSF modules. osFamily ("linux", "windows", "") filters module search paths.
func parseNmapServices(xmlPath, osFamily string) ([]ServiceEnumResult, error) {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, err
	}

	var run nmapRunXML
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []ServiceEnumResult

	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			state := port.State.State
			if state != "open" && state != "filtered" {
				continue
			}
			key := strings.Join([]string{strconv.Itoa(port.PortID), port.Protocol}, "/")
			if seen[key] {
				continue
			}
			seen[key] = true

			// Only search for MSF modules on open ports; filtered ports have uncertain service info.
			var modules []string
			if state == "open" {
				modules = findMsfModulesForService(port.Service.Name, port.Service.Product, osFamily)
			} else {
				modules = []string{}
			}
			results = append(results, ServiceEnumResult{
				Port:     port.PortID,
				Protocol: port.Protocol,
				State:    state,
				Name:     port.Service.Name,
				Product:  port.Service.Product,
				Version:  port.Service.Version,
				Modules:  modules,
			})
		}
	}
	if results == nil {
		results = []ServiceEnumResult{}
	}
	return results, nil
}

// serviceSearchTerm derives the most useful grep keyword from a service product/name pair.
// Returns "" when the term would be too generic to be meaningful.
func serviceSearchTerm(serviceName, product string) string {
	if product != "" {
		words := strings.Fields(strings.ToLower(product))
		if len(words) > 0 {
			switch words[0] {
			case "microsoft":
				if len(words) >= 2 {
					switch words[1] {
					case "sql":
						return "mssql"
					case "iis":
						return "iis"
					case "exchange":
						return "exchange"
					default:
						if len(words) >= 3 && len(words[2]) >= 3 {
							return words[2]
						}
					}
				}
			default:
				if len(words[0]) >= 3 {
					return words[0]
				}
			}
		}
	}

	sn := strings.ToLower(serviceName)
	switch sn {
	case "ms-wbt-server":
		return "rdp"
	case "netbios-ssn", "microsoft-ds":
		return "smb"
	case "http", "http-alt", "http-proxy", "https", "ssl", "tcpwrapped", "unknown", "":
		return ""
	}
	return sn
}

// findMsfModulesForService searches MSF modules for files referencing the service.
// osFamily ("linux", "windows", "") restricts exploit search to OS-specific subdirs.
func findMsfModulesForService(serviceName, product, osFamily string) []string {
	term := serviceSearchTerm(serviceName, product)
	if term == "" {
		return []string{}
	}

	var exploitDirs []string
	switch strings.ToLower(osFamily) {
	case "linux":
		exploitDirs = []string{
			"/usr/share/metasploit-framework/modules/exploits/linux",
			"/usr/share/metasploit-framework/modules/exploits/unix",
			"/usr/share/metasploit-framework/modules/exploits/multi",
		}
	case "windows":
		exploitDirs = []string{
			"/usr/share/metasploit-framework/modules/exploits/windows",
			"/usr/share/metasploit-framework/modules/exploits/multi",
		}
	default:
		exploitDirs = []string{
			"/usr/share/metasploit-framework/modules/exploits",
		}
	}
	searchDirs := append(exploitDirs,
		"/usr/share/metasploit-framework/modules/auxiliary/scanner",
	)

	seen := map[string]bool{}
	var modules []string

	for _, dir := range searchDirs {
		cmd := exec.Command("grep", "-rl", "--include=*.rb", "-i", term, dir)
		out, _ := cmd.Output()
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			mod := filePathToMsfModule(line)
			if !seen[mod] {
				seen[mod] = true
				modules = append(modules, mod)
			}
			if len(modules) >= 30 {
				goto done
			}
		}
	}
done:
	if modules == nil {
		modules = []string{}
	}
	return modules
}

// findMsfModules searches the Metasploit module tree for files referencing the given CVE ID.
func findMsfModules(cveID string) []string {
	searchDirs := []string{
		"/usr/share/metasploit-framework/modules/exploits",
		"/usr/share/metasploit-framework/modules/auxiliary",
		"/usr/share/metasploit-framework/modules/post",
	}

	var modules []string
	for _, dir := range searchDirs {
		cmd := exec.Command("grep", "-rl", "--include=*.rb", "-i", cveID, dir)
		out, _ := cmd.Output()
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			modules = append(modules, filePathToMsfModule(line))
		}
	}
	if modules == nil {
		modules = []string{}
	}
	return modules
}

// filePathToMsfModule converts an absolute .rb path to a use-ready module name.
// e.g. /usr/share/metasploit-framework/modules/exploits/multi/http/foo.rb → exploit/multi/http/foo
func filePathToMsfModule(path string) string {
	const prefix = "/usr/share/metasploit-framework/modules/"
	trimmed := strings.TrimPrefix(path, prefix)
	trimmed = strings.TrimSuffix(trimmed, ".rb")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 {
		return trimmed
	}
	switch parts[0] {
	case "exploits":
		return "exploit/" + parts[1]
	case "auxiliary":
		return "auxiliary/" + parts[1]
	case "post":
		return "post/" + parts[1]
	case "payloads":
		return "payload/" + parts[1]
	default:
		return trimmed
	}
}
