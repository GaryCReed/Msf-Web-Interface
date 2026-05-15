package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// startFTPServer binds an upload-only FTP server on the given port.
// Accepted files must end in .cap; they are written to handshakeDir and
// immediately queued for hcxpcapngtool processing so they appear in the
// Wifi Handshakes tab automatically.
// Authentication reuses the same Linux PAM stack as the web login.
func startFTPServer(port int) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("FTP server: failed to bind %s: %v", addr, err)
		return
	}
	log.Printf("FTP server listening on %s (upload .cap files to handshakes dir)", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("FTP accept error: %v", err)
			continue
		}
		go handleFTPConn(conn)
	}
}

// ── Per-connection session ────────────────────────────────────────────────────

type ftpSession struct {
	ctrl          net.Conn
	r             *bufio.Reader
	authenticated bool
	username      string
	pasvLn        net.Listener
}

func handleFTPConn(ctrl net.Conn) {
	defer ctrl.Close()
	s := &ftpSession{ctrl: ctrl, r: bufio.NewReader(ctrl)}
	s.send("220 BagaHoldin FTP — upload .cap files only.\r\n")
	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(strings.TrimSpace(parts[0]))
		arg := ""
		if len(parts) > 1 {
			arg = strings.TrimSpace(parts[1])
		}
		if !s.dispatch(cmd, arg) {
			return
		}
	}
}

func (s *ftpSession) send(msg string) {
	s.ctrl.Write([]byte(msg)) //nolint:errcheck
}

func (s *ftpSession) dispatch(cmd, arg string) (keepAlive bool) {
	switch cmd {
	case "USER":
		s.username = arg
		s.authenticated = false
		s.send("331 Password required.\r\n")

	case "PASS":
		if s.username == "" {
			s.send("503 USER first.\r\n")
			return true
		}
		if authenticateLinuxUser(s.username, arg) == nil {
			s.authenticated = true
			s.send("230 Logged in.\r\n")
		} else {
			s.send("530 Login incorrect.\r\n")
		}

	case "SYST":
		s.send("215 UNIX Type: L8.\r\n")

	case "FEAT":
		s.send("211-Features:\r\n211 End.\r\n")

	case "NOOP":
		s.send("200 OK.\r\n")

	case "QUIT":
		s.send("221 Goodbye.\r\n")
		if s.pasvLn != nil {
			s.pasvLn.Close()
		}
		return false

	case "TYPE":
		s.send("200 Type set.\r\n")

	case "MODE":
		s.send("200 Mode set.\r\n")

	case "STRU":
		s.send("200 Structure set.\r\n")

	case "PWD", "XPWD":
		s.send("257 \"/\" is the current directory.\r\n")

	case "CWD", "XCWD":
		s.send("250 Directory changed to /.\r\n")

	case "CDUP":
		s.send("250 Directory changed to /.\r\n")

	case "PASV":
		if !s.authenticated {
			s.send("530 Not logged in.\r\n")
			return true
		}
		s.openPASV()

	case "STOR":
		if !s.authenticated {
			s.send("530 Not logged in.\r\n")
			return true
		}
		s.handleSTOR(arg)

	case "LIST", "NLST", "MLSD":
		if !s.authenticated {
			s.send("530 Not logged in.\r\n")
			return true
		}
		s.send("150 Opening data connection.\r\n")
		if dc := s.dataConn(); dc != nil {
			dc.Close()
		}
		s.send("226 Transfer complete.\r\n")

	case "EPSV":
		// Extended passive — some clients send this first.
		if !s.authenticated {
			s.send("530 Not logged in.\r\n")
			return true
		}
		s.openEPSV()

	default:
		s.send("502 Command not implemented.\r\n")
	}
	return true
}

// ── Passive data connection ───────────────────────────────────────────────────

func (s *ftpSession) openPASV() {
	if s.pasvLn != nil {
		s.pasvLn.Close()
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		s.send("425 Cannot open data connection.\r\n")
		return
	}
	s.pasvLn = ln

	port := ln.Addr().(*net.TCPAddr).Port

	// Derive host from the control connection's local address.
	localHost, _, _ := net.SplitHostPort(s.ctrl.LocalAddr().String())
	ip := net.ParseIP(localHost).To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1).To4()
	}
	s.send(fmt.Sprintf("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).\r\n",
		ip[0], ip[1], ip[2], ip[3], port/256, port%256))
}

func (s *ftpSession) openEPSV() {
	if s.pasvLn != nil {
		s.pasvLn.Close()
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		s.send("425 Cannot open data connection.\r\n")
		return
	}
	s.pasvLn = ln
	port := ln.Addr().(*net.TCPAddr).Port
	s.send(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|).\r\n", port))
}

func (s *ftpSession) dataConn() net.Conn {
	if s.pasvLn == nil {
		return nil
	}
	if tcpLn, ok := s.pasvLn.(*net.TCPListener); ok {
		tcpLn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	}
	conn, err := s.pasvLn.Accept()
	s.pasvLn.Close()
	s.pasvLn = nil
	if err != nil {
		return nil
	}
	return conn
}

// ── File upload ───────────────────────────────────────────────────────────────

func (s *ftpSession) handleSTOR(filename string) {
	if handshakeDir == "" {
		s.send("550 Handshake storage not initialised.\r\n")
		return
	}

	name := sanitiseName(filepath.Base(filename))
	if !strings.HasSuffix(strings.ToLower(name), ".cap") {
		s.send("550 Only .cap files are accepted.\r\n")
		return
	}

	dc := s.dataConn()
	if dc == nil {
		s.send("425 Cannot open data connection.\r\n")
		return
	}
	defer dc.Close()

	handshakesMu.Lock()
	name = uniqueName(name)
	dstPath := filepath.Join(handshakeDir, name)
	dst, err := os.Create(dstPath)
	if err != nil {
		handshakesMu.Unlock()
		s.send("550 Cannot create file.\r\n")
		return
	}

	s.send("150 File accepted; transfer starting.\r\n")

	size, copyErr := io.Copy(dst, dc)
	dst.Close()

	if copyErr != nil || size == 0 {
		handshakesMu.Unlock()
		os.Remove(dstPath)
		s.send("426 Transfer aborted or empty file.\r\n")
		return
	}

	entry := &HandshakeEntry{
		Name:       name,
		OrigName:   filepath.Base(filename),
		Size:       size,
		Status:     "processing",
		UploadedAt: time.Now(),
	}
	handshakesLog = append(handshakesLog, entry)
	handshakesIdx[name] = entry
	handshakesMu.Unlock()

	go processHandshake(entry)

	log.Printf("FTP: %s uploaded %s (%d bytes)", s.username, name, size)
	s.send("226 Transfer complete.\r\n")
}
