package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ── Structs ───────────────────────────────────────────────────────────────────

type SMTPProfile struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	FromAddress string `json:"from_address"`
	FromName    string `json:"from_name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         string `json:"tls"` // none | starttls | tls
	CreatedAt   string `json:"created_at"`
}

type EmailTemplate struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	HTMLBody  string `json:"html_body"`
	TextBody  string `json:"text_body"`
	CreatedAt string `json:"created_at"`
}

type LandingPage struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	HTML               string `json:"html"`
	RedirectURL        string `json:"redirect_url"`
	CaptureCredentials bool   `json:"capture_credentials"`
	CreatedAt          string `json:"created_at"`
}

type TargetGroup struct {
	ID        int      `json:"id"`
	Name      string   `json:"name"`
	Targets   []Target `json:"targets,omitempty"`
	CreatedAt string   `json:"created_at"`
}

type Target struct {
	ID        int    `json:"id"`
	GroupID   int    `json:"group_id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Position  string `json:"position"`
}

type Campaign struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	SmtpID      int    `json:"smtp_id"`
	TemplateID  int    `json:"template_id"`
	PageID      int    `json:"page_id"`
	GroupID     int    `json:"group_id"`
	PhishURL    string `json:"phish_url"`
	LaunchDate  string `json:"launch_date"`
	CreatedAt   string `json:"created_at"`
	CompletedAt string `json:"completed_at,omitempty"`
	// Computed summary counts
	Sent      int `json:"sent"`
	Opened    int `json:"opened"`
	Clicked   int `json:"clicked"`
	Submitted int `json:"submitted"`
}

type PhishResult struct {
	ID            int    `json:"id"`
	CampaignID    int    `json:"campaign_id"`
	RID           string `json:"rid"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Position      string `json:"position"`
	Status        string `json:"status"`
	SentAt        string `json:"sent_at,omitempty"`
	OpenedAt      string `json:"opened_at,omitempty"`
	ClickedAt     string `json:"clicked_at,omitempty"`
	SubmittedAt   string `json:"submitted_at,omitempty"`
	SubmittedData string `json:"submitted_data,omitempty"`
}

// ── DB helpers ────────────────────────────────────────────────────────────────

// SMTP profiles

func listSMTP(db *DB) ([]SMTPProfile, error) {
	rows, err := db.conn.Query(`SELECT id, name, from_address, from_name, host, port, username, password, tls, created_at FROM phish_smtp ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SMTPProfile
	for rows.Next() {
		var s SMTPProfile
		if err := rows.Scan(&s.ID, &s.Name, &s.FromAddress, &s.FromName, &s.Host, &s.Port, &s.Username, &s.Password, &s.TLS, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if out == nil {
		out = []SMTPProfile{}
	}
	return out, rows.Err()
}

func getSMTP(db *DB, id int) (*SMTPProfile, error) {
	s := &SMTPProfile{}
	err := db.conn.QueryRow(`SELECT id, name, from_address, from_name, host, port, username, password, tls, created_at FROM phish_smtp WHERE id = ?`, id).
		Scan(&s.ID, &s.Name, &s.FromAddress, &s.FromName, &s.Host, &s.Port, &s.Username, &s.Password, &s.TLS, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func createSMTP(db *DB, s SMTPProfile) (int64, error) {
	res, err := db.conn.Exec(`INSERT INTO phish_smtp (name, from_address, from_name, host, port, username, password, tls) VALUES (?,?,?,?,?,?,?,?)`,
		s.Name, s.FromAddress, s.FromName, s.Host, s.Port, s.Username, s.Password, s.TLS)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func updateSMTP(db *DB, s SMTPProfile) error {
	_, err := db.conn.Exec(`UPDATE phish_smtp SET name=?, from_address=?, from_name=?, host=?, port=?, username=?, password=?, tls=? WHERE id=?`,
		s.Name, s.FromAddress, s.FromName, s.Host, s.Port, s.Username, s.Password, s.TLS, s.ID)
	return err
}

func deleteSMTP(db *DB, id int) error {
	_, err := db.conn.Exec(`DELETE FROM phish_smtp WHERE id=?`, id)
	return err
}

// Email templates

func listTemplates(db *DB) ([]EmailTemplate, error) {
	rows, err := db.conn.Query(`SELECT id, name, subject, html_body, text_body, created_at FROM phish_templates ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EmailTemplate
	for rows.Next() {
		var t EmailTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Subject, &t.HTMLBody, &t.TextBody, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if out == nil {
		out = []EmailTemplate{}
	}
	return out, rows.Err()
}

func getTemplate(db *DB, id int) (*EmailTemplate, error) {
	t := &EmailTemplate{}
	err := db.conn.QueryRow(`SELECT id, name, subject, html_body, text_body, created_at FROM phish_templates WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.Subject, &t.HTMLBody, &t.TextBody, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func createTemplate(db *DB, t EmailTemplate) (int64, error) {
	res, err := db.conn.Exec(`INSERT INTO phish_templates (name, subject, html_body, text_body) VALUES (?,?,?,?)`,
		t.Name, t.Subject, t.HTMLBody, t.TextBody)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func updateTemplate(db *DB, t EmailTemplate) error {
	_, err := db.conn.Exec(`UPDATE phish_templates SET name=?, subject=?, html_body=?, text_body=? WHERE id=?`,
		t.Name, t.Subject, t.HTMLBody, t.TextBody, t.ID)
	return err
}

func deleteTemplate(db *DB, id int) error {
	_, err := db.conn.Exec(`DELETE FROM phish_templates WHERE id=?`, id)
	return err
}

// Landing pages

func listPages(db *DB) ([]LandingPage, error) {
	rows, err := db.conn.Query(`SELECT id, name, html, redirect_url, capture_credentials, created_at FROM phish_pages ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LandingPage
	for rows.Next() {
		var p LandingPage
		var cc int
		if err := rows.Scan(&p.ID, &p.Name, &p.HTML, &p.RedirectURL, &cc, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.CaptureCredentials = cc != 0
		out = append(out, p)
	}
	if out == nil {
		out = []LandingPage{}
	}
	return out, rows.Err()
}

func getPage(db *DB, id int) (*LandingPage, error) {
	p := &LandingPage{}
	var cc int
	err := db.conn.QueryRow(`SELECT id, name, html, redirect_url, capture_credentials, created_at FROM phish_pages WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.HTML, &p.RedirectURL, &cc, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	p.CaptureCredentials = cc != 0
	return p, nil
}

func createPage(db *DB, p LandingPage) (int64, error) {
	cc := 0
	if p.CaptureCredentials {
		cc = 1
	}
	res, err := db.conn.Exec(`INSERT INTO phish_pages (name, html, redirect_url, capture_credentials) VALUES (?,?,?,?)`,
		p.Name, p.HTML, p.RedirectURL, cc)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func updatePage(db *DB, p LandingPage) error {
	cc := 0
	if p.CaptureCredentials {
		cc = 1
	}
	_, err := db.conn.Exec(`UPDATE phish_pages SET name=?, html=?, redirect_url=?, capture_credentials=? WHERE id=?`,
		p.Name, p.HTML, p.RedirectURL, cc, p.ID)
	return err
}

func deletePage(db *DB, id int) error {
	_, err := db.conn.Exec(`DELETE FROM phish_pages WHERE id=?`, id)
	return err
}

// Groups & targets

func listGroups(db *DB) ([]TargetGroup, error) {
	rows, err := db.conn.Query(`SELECT id, name, created_at FROM phish_groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetGroup
	for rows.Next() {
		var g TargetGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if out == nil {
		out = []TargetGroup{}
	}
	return out, rows.Err()
}

func getGroup(db *DB, id int) (*TargetGroup, error) {
	g := &TargetGroup{}
	err := db.conn.QueryRow(`SELECT id, name, created_at FROM phish_groups WHERE id=?`, id).
		Scan(&g.ID, &g.Name, &g.CreatedAt)
	if err != nil {
		return nil, err
	}
	targets, err := getTargets(db, id)
	if err != nil {
		return nil, err
	}
	g.Targets = targets
	return g, nil
}

func getTargets(db *DB, groupID int) ([]Target, error) {
	rows, err := db.conn.Query(`SELECT id, group_id, first_name, last_name, email, position FROM phish_targets WHERE group_id=? ORDER BY id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.GroupID, &t.FirstName, &t.LastName, &t.Email, &t.Position); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if out == nil {
		out = []Target{}
	}
	return out, rows.Err()
}

func createGroup(db *DB, name string) (int64, error) {
	res, err := db.conn.Exec(`INSERT INTO phish_groups (name) VALUES (?)`, name)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func updateGroup(db *DB, id int, name string) error {
	_, err := db.conn.Exec(`UPDATE phish_groups SET name=? WHERE id=?`, name, id)
	return err
}

func deleteGroup(db *DB, id int) error {
	_, err := db.conn.Exec(`DELETE FROM phish_groups WHERE id=?`, id)
	return err
}

func insertTargets(db *DB, groupID int, targets []Target) error {
	for _, t := range targets {
		_, err := db.conn.Exec(`INSERT INTO phish_targets (group_id, first_name, last_name, email, position) VALUES (?,?,?,?,?)`,
			groupID, t.FirstName, t.LastName, t.Email, t.Position)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteTarget(db *DB, id int) error {
	_, err := db.conn.Exec(`DELETE FROM phish_targets WHERE id=?`, id)
	return err
}

// Campaigns

func listCampaigns(db *DB) ([]Campaign, error) {
	rows, err := db.conn.Query(`SELECT id, name, status, COALESCE(smtp_id,0), COALESCE(template_id,0), COALESCE(page_id,0), COALESCE(group_id,0), phish_url, COALESCE(launch_date,''), created_at, COALESCE(completed_at,'') FROM phish_campaigns ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Campaign
	for rows.Next() {
		var c Campaign
		if err := rows.Scan(&c.ID, &c.Name, &c.Status, &c.SmtpID, &c.TemplateID, &c.PageID, &c.GroupID, &c.PhishURL, &c.LaunchDate, &c.CreatedAt, &c.CompletedAt); err != nil {
			return nil, err
		}
		enrichCampaignCounts(db, &c)
		out = append(out, c)
	}
	if out == nil {
		out = []Campaign{}
	}
	return out, rows.Err()
}

func getCampaign(db *DB, id int) (*Campaign, error) {
	c := &Campaign{}
	err := db.conn.QueryRow(`SELECT id, name, status, COALESCE(smtp_id,0), COALESCE(template_id,0), COALESCE(page_id,0), COALESCE(group_id,0), phish_url, COALESCE(launch_date,''), created_at, COALESCE(completed_at,'') FROM phish_campaigns WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &c.Status, &c.SmtpID, &c.TemplateID, &c.PageID, &c.GroupID, &c.PhishURL, &c.LaunchDate, &c.CreatedAt, &c.CompletedAt)
	if err != nil {
		return nil, err
	}
	enrichCampaignCounts(db, c)
	return c, nil
}

func enrichCampaignCounts(db *DB, c *Campaign) {
	db.conn.QueryRow(`SELECT COUNT(*) FROM phish_results WHERE campaign_id=? AND status NOT IN ('pending','error')`, c.ID).Scan(&c.Sent)       //nolint:errcheck
	db.conn.QueryRow(`SELECT COUNT(*) FROM phish_results WHERE campaign_id=? AND opened_at IS NOT NULL AND opened_at != ''`, c.ID).Scan(&c.Opened)    //nolint:errcheck
	db.conn.QueryRow(`SELECT COUNT(*) FROM phish_results WHERE campaign_id=? AND clicked_at IS NOT NULL AND clicked_at != ''`, c.ID).Scan(&c.Clicked)  //nolint:errcheck
	db.conn.QueryRow(`SELECT COUNT(*) FROM phish_results WHERE campaign_id=? AND submitted_at IS NOT NULL AND submitted_at != ''`, c.ID).Scan(&c.Submitted) //nolint:errcheck
}

func createCampaign(db *DB, c Campaign) (int64, error) {
	res, err := db.conn.Exec(`INSERT INTO phish_campaigns (name, status, smtp_id, template_id, page_id, group_id, phish_url, launch_date) VALUES (?,?,?,?,?,?,?,?)`,
		c.Name, "pending", nullableInt(c.SmtpID), nullableInt(c.TemplateID), nullableInt(c.PageID), nullableInt(c.GroupID), c.PhishURL, nullableStr(c.LaunchDate))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullableStr(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

func setCampaignStatus(db *DB, id int, status string) error {
	if status == "completed" {
		_, err := db.conn.Exec(`UPDATE phish_campaigns SET status=?, completed_at=CURRENT_TIMESTAMP WHERE id=?`, status, id)
		return err
	}
	_, err := db.conn.Exec(`UPDATE phish_campaigns SET status=? WHERE id=?`, status, id)
	return err
}

func deleteCampaign(db *DB, id int) error {
	_, err := db.conn.Exec(`DELETE FROM phish_campaigns WHERE id=?`, id)
	return err
}

// Results

func listResults(db *DB, campaignID int) ([]PhishResult, error) {
	rows, err := db.conn.Query(`SELECT id, campaign_id, rid, email, first_name, last_name, position, status, COALESCE(sent_at,''), COALESCE(opened_at,''), COALESCE(clicked_at,''), COALESCE(submitted_at,''), submitted_data FROM phish_results WHERE campaign_id=? ORDER BY id`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PhishResult
	for rows.Next() {
		var r PhishResult
		if err := rows.Scan(&r.ID, &r.CampaignID, &r.RID, &r.Email, &r.FirstName, &r.LastName, &r.Position, &r.Status, &r.SentAt, &r.OpenedAt, &r.ClickedAt, &r.SubmittedAt, &r.SubmittedData); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []PhishResult{}
	}
	return out, rows.Err()
}

func getResultByRID(db *DB, rid string) (*PhishResult, error) {
	r := &PhishResult{}
	err := db.conn.QueryRow(`SELECT id, campaign_id, rid, email, first_name, last_name, position, status, COALESCE(sent_at,''), COALESCE(opened_at,''), COALESCE(clicked_at,''), COALESCE(submitted_at,''), submitted_data FROM phish_results WHERE rid=?`, rid).
		Scan(&r.ID, &r.CampaignID, &r.RID, &r.Email, &r.FirstName, &r.LastName, &r.Position, &r.Status, &r.SentAt, &r.OpenedAt, &r.ClickedAt, &r.SubmittedAt, &r.SubmittedData)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func insertResult(db *DB, r PhishResult) error {
	_, err := db.conn.Exec(`INSERT INTO phish_results (campaign_id, rid, email, first_name, last_name, position, status) VALUES (?,?,?,?,?,?,?)`,
		r.CampaignID, r.RID, r.Email, r.FirstName, r.LastName, r.Position, r.Status)
	return err
}

func markResultSent(db *DB, rid string) {
	db.conn.Exec(`UPDATE phish_results SET status='sent', sent_at=CURRENT_TIMESTAMP WHERE rid=? AND status='pending'`, rid) //nolint:errcheck
}

func markResultError(db *DB, rid string) {
	db.conn.Exec(`UPDATE phish_results SET status='error' WHERE rid=? AND status='pending'`, rid) //nolint:errcheck
}

func markResultOpened(db *DB, rid string) {
	db.conn.Exec(`UPDATE phish_results SET status='opened', opened_at=CURRENT_TIMESTAMP WHERE rid=? AND opened_at='' AND status NOT IN ('clicked','submitted')`, rid) //nolint:errcheck
}

func markResultClicked(db *DB, rid string) {
	db.conn.Exec(`UPDATE phish_results SET status='clicked', clicked_at=CURRENT_TIMESTAMP WHERE rid=? AND clicked_at='' AND status NOT IN ('submitted')`, rid) //nolint:errcheck
}

func markResultSubmitted(db *DB, rid string, data string) {
	db.conn.Exec(`UPDATE phish_results SET status='submitted', submitted_at=CURRENT_TIMESTAMP, submitted_data=? WHERE rid=?`, data, rid) //nolint:errcheck
}

// ── RID generator ─────────────────────────────────────────────────────────────

func generateRID() string {
	b := make([]byte, 12)
	rand.Read(b) //nolint:errcheck
	return base64.RawURLEncoding.EncodeToString(b)
}

// ── Email sender ──────────────────────────────────────────────────────────────

type emailData struct {
	FirstName   string
	LastName    string
	Email       string
	Position    string
	From        string
	TrackingURL string
	Tracker     template.HTML
}

func renderTemplate(src string, d emailData) (string, error) {
	t, err := template.New("t").Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func sendPhishEmail(profile SMTPProfile, target Target, tmpl EmailTemplate, rid, phishURL string) error {
	clickURL := fmt.Sprintf("%s/t/click/%s", strings.TrimRight(phishURL, "/"), rid)
	openURL := fmt.Sprintf("%s/t/open/%s", strings.TrimRight(phishURL, "/"), rid)

	d := emailData{
		FirstName:   target.FirstName,
		LastName:    target.LastName,
		Email:       target.Email,
		Position:    target.Position,
		From:        fmt.Sprintf("%s <%s>", profile.FromName, profile.FromAddress),
		TrackingURL: clickURL,
		Tracker:     template.HTML(fmt.Sprintf(`<img src="%s" width="1" height="1" alt="" style="display:none" />`, openURL)),
	}

	subject, err := renderTemplate(tmpl.Subject, d)
	if err != nil {
		subject = tmpl.Subject
	}
	htmlBody, err := renderTemplate(tmpl.HTMLBody, d)
	if err != nil {
		htmlBody = tmpl.HTMLBody
	}
	textBody, err := renderTemplate(tmpl.TextBody, d)
	if err != nil {
		textBody = tmpl.TextBody
	}

	// Build MIME multipart message
	var msg bytes.Buffer
	from := mime.QEncoding.Encode("utf-8", profile.FromName) + " <" + profile.FromAddress + ">"
	msg.WriteString("From: " + from + "\r\n")
	msg.WriteString("To: " + target.Email + "\r\n")
	msg.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")

	mw := multipart.NewWriter(&msg)
	msg.WriteString("Content-Type: multipart/alternative; boundary=\"" + mw.Boundary() + "\"\r\n\r\n")

	if textBody != "" {
		pw, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}, "Content-Transfer-Encoding": {"base64"}})
		pw.Write([]byte(base64.StdEncoding.EncodeToString([]byte(textBody)))) //nolint:errcheck
	}
	if htmlBody != "" {
		pw, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=utf-8"}, "Content-Transfer-Encoding": {"base64"}})
		pw.Write([]byte(base64.StdEncoding.EncodeToString([]byte(htmlBody)))) //nolint:errcheck
	}
	mw.Close()

	addr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	switch profile.TLS {
	case "tls":
		tlsCfg := &tls.Config{ServerName: profile.Host, InsecureSkipVerify: false} //nolint:gosec
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("tls dial: %w", err)
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, profile.Host)
		if err != nil {
			return err
		}
		defer client.Close()
		if profile.Username != "" {
			if err := client.Auth(smtp.PlainAuth("", profile.Username, profile.Password, profile.Host)); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
		return doSMTPSend(client, profile.FromAddress, target.Email, msg.Bytes())

	case "starttls":
		client, err := smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		defer client.Close()
		tlsCfg := &tls.Config{ServerName: profile.Host} //nolint:gosec
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		if profile.Username != "" {
			if err := client.Auth(smtp.PlainAuth("", profile.Username, profile.Password, profile.Host)); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
		return doSMTPSend(client, profile.FromAddress, target.Email, msg.Bytes())

	default: // none
		var auth smtp.Auth
		if profile.Username != "" {
			auth = smtp.PlainAuth("", profile.Username, profile.Password, profile.Host)
		}
		return smtp.SendMail(addr, auth, profile.FromAddress, []string{target.Email}, msg.Bytes())
	}
}

func doSMTPSend(client *smtp.Client, from, to string, msg []byte) error {
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	_, err = wc.Write(msg)
	wc.Close()
	return err
}

// ── Campaign runner ───────────────────────────────────────────────────────────

func launchCampaign(db *DB, campaignID int) {
	campaign, err := getCampaign(db, campaignID)
	if err != nil {
		log.Printf("phishing: getCampaign %d: %v", campaignID, err)
		return
	}
	if err := setCampaignStatus(db, campaignID, "in-progress"); err != nil {
		log.Printf("phishing: set in-progress %d: %v", campaignID, err)
		return
	}

	profile, err := getSMTP(db, campaign.SmtpID)
	if err != nil {
		log.Printf("phishing: getSMTP %d: %v", campaign.SmtpID, err)
		setCampaignStatus(db, campaignID, "completed") //nolint:errcheck
		return
	}
	tmpl, err := getTemplate(db, campaign.TemplateID)
	if err != nil {
		log.Printf("phishing: getTemplate %d: %v", campaign.TemplateID, err)
		setCampaignStatus(db, campaignID, "completed") //nolint:errcheck
		return
	}
	targets, err := getTargets(db, campaign.GroupID)
	if err != nil {
		log.Printf("phishing: getTargets group %d: %v", campaign.GroupID, err)
		setCampaignStatus(db, campaignID, "completed") //nolint:errcheck
		return
	}

	for _, target := range targets {
		rid := generateRID()
		_ = insertResult(db, PhishResult{
			CampaignID: campaignID,
			RID:        rid,
			Email:      target.Email,
			FirstName:  target.FirstName,
			LastName:   target.LastName,
			Position:   target.Position,
			Status:     "pending",
		})

		if err := sendPhishEmail(*profile, target, *tmpl, rid, campaign.PhishURL); err != nil {
			log.Printf("phishing: send to %s: %v", target.Email, err)
			markResultError(db, rid)
		} else {
			markResultSent(db, rid)
		}
		time.Sleep(1 * time.Second)
	}

	setCampaignStatus(db, campaignID, "completed") //nolint:errcheck
	log.Printf("phishing: campaign %d completed (%d targets)", campaignID, len(targets))
}

// ── Authenticated API handlers ────────────────────────────────────────────────

// Sending profiles

func handleListSMTP(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		list, err := listSMTP(db)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"db error"}`)
			return
		}
		data, _ := encodeJSON(list)
		fmt.Fprintf(w, `{"profiles":%s}`, data)
	}
}

func handleCreateSMTP(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var s SMTPProfile
		if err := parseJSON(r, &s); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid json"}`)
			return
		}
		id, err := createSMTP(db, s)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		s.ID = int(id)
		data, _ := encodeJSON(s)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"profile":%s}`, data)
	}
}

func handleUpdateSMTP(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid id"}`)
			return
		}
		var s SMTPProfile
		if err := parseJSON(r, &s); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid json"}`)
			return
		}
		s.ID = id
		if err := updateSMTP(db, s); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		data, _ := encodeJSON(s)
		fmt.Fprintf(w, `{"profile":%s}`, data)
	}
}

func handleDeleteSMTP(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid id"}`)
			return
		}
		if err := deleteSMTP(db, id); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"db error"}`)
			return
		}
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}

func handleTestSMTP(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid id"}`)
			return
		}
		var req struct {
			To string `json:"to"`
		}
		if err := parseJSON(r, &req); err != nil || req.To == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"to address required"}`)
			return
		}
		profile, err := getSMTP(db, id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"profile not found"}`)
			return
		}
		testTarget := Target{Email: req.To, FirstName: "Test", LastName: "User"}
		testTmpl := EmailTemplate{
			Subject:  "BagaHoldin SMTP Test",
			HTMLBody: "<p>This is a test email from BagaHoldin. SMTP profile is working correctly.</p>",
			TextBody: "This is a test email from BagaHoldin. SMTP profile is working correctly.",
		}
		if err := sendPhishEmail(*profile, testTarget, testTmpl, "test", "http://localhost"); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		fmt.Fprint(w, `{"status":"sent"}`)
	}
}

// Email templates

func handleListTemplates(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		list, _ := listTemplates(db)
		data, _ := encodeJSON(list)
		fmt.Fprintf(w, `{"templates":%s}`, data)
	}
}

func handleCreateTemplate(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var t EmailTemplate
		if err := parseJSON(r, &t); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid json"}`)
			return
		}
		id, err := createTemplate(db, t)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		t.ID = int(id)
		data, _ := encodeJSON(t)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"template":%s}`, data)
	}
}

func handleUpdateTemplate(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		var t EmailTemplate
		parseJSON(r, &t) //nolint:errcheck
		t.ID = id
		updateTemplate(db, t) //nolint:errcheck
		data, _ := encodeJSON(t)
		fmt.Fprintf(w, `{"template":%s}`, data)
	}
}

func handleDeleteTemplate(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		deleteTemplate(db, id) //nolint:errcheck
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}

// Landing pages

func handleListPages(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		list, _ := listPages(db)
		data, _ := encodeJSON(list)
		fmt.Fprintf(w, `{"pages":%s}`, data)
	}
}

func handleCreatePage(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var p LandingPage
		if err := parseJSON(r, &p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid json"}`)
			return
		}
		id, err := createPage(db, p)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		p.ID = int(id)
		data, _ := encodeJSON(p)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"page":%s}`, data)
	}
}

func handleUpdatePage(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		var p LandingPage
		parseJSON(r, &p) //nolint:errcheck
		p.ID = id
		updatePage(db, p) //nolint:errcheck
		data, _ := encodeJSON(p)
		fmt.Fprintf(w, `{"page":%s}`, data)
	}
}

func handleDeletePage(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		deletePage(db, id) //nolint:errcheck
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}

// Groups & targets

func handleListGroups(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		list, _ := listGroups(db)
		data, _ := encodeJSON(list)
		fmt.Fprintf(w, `{"groups":%s}`, data)
	}
}

func handleGetGroup(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		g, err := getGroup(db, id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		data, _ := encodeJSON(g)
		fmt.Fprintf(w, `{"group":%s}`, data)
	}
}

func handleCreateGroup(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var req struct {
			Name    string   `json:"name"`
			Targets []Target `json:"targets"`
		}
		if err := parseJSON(r, &req); err != nil || req.Name == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"name required"}`)
			return
		}
		id, err := createGroup(db, req.Name)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"db error"}`)
			return
		}
		if len(req.Targets) > 0 {
			insertTargets(db, int(id), req.Targets) //nolint:errcheck
		}
		g, _ := getGroup(db, int(id))
		data, _ := encodeJSON(g)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"group":%s}`, data)
	}
}

func handleUpdateGroup(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		var req struct {
			Name string `json:"name"`
		}
		parseJSON(r, &req) //nolint:errcheck
		updateGroup(db, id, req.Name) //nolint:errcheck
		g, _ := getGroup(db, id)
		data, _ := encodeJSON(g)
		fmt.Fprintf(w, `{"group":%s}`, data)
	}
}

func handleDeleteGroup(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		deleteGroup(db, id) //nolint:errcheck
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}

func handleAddTarget(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		groupID, _ := strconv.Atoi(chi.URLParam(r, "id"))
		var t Target
		if err := parseJSON(r, &t); err != nil || t.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"email required"}`)
			return
		}
		insertTargets(db, groupID, []Target{t}) //nolint:errcheck
		g, _ := getGroup(db, groupID)
		data, _ := encodeJSON(g)
		fmt.Fprintf(w, `{"group":%s}`, data)
	}
}

func handleDeleteTarget(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		targetID, _ := strconv.Atoi(chi.URLParam(r, "tid"))
		deleteTarget(db, targetID) //nolint:errcheck
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}

// handleImportTargets parses a CSV (first_name,last_name,email,position header optional)
// and bulk-inserts into the given group.
func handleImportTargets(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		groupID, _ := strconv.Atoi(chi.URLParam(r, "id"))

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"read error"}`)
			return
		}

		cr := csv.NewReader(strings.NewReader(string(body)))
		records, err := cr.ReadAll()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"csv parse error: %s"}`, err.Error())
			return
		}

		var targets []Target
		for i, rec := range records {
			if i == 0 && len(rec) > 0 && strings.EqualFold(rec[0], "first_name") {
				continue // skip header row
			}
			if len(rec) < 3 {
				continue
			}
			t := Target{
				FirstName: strings.TrimSpace(rec[0]),
				LastName:  strings.TrimSpace(rec[1]),
				Email:     strings.TrimSpace(rec[2]),
			}
			if len(rec) > 3 {
				t.Position = strings.TrimSpace(rec[3])
			}
			if t.Email != "" {
				targets = append(targets, t)
			}
		}

		if err := insertTargets(db, groupID, targets); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"db error"}`)
			return
		}
		fmt.Fprintf(w, `{"imported":%d}`, len(targets))
	}
}

// Campaigns

func handleListCampaigns(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		list, _ := listCampaigns(db)
		data, _ := encodeJSON(list)
		fmt.Fprintf(w, `{"campaigns":%s}`, data)
	}
}

func handleCreateCampaign(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		var c Campaign
		if err := parseJSON(r, &c); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid json"}`)
			return
		}
		id, err := createCampaign(db, c)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":%q}`, err.Error())
			return
		}
		c.ID = int(id)
		// Launch asynchronously
		go launchCampaign(db, c.ID)
		data, _ := encodeJSON(c)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"campaign":%s}`, data)
	}
}

func handleDeleteCampaign(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		deleteCampaign(db, id) //nolint:errcheck
		fmt.Fprint(w, `{"status":"deleted"}`)
	}
}

func handleCompleteCampaign(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		setCampaignStatus(db, id, "completed") //nolint:errcheck
		fmt.Fprint(w, `{"status":"completed"}`)
	}
}

func handleGetCampaignResults(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := validateToken(extractToken(r)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Invalid token"}`)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		c, err := getCampaign(db, id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		results, _ := listResults(db, id)
		camData, _ := encodeJSON(c)
		resData, _ := encodeJSON(results)
		fmt.Fprintf(w, `{"campaign":%s,"results":%s}`, camData, resData)
	}
}

// ── Public tracking handlers ──────────────────────────────────────────────────

// 1×1 transparent GIF
var trackingPixel, _ = base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

func handlePhishOpen(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rid := chi.URLParam(r, "rid")
		if rid != "" && db.conn != nil {
			go markResultOpened(db, rid)
		}
		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Write(trackingPixel) //nolint:errcheck
	}
}

func handlePhishClick(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rid := chi.URLParam(r, "rid")
		if db.conn == nil {
			http.NotFound(w, r)
			return
		}
		go markResultClicked(db, rid)

		result, err := getResultByRID(db, rid)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		campaign, err := getCampaign(db, result.CampaignID)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if campaign.PageID != 0 {
			page, err := getPage(db, campaign.PageID)
			if err == nil {
				// Inject the submit form action if capture_credentials
				html := page.HTML
				if page.CaptureCredentials {
					// Replace any <form> action to point to our submit handler
					submitURL := fmt.Sprintf("/t/submit/%s", rid)
					html = strings.ReplaceAll(html, `action=""`, fmt.Sprintf(`action="%s" method="POST"`, submitURL))
					// Fallback: inject a hidden rid field into any form
					html = strings.ReplaceAll(html, "</form>", fmt.Sprintf(`<input type="hidden" name="__rid" value="%s" /></form>`, rid))
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(html)) //nolint:errcheck
				return
			}
		}
		// No landing page — redirect to phish_url or 404
		if campaign.PhishURL != "" {
			http.Redirect(w, r, campaign.PhishURL, http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}
}

func handlePhishSubmit(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rid := chi.URLParam(r, "rid")
		r.ParseForm() //nolint:errcheck

		// Collect all form fields except the internal __rid
		formData := map[string]string{}
		for k, v := range r.Form {
			if k == "__rid" {
				continue
			}
			formData[k] = strings.Join(v, ", ")
		}
		dataJSON, _ := json.Marshal(formData)

		if db.conn != nil {
			markResultSubmitted(db, rid, string(dataJSON))
		}

		// Redirect to configured redirect URL if available
		if db.conn != nil {
			if result, err := getResultByRID(db, rid); err == nil {
				if campaign, err := getCampaign(db, result.CampaignID); err == nil && campaign.PageID != 0 {
					if page, err := getPage(db, campaign.PageID); err == nil && page.RedirectURL != "" {
						http.Redirect(w, r, page.RedirectURL, http.StatusFound)
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><body><p>Thank you.</p></body></html>`)) //nolint:errcheck
	}
}

func handlePhishPage(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rid := chi.URLParam(r, "rid")
		if db.conn == nil {
			http.NotFound(w, r)
			return
		}
		result, err := getResultByRID(db, rid)
		if err != nil {
			// rid might be a page id for preview
			http.NotFound(w, r)
			return
		}
		campaign, err := getCampaign(db, result.CampaignID)
		if err != nil || campaign.PageID == 0 {
			http.NotFound(w, r)
			return
		}
		page, err := getPage(db, campaign.PageID)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page.HTML)) //nolint:errcheck
	}
}

// handlePreviewPage serves a landing page HTML by page ID for preview (authenticated).
func handlePreviewPage(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := validateToken(extractToken(r)); err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		id, _ := strconv.Atoi(chi.URLParam(r, "id"))
		page, err := getPage(db, id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page.HTML)) //nolint:errcheck
	}
}

// isMemoryDB returns true when there is no real DB connection (used to guard
// phishing handlers that need a DB in tests/dev without SQLite).
func (db *DB) isMemoryDB() bool {
	return db.isMemory || db.conn == nil
}

// smtpAddr resolves the outbound IP for PASV responses (reused from ftp.go pattern).
var _ = net.Dial // keep net import used
