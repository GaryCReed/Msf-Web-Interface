package main

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	conn       *sql.DB
	memory     *MemoryDB
	isMemory   bool
	isPostgres bool
}

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	CreatedAt    string `json:"created_at"`
}

type Session struct {
	ID          int    `json:"id"`
	UserID      int    `json:"user_id"`
	ProjectID   *int   `json:"project_id,omitempty"`
	SessionName string `json:"session_name"`
	TargetHost  string `json:"target_host"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Project struct {
	ID           int    `json:"id"`
	UserID       int    `json:"user_id"`
	Name         string `json:"name"`
	NetworkRange string `json:"network_range"`
	CreatedAt    string `json:"created_at"`
}

type ProjectHost struct {
	ID        int    `json:"id"`
	ProjectID int    `json:"project_id"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	Online    bool   `json:"online"`
	LastSeen  string `json:"last_seen"`
	FirstSeen string `json:"first_seen"`
}

// In-memory user store for development
type MemoryDB struct {
	users        map[string]*User
	sessions     map[int][]Session
	projects     map[int]*Project
	projectHosts map[int][]*ProjectHost // keyed by projectID
	vulnResults  map[int]string // sessionID → JSON blob
	cveResults   map[int]string // sessionID → JSON blob
	enumResults  map[int]string // sessionID → JSON blob
	lootData            map[int][]byte // sessionID → XML bytes
	searchsploitResults map[int]string // sessionID → JSON blob
	feroxResults        map[int]string // sessionID → JSON blob
	mutex        sync.RWMutex
	nextID       int
	nextProjID   int
	nextHostID   int
}

var memoryDB *MemoryDB

func NewDB(dbURL string) (*DB, error) {
	if strings.HasPrefix(dbURL, "memory://") {
		// Use in-memory store
		if memoryDB == nil {
			memoryDB = &MemoryDB{
				users:        make(map[string]*User),
				sessions:     make(map[int][]Session),
				projects:     make(map[int]*Project),
				projectHosts: make(map[int][]*ProjectHost),
				vulnResults:  make(map[int]string),
				cveResults:   make(map[int]string),
				enumResults:  make(map[int]string),
				lootData:            make(map[int][]byte),
				searchsploitResults: make(map[int]string),
				feroxResults:        make(map[int]string),
				nextID:       1,
				nextProjID:   1,
				nextHostID:   1,
			}
		}
		return &DB{memory: memoryDB, isMemory: true}, nil
	}

	if strings.HasPrefix(dbURL, "sqlite3://") {
		dbPath := strings.TrimPrefix(dbURL, "sqlite3://")
		conn, err := sql.Open("sqlite3", dbPath)
		if err != nil {
			return nil, err
		}

		if err := conn.Ping(); err != nil {
			return nil, err
		}

		return &DB{conn: conn, isMemory: false}, nil
	}

	// Fallback to PostgreSQL
	conn, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}

	if err := conn.Ping(); err != nil {
		return nil, err
	}

	return &DB{conn: conn, isMemory: false, isPostgres: true}, nil
}

func (db *DB) Close() error {
	if db.isMemory {
		return nil // Nothing to close for memory DB
	}
	return db.conn.Close()
}

// rebind converts ? placeholders to $1, $2, ... for PostgreSQL.
// SQLite and in-memory mode use ? unchanged.
func (db *DB) rebind(query string) string {
	if !db.isPostgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (db *DB) Migrate() error {
	if db.isMemory {
		return nil // No migration needed for memory DB
	}

	var schema string
	if db.isPostgres {
		schema = `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS projects (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			network_range TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS sessions (
			id SERIAL PRIMARY KEY,
			user_id INTEGER,
			project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
			session_name TEXT,
			target_host TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS project_hosts (
			id SERIAL PRIMARY KEY,
			project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			hostname TEXT NOT NULL DEFAULT '',
			online BOOLEAN NOT NULL DEFAULT TRUE,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(project_id, ip)
		);
		CREATE TABLE IF NOT EXISTS exploits (
			id SERIAL PRIMARY KEY,
			session_id INTEGER,
			exploit_name TEXT,
			exploit_path TEXT,
			options TEXT,
			status TEXT,
			output TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS commands (
			id SERIAL PRIMARY KEY,
			session_id INTEGER,
			command TEXT NOT NULL,
			output TEXT,
			status TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS vuln_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS cve_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS enum_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS loot_data (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS searchsploit_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS ferox_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);`
	} else {
		schema = `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS projects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			network_range TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
			session_name TEXT,
			target_host TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS project_hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			hostname TEXT NOT NULL DEFAULT '',
			online INTEGER NOT NULL DEFAULT 1,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(project_id, ip)
		);
		CREATE TABLE IF NOT EXISTS exploits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id INTEGER,
			exploit_name TEXT,
			exploit_path TEXT,
			options TEXT,
			status TEXT,
			output TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS commands (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id INTEGER,
			command TEXT NOT NULL,
			output TEXT,
			status TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS vuln_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS cve_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS enum_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS loot_data (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS searchsploit_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);
		CREATE TABLE IF NOT EXISTS ferox_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);`
	}

	_, err := db.conn.Exec(schema)
	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	// Add project_id to existing sessions tables (idempotent)
	if db.isPostgres {
		db.conn.Exec(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL`)
	} else {
		// SQLite: ignore error if column already exists
		db.conn.Exec(`ALTER TABLE sessions ADD COLUMN project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL`)
	}

	// Ensure tables added after initial release exist in older databases.
	// These are idempotent — CREATE TABLE IF NOT EXISTS is safe to run repeatedly.
	newTables := []string{
		`CREATE TABLE IF NOT EXISTS loot_data (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS searchsploit_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS ferox_results (
			session_id INTEGER PRIMARY KEY,
			data       TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		)`,
	}
	for _, t := range newTables {
		db.conn.Exec(t) //nolint:errcheck — IF NOT EXISTS means this is safe to ignore
	}

	return nil
}

// MemoryDB methods

func (m *MemoryDB) CreateUser(username, email, password string) (*User, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.users[username]; exists {
		return nil, fmt.Errorf("user already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		ID:           m.nextID,
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
	}

	m.users[username] = user
	m.nextID++

	return user, nil
}

func (m *MemoryDB) GetUser(username string) (*User, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (m *MemoryDB) CreateSession(userID int, sessionName, targetHost string) (*Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	session := Session{
		ID:          m.nextID,
		UserID:      userID,
		SessionName: sessionName,
		TargetHost:  targetHost,
		CreatedAt:   time.Now().Format("2006-01-02 15:04:05"),
		UpdatedAt:   time.Now().Format("2006-01-02 15:04:05"),
	}

	m.sessions[userID] = append(m.sessions[userID], session)
	m.nextID++

	return &session, nil
}

func (m *MemoryDB) GetUserSessions(userID int) ([]Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	sessions, exists := m.sessions[userID]
	if !exists {
		return []Session{}, nil
	}

	// Return a copy to avoid race conditions
	result := make([]Session, len(sessions))
	copy(result, sessions)

	return result, nil
}

// ── MemoryDB project methods ──────────────────────────────────────────────────

func (m *MemoryDB) CreateProject(userID int, name, networkRange string) (*Project, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	p := &Project{
		ID:           m.nextProjID,
		UserID:       userID,
		Name:         name,
		NetworkRange: networkRange,
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
	}
	m.projects[m.nextProjID] = p
	m.nextProjID++
	return p, nil
}

func (m *MemoryDB) GetUserProjects(userID int) ([]*Project, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var result []*Project
	for _, p := range m.projects {
		if p.UserID == userID {
			copy := *p
			result = append(result, &copy)
		}
	}
	if result == nil {
		result = []*Project{}
	}
	return result, nil
}

func (m *MemoryDB) GetProject(projectID, userID int) (*Project, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	p, ok := m.projects[projectID]
	if !ok || p.UserID != userID {
		return nil, fmt.Errorf("project not found")
	}
	copy := *p
	return &copy, nil
}

func (m *MemoryDB) DeleteProject(projectID, userID int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	p, ok := m.projects[projectID]
	if !ok || p.UserID != userID {
		return fmt.Errorf("project not found")
	}
	delete(m.projects, projectID)
	// Delete all sessions that belonged to this project.
	for uid, ss := range m.sessions {
		kept := ss[:0]
		for _, s := range ss {
			if s.ProjectID == nil || *s.ProjectID != projectID {
				kept = append(kept, s)
			}
		}
		m.sessions[uid] = kept
	}
	return nil
}

func (m *MemoryDB) UpdateProject(projectID, userID int, name, networkRange string) (*Project, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	p, ok := m.projects[projectID]
	if !ok || p.UserID != userID {
		return nil, fmt.Errorf("project not found")
	}
	p.Name = name
	p.NetworkRange = networkRange
	copy := *p
	return &copy, nil
}

func (m *MemoryDB) GetProjectSessions(projectID, userID int) ([]Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	p, ok := m.projects[projectID]
	if !ok || p.UserID != userID {
		return nil, fmt.Errorf("project not found")
	}

	var result []Session
	for _, ss := range m.sessions {
		for _, s := range ss {
			if s.ProjectID != nil && *s.ProjectID == projectID {
				result = append(result, s)
			}
		}
	}
	if result == nil {
		result = []Session{}
	}
	return result, nil
}

func (m *MemoryDB) CreateProjectSession(userID, projectID int, sessionName, targetHost string) (*Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pid := projectID
	session := Session{
		ID:          m.nextID,
		UserID:      userID,
		ProjectID:   &pid,
		SessionName: sessionName,
		TargetHost:  targetHost,
		CreatedAt:   time.Now().Format("2006-01-02 15:04:05"),
		UpdatedAt:   time.Now().Format("2006-01-02 15:04:05"),
	}
	m.sessions[userID] = append(m.sessions[userID], session)
	m.nextID++
	return &session, nil
}

// DB wrapper methods

// CreateUser creates a new user with username and password
func (db *DB) CreateUser(username, email, password string) (*User, error) {
	if db.isMemory {
		return db.memory.CreateUser(username, email, password)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{}
	err = db.conn.QueryRow(
		db.rebind("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?) RETURNING id, username, email, created_at"),
		username, email, string(hash),
	).Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetUser retrieves a user by username
func (db *DB) GetUser(username string) (*User, error) {
	if db.isMemory {
		return db.memory.GetUser(username)
	}

	user := &User{}
	err := db.conn.QueryRow(
		db.rebind("SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?"),
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return user, nil
}

// VerifyPassword checks if the provided password matches the user's hash
func (u *User) VerifyPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
}

// GetOrCreateUser returns an existing user by username, or creates one if not found.
// Authentication is handled externally (PAM/sudo); no app password is stored.
func (db *DB) GetOrCreateUser(username string) (*User, error) {
	if db.isMemory {
		return db.memory.GetOrCreateUser(username)
	}
	user, err := db.GetUser(username)
	if err == nil {
		return user, nil
	}
	// Use username@localhost as a unique placeholder email.
	email := username + "@localhost"
	// Placeholder hash — never verified; PAM handles auth.
	hash, _ := bcrypt.GenerateFromPassword([]byte(email), bcrypt.MinCost)
	user = &User{}
	err = db.conn.QueryRow(
		db.rebind("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?) RETURNING id, username, email, created_at"),
		username, email, string(hash),
	).Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}

func (m *MemoryDB) GetOrCreateUser(username string) (*User, error) {
	if user, err := m.GetUser(username); err == nil {
		return user, nil
	}
	email := username + "@localhost"
	hash, _ := bcrypt.GenerateFromPassword([]byte(email), bcrypt.MinCost)
	m.mutex.Lock()
	defer m.mutex.Unlock()
	user := &User{
		ID:           m.nextID,
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now().Format("2006-01-02 15:04:05"),
	}
	m.users[username] = user
	m.nextID++
	return user, nil
}

// CreateSession creates a new session for a user
func (db *DB) CreateSession(userID int, sessionName, targetHost string) (*Session, error) {
	if db.isMemory {
		return db.memory.CreateSession(userID, sessionName, targetHost)
	}

	session := &Session{}
	err := db.conn.QueryRow(
		db.rebind("INSERT INTO sessions (user_id, session_name, target_host) VALUES (?, ?, ?) RETURNING id, user_id, session_name, target_host, created_at, updated_at"),
		userID, sessionName, targetHost,
	).Scan(&session.ID, &session.UserID, &session.SessionName, &session.TargetHost, &session.CreatedAt, &session.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// GetSession retrieves a single session by ID, verifying it belongs to the given user
func (m *MemoryDB) GetSession(sessionID, userID int) (*Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, sessions := range m.sessions {
		for _, s := range sessions {
			if s.ID == sessionID {
				if s.UserID != userID {
					return nil, fmt.Errorf("session not found")
				}
				copy := s
				return &copy, nil
			}
		}
	}
	return nil, fmt.Errorf("session not found")
}

func (m *MemoryDB) DeleteSession(sessionID, userID int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	sessions, ok := m.sessions[userID]
	if !ok {
		return fmt.Errorf("session not found")
	}
	for i, s := range sessions {
		if s.ID == sessionID {
			m.sessions[userID] = append(sessions[:i], sessions[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("session not found")
}

func (db *DB) GetSession(sessionID, userID int) (*Session, error) {
	if db.isMemory {
		return db.memory.GetSession(sessionID, userID)
	}

	session := &Session{}
	var pid sql.NullInt64
	err := db.conn.QueryRow(
		db.rebind("SELECT id, user_id, project_id, session_name, target_host, created_at, updated_at FROM sessions WHERE id = ? AND user_id = ?"),
		sessionID, userID,
	).Scan(&session.ID, &session.UserID, &pid, &session.SessionName, &session.TargetHost, &session.CreatedAt, &session.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	if pid.Valid {
		id := int(pid.Int64)
		session.ProjectID = &id
	}
	return session, nil
}

func (db *DB) DeleteSession(sessionID, userID int) error {
	if db.isMemory {
		return db.memory.DeleteSession(sessionID, userID)
	}

	result, err := db.conn.Exec(db.rebind("DELETE FROM sessions WHERE id = ? AND user_id = ?"), sessionID, userID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("session not found")
	}
	return nil
}

// GetUserSessions retrieves all sessions for a user
func (db *DB) GetUserSessions(userID int) ([]Session, error) {
	if db.isMemory {
		return db.memory.GetUserSessions(userID)
	}

	rows, err := db.conn.Query(
		db.rebind("SELECT id, user_id, project_id, session_name, target_host, created_at, updated_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC"),
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		var pid sql.NullInt64
		if err := rows.Scan(&session.ID, &session.UserID, &pid, &session.SessionName, &session.TargetHost, &session.CreatedAt, &session.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		if pid.Valid {
			id := int(pid.Int64)
			session.ProjectID = &id
		}
		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

// GetProjectSessions retrieves all sessions belonging to a project, verifying project ownership.
func (db *DB) GetProjectSessions(projectID, userID int) ([]Session, error) {
	if db.isMemory {
		return db.memory.GetProjectSessions(projectID, userID)
	}

	rows, err := db.conn.Query(
		db.rebind(`SELECT s.id, s.user_id, s.project_id, s.session_name, s.target_host, s.created_at, s.updated_at
		FROM sessions s
		JOIN projects p ON s.project_id = p.id
		WHERE s.project_id = ? AND p.user_id = ?
		ORDER BY s.created_at DESC`),
		projectID, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		var pid sql.NullInt64
		if err := rows.Scan(&session.ID, &session.UserID, &pid, &session.SessionName, &session.TargetHost, &session.CreatedAt, &session.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		if pid.Valid {
			id := int(pid.Int64)
			session.ProjectID = &id
		}
		sessions = append(sessions, session)
	}
	if sessions == nil {
		sessions = []Session{}
	}
	return sessions, rows.Err()
}

// CreateProjectSession creates a session associated with a project.
func (db *DB) CreateProjectSession(userID, projectID int, sessionName, targetHost string) (*Session, error) {
	if db.isMemory {
		return db.memory.CreateProjectSession(userID, projectID, sessionName, targetHost)
	}

	session := &Session{}
	var pid sql.NullInt64
	err := db.conn.QueryRow(
		db.rebind("INSERT INTO sessions (user_id, project_id, session_name, target_host) VALUES (?, ?, ?, ?) RETURNING id, user_id, project_id, session_name, target_host, created_at, updated_at"),
		userID, projectID, sessionName, targetHost,
	).Scan(&session.ID, &session.UserID, &pid, &session.SessionName, &session.TargetHost, &session.CreatedAt, &session.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	if pid.Valid {
		id := int(pid.Int64)
		session.ProjectID = &id
	}
	return session, nil
}

// CreateProject creates a new project for a user.
func (db *DB) CreateProject(userID int, name, networkRange string) (*Project, error) {
	if db.isMemory {
		return db.memory.CreateProject(userID, name, networkRange)
	}

	p := &Project{}
	err := db.conn.QueryRow(
		db.rebind("INSERT INTO projects (user_id, name, network_range) VALUES (?, ?, ?) RETURNING id, user_id, name, network_range, created_at"),
		userID, name, networkRange,
	).Scan(&p.ID, &p.UserID, &p.Name, &p.NetworkRange, &p.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create project: %w", err)
	}
	return p, nil
}

// GetUserProjects retrieves all projects for a user.
func (db *DB) GetUserProjects(userID int) ([]*Project, error) {
	if db.isMemory {
		return db.memory.GetUserProjects(userID)
	}

	rows, err := db.conn.Query(
		db.rebind("SELECT id, user_id, name, network_range, created_at FROM projects WHERE user_id = ? ORDER BY created_at DESC"),
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		p := &Project{}
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.NetworkRange, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		projects = append(projects, p)
	}
	if projects == nil {
		projects = []*Project{}
	}
	return projects, rows.Err()
}

// GetProject retrieves a single project by ID, verifying ownership.
func (db *DB) GetProject(projectID, userID int) (*Project, error) {
	if db.isMemory {
		return db.memory.GetProject(projectID, userID)
	}

	p := &Project{}
	err := db.conn.QueryRow(
		db.rebind("SELECT id, user_id, name, network_range, created_at FROM projects WHERE id = ? AND user_id = ?"),
		projectID, userID,
	).Scan(&p.ID, &p.UserID, &p.Name, &p.NetworkRange, &p.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	return p, nil
}

// DeleteProject deletes a project (and cascades to its sessions).
func (db *DB) DeleteProject(projectID, userID int) error {
	if db.isMemory {
		return db.memory.DeleteProject(projectID, userID)
	}

	result, err := db.conn.Exec(db.rebind("DELETE FROM projects WHERE id = ? AND user_id = ?"), projectID, userID)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}

// UpdateProject updates a project's name and network range.
func (db *DB) UpdateProject(projectID, userID int, name, networkRange string) (*Project, error) {
	if db.isMemory {
		return db.memory.UpdateProject(projectID, userID, name, networkRange)
	}
	p := &Project{}
	err := db.conn.QueryRow(
		db.rebind("UPDATE projects SET name = ?, network_range = ? WHERE id = ? AND user_id = ? RETURNING id, user_id, name, network_range, created_at"),
		name, networkRange, projectID, userID,
	).Scan(&p.ID, &p.UserID, &p.Name, &p.NetworkRange, &p.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	return p, nil
}

// GetProjectHosts returns all persisted hosts for a project.
func (db *DB) GetProjectHosts(projectID, userID int) ([]*ProjectHost, error) {
	if db.isMemory {
		return db.memory.GetProjectHosts(projectID, userID)
	}

	// Verify ownership
	var ownerID int
	err := db.conn.QueryRow(db.rebind("SELECT user_id FROM projects WHERE id = ?"), projectID).Scan(&ownerID)
	if err != nil || ownerID != userID {
		return nil, fmt.Errorf("project not found")
	}

	rows, err := db.conn.Query(
		db.rebind("SELECT id, project_id, ip, hostname, online, last_seen, first_seen FROM project_hosts WHERE project_id = ? ORDER BY ip"),
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	defer rows.Close()

	var hosts []*ProjectHost
	for rows.Next() {
		h := &ProjectHost{}
		var onlineInt int
		if err := rows.Scan(&h.ID, &h.ProjectID, &h.IP, &h.Hostname, &onlineInt, &h.LastSeen, &h.FirstSeen); err != nil {
			return nil, fmt.Errorf("scan error: %w", err)
		}
		h.Online = onlineInt != 0
		hosts = append(hosts, h)
	}
	if hosts == nil {
		hosts = []*ProjectHost{}
	}
	return hosts, rows.Err()
}

// UpsertScanResults persists scan results for a project.
// Online hosts are upserted (inserted or updated). All other known hosts are marked offline.
func (db *DB) UpsertScanResults(projectID int, online []ScanResult) error {
	if db.isMemory {
		return db.memory.UpsertScanResults(projectID, online)
	}

	// Upsert each online host
	if db.isPostgres {
		for _, h := range online {
			_, err := db.conn.Exec(
				`INSERT INTO project_hosts (project_id, ip, hostname, online, last_seen)
				 VALUES ($1, $2, $3, true, NOW())
				 ON CONFLICT (project_id, ip) DO UPDATE SET
				   hostname = EXCLUDED.hostname,
				   online   = true,
				   last_seen = NOW()`,
				projectID, h.IP, h.Hostname,
			)
			if err != nil {
				return fmt.Errorf("upsert host: %w", err)
			}
		}
		// Mark everyone not in the online set as offline
		if len(online) == 0 {
			_, err := db.conn.Exec(`UPDATE project_hosts SET online = false WHERE project_id = $1`, projectID)
			return err
		}
		ips := make([]interface{}, len(online)+1)
		ips[0] = projectID
		placeholders := make([]string, len(online))
		for i, h := range online {
			ips[i+1] = h.IP
			placeholders[i] = fmt.Sprintf("$%d", i+2)
		}
		q := fmt.Sprintf(
			`UPDATE project_hosts SET online = false WHERE project_id = $1 AND ip NOT IN (%s)`,
			strings.Join(placeholders, ","),
		)
		_, err := db.conn.Exec(q, ips...)
		return err
	}

	// SQLite
	for _, h := range online {
		_, err := db.conn.Exec(
			`INSERT INTO project_hosts (project_id, ip, hostname, online, last_seen)
			 VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
			 ON CONFLICT(project_id, ip) DO UPDATE SET
			   hostname  = excluded.hostname,
			   online    = 1,
			   last_seen = CURRENT_TIMESTAMP`,
			projectID, h.IP, h.Hostname,
		)
		if err != nil {
			return fmt.Errorf("upsert host: %w", err)
		}
	}
	if len(online) == 0 {
		_, err := db.conn.Exec(`UPDATE project_hosts SET online = 0 WHERE project_id = ?`, projectID)
		return err
	}
	ips := make([]interface{}, len(online)+1)
	ips[0] = projectID
	placeholders := make([]string, len(online))
	for i, h := range online {
		ips[i+1] = h.IP
		placeholders[i] = "?"
	}
	q := fmt.Sprintf(
		`UPDATE project_hosts SET online = 0 WHERE project_id = ? AND ip NOT IN (%s)`,
		strings.Join(placeholders, ","),
	)
	_, err := db.conn.Exec(q, ips...)
	return err
}

// ── MemoryDB project host methods ─────────────────────────────────────────────

func (m *MemoryDB) GetProjectHosts(projectID, userID int) ([]*ProjectHost, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	p, ok := m.projects[projectID]
	if !ok || p.UserID != userID {
		return nil, fmt.Errorf("project not found")
	}

	hosts := m.projectHosts[projectID]
	result := make([]*ProjectHost, len(hosts))
	for i, h := range hosts {
		copy := *h
		result[i] = &copy
	}
	return result, nil
}

func (m *MemoryDB) UpsertScanResults(projectID int, online []ScanResult) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now().Format("2006-01-02 15:04:05")
	onlineSet := make(map[string]bool, len(online))
	for _, h := range online {
		onlineSet[h.IP] = true
	}

	// Update existing entries
	existing := m.projectHosts[projectID]
	for _, h := range existing {
		if onlineSet[h.IP] {
			h.Online = true
			h.LastSeen = now
		} else {
			h.Online = false
		}
	}

	// Insert new hosts not yet seen
	existingSet := make(map[string]bool, len(existing))
	for _, h := range existing {
		existingSet[h.IP] = true
	}
	for _, h := range online {
		if !existingSet[h.IP] {
			m.projectHosts[projectID] = append(m.projectHosts[projectID], &ProjectHost{
				ID:        m.nextHostID,
				ProjectID: projectID,
				IP:        h.IP,
				Hostname:  h.Hostname,
				Online:    true,
				LastSeen:  now,
				FirstSeen: now,
			})
			m.nextHostID++
		}
	}
	return nil
}

// ── CVE results persistence ───────────────────────────────────────────────────

func (db *DB) SaveVulnResults(sessionID int, data string) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		db.memory.vulnResults[sessionID] = data
		db.memory.mutex.Unlock()
		return nil
	}
	q := db.rebind(`INSERT INTO vuln_results (session_id, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`)
	_, err := db.conn.Exec(q, sessionID, data)
	return err
}

func (db *DB) GetVulnResults(sessionID int) (string, error) {
	if db.isMemory {
		db.memory.mutex.RLock()
		data := db.memory.vulnResults[sessionID]
		db.memory.mutex.RUnlock()
		if data == "" {
			return "", fmt.Errorf("not found")
		}
		return data, nil
	}
	var data string
	q := db.rebind(`SELECT data FROM vuln_results WHERE session_id = ?`)
	err := db.conn.QueryRow(q, sessionID).Scan(&data)
	return data, err
}

func (db *DB) SaveCVEResults(sessionID int, data string) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		db.memory.cveResults[sessionID] = data
		db.memory.mutex.Unlock()
		return nil
	}
	q := db.rebind(`INSERT INTO cve_results (session_id, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`)
	_, err := db.conn.Exec(q, sessionID, data)
	return err
}

func (db *DB) GetCVEResults(sessionID int) (string, error) {
	if db.isMemory {
		db.memory.mutex.RLock()
		data := db.memory.cveResults[sessionID]
		db.memory.mutex.RUnlock()
		if data == "" {
			return "", fmt.Errorf("not found")
		}
		return data, nil
	}
	var data string
	q := db.rebind(`SELECT data FROM cve_results WHERE session_id = ?`)
	err := db.conn.QueryRow(q, sessionID).Scan(&data)
	if err != nil {
		return "", err
	}
	return data, nil
}

func (db *DB) SaveEnumResults(sessionID int, data string) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		db.memory.enumResults[sessionID] = data
		db.memory.mutex.Unlock()
		return nil
	}
	q := db.rebind(`INSERT INTO enum_results (session_id, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`)
	_, err := db.conn.Exec(q, sessionID, data)
	return err
}

func (db *DB) GetEnumResults(sessionID int) (string, error) {
	if db.isMemory {
		db.memory.mutex.RLock()
		data := db.memory.enumResults[sessionID]
		db.memory.mutex.RUnlock()
		if data == "" {
			return "", fmt.Errorf("not found")
		}
		return data, nil
	}
	var data string
	q := db.rebind(`SELECT data FROM enum_results WHERE session_id = ?`)
	err := db.conn.QueryRow(q, sessionID).Scan(&data)
	if err != nil {
		return "", err
	}
	return data, nil
}

// ── Loot XML persistence ──────────────────────────────────────────────────────

func (db *DB) SaveLootData(sessionID int, data []byte) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		db.memory.lootData[sessionID] = data
		db.memory.mutex.Unlock()
		return nil
	}
	q := db.rebind(`INSERT INTO loot_data (session_id, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`)
	_, err := db.conn.Exec(q, sessionID, string(data))
	return err
}

func (db *DB) GetLootData(sessionID int) ([]byte, error) {
	if db.isMemory {
		db.memory.mutex.RLock()
		data := db.memory.lootData[sessionID]
		db.memory.mutex.RUnlock()
		if data == nil {
			return nil, fmt.Errorf("not found")
		}
		return data, nil
	}
	var data string
	q := db.rebind(`SELECT data FROM loot_data WHERE session_id = ?`)
	err := db.conn.QueryRow(q, sessionID).Scan(&data)
	if err != nil {
		return nil, err
	}
	return []byte(data), nil
}

// ── Searchsploit results persistence ─────────────────────────────────────────

func (db *DB) SaveSearchsploitResults(sessionID int, data string) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		db.memory.searchsploitResults[sessionID] = data
		db.memory.mutex.Unlock()
		return nil
	}
	q := db.rebind(`INSERT INTO searchsploit_results (session_id, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`)
	_, err := db.conn.Exec(q, sessionID, data)
	return err
}

func (db *DB) GetSearchsploitResults(sessionID int) (string, error) {
	if db.isMemory {
		db.memory.mutex.RLock()
		data := db.memory.searchsploitResults[sessionID]
		db.memory.mutex.RUnlock()
		if data == "" {
			return "", fmt.Errorf("not found")
		}
		return data, nil
	}
	var data string
	q := db.rebind(`SELECT data FROM searchsploit_results WHERE session_id = ?`)
	err := db.conn.QueryRow(q, sessionID).Scan(&data)
	return data, err
}

// ── Feroxbuster results persistence ──────────────────────────────────────────

func (db *DB) SaveFeroxResults(sessionID int, data string) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		db.memory.feroxResults[sessionID] = data
		db.memory.mutex.Unlock()
		return nil
	}
	q := db.rebind(`INSERT INTO ferox_results (session_id, data, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`)
	_, err := db.conn.Exec(q, sessionID, data)
	return err
}

func (db *DB) GetFeroxResults(sessionID int) (string, error) {
	if db.isMemory {
		db.memory.mutex.RLock()
		data := db.memory.feroxResults[sessionID]
		db.memory.mutex.RUnlock()
		if data == "" {
			return "", fmt.Errorf("not found")
		}
		return data, nil
	}
	var data string
	q := db.rebind(`SELECT data FROM ferox_results WHERE session_id = ?`)
	err := db.conn.QueryRow(q, sessionID).Scan(&data)
	return data, err
}

func (db *DB) DeleteFeroxResults(sessionID int) error {
	if db.isMemory {
		db.memory.mutex.Lock()
		delete(db.memory.feroxResults, sessionID)
		db.memory.mutex.Unlock()
		return nil
	}
	_, err := db.conn.Exec(db.rebind(`DELETE FROM ferox_results WHERE session_id = ?`), sessionID)
	return err
}

