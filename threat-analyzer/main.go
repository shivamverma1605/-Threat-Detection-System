package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type LogRecord struct {
	ID            int64     `json:"id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	UserID        string    `json:"userId"`
	IPAddress     string    `json:"ipAddress"`
	Action        string    `json:"action"`
	FileName      *string   `json:"fileName,omitempty"`
	DatabaseQuery *string   `json:"databaseQuery,omitempty"`
}

type Threat struct {
	ID        int64     `json:"id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	UserID    string    `json:"userId"`
	IPAddress string    `json:"ipAddress"`
	Action    string    `json:"action"`
	FileName  *string   `json:"fileName,omitempty"`
	Type      string    `json:"threatType"`
	Severity  string    `json:"severity"`
}

var db *sql.DB

const (
	lookbackHours               = 24
	credentialStuffingFailCount = 5
	credentialStuffingWindow    = 10 * time.Minute
	privEscWindow               = 5 * time.Minute
	accountTakeoverWindow       = 10 * time.Minute
	rapidFileAccessCount        = 5
	rapidFileAccessWindow       = 30 * time.Second
	offHoursStart               = 2
	offHoursEnd                 = 5
)

func main() {

	dsn := getenv("DB_DSN", "file:threatdb?mode=memory&cache=shared")
	var err error
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	if err := ensureSchema(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/threats/analyze", analyzeHandler)
	mux.HandleFunc("/api/threats", threatsHandler)
	mux.HandleFunc("/api/threats/", threatByIDOrSearch)

	addr := getenv("ADDR", ":8082")
	log.Println("threat-analyzer listening on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func ensureSchema() error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS threats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  user_id TEXT,
  ip_address TEXT,
  action TEXT,
  file_name TEXT,
  threat_type TEXT,
  severity TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`)
	return err
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Pull recent logs via the Log Ingestor API.
	ingestorURL := getenv("INGESTOR_URL", "http://localhost:8081/api/logs?limit=5000")
	resp, err := http.Get(ingestorURL)
	if err != nil {
		http.Error(w, "failed to fetch logs: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "log-ingestor returned "+resp.Status, http.StatusBadGateway)
		return
	}
	var logs []LogRecord
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		http.Error(w, "decode logs: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Restrict to recent lookback window.
	cut := time.Now().Add(-lookbackHours * time.Hour)
	filtered := logs[:0]
	for _, lr := range logs {
		if !lr.Timestamp.Before(cut) {
			filtered = append(filtered, lr)
		}
	}

	alerts := detectThreats(filtered)
	for _, t := range alerts {
		_, err := db.Exec(`
INSERT INTO threats (timestamp, user_id, ip_address, action, file_name, threat_type, severity)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.Timestamp.Format(time.RFC3339), t.UserID, t.IPAddress, t.Action, t.FileName, t.Type, t.Severity,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"inserted": len(alerts)})
}

func threatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := parseInt(r.URL.Query().Get("limit"), 200)
	offset := parseInt(r.URL.Query().Get("offset"), 0)
	rows, err := db.Query(`
SELECT id, timestamp, user_id, ip_address, action, file_name, threat_type, severity
FROM threats ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []Threat
	for rows.Next() {
		var t Threat
		var ts string
		if err := rows.Scan(&t.ID, &ts, &t.UserID, &t.IPAddress, &t.Action, &t.FileName, &t.Type, &t.Severity); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t.Timestamp, _ = time.Parse(time.RFC3339, ts)
		out = append(out, t)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func threatByIDOrSearch(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/threats/")
	if path == "search" && r.Method == http.MethodGet {
		searchThreats(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var t Threat
	var ts string
	err = db.QueryRow(`
SELECT id, timestamp, user_id, ip_address, action, file_name, threat_type, severity
FROM threats WHERE id = ?`, id).Scan(&t.ID, &ts, &t.UserID, &t.IPAddress, &t.Action, &t.FileName, &t.Type, &t.Severity)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Timestamp, _ = time.Parse(time.RFC3339, ts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

func searchThreats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	userID := q.Get("userId")
	typ := q.Get("type")
	from := q.Get("from")
	to := q.Get("to")

	var clauses []string
	var args []any
	if userID != "" {
		clauses = append(clauses, "user_id = ?")
		args = append(args, userID)
	}
	if typ != "" {
		clauses = append(clauses, "threat_type = ?")
		args = append(args, typ)
	}
	if from != "" {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, from)
	}
	if to != "" {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, to)
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := db.Query(`
SELECT id, timestamp, user_id, ip_address, action, file_name, threat_type, severity
FROM threats `+where+` ORDER BY timestamp DESC LIMIT 500`, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []Threat
	for rows.Next() {
		var t Threat
		var ts string
		if err := rows.Scan(&t.ID, &ts, &t.UserID, &t.IPAddress, &t.Action, &t.FileName, &t.Type, &t.Severity); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t.Timestamp, _ = time.Parse(time.RFC3339, ts)
		out = append(out, t)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func detectThreats(logs []LogRecord) []Threat {
	var alerts []Threat
	byUser := map[string][]LogRecord{}
	byIP := map[string][]LogRecord{}
	for _, lr := range logs {
		byUser[lr.UserID] = append(byUser[lr.UserID], lr)
		byIP[lr.IPAddress] = append(byIP[lr.IPAddress], lr)
	}
	for _, arr := range byUser {
		sort.Slice(arr, func(i, j int) bool { return arr[i].Timestamp.Before(arr[j].Timestamp) })
	}
	for _, arr := range byIP {
		sort.Slice(arr, func(i, j int) bool { return arr[i].Timestamp.Before(arr[j].Timestamp) })
	}

	// 1) Credential Stuffing
	for user, arr := range byUser {
		var failTimes []time.Time
		var lastSuccess time.Time
		var successIP string
		for _, e := range arr {
			if strings.EqualFold(e.Action, "loginFailed") {
				failTimes = append(failTimes, e.Timestamp)
			}
			if strings.EqualFold(e.Action, "loginSuccess") {
				pruned := failTimes[:0]
				for _, t := range failTimes {
					if e.Timestamp.Sub(t) <= credentialStuffingWindow {
						pruned = append(pruned, t)
					}
				}
				failTimes = pruned
				if len(failTimes) >= credentialStuffingFailCount {
					lastSuccess = e.Timestamp
					successIP = e.IPAddress
				}
			}
			if isSensitiveFile(e.FileName) && !lastSuccess.IsZero() && e.Timestamp.After(lastSuccess) {
				alerts = append(alerts, Threat{
					Timestamp: e.Timestamp,
					UserID:    user,
					IPAddress: successIP,
					Action:    e.Action,
					FileName:  e.FileName,
					Type:      "CredentialStuffing",
					Severity:  "High",
				})
				lastSuccess = time.Time{}
			}
		}
	}

	// 2) Privilege Escalation
	for _, arr := range byUser {
		var lastFail *time.Time
		for _, e := range arr {
			if strings.EqualFold(e.Action, "loginFailed") {
				t := e.Timestamp
				lastFail = &t
			} else if isDBModification(e) && lastFail != nil && e.Timestamp.Sub(*lastFail) <= privEscWindow {
				alerts = append(alerts, Threat{
					Timestamp: e.Timestamp,
					UserID:    e.UserID,
					IPAddress: e.IPAddress,
					Action:    e.Action,
					FileName:  e.FileName,
					Type:      "PrivilegeEscalation",
					Severity:  "High",
				})
				lastFail = nil
			}
		}
	}

	// 3) Account Takeover
	for user, arr := range byUser {
		var lastLoginFromIP *struct {
			t  time.Time
			ip string
		}
		for _, e := range arr {
			if strings.EqualFold(e.Action, "loginSuccess") {
				if lastLoginFromIP != nil && e.Timestamp.Sub(lastLoginFromIP.t) <= accountTakeoverWindow && e.IPAddress != lastLoginFromIP.ip {
					lastLoginFromIP = &struct {
						t  time.Time
						ip string
					}{t: e.Timestamp, ip: e.IPAddress}
				} else {
					lastLoginFromIP = &struct {
						t  time.Time
						ip string
					}{t: e.Timestamp, ip: e.IPAddress}
				}
			}
			if lastLoginFromIP != nil && isRestrictedFile(e.FileName) && e.Timestamp.Sub(lastLoginFromIP.t) <= accountTakeoverWindow {
				alerts = append(alerts, Threat{
					Timestamp: e.Timestamp,
					UserID:    user,
					IPAddress: e.IPAddress,
					Action:    e.Action,
					FileName:  e.FileName,
					Type:      "AccountTakeover",
					Severity:  "High",
				})
				lastLoginFromIP = nil
			}
		}
	}

	// 4) Rapid File Access
	for user, arr := range byUser {
		var window []LogRecord
		for _, e := range arr {
			if !isRestrictedFile(e.FileName) || !strings.EqualFold(e.Action, "fileAccess") {
				continue
			}
			window = append(window, e)
			start := 0
			for i := 0; i < len(window); i++ {
				if window[len(window)-1].Timestamp.Sub(window[i].Timestamp) <= rapidFileAccessWindow {
					start = i
					break
				}
			}
			window = window[start:]
			if len(window) >= rapidFileAccessCount {
				last := window[len(window)-1]
				alerts = append(alerts, Threat{
					Timestamp: last.Timestamp,
					UserID:    user,
					IPAddress: last.IPAddress,
					Action:    last.Action,
					FileName:  last.FileName,
					Type:      "DataExfiltration",
					Severity:  "High",
				})
				window = nil
			}
		}
	}

	// 5) Off-Hours File Access
	for _, e := range logs {
		if strings.EqualFold(e.Action, "fileAccess") && isRestrictedFile(e.FileName) {
			h := e.Timestamp.Hour()
			if h >= offHoursStart && h < offHoursEnd {
				alerts = append(alerts, Threat{
					Timestamp: e.Timestamp,
					UserID:    e.UserID,
					IPAddress: e.IPAddress,
					Action:    e.Action,
					FileName:  e.FileName,
					Type:      "InsiderThreat",
					Severity:  "Medium",
				})
			}
		}
	}
	return alerts
}

func isDBModification(e LogRecord) bool {
	if e.DatabaseQuery == nil {
		return false
	}
	q := strings.ToUpper(strings.TrimSpace(*e.DatabaseQuery))
	return strings.HasPrefix(q, "DELETE") || strings.HasPrefix(q, "INSERT") || strings.HasPrefix(q, "UPDATE")
}

func isSensitiveFile(fn *string) bool { return isRestrictedFile(fn) }

func isRestrictedFile(fn *string) bool {
	if fn == nil {
		return false
	}
	name := strings.ToLower(*fn)
	return strings.Contains(name, "/secure/") || strings.Contains(name, "payroll") || strings.Contains(name, "restricted") || strings.Contains(name, "secret")
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return def
	}
	return v
}
