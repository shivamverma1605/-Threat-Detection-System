// log-ingestor/main.go
package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
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

var db *sql.DB

func main() {
	// In-memory SQLite; stays alive while this process runs.
	dsn := getenv("DB_DSN", "file:logdb?mode=memory&cache=shared")
	fmt.Println("dsn", dsn)
	var err error
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// SQLite + database/sql: one open conn avoids "database is locked" issues.
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	if err := ensureSchema(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/logs", logsHandler)
	mux.HandleFunc("/api/logs/", logByIDOrSearch)

	addr := getenv("ADDR", ":8081")
	log.Println("log-ingestor listening on", addr)
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
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  user_id TEXT,
  ip_address TEXT,
  action TEXT,
  file_name TEXT,
  database_query TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`)
	return err
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var lr LogRecord
		if err := json.NewDecoder(r.Body).Decode(&lr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if lr.Timestamp.IsZero() {
			http.Error(w, "timestamp required (RFC3339)", http.StatusBadRequest)
			return
		}
		res, err := db.Exec(`
INSERT INTO logs (timestamp, user_id, ip_address, action, file_name, database_query)
VALUES (?, ?, ?, ?, ?, ?)`,
			lr.Timestamp.Format(time.RFC3339), lr.UserID, lr.IPAddress, lr.Action, lr.FileName, lr.DatabaseQuery,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		id, _ := res.LastInsertId()
		fmt.Println("ID->", id)
		lr.ID = id
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(lr)
	case http.MethodGet:
		limit := parseInt(r.URL.Query().Get("limit"), 200)
		offset := parseInt(r.URL.Query().Get("offset"), 0)
		rows, err := db.Query(`
SELECT id, timestamp, user_id, ip_address, action, file_name, database_query
FROM logs
ORDER BY id DESC
LIMIT ? OFFSET ?`, limit, offset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var out []LogRecord
		for rows.Next() {
			var ts string
			var lr LogRecord
			if err := rows.Scan(&lr.ID, &ts, &lr.UserID, &lr.IPAddress, &lr.Action, &lr.FileName, &lr.DatabaseQuery); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			t, _ := time.Parse(time.RFC3339, ts)
			lr.Timestamp = t
			out = append(out, lr)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func logByIDOrSearch(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	if path == "search" && r.Method == http.MethodGet {
		searchLogs(w, r)
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
	var ts string
	var lr LogRecord
	err = db.QueryRow(`
SELECT id, timestamp, user_id, ip_address, action, file_name, database_query
FROM logs WHERE id = ?`, id).Scan(&lr.ID, &ts, &lr.UserID, &lr.IPAddress, &lr.Action, &lr.FileName, &lr.DatabaseQuery)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lr.Timestamp, _ = time.Parse(time.RFC3339, ts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lr)
}

func searchLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	userID := q.Get("userId")
	ip := q.Get("ipAddress")
	action := q.Get("action")
	from := q.Get("from")
	to := q.Get("to")

	var clauses []string
	var args []any
	if userID != "" {
		clauses = append(clauses, "user_id = ?")
		args = append(args, userID)
	}
	if ip != "" {
		clauses = append(clauses, "ip_address = ?")
		args = append(args, ip)
	}
	if action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, action)
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
SELECT id, timestamp, user_id, ip_address, action, file_name, database_query
FROM logs `+where+` ORDER BY timestamp DESC LIMIT 500`, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []LogRecord
	for rows.Next() {
		var ts string
		var lr LogRecord
		if err := rows.Scan(&lr.ID, &ts, &lr.UserID, &lr.IPAddress, &lr.Action, &lr.FileName, &lr.DatabaseQuery); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		lr.Timestamp, _ = time.Parse(time.RFC3339, ts)
		out = append(out, lr)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
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
