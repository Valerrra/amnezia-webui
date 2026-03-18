package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "time"

    _ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() error {
    path := envOr("DB_PATH", "/opt/amnezia-webui/data/amnezia.db")
    dir := filepath.Dir(path)
    if err := os.MkdirAll(dir, 0o700); err != nil {
        return fmt.Errorf("mkdir db dir: %w", err)
    }

    d, err := sql.Open("sqlite", path)
    if err != nil {
        return fmt.Errorf("open db: %w", err)
    }
    d.SetMaxOpenConns(1)
    if _, err := d.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
        return fmt.Errorf("pragma: %w", err)
    }

    stmts := []string{
        `CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol_id TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT,
            public_key TEXT,
            private_key TEXT,
            preshared_key TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );`,
        `CREATE TABLE IF NOT EXISTS client_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            format TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
        );`,
        `CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            resolved_at TEXT
        );`,
        `CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );`,
        `CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );`,
        `CREATE TABLE IF NOT EXISTS split_tunnel (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mode TEXT NOT NULL,
            domains TEXT NOT NULL,
            subnets TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );`,
    }

    for _, stmt := range stmts {
        if _, err := d.Exec(stmt); err != nil {
            return fmt.Errorf("migrate: %w", err)
        }
    }

    db = d
    return nil
}

func nowTS() string {
    return time.Now().UTC().Format(time.RFC3339)
}

func getSplitTunnelConfig() (SplitTunnelConfig, error) {
    if db == nil {
        return SplitTunnelConfig{}, fmt.Errorf("db not initialized")
    }
    row := db.QueryRow(`SELECT mode, domains, subnets, updated_at FROM split_tunnel WHERE id = 1`)
    var mode, domainsRaw, subnetsRaw, updatedAt string
    if err := row.Scan(&mode, &domainsRaw, &subnetsRaw, &updatedAt); err != nil {
        if err == sql.ErrNoRows {
            return SplitTunnelConfig{
                Mode:      "exclude",
                Domains:   []string{},
                Subnets:   []string{},
                UpdatedAt: "",
            }, nil
        }
        return SplitTunnelConfig{}, err
    }
    var domains []string
    var subnets []string
    _ = json.Unmarshal([]byte(domainsRaw), &domains)
    _ = json.Unmarshal([]byte(subnetsRaw), &subnets)
    return SplitTunnelConfig{
        Mode:      mode,
        Domains:   domains,
        Subnets:   subnets,
        UpdatedAt: updatedAt,
    }, nil
}

func saveSplitTunnelConfig(cfg SplitTunnelConfig) error {
    if db == nil {
        return fmt.Errorf("db not initialized")
    }
    domainsRaw, _ := json.Marshal(cfg.Domains)
    subnetsRaw, _ := json.Marshal(cfg.Subnets)
    res, err := db.Exec(`UPDATE split_tunnel SET mode = ?, domains = ?, subnets = ?, updated_at = ? WHERE id = 1`,
        cfg.Mode, string(domainsRaw), string(subnetsRaw), cfg.UpdatedAt)
    if err != nil {
        return err
    }
    if rows, _ := res.RowsAffected(); rows > 0 {
        return nil
    }
    _, err = db.Exec(`INSERT INTO split_tunnel (id, mode, domains, subnets, updated_at) VALUES (1, ?, ?, ?, ?)`,
        cfg.Mode, string(domainsRaw), string(subnetsRaw), cfg.UpdatedAt)
    return err
}
