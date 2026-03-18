package main

import (
    "fmt"
    "strconv"
    "time"
)

func startAlertMonitor() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    for {
        runAlertsCheck()
        <-ticker.C
    }
}

func runAlertsCheck() {
    stats, err := readHostStats()
    if err != nil {
        return
    }
    load1, _ := strconv.ParseFloat(stats.Load1, 64)
    memUsed, _ := strconv.ParseFloat(stats.MemUsedPerc, 64)

    loadThresh := getSettingFloat("alert_load1", 1.5)
    memThresh := getSettingFloat("alert_mem", 85.0)

    updateAlert("load1", "warning", fmt.Sprintf("High load: %.2f (threshold %.2f)", load1, loadThresh), load1 >= loadThresh)
    updateAlert("mem", "warning", fmt.Sprintf("High memory usage: %.1f%% (threshold %.1f%%)", memUsed, memThresh), memUsed >= memThresh)
}

func getSettingFloat(key string, def float64) float64 {
    if db == nil {
        return def
    }
    var val string
    if err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val); err != nil {
        return def
    }
    f, err := strconv.ParseFloat(val, 64)
    if err != nil {
        return def
    }
    return f
}

func updateAlert(key, level, message string, active bool) {
    if db == nil {
        return
    }
    var id int64
    err := db.QueryRow(`SELECT id FROM alerts WHERE key = ? AND resolved_at IS NULL ORDER BY id DESC LIMIT 1`, key).Scan(&id)
    if active {
        if err == nil {
            return
        }
        _, _ = db.Exec(`INSERT INTO alerts(key, level, message, created_at) VALUES(?,?,?,?)`, key, level, message, nowTS())
        return
    }
    if err == nil {
        _, _ = db.Exec(`UPDATE alerts SET resolved_at = ? WHERE id = ?`, nowTS(), id)
    }
}

func listActiveAlerts() ([]Alert, error) {
    if db == nil {
        return nil, fmt.Errorf("db not initialized")
    }
    rows, err := db.Query(`SELECT id, key, level, message, created_at, resolved_at FROM alerts WHERE resolved_at IS NULL ORDER BY id DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    alerts := []Alert{}
    for rows.Next() {
        var a Alert
        if err := rows.Scan(&a.ID, &a.Key, &a.Level, &a.Message, &a.CreatedAt, &a.ResolvedAt); err != nil {
            return nil, err
        }
        alerts = append(alerts, a)
    }
    return alerts, nil
}
