package main

import (
    "context"
    "embed"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "io/fs"
    "log"
    "net"
    "net/url"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"
)

//go:embed web/*
var webFS embed.FS

var (
    installMu   sync.Mutex
    installing = map[string]bool{}
)

type ContainerInfo struct {
    ID         string `json:"id"`
    Image      string `json:"image"`
    Command    string `json:"command"`
    CreatedAt  string `json:"created_at"`
    RunningFor string `json:"running_for"`
    Ports      string `json:"ports"`
    State      string `json:"state"`
    Status     string `json:"status"`
    Names      string `json:"names"`
    Labels     string `json:"labels"`
    Mounts     string `json:"mounts"`
    Networks   string `json:"networks"`
    StartedAt  string `json:"started_at"`
    ConfigPath string `json:"config_path"`
    CpuPerc    string `json:"cpu_perc"`
    MemUsage   string `json:"mem_usage"`
    MemPerc    string `json:"mem_perc"`
    NetIO      string `json:"net_io"`
    BlockIO    string `json:"block_io"`
    PIDs       string `json:"pids"`
    Connections string `json:"connections"`
}

type APIError struct {
    Error string `json:"error"`
}

type Health struct {
    Time      string `json:"time"`
    DockerOK  bool   `json:"docker_ok"`
    DockerVer string `json:"docker_version"`
}

type Protocol struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Container   string `json:"container"`
    Folder      string `json:"-"`
    Description string `json:"description"`
    Fields      []Field `json:"fields,omitempty"`
}

type ProtocolStatus struct {
    ID        string `json:"id"`
    Name      string `json:"name"`
    Container string `json:"container"`
    Installed bool   `json:"installed"`
    Running   bool   `json:"running"`
    Status    string `json:"status"`
    Ports     string `json:"ports"`
    Fields    []Field `json:"fields,omitempty"`
}

type Field struct {
    Key         string   `json:"key"`
    Label       string   `json:"label"`
    Type        string   `json:"type"`
    Default     string   `json:"default"`
    Required    bool     `json:"required"`
    Placeholder string   `json:"placeholder,omitempty"`
    Options     []string `json:"options,omitempty"`
    Sensitive   bool     `json:"sensitive,omitempty"`
}

type ContainerStats struct {
    Name     string `json:"Name"`
    CPUPerc  string `json:"CPUPerc"`
    MemUsage string `json:"MemUsage"`
    MemPerc  string `json:"MemPerc"`
    NetIO    string `json:"NetIO"`
    BlockIO  string `json:"BlockIO"`
    PIDs     string `json:"PIDs"`
}

type PortUsage struct {
    Port      string `json:"port"`
    Proto     string `json:"proto"`
    Container string `json:"container"`
    Service   string `json:"service"`
}

type HostStats struct {
    Time        string `json:"time"`
    Load1       string `json:"load1"`
    Load5       string `json:"load5"`
    Load15      string `json:"load15"`
    CpuCores    int    `json:"cpu_cores"`
    CpuLoadPerc string `json:"cpu_load_perc"`
    UptimeSec   string `json:"uptime_sec"`
    MemTotalKB  string `json:"mem_total_kb"`
    MemAvailKB  string `json:"mem_avail_kb"`
    MemUsedKB   string `json:"mem_used_kb"`
    MemUsedPerc string `json:"mem_used_perc"`
}

type Alert struct {
    ID         int64  `json:"id"`
    Key        string `json:"key"`
    Level      string `json:"level"`
    Message    string `json:"message"`
    CreatedAt  string `json:"created_at"`
    ResolvedAt string `json:"resolved_at,omitempty"`
}

type Client struct {
    ID         int64  `json:"id"`
    ProtocolID string `json:"protocol_id"`
    Name       string `json:"name"`
    Address    string `json:"address"`
    PublicKey  string `json:"public_key,omitempty"`
    CreatedAt  string `json:"created_at"`
}

type ClientFull struct {
    ID           int64
    ProtocolID   string
    Name         string
    Address      string
    PublicKey    string
    PrivateKey   string
    PresharedKey string
    CreatedAt    string
}

type SplitTunnelConfig struct {
    Mode      string   `json:"mode"`
    Domains   []string `json:"domains"`
    Subnets   []string `json:"subnets"`
    UpdatedAt string   `json:"updated_at,omitempty"`
}

func main() {
    port := envOr("WEBUI_PORT", "8090")
    user := envOr("WEBUI_USER", "admin")
    pass := envOr("WEBUI_PASSWORD", "changeme")

    if err := initDB(); err != nil {
        log.Fatalf("db init failed: %v", err)
    }
    go startAlertMonitor()

    staticFS, err := fs.Sub(webFS, "web")
    if err != nil {
        log.Fatalf("failed to init web assets: %v", err)
    }

    mux := http.NewServeMux()

    mux.Handle("/api/health", withBasicAuth(user, pass, http.HandlerFunc(handleHealth)))
    mux.Handle("/api/containers", withBasicAuth(user, pass, http.HandlerFunc(handleContainers)))
    mux.Handle("/api/containers/", withBasicAuth(user, pass, http.HandlerFunc(handleContainerAction)))
    mux.Handle("/api/protocols", withBasicAuth(user, pass, http.HandlerFunc(handleProtocols)))
    mux.Handle("/api/protocols/", withBasicAuth(user, pass, http.HandlerFunc(handleProtocolAction)))
    mux.Handle("/api/monitoring", withBasicAuth(user, pass, http.HandlerFunc(handleMonitoring)))
    mux.Handle("/api/ports", withBasicAuth(user, pass, http.HandlerFunc(handlePorts)))
    mux.Handle("/api/alerts", withBasicAuth(user, pass, http.HandlerFunc(handleAlerts)))
    mux.Handle("/api/clients", withBasicAuth(user, pass, http.HandlerFunc(handleClients)))
    mux.Handle("/api/clients/", withBasicAuth(user, pass, http.HandlerFunc(handleClientExport)))
    mux.Handle("/api/server/restart", withBasicAuth(user, pass, http.HandlerFunc(handleServerRestart)))
    mux.Handle("/api/split-tunnel", withBasicAuth(user, pass, http.HandlerFunc(handleSplitTunnel)))

    mux.Handle("/", withBasicAuth(user, pass, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        serveIndex(staticFS, w, r)
    })))
    mux.Handle("/static/", withBasicAuth(user, pass, http.StripPrefix("/static/", http.FileServer(http.FS(staticFS)))))

    srv := &http.Server{
        Addr:              ":" + port,
        Handler:           logRequests(mux),
        ReadHeaderTimeout: 5 * time.Second,
    }

    log.Printf("Amnezia WebUI listening on :%s", port)
    if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
        log.Fatalf("server error: %v", err)
    }
}

func envOr(key, def string) string {
    v := strings.TrimSpace(os.Getenv(key))
    if v == "" {
        return def
    }
    return v
}

func withBasicAuth(user, pass string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        u, p, ok := r.BasicAuth()
        if !ok || u != user || p != pass {
            w.Header().Set("WWW-Authenticate", "Basic realm=\"Amnezia WebUI\"")
            w.WriteHeader(http.StatusUnauthorized)
            _ = json.NewEncoder(w).Encode(APIError{Error: "unauthorized"})
            return
        }
        next.ServeHTTP(w, r)
    })
}

func serveIndex(staticFS fs.FS, w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        http.NotFound(w, r)
        return
    }
    data, err := fs.ReadFile(staticFS, "index.html")
    if err != nil {
        http.Error(w, "index not found", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write(data)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    dockerVer, err := runCmd("docker", "--version")
    resp := Health{
        Time:     time.Now().Format(time.RFC3339),
        DockerOK: err == nil,
    }
    if err == nil {
        resp.DockerVer = strings.TrimSpace(dockerVer)
    }
    writeJSON(w, resp)
}

func handleContainers(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        methodNotAllowed(w)
        return
    }

    out, err := runCmd("docker", "ps", "-a", "--format", "{{json .}}")
    if err != nil {
        writeJSONErr(w, http.StatusInternalServerError, err)
        return
    }

    stats := getContainerStats()
    containers := parseContainers(out, stats)
    writeJSON(w, containers)
}

func handleContainerAction(w http.ResponseWriter, r *http.Request) {
    // /api/containers/{name}/action
    if r.Method != http.MethodPost && r.Method != http.MethodGet {
        methodNotAllowed(w)
        return
    }

    path := strings.TrimPrefix(r.URL.Path, "/api/containers/")
    parts := strings.Split(path, "/")
    if len(parts) < 2 {
        http.NotFound(w, r)
        return
    }
    name := parts[0]
    action := parts[1]

    switch action {
    case "start", "stop", "restart":
        if r.Method != http.MethodPost {
            methodNotAllowed(w)
            return
        }
        if err := runCmdNoOutput("docker", action, name); err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, map[string]string{"status": "ok"})
        return
    case "logs":
        if r.Method != http.MethodGet {
            methodNotAllowed(w)
            return
        }
        tail := 200
        if v := r.URL.Query().Get("tail"); v != "" {
            if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
                tail = n
            }
        }
        out, err := runCmd("docker", "logs", "--tail", strconv.Itoa(tail), name)
        if err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, map[string]string{"logs": out})
        return
    case "export":
        if r.Method != http.MethodGet {
            methodNotAllowed(w)
            return
        }
        path, ok := configPathForContainer(name)
        if !ok {
            writeJSONErr(w, http.StatusNotFound, fmt.Errorf("export not supported for container %s", name))
            return
        }
        out, err := runCmd("docker", "exec", name, "sh", "-c", "cat "+shellEscape(path))
        if err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, map[string]string{"path": path, "content": out})
        return
    case "config":
        if r.Method == http.MethodGet {
            path, ok := configPathForContainer(name)
            if !ok {
                writeJSONErr(w, http.StatusNotFound, fmt.Errorf("config not supported for container %s", name))
                return
            }
            out, err := runCmd("docker", "exec", name, "sh", "-c", "cat "+shellEscape(path))
            if err != nil {
                writeJSONErr(w, http.StatusInternalServerError, err)
                return
            }
            writeJSON(w, map[string]string{"path": path, "content": out})
            return
        }
        if r.Method == http.MethodPost {
            path, ok := configPathForContainer(name)
            if !ok {
                writeJSONErr(w, http.StatusNotFound, fmt.Errorf("config not supported for container %s", name))
                return
            }
            body, err := io.ReadAll(io.LimitReader(r.Body, 512*1024))
            if err != nil {
                writeJSONErr(w, http.StatusBadRequest, err)
                return
            }
            var payload struct {
                Content string `json:"content"`
            }
            if err := json.Unmarshal(body, &payload); err != nil {
                writeJSONErr(w, http.StatusBadRequest, err)
                return
            }
            if err := writeFileInContainer(name, path, payload.Content); err != nil {
                writeJSONErr(w, http.StatusInternalServerError, err)
                return
            }
            writeJSON(w, map[string]string{"status": "ok"})
            return
        }
        methodNotAllowed(w)
        return
    default:
        http.NotFound(w, r)
        return
    }
}

func handleMonitoring(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        methodNotAllowed(w)
        return
    }
    stats, err := readHostStats()
    if err != nil {
        writeJSONErr(w, http.StatusInternalServerError, err)
        return
    }
    writeJSON(w, stats)
}

func handleProtocols(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        methodNotAllowed(w)
        return
    }
    out, err := runCmd("docker", "ps", "-a", "--format", "{{json .}}")
    if err != nil {
        writeJSONErr(w, http.StatusInternalServerError, err)
        return
    }
    containers := parseContainers(out, nil)
    byName := map[string]ContainerInfo{}
    for _, c := range containers {
        byName[c.Names] = c
    }

    statuses := make([]ProtocolStatus, 0)
    for _, p := range protocols() {
        c, ok := byName[p.Container]
        status := ProtocolStatus{
            ID:        p.ID,
            Name:      p.Name,
            Container: p.Container,
            Installed: ok,
            Running:   ok && c.State == "running",
            Status:    c.Status,
            Ports:     c.Ports,
            Fields:    p.Fields,
        }
        statuses = append(statuses, status)
    }
    writeJSON(w, statuses)
}

func handleProtocolAction(w http.ResponseWriter, r *http.Request) {
    // /api/protocols/{id}/install|remove
    if r.Method != http.MethodPost {
        methodNotAllowed(w)
        return
    }
    path := strings.TrimPrefix(r.URL.Path, "/api/protocols/")
    parts := strings.Split(path, "/")
    if len(parts) < 2 {
        http.NotFound(w, r)
        return
    }
    id := parts[0]
    action := parts[1]

    p, ok := protocolByID(id)
    if !ok {
        writeJSONErr(w, http.StatusNotFound, fmt.Errorf("unknown protocol: %s", id))
        return
    }

    switch action {
    case "install":
        var payload struct {
            Options map[string]string `json:"options"`
        }
        if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
            writeJSONErr(w, http.StatusBadRequest, err)
            return
        }
        if !beginInstall(id) {
            writeJSONErr(w, http.StatusConflict, fmt.Errorf("install already in progress"))
            return
        }
        defer endInstall(id)
        if err := installProtocol(p, payload.Options); err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, map[string]string{"status": "ok"})
        return
    case "remove":
        if err := removeProtocol(p); err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, map[string]string{"status": "ok"})
        return
    default:
        http.NotFound(w, r)
        return
    }
}

func handleServerRestart(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        methodNotAllowed(w)
        return
    }
    go func() {
        _ = runCmdNoOutput("sh", "-c", "sleep 1 && systemctl reboot")
    }()
    writeJSON(w, map[string]string{"status": "restarting"})
}

func handlePorts(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        methodNotAllowed(w)
        return
    }
    writeJSON(w, listPortUsage())
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        methodNotAllowed(w)
        return
    }
    alerts, err := listActiveAlerts()
    if err != nil {
        writeJSONErr(w, http.StatusInternalServerError, err)
        return
    }
    writeJSON(w, alerts)
}

func handleSplitTunnel(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        cfg, err := getSplitTunnelConfig()
        if err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, cfg)
        return
    case http.MethodPost:
        var payload struct {
            Mode    string   `json:"mode"`
            Domains []string `json:"domains"`
            Subnets []string `json:"subnets"`
            Apply   bool     `json:"apply"`
        }
        if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
            writeJSONErr(w, http.StatusBadRequest, err)
            return
        }
        mode := strings.ToLower(strings.TrimSpace(payload.Mode))
        if mode != "include" && mode != "exclude" {
            mode = "exclude"
        }
        cfg := SplitTunnelConfig{
            Mode:      mode,
            Domains:   normalizeList(payload.Domains),
            Subnets:   normalizeList(payload.Subnets),
            UpdatedAt: nowTS(),
        }
        if err := saveSplitTunnelConfig(cfg); err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        if payload.Apply {
            go func(c SplitTunnelConfig) {
                if err := applySplitTunnel(c); err != nil {
                    log.Printf("split-tunnel apply error: %v", err)
                }
            }(cfg)
        }
        writeJSON(w, cfg)
        return
    default:
        methodNotAllowed(w)
        return
    }
}

func handleClients(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        protocolID := r.URL.Query().Get("protocol")
        clients, err := listClients(protocolID)
        if err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, clients)
        return
    case http.MethodPost:
        var payload struct {
            ProtocolID string `json:"protocol_id"`
            Name       string `json:"name"`
        }
        if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
            writeJSONErr(w, http.StatusBadRequest, err)
            return
        }
        client, exports, err := createClient(payload.ProtocolID, payload.Name)
        if err != nil {
            writeJSONErr(w, http.StatusBadRequest, err)
            return
        }
        writeJSON(w, map[string]any{
            "client":  client,
            "exports": exports,
        })
        return
    default:
        methodNotAllowed(w)
        return
    }
}

func handleClientExport(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/api/clients/")
    parts := strings.Split(path, "/")
    if len(parts) == 1 && r.Method == http.MethodDelete {
        id, err := strconv.ParseInt(parts[0], 10, 64)
        if err != nil {
            writeJSONErr(w, http.StatusBadRequest, fmt.Errorf("invalid client id"))
            return
        }
        if err := deleteClient(id); err != nil {
            writeJSONErr(w, http.StatusInternalServerError, err)
            return
        }
        writeJSON(w, map[string]string{"status": "deleted"})
        return
    }
    if len(parts) < 2 || parts[1] != "export" || r.Method != http.MethodGet {
        http.NotFound(w, r)
        return
    }
    id, err := strconv.ParseInt(parts[0], 10, 64)
    if err != nil {
        writeJSONErr(w, http.StatusBadRequest, fmt.Errorf("invalid client id"))
        return
    }
    exports, err := getClientExports(id)
    if err != nil {
        writeJSONErr(w, http.StatusInternalServerError, err)
        return
    }
    client, _ := getClientByID(id)
    full, _ := getClientFull(id)

    if exports["config"] == "" {
        if p, ok := protocolByID(full.ProtocolID); ok {
            if cfg, err := rebuildClientConfig(p, full); err == nil && cfg != "" {
                exports["config"] = cfg
                _ = insertClientConfig(id, "config", cfg, nowTS())
            }
        }
    }
    if cfg := exports["config"]; cfg != "" {
        vpnVal := exports["vpn"]
        if vpnVal == "" {
            if p, ok := protocolByID(client.ProtocolID); ok {
                amn := buildAmneziaConfigFromProtocol(p, cfg, client.Name)
                if amn != "" {
                    exports["vpn"] = buildVPNString(amn)
                }
            }
        } else if _, err := decodeVPN(vpnVal); err != nil {
            if p, ok := protocolByID(client.ProtocolID); ok {
                amn := buildAmneziaConfigFromProtocol(p, cfg, client.Name)
                if amn != "" {
                    exports["vpn"] = buildVPNString(amn)
                }
            }
        }
    }
    if exports["telegram"] == "" {
        if telegram := telegramFromSocksConfig(exports["config"]); telegram != "" {
            exports["telegram"] = telegram
        }
    }

    resp := map[string]any{}
    for k, v := range exports {
        resp[k] = v
    }

    if vpn := exports["vpn"]; vpn != "" {
        if raw, err := decodeVPN(vpn); err == nil {
            chunks := buildQrChunks(raw)
            pngs := []string{}
            for _, chunk := range chunks {
                if qr, err := buildQRPngBase64(chunk); err == nil {
                    pngs = append(pngs, qr)
                }
            }
            if len(pngs) > 0 {
                resp["qr_pngs"] = pngs
                resp["qr_png"] = pngs[0]
            }
        }
    }

    writeJSON(w, resp)
}

func beginInstall(id string) bool {
    installMu.Lock()
    defer installMu.Unlock()
    if installing[id] {
        return false
    }
    installing[id] = true
    return true
}

func endInstall(id string) {
    installMu.Lock()
    defer installMu.Unlock()
    delete(installing, id)
}

func writeJSON(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type", "application/json")
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    _ = enc.Encode(v)
}

func writeJSONErr(w http.ResponseWriter, code int, err error) {
    w.WriteHeader(code)
    _ = json.NewEncoder(w).Encode(APIError{Error: err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
    w.WriteHeader(http.StatusMethodNotAllowed)
    _ = json.NewEncoder(w).Encode(APIError{Error: "method not allowed"})
}

func runCmd(name string, args ...string) (string, error) {
    cmd := exec.Command(name, args...)
    cmd.Env = os.Environ()
    out, err := cmd.CombinedOutput()
    if err != nil {
        return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
    }
    return string(out), nil
}

func runCmdNoOutput(name string, args ...string) error {
    cmd := exec.Command(name, args...)
    cmd.Env = os.Environ()
    cmd.Stdout = io.Discard
    cmd.Stderr = io.Discard
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
    }
    return nil
}

func logRequests(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        next.ServeHTTP(w, r)
        log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
    })
}

func inspectStartedAt(name string) (string, error) {
    out, err := runCmd("docker", "inspect", "--format", "{{.State.StartedAt}}", name)
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(out), nil
}

func configPathForContainer(name string) (string, bool) {
    switch name {
    case "amnezia-awg":
        return "/opt/amnezia/awg/wg0.conf", true
    case "amnezia-awg2":
        return "/opt/amnezia/awg/awg0.conf", true
    case "amnezia-wireguard":
        return "/opt/amnezia/wireguard/wg0.conf", true
    case "amnezia-openvpn", "amnezia-openvpn-cloak", "amnezia-shadowsocks":
        return "/opt/amnezia/openvpn/server.conf", true
    case "amnezia-xray":
        return "/opt/amnezia/xray/server.json", true
    case "amnezia-socks5proxy":
        return "/usr/local/3proxy/conf/3proxy.cfg", true
    case "amnezia-dns":
        return "/opt/amnezia/dns/unbound.conf", true
    case "amnezia-sftp":
        return "/etc/ssh/sshd_config", true
    default:
        return "", false
    }
}

func writeFileInContainer(name, path, content string) error {
    cmd := exec.Command("docker", "exec", "-i", name, "sh", "-c", "cat > "+shellEscape(path))
    cmd.Env = os.Environ()
    cmd.Stdin = strings.NewReader(content)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("write config: %w: %s", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func shellEscape(s string) string {
    // minimal escaping for paths without spaces
    if strings.ContainsAny(s, " \\\"'$`") {
        return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
    }
    return s
}

func parseContainers(out string, stats map[string]ContainerStats) []ContainerInfo {
    lines := strings.Split(strings.TrimSpace(out), "\n")
    containers := make([]ContainerInfo, 0, len(lines))
    for _, line := range lines {
        if strings.TrimSpace(line) == "" {
            continue
        }
        var raw map[string]string
        if err := json.Unmarshal([]byte(line), &raw); err != nil {
            continue
        }
        name := raw["Names"]
        info := ContainerInfo{
            ID:         raw["ID"],
            Image:      raw["Image"],
            Command:    raw["Command"],
            CreatedAt:  raw["CreatedAt"],
            RunningFor: raw["RunningFor"],
            Ports:      raw["Ports"],
            State:      raw["State"],
            Status:     raw["Status"],
            Names:      name,
            Labels:     raw["Labels"],
            Mounts:     raw["Mounts"],
            Networks:   raw["Networks"],
        }

        if startedAt, err := inspectStartedAt(name); err == nil {
            info.StartedAt = startedAt
        }
        if path, ok := configPathForContainer(name); ok {
            info.ConfigPath = path
        }
        if stats != nil {
            if s, ok := stats[name]; ok {
                info.CpuPerc = s.CPUPerc
                info.MemUsage = s.MemUsage
                info.MemPerc = s.MemPerc
                info.NetIO = s.NetIO
                info.BlockIO = s.BlockIO
                info.PIDs = s.PIDs
            }
        }
        info.Connections = connectionsForContainer(info)
        containers = append(containers, info)
    }
    return containers
}

func protocols() []Protocol {
    return []Protocol{
        {ID: "awg", Name: "AmneziaWG (legacy)", Container: "amnezia-awg", Folder: "awg_legacy", Description: "AWG v1.5", Fields: []Field{
            {Key: "port", Label: "Порт (UDP)", Type: "number", Default: "55424", Required: true},
        }},
        {ID: "awg2", Name: "AmneziaWG v2", Container: "amnezia-awg2", Folder: "awg", Description: "AWG v2", Fields: []Field{
            {Key: "port", Label: "Порт (UDP)", Type: "number", Default: "55424", Required: true},
        }},
        {ID: "wireguard", Name: "WireGuard", Container: "amnezia-wireguard", Folder: "wireguard", Fields: []Field{
            {Key: "port", Label: "Порт (UDP)", Type: "number", Default: "51820", Required: true},
        }},
        {ID: "openvpn", Name: "OpenVPN", Container: "amnezia-openvpn", Folder: "openvpn", Fields: []Field{
            {Key: "port", Label: "Порт", Type: "number", Default: "1194", Required: true},
            {Key: "transport", Label: "Транспорт", Type: "select", Default: "udp", Required: true, Options: []string{"udp", "tcp"}},
        }},
        {ID: "cloak", Name: "OpenVPN over Cloak", Container: "amnezia-openvpn-cloak", Folder: "openvpn_cloak", Fields: []Field{
            {Key: "port", Label: "Порт (TCP)", Type: "number", Default: "443", Required: true},
            {Key: "site", Label: "Fake site", Type: "text", Default: "tile.openstreetmap.org", Required: true},
        }},
        {ID: "shadowsocks", Name: "OpenVPN over Shadowsocks", Container: "amnezia-shadowsocks", Folder: "openvpn_shadowsocks", Fields: []Field{
            {Key: "port", Label: "Порт", Type: "number", Default: "6789", Required: true},
        }},
        {ID: "xray", Name: "Xray (Reality)", Container: "amnezia-xray", Folder: "xray", Fields: []Field{
            {Key: "port", Label: "Порт (TCP)", Type: "number", Default: "443", Required: true},
            {Key: "site", Label: "Site", Type: "text", Default: "www.googletagmanager.com", Required: true},
        }},
        {ID: "ipsec", Name: "IPsec/IKEv2", Container: "amnezia-ipsec", Folder: "ipsec"},
        {ID: "dns", Name: "AmneziaDNS", Container: "amnezia-dns", Folder: "dns"},
        {ID: "socks5", Name: "SOCKS5 Proxy", Container: "amnezia-socks5proxy", Folder: "socks5_proxy", Fields: []Field{
            {Key: "port", Label: "Порт (TCP)", Type: "number", Default: "38080", Required: true},
            {Key: "user", Label: "Логин", Type: "text", Default: "proxy_user", Required: true},
            {Key: "pass", Label: "Пароль", Type: "password", Default: "proxy_pass", Required: true, Sensitive: true},
        }},
        {ID: "sftp", Name: "SFTP", Container: "amnezia-sftp", Folder: "sftp", Fields: []Field{
            {Key: "port", Label: "Порт (TCP)", Type: "number", Default: "2222", Required: true},
            {Key: "user", Label: "Логин", Type: "text", Default: "sftp_user", Required: true},
            {Key: "pass", Label: "Пароль", Type: "password", Default: "sftp_pass", Required: true, Sensitive: true},
        }},
    }
}

func protocolByID(id string) (Protocol, bool) {
    for _, p := range protocols() {
        if p.ID == id {
            return p, true
        }
    }
    return Protocol{}, false
}

func installProtocol(p Protocol, options map[string]string) error {
    if _, err := runCmd("docker", "--version"); err != nil {
        return fmt.Errorf("docker not available: %w", err)
    }
    if options == nil {
        options = map[string]string{}
    }

    if err := ensureNotInstalled(p.Container); err != nil {
        return err
    }
    if err := ensurePortsAvailable(p, options); err != nil {
        return err
    }
    if err := ensureDockerNetwork(); err != nil {
        return err
    }

    scriptsDir := envOr("SCRIPTS_DIR", "/opt/amnezia-webui/scripts")
    srcDir := filepath.Join(scriptsDir, p.Folder)
    dstDir := filepath.Join("/opt/amnezia", p.Container)

    if err := runCmdNoOutput("mkdir", "-p", dstDir); err != nil {
        return fmt.Errorf("mkdir %s: %w", dstDir, err)
    }
    if err := runCmdNoOutput("sh", "-c", fmt.Sprintf("cp -r %s/. %s/", shellEscape(srcDir), shellEscape(dstDir))); err != nil {
        return fmt.Errorf("copy scripts: %w", err)
    }
    _ = runCmdNoOutput("sh", "-c", fmt.Sprintf("chmod +x %s/*.sh", shellEscape(dstDir)))

    if err := runCmdNoOutput("docker", "build", "--no-cache", "--pull", "-t", p.Container, dstDir); err != nil {
        return fmt.Errorf("docker build: %w", err)
    }

    env := protocolEnv(p, options)
    if err := runHostScript(filepath.Join(dstDir, "run_container.sh"), env); err != nil {
        return fmt.Errorf("run container: %w", err)
    }

    if err := runContainerConfigure(p.Container, filepath.Join(dstDir, "configure_container.sh"), env); err != nil {
        return fmt.Errorf("configure container: %w", err)
    }

    if _, err := os.Stat(filepath.Join(dstDir, "start.sh")); err == nil {
        if err := uploadStartAndRun(p.Container, filepath.Join(dstDir, "start.sh"), env); err != nil {
            return fmt.Errorf("start script: %w", err)
        }
    }

    return nil
}

func removeProtocol(p Protocol) error {
    _ = runCmdNoOutput("docker", "rm", "-f", p.Container)
    _ = runCmdNoOutput("docker", "rmi", p.Container)
    return nil
}

func ensureDockerNetwork() error {
    if err := runCmdNoOutput("docker", "network", "inspect", "amnezia-dns-net"); err == nil {
        return nil
    }
    return runCmdNoOutput("docker", "network", "create",
        "--driver", "bridge",
        "--subnet=172.29.172.0/24",
        "--opt", "com.docker.network.bridge.name=amn0",
        "amnezia-dns-net",
    )
}

func ensureNotInstalled(container string) error {
    if err := runCmdNoOutput("docker", "inspect", container); err == nil {
        return fmt.Errorf("container %s already installed", container)
    }
    return nil
}

type portBinding struct {
    Port  string
    Proto string
}

type portOwner struct {
    Container string
    Service   string
}

func ensurePortsAvailable(p Protocol, options map[string]string) error {
    desired := desiredPortsForProtocol(p, options)
    if len(desired) == 0 {
        return nil
    }
    used := usedPortsMap()
    for _, d := range desired {
        if d.Port == "" || d.Proto == "" {
            continue
        }
        key := strings.ToLower(d.Port + "/" + d.Proto)
        if owner, ok := used[key]; ok {
            name := owner.Service
            if name == "" {
                name = owner.Container
            }
            return fmt.Errorf("порт %s/%s уже занят: %s", d.Port, d.Proto, name)
        }
    }
    return nil
}

func desiredPortsForProtocol(p Protocol, options map[string]string) []portBinding {
    get := func(key string) string {
        if v, ok := options[key]; ok && strings.TrimSpace(v) != "" {
            return strings.TrimSpace(v)
        }
        return defaultForField(p, key)
    }
    switch p.ID {
    case "wireguard", "awg", "awg2":
        return []portBinding{{Port: get("port"), Proto: "udp"}}
    case "openvpn":
        port := get("port")
        transport := strings.ToLower(get("transport"))
        if transport != "tcp" {
            transport = "udp"
        }
        return []portBinding{{Port: port, Proto: transport}}
    case "cloak":
        return []portBinding{{Port: get("port"), Proto: "tcp"}}
    case "shadowsocks":
        return []portBinding{{Port: get("port"), Proto: "tcp"}}
    case "xray":
        return []portBinding{{Port: get("port"), Proto: "tcp"}}
    case "socks5":
        return []portBinding{{Port: get("port"), Proto: "tcp"}}
    case "sftp":
        return []portBinding{{Port: get("port"), Proto: "tcp"}}
    case "dns":
        return []portBinding{
            {Port: "53", Proto: "udp"},
            {Port: "53", Proto: "tcp"},
        }
    case "ipsec":
        return []portBinding{
            {Port: "500", Proto: "udp"},
            {Port: "4500", Proto: "udp"},
        }
    default:
        return nil
    }
}

func defaultForField(p Protocol, key string) string {
    for _, f := range p.Fields {
        if f.Key == key {
            return f.Default
        }
    }
    return ""
}

func usedPortsMap() map[string]portOwner {
    m := map[string]portOwner{}
    for _, u := range listPortUsage() {
        key := strings.ToLower(u.Port + "/" + u.Proto)
        if _, ok := m[key]; ok {
            continue
        }
        m[key] = portOwner{Container: u.Container, Service: u.Service}
    }
    return m
}

func listPortUsage() []PortUsage {
    out, err := runCmd("docker", "ps", "--format", "{{.Names}}|{{.Ports}}")
    if err != nil {
        return nil
    }
    lines := strings.Split(strings.TrimSpace(out), "\n")
    usage := []PortUsage{}
    seen := map[string]bool{}
    for _, line := range lines {
        if strings.TrimSpace(line) == "" {
            continue
        }
        parts := strings.SplitN(line, "|", 2)
        name := strings.TrimSpace(parts[0])
        ports := ""
        if len(parts) > 1 {
            ports = parts[1]
        }
        service := protocolNameByContainer(name)
        for _, b := range parseHostPorts(ports) {
            key := name + "|" + b.Port + "/" + b.Proto
            if seen[key] {
                continue
            }
            seen[key] = true
            usage = append(usage, PortUsage{
                Port:      b.Port,
                Proto:     b.Proto,
                Container: name,
                Service:   service,
            })
        }
    }
    return usage
}

func parseHostPorts(ports string) []portBinding {
    if strings.TrimSpace(ports) == "" {
        return nil
    }
    parts := strings.Split(ports, ",")
    out := []portBinding{}
    seen := map[string]bool{}
    for _, part := range parts {
        p := strings.TrimSpace(part)
        if !strings.Contains(p, "->") {
            continue
        }
        lr := strings.SplitN(p, "->", 2)
        hostPart := strings.TrimSpace(lr[0])
        contPart := strings.TrimSpace(lr[1])
        idx := strings.LastIndex(hostPart, ":")
        if idx == -1 {
            continue
        }
        port := strings.TrimSpace(hostPart[idx+1:])
        if port == "" {
            continue
        }
        proto := ""
        if slash := strings.LastIndex(contPart, "/"); slash != -1 {
            proto = strings.TrimSpace(contPart[slash+1:])
        }
        if proto == "" {
            continue
        }
        key := port + "/" + proto
        if seen[key] {
            continue
        }
        seen[key] = true
        out = append(out, portBinding{Port: port, Proto: proto})
    }
    return out
}

func protocolNameByContainer(container string) string {
    for _, p := range protocols() {
        if p.Container == container {
            return p.Name
        }
    }
    return container
}

func listClients(protocolID string) ([]Client, error) {
    if db == nil {
        return nil, fmt.Errorf("db not initialized")
    }
    rows, err := db.Query(`SELECT id, protocol_id, name, address, public_key, created_at FROM clients WHERE (? = '' OR protocol_id = ?) ORDER BY id DESC`, protocolID, protocolID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    out := []Client{}
    for rows.Next() {
        var c Client
        if err := rows.Scan(&c.ID, &c.ProtocolID, &c.Name, &c.Address, &c.PublicKey, &c.CreatedAt); err != nil {
            return nil, err
        }
        out = append(out, c)
    }
    return out, nil
}

func getClientByID(id int64) (Client, error) {
    if db == nil {
        return Client{}, fmt.Errorf("db not initialized")
    }
    row := db.QueryRow(`SELECT id, protocol_id, name, address, public_key, created_at FROM clients WHERE id = ?`, id)
    var c Client
    if err := row.Scan(&c.ID, &c.ProtocolID, &c.Name, &c.Address, &c.PublicKey, &c.CreatedAt); err != nil {
        return Client{}, err
    }
    return c, nil
}

func getClientFull(id int64) (ClientFull, error) {
    if db == nil {
        return ClientFull{}, fmt.Errorf("db not initialized")
    }
    row := db.QueryRow(`SELECT id, protocol_id, name, address, public_key, private_key, preshared_key, created_at FROM clients WHERE id = ?`, id)
    var c ClientFull
    if err := row.Scan(&c.ID, &c.ProtocolID, &c.Name, &c.Address, &c.PublicKey, &c.PrivateKey, &c.PresharedKey, &c.CreatedAt); err != nil {
        return ClientFull{}, err
    }
    return c, nil
}

func getClientExports(id int64) (map[string]string, error) {
    if db == nil {
        return nil, fmt.Errorf("db not initialized")
    }
    rows, err := db.Query(`SELECT format, content FROM client_configs WHERE client_id = ? ORDER BY id DESC`, id)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    out := map[string]string{}
    for rows.Next() {
        var format, content string
        if err := rows.Scan(&format, &content); err != nil {
            return nil, err
        }
        if format == "wg" {
            out["config"] = content
        } else {
            out[format] = content
        }
    }
    return out, nil
}

func decodeVPN(vpn string) ([]byte, error) {
    vpn = strings.TrimSpace(vpn)
    if strings.HasPrefix(vpn, "vpn://") {
        vpn = strings.TrimPrefix(vpn, "vpn://")
    }
    if vpn == "" {
        return nil, fmt.Errorf("empty vpn")
    }
    return base64.RawURLEncoding.DecodeString(vpn)
}

func buildAmneziaConfigFromProtocol(p Protocol, config, name string) string {
    desc := nameOrDefault(name, p.Name)
    withSplit := func(raw string) string {
        cfg, err := getSplitTunnelConfig()
        if err != nil {
            return raw
        }
        return applySplitTunnelToJSON(raw, cfg)
    }
    switch p.ID {
    case "wireguard":
        return withSplit(buildAmneziaConfigFromWireGuardConfig(config, "wireguard", p.Container, desc, ""))
    case "awg", "awg2":
        return withSplit(buildAmneziaConfigFromWireGuardConfig(config, "awg", p.Container, desc, ""))
    case "openvpn", "cloak", "shadowsocks":
        return withSplit(buildAmneziaConfigFromOpenVPNConfig(config, desc))
    case "xray":
        if strings.HasPrefix(strings.TrimSpace(config), "{") {
            return withSplit(buildAmneziaConfigFromXrayConfig(config, desc))
        }
        return ""
    default:
        return ""
    }
}

func telegramFromSocksConfig(config string) string {
    lines := strings.Split(config, "\n")
    vals := map[string]string{}
    for _, line := range lines {
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 {
            continue
        }
        key := strings.TrimSpace(parts[0])
        val := strings.TrimSpace(parts[1])
        if key != "" && val != "" {
            vals[strings.ToLower(key)] = val
        }
    }
    server := vals["server"]
    port := vals["port"]
    user := vals["user"]
    pass := vals["pass"]
    if server == "" || port == "" || user == "" || pass == "" {
        return ""
    }
    return fmt.Sprintf("https://t.me/socks?server=%s&port=%s&user=%s&pass=%s",
        url.QueryEscape(server), url.QueryEscape(port), url.QueryEscape(user), url.QueryEscape(pass))
}

func normalizeList(items []string) []string {
    seen := map[string]bool{}
    out := []string{}
    for _, item := range items {
        t := strings.TrimSpace(item)
        if t == "" {
            continue
        }
        key := strings.ToLower(t)
        if seen[key] {
            continue
        }
        seen[key] = true
        out = append(out, t)
    }
    return out
}

func applySplitTunnel(cfg SplitTunnelConfig) error {
    if db == nil {
        return fmt.Errorf("db not initialized")
    }
    type clientRow struct {
        id         int64
        protocolID string
        name       string
    }
    rows, err := db.Query(`SELECT id, protocol_id, name FROM clients ORDER BY id DESC`)
    if err != nil {
        return err
    }
    items := []clientRow{}
    for rows.Next() {
        var item clientRow
        if err := rows.Scan(&item.id, &item.protocolID, &item.name); err != nil {
            continue
        }
        items = append(items, item)
    }
    rows.Close()

    for _, item := range items {
        id := item.id
        protocolID := item.protocolID
        name := item.name
        exports, _ := getClientExports(id)
        amn := exports["amnezia_json"]
        if amn == "" {
            config := exports["config"]
            if config == "" {
                if full, err := getClientFull(id); err == nil {
                    if p, ok := protocolByID(full.ProtocolID); ok {
                        if cfgStr, err := rebuildClientConfig(p, full); err == nil {
                            config = cfgStr
                        }
                    }
                }
            }
            if config != "" {
                if p, ok := protocolByID(protocolID); ok {
                    amn = buildAmneziaConfigFromProtocol(p, config, name)
                }
            }
        }
        if amn == "" {
            continue
        }
        amn = applySplitTunnelToJSON(amn, cfg)
        vpn := buildVPNString(amn)
        _ = insertClientConfig(id, "amnezia_json", amn, nowTS())
        _ = insertClientConfig(id, "vpn", vpn, nowTS())
    }
    if envOr("SPLIT_TUNNEL_SYSTEM", "") == "1" {
        if err := applySplitTunnelSystem(cfg); err != nil {
            log.Printf("split-tunnel system apply error: %v", err)
        }
    }
    log.Printf("split-tunnel applied: mode=%s domains=%d subnets=%d", cfg.Mode, len(cfg.Domains), len(cfg.Subnets))
    return nil
}

func splitTunnelType(mode string, sites []string) int {
    if len(sites) == 0 {
        return 0
    }
    switch strings.ToLower(mode) {
    case "include":
        return 1
    case "exclude":
        return 2
    default:
        return 0
    }
}

func splitTunnelSites(cfg SplitTunnelConfig) []string {
    uniq := map[string]bool{}
    add := func(val string) {
        val = strings.TrimSpace(val)
        if val == "" {
            return
        }
        if uniq[val] {
            return
        }
        uniq[val] = true
    }
    addCIDR := func(ip net.IP) {
        if ip == nil {
            return
        }
        if ip.To4() != nil {
            add(ip.String() + "/32")
        } else {
            add(ip.String() + "/128")
        }
    }
    resolveDomain := func(domain string) {
        domain = strings.TrimSpace(domain)
        if domain == "" {
            return
        }
        if ip := net.ParseIP(domain); ip != nil {
            addCIDR(ip)
            return
        }
        if _, _, err := net.ParseCIDR(domain); err == nil {
            add(domain)
            return
        }
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
        if err != nil {
            log.Printf("split-tunnel resolve failed for %s: %v", domain, err)
            return
        }
        for _, ip := range ips {
            addCIDR(ip.IP)
        }
    }
    for _, s := range cfg.Subnets {
        resolveDomain(s)
    }
    for _, d := range cfg.Domains {
        resolveDomain(d)
    }
    out := make([]string, 0, len(uniq))
    for val := range uniq {
        out = append(out, val)
    }
    sort.Strings(out)
    return out
}

func applySplitTunnelToJSON(raw string, cfg SplitTunnelConfig) string {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return raw
    }
    var top map[string]any
    if err := json.Unmarshal([]byte(raw), &top); err != nil {
        return raw
    }
    sites := splitTunnelSites(cfg)
    mode := splitTunnelType(cfg.Mode, sites)
    if mode == 1 {
        addDns := func(val string) {
            if ip := net.ParseIP(val); ip != nil {
                if ip.To4() != nil {
                    sites = append(sites, ip.String()+"/32")
                } else {
                    sites = append(sites, ip.String()+"/128")
                }
            }
        }
        if dns1, ok := top[config_key_dns1].(string); ok && dns1 != "" {
            addDns(dns1)
        }
        if dns2, ok := top[config_key_dns2].(string); ok && dns2 != "" {
            addDns(dns2)
        }
    }
    top[config_key_splitTunnelType] = mode
    top[config_key_splitTunnelSites] = sites
    out, err := json.Marshal(top)
    if err != nil {
        return raw
    }
    return string(out)
}

func applySplitTunnelSystem(cfg SplitTunnelConfig) error {
    sites := splitTunnelSites(cfg)
    mode := splitTunnelType(cfg.Mode, sites)
    if mode == 0 {
        _ = runCmdNoOutput("nft", "delete", "table", "inet", "split_tunnel")
        return nil
    }

    v4 := []string{}
    v6 := []string{}
    for _, s := range sites {
        if strings.Contains(s, ":") {
            v6 = append(v6, s)
        } else {
            v4 = append(v4, s)
        }
    }
    if hostIP, err := hostPublicIP(); err == nil && hostIP != "" {
        v4 = append(v4, hostIP+"/32")
    }
    // Always bypass FI host to avoid loop if configured
    v4 = append(v4, "109.206.243.245/32")

    bypassV4 := []string{
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "100.64.0.0/10",
    }
    bypassV6 := []string{
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    }

    makeElems := func(items []string) string {
        if len(items) == 0 {
            return ""
        }
        return strings.Join(items, ", ")
    }
    v4Elems := makeElems(v4)
    v6Elems := makeElems(v6)
    bp4Elems := makeElems(bypassV4)
    bp6Elems := makeElems(bypassV6)

    // Build nft script (delete existing table first to avoid "flush" errors)
    _ = runCmdNoOutput("nft", "delete", "table", "inet", "split_tunnel")
    var b strings.Builder
    b.WriteString("add table inet split_tunnel\n")
    b.WriteString("add set inet split_tunnel split_v4 { type ipv4_addr; flags interval; }\n")
    b.WriteString("add set inet split_tunnel split_v6 { type ipv6_addr; flags interval; }\n")
    b.WriteString("add set inet split_tunnel bypass_v4 { type ipv4_addr; flags interval; }\n")
    b.WriteString("add set inet split_tunnel bypass_v6 { type ipv6_addr; flags interval; }\n")
    if v4Elems != "" {
        b.WriteString("add element inet split_tunnel split_v4 { " + v4Elems + " }\n")
    }
    if v6Elems != "" {
        b.WriteString("add element inet split_tunnel split_v6 { " + v6Elems + " }\n")
    }
    if bp4Elems != "" {
        b.WriteString("add element inet split_tunnel bypass_v4 { " + bp4Elems + " }\n")
    }
    if bp6Elems != "" {
        b.WriteString("add element inet split_tunnel bypass_v6 { " + bp6Elems + " }\n")
    }
    b.WriteString("add chain inet split_tunnel prerouting { type filter hook prerouting priority mangle; policy accept; }\n")
    b.WriteString("add chain inet split_tunnel output { type route hook output priority mangle; policy accept; }\n")

    // common bypass rules
    b.WriteString("add rule inet split_tunnel prerouting ip daddr @bypass_v4 return\n")
    b.WriteString("add rule inet split_tunnel prerouting ip6 daddr @bypass_v6 return\n")
    b.WriteString("add rule inet split_tunnel output ip daddr @bypass_v4 return\n")
    b.WriteString("add rule inet split_tunnel output ip6 daddr @bypass_v6 return\n")

    if mode == 1 {
        b.WriteString("add rule inet split_tunnel prerouting ip daddr @split_v4 meta mark set 1 tproxy to :12345 accept\n")
        b.WriteString("add rule inet split_tunnel prerouting ip6 daddr @split_v6 meta mark set 1 tproxy to :12345 accept\n")
        b.WriteString("add rule inet split_tunnel output ip daddr @split_v4 meta mark set 1 accept\n")
        b.WriteString("add rule inet split_tunnel output ip6 daddr @split_v6 meta mark set 1 accept\n")
    } else if mode == 2 {
        b.WriteString("add rule inet split_tunnel prerouting ip daddr @split_v4 return\n")
        b.WriteString("add rule inet split_tunnel prerouting ip6 daddr @split_v6 return\n")
        b.WriteString("add rule inet split_tunnel output ip daddr @split_v4 return\n")
        b.WriteString("add rule inet split_tunnel output ip6 daddr @split_v6 return\n")
        b.WriteString("add rule inet split_tunnel prerouting meta l4proto { tcp, udp } meta mark set 1 tproxy to :12345 accept\n")
        b.WriteString("add rule inet split_tunnel output meta l4proto { tcp, udp } meta mark set 1 accept\n")
    }

    cmd := exec.Command("nft", "-f", "-")
    cmd.Env = os.Environ()
    cmd.Stdin = strings.NewReader(b.String())
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("nft apply: %w: %s", err, strings.TrimSpace(string(out)))
    }

    _ = runCmdNoOutput("sysctl", "-w", "net.ipv4.ip_nonlocal_bind=1")
    _ = runCmdNoOutput("sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
    _ = runCmdNoOutput("sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")

    // policy routing for marked packets
    _ = runCmdNoOutput("ip", "rule", "del", "fwmark", "1", "lookup", "100")
    _ = runCmdNoOutput("ip", "-6", "rule", "del", "fwmark", "1", "lookup", "100")
    _ = runCmdNoOutput("ip", "rule", "add", "fwmark", "1", "lookup", "100")
    _ = runCmdNoOutput("ip", "-6", "rule", "add", "fwmark", "1", "lookup", "100")
    _ = runCmdNoOutput("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
    _ = runCmdNoOutput("ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", "100")
    return nil
}

func deleteClient(id int64) error {
    if db == nil {
        return fmt.Errorf("db not initialized")
    }
    _, err := db.Exec(`DELETE FROM clients WHERE id = ?`, id)
    return err
}

func createClient(protocolID, name string) (Client, map[string]string, error) {
    if protocolID == "" {
        return Client{}, nil, fmt.Errorf("protocol_id required")
    }
    if name == "" {
        name = fmt.Sprintf("%s-client-%d", protocolID, time.Now().Unix())
    }
    p, ok := protocolByID(protocolID)
    if !ok {
        return Client{}, nil, fmt.Errorf("unknown protocol")
    }
    if err := ensureInstalled(p.Container); err != nil {
        return Client{}, nil, err
    }

    switch protocolID {
    case "wireguard", "awg", "awg2":
        return createWGClient(p, name)
    case "openvpn", "cloak", "shadowsocks":
        return createOpenVPNClient(p, name)
    case "xray":
        return createXrayClient(p, name)
    case "ipsec":
        return createIPSecClient(p, name)
    case "socks5":
        return createSocksClient(p, name)
    default:
        return Client{}, nil, fmt.Errorf("protocol not supported yet")
    }
}

func ensureInstalled(container string) error {
    if err := runCmdNoOutput("docker", "inspect", container); err != nil {
        return fmt.Errorf("container %s not installed", container)
    }
    return nil
}

func runHostScript(path string, env map[string]string) error {
    content, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    script := strings.ReplaceAll(string(content), "sudo ", "")
    cmd := exec.Command("bash", "-s")
    cmd.Env = mergeEnv(env)
    cmd.Stdin = strings.NewReader(script)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("script %s: %w: %s", path, err, strings.TrimSpace(string(out)))
    }
    return nil
}

func runContainerConfigure(container, path string, env map[string]string) error {
    content, err := os.ReadFile(path)
    if err != nil {
        // script may be empty
        return nil
    }
    if strings.TrimSpace(string(content)) == "" {
        return nil
    }
    args := []string{"exec", "-i"}
    for k, v := range env {
        args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
    }
    args = append(args, container, "bash", "-s")
    cmd := exec.Command("docker", args...)
    cmd.Env = os.Environ()
    cmd.Stdin = strings.NewReader(string(content))
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("exec configure: %w: %s", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func uploadStartAndRun(container, path string, env map[string]string) error {
    content, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    // write start.sh
    cmdWrite := exec.Command("docker", "exec", "-i", container, "sh", "-c", "cat > /opt/amnezia/start.sh")
    cmdWrite.Env = os.Environ()
    cmdWrite.Stdin = strings.NewReader(string(content))
    if out, err := cmdWrite.CombinedOutput(); err != nil {
        return fmt.Errorf("upload start.sh: %w: %s", err, strings.TrimSpace(string(out)))
    }

    // run start.sh in background with env
    args := []string{"exec", "-d"}
    for k, v := range env {
        args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
    }
    args = append(args, container, "sh", "-c", "chmod a+x /opt/amnezia/start.sh && /opt/amnezia/start.sh")
    cmd := exec.Command("docker", args...)
    cmd.Env = os.Environ()
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("run start.sh: %w: %s", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func mergeEnv(env map[string]string) []string {
    merged := append([]string{}, os.Environ()...)
    for k, v := range env {
        merged = append(merged, fmt.Sprintf("%s=%s", k, v))
    }
    return merged
}

func protocolEnv(p Protocol, options map[string]string) map[string]string {
    env := map[string]string{}

    env["CONTAINER_NAME"] = p.Container
    env["DOCKERFILE_FOLDER"] = "/opt/amnezia/" + p.Container

    env["OPENVPN_SUBNET_IP"] = "10.8.0.0"
    env["OPENVPN_SUBNET_CIDR"] = "24"
    env["OPENVPN_SUBNET_MASK"] = "255.255.255.0"
    env["OPENVPN_PORT"] = "1194"
    env["OPENVPN_TRANSPORT_PROTO"] = "udp"
    env["OPENVPN_NCP_DISABLE"] = ""
    env["OPENVPN_CIPHER"] = "AES-256-GCM"
    env["OPENVPN_HASH"] = "SHA512"
    env["OPENVPN_TLS_AUTH"] = "tls-auth /opt/amnezia/openvpn/ta.key 0"
    env["OPENVPN_ADDITIONAL_CLIENT_CONFIG"] = ""
    env["OPENVPN_ADDITIONAL_SERVER_CONFIG"] = ""

    env["SHADOWSOCKS_SERVER_PORT"] = "6789"
    env["SHADOWSOCKS_LOCAL_PORT"] = "8585"
    env["SHADOWSOCKS_CIPHER"] = "chacha20-ietf-poly1305"

    env["CLOAK_SERVER_PORT"] = "443"
    env["FAKE_WEB_SITE_ADDRESS"] = "tile.openstreetmap.org"

    env["XRAY_SITE_NAME"] = "www.googletagmanager.com"
    env["XRAY_SERVER_PORT"] = "443"

    env["WIREGUARD_SUBNET_IP"] = "10.8.1.0"
    env["WIREGUARD_SUBNET_CIDR"] = "24"
    env["WIREGUARD_SUBNET_MASK"] = "255.255.255.0"
    env["WIREGUARD_SERVER_PORT"] = "51820"

    env["IPSEC_VPN_L2TP_NET"] = "192.168.42.0/24"
    env["IPSEC_VPN_L2TP_POOL"] = "192.168.42.10-192.168.42.250"
    env["IPSEC_VPN_L2TP_LOCAL"] = "192.168.42.1"
    env["IPSEC_VPN_XAUTH_NET"] = "192.168.43.0/24"
    env["IPSEC_VPN_XAUTH_POOL"] = "192.168.43.10-192.168.43.250"
    env["IPSEC_VPN_SHA2_TRUNCBUG"] = "yes"
    env["IPSEC_VPN_VPN_ANDROID_MTU_FIX"] = "yes"
    env["IPSEC_VPN_DISABLE_IKEV2"] = "no"
    env["IPSEC_VPN_DISABLE_L2TP"] = "no"
    env["IPSEC_VPN_DISABLE_XAUTH"] = "no"
    env["IPSEC_VPN_C2C_TRAFFIC"] = "no"

    env["PRIMARY_SERVER_DNS"] = "1.1.1.1"
    env["SECONDARY_SERVER_DNS"] = "1.0.0.1"

    env["SFTP_PORT"] = "2222"
    env["SFTP_USER"] = "sftp_user"
    env["SFTP_PASSWORD"] = "sftp_pass"

    env["AWG_SUBNET_IP"] = "10.8.1.0"
    env["AWG_SERVER_PORT"] = "55424"
    env["JUNK_PACKET_COUNT"] = "3"
    env["JUNK_PACKET_MIN_SIZE"] = "10"
    env["JUNK_PACKET_MAX_SIZE"] = "30"
    env["INIT_PACKET_JUNK_SIZE"] = "15"
    env["RESPONSE_PACKET_JUNK_SIZE"] = "18"
    env["COOKIE_REPLY_PACKET_JUNK_SIZE"] = "20"
    env["TRANSPORT_PACKET_JUNK_SIZE"] = "23"
    env["INIT_PACKET_MAGIC_HEADER"] = "1020325451"
    env["RESPONSE_PACKET_MAGIC_HEADER"] = "3288052141"
    env["UNDERLOAD_PACKET_MAGIC_HEADER"] = "1766607858"
    env["TRANSPORT_PACKET_MAGIC_HEADER"] = "2528465083"
    env["SPECIAL_JUNK_1"] = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
    env["SPECIAL_JUNK_2"] = ""
    env["SPECIAL_JUNK_3"] = ""
    env["SPECIAL_JUNK_4"] = ""
    env["SPECIAL_JUNK_5"] = ""

    env["SOCKS5_PROXY_PORT"] = "38080"
    env["SOCKS5_USER"] = "users proxy_user:CL:proxy_pass"
    env["SOCKS5_AUTH_TYPE"] = "strong"

    applyProtocolOptions(p, env, options)

    env["SERVER_IP_ADDRESS"] = envOr("SERVER_IP_ADDRESS", detectServerIP())

    return env
}

func detectServerIP() string {
    out, err := runCmd("sh", "-c", "hostname -I | awk '{print $1}'")
    if err != nil {
        return ""
    }
    return strings.TrimSpace(out)
}

func applyProtocolOptions(p Protocol, env map[string]string, options map[string]string) {
    if options == nil {
        return
    }
    get := func(key string) string {
        if v, ok := options[key]; ok {
            return strings.TrimSpace(v)
        }
        return ""
    }
    switch p.ID {
    case "awg", "awg2":
        if v := get("port"); v != "" {
            env["AWG_SERVER_PORT"] = v
        }
    case "wireguard":
        if v := get("port"); v != "" {
            env["WIREGUARD_SERVER_PORT"] = v
        }
    case "openvpn":
        if v := get("port"); v != "" {
            env["OPENVPN_PORT"] = v
        }
        if v := get("transport"); v != "" {
            env["OPENVPN_TRANSPORT_PROTO"] = v
        }
    case "cloak":
        if v := get("port"); v != "" {
            env["CLOAK_SERVER_PORT"] = v
        }
        if v := get("site"); v != "" {
            env["FAKE_WEB_SITE_ADDRESS"] = v
        }
    case "shadowsocks":
        if v := get("port"); v != "" {
            env["SHADOWSOCKS_SERVER_PORT"] = v
        }
    case "xray":
        if v := get("port"); v != "" {
            env["XRAY_SERVER_PORT"] = v
        }
        if v := get("site"); v != "" {
            env["XRAY_SITE_NAME"] = v
        }
    case "socks5":
        if v := get("port"); v != "" {
            env["SOCKS5_PROXY_PORT"] = v
        }
        user := get("user")
        pass := get("pass")
        if user != "" && pass != "" {
            env["SOCKS5_USER"] = fmt.Sprintf("users %s:CL:%s", user, pass)
            env["SOCKS5_AUTH_TYPE"] = "strong"
        } else {
            env["SOCKS5_USER"] = ""
            env["SOCKS5_AUTH_TYPE"] = "none"
        }
    case "sftp":
        if v := get("port"); v != "" {
            env["SFTP_PORT"] = v
        }
        if v := get("user"); v != "" {
            env["SFTP_USER"] = v
        }
        if v := get("pass"); v != "" {
            env["SFTP_PASSWORD"] = v
        }
    }
}

func getContainerStats() map[string]ContainerStats {
    out, err := runCmd("docker", "stats", "--no-stream", "--format", "{{json .}}")
    if err != nil {
        return map[string]ContainerStats{}
    }
    stats := map[string]ContainerStats{}
    lines := strings.Split(strings.TrimSpace(out), "\n")
    for _, line := range lines {
        if strings.TrimSpace(line) == "" {
            continue
        }
        var s ContainerStats
        if err := json.Unmarshal([]byte(line), &s); err != nil {
            continue
        }
        if s.Name != "" {
            stats[s.Name] = s
        }
    }
    return stats
}

func readHostStats() (HostStats, error) {
    hs := HostStats{Time: time.Now().Format(time.RFC3339)}
    if data, err := os.ReadFile("/proc/loadavg"); err == nil {
        parts := strings.Fields(string(data))
        if len(parts) >= 3 {
            hs.Load1 = parts[0]
            hs.Load5 = parts[1]
            hs.Load15 = parts[2]
        }
    }
    hs.CpuCores = runtime.NumCPU()
    if hs.CpuCores > 0 && hs.Load1 != "" {
        if load1, err := strconv.ParseFloat(hs.Load1, 64); err == nil {
            perc := (load1 / float64(hs.CpuCores)) * 100
            if perc < 0 {
                perc = 0
            }
            hs.CpuLoadPerc = fmt.Sprintf("%.0f", perc)
        }
    }
    if data, err := os.ReadFile("/proc/uptime"); err == nil {
        parts := strings.Fields(string(data))
        if len(parts) >= 1 {
            hs.UptimeSec = parts[0]
        }
    }
    if data, err := os.ReadFile("/proc/meminfo"); err == nil {
        lines := strings.Split(string(data), "\n")
        var total, avail int64
        for _, line := range lines {
            if strings.HasPrefix(line, "MemTotal:") {
                fmt.Sscanf(line, "MemTotal: %d kB", &total)
            } else if strings.HasPrefix(line, "MemAvailable:") {
                fmt.Sscanf(line, "MemAvailable: %d kB", &avail)
            }
        }
        hs.MemTotalKB = fmt.Sprintf("%d", total)
        hs.MemAvailKB = fmt.Sprintf("%d", avail)
        used := total - avail
        if used < 0 {
            used = 0
        }
        hs.MemUsedKB = fmt.Sprintf("%d", used)
        if total > 0 {
            perc := (float64(used) / float64(total)) * 100
            hs.MemUsedPerc = fmt.Sprintf("%.1f", perc)
        }
    }
    return hs, nil
}

func connectionsForContainer(info ContainerInfo) string {
    switch info.Names {
    case "amnezia-awg":
        return wgActivePeers(info.Names, "wg0", "wg")
    case "amnezia-awg2":
        return wgActivePeers(info.Names, "awg0", "awg")
    case "amnezia-wireguard":
        return wgActivePeers(info.Names, "wg0", "wg")
    case "amnezia-openvpn", "amnezia-openvpn-cloak", "amnezia-shadowsocks":
        return openvpnClients(info.Names)
    case "amnezia-socks5proxy", "amnezia-xray", "amnezia-sftp":
        return tcpActiveConnections(info.Names)
    case "amnezia-ipsec":
        return ipsecConnections(info.Names)
    case "amnezia-dns":
        return dnsConnections(info.Names)
    default:
        return "-"
    }
}

func wgActivePeers(container, iface, tool string) string {
    cmd := fmt.Sprintf("%s show %s latest-handshakes 2>/dev/null", tool, iface)
    if tool == "wg" {
        cmd = fmt.Sprintf("wg show %s latest-handshakes 2>/dev/null || awg show %s latest-handshakes 2>/dev/null", iface, iface)
    }
    out, err := runCmd("docker", "exec", container, "sh", "-c", cmd)
    if err != nil || strings.TrimSpace(out) == "" {
        return "0"
    }
    now := time.Now().Unix()
    count := 0
    lines := strings.Split(strings.TrimSpace(out), "\n")
    for _, line := range lines {
        parts := strings.Fields(line)
        if len(parts) < 2 {
            continue
        }
        ts, err := strconv.ParseInt(parts[1], 10, 64)
        if err != nil || ts == 0 {
            continue
        }
        if now-ts <= 180 {
            count++
        }
    }
    return strconv.Itoa(count)
}

func openvpnClients(container string) string {
    cmd := "test -f /opt/amnezia/openvpn/openvpn-status.log && awk -F, '/^CLIENT_LIST/ {c++} END{print c+0}' /opt/amnezia/openvpn/openvpn-status.log || echo 0"
    out, err := runCmd("docker", "exec", container, "sh", "-c", cmd)
    if err != nil {
        return "0"
    }
    return strings.TrimSpace(out)
}

func tcpActiveConnections(container string) string {
    port, ok := hostPortForContainer(container, "tcp")
    if !ok {
        return "0"
    }
    cmd := fmt.Sprintf("ss -Htan state established '( sport = :%s )' | wc -l", port)
    out, err := runCmd("sh", "-c", cmd)
    if err != nil {
        return "0"
    }
    return strings.TrimSpace(out)
}

func ipsecConnections(container string) string {
    cmd := "ipsec statusall 2>/dev/null | grep -c 'ESTABLISHED' || true"
    out, err := runCmd("docker", "exec", container, "sh", "-c", cmd)
    if err != nil {
        return "0"
    }
    return strings.TrimSpace(out)
}

func dnsConnections(container string) string {
    cmd := "unbound-control stats_noreset 2>/dev/null | awk -F= '/num\\.queries/ {print $2}' | head -n1"
    out, err := runCmd("docker", "exec", container, "sh", "-c", cmd)
    if err == nil && strings.TrimSpace(out) != "" {
        return strings.TrimSpace(out)
    }
    return "0"
}

func hostPortForContainer(container, proto string) (string, bool) {
    out, err := runCmd("docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", container)
    if err != nil {
        return "", false
    }
    var ports map[string][]struct {
        HostPort string `json:"HostPort"`
    }
    if err := json.Unmarshal([]byte(out), &ports); err != nil {
        return "", false
    }
    for key, bindings := range ports {
        if !strings.HasSuffix(key, "/"+proto) {
            continue
        }
        if len(bindings) > 0 && bindings[0].HostPort != "" {
            return bindings[0].HostPort, true
        }
    }
    return "", false
}
