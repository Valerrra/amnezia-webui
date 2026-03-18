package main

import (
    "bytes"
    "compress/zlib"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "net"
    "net/url"
    "os/exec"
    "regexp"
    "strconv"
    "strings"
    "time"

    "github.com/skip2/go-qrcode"
)

type wgConfig struct {
    Interface map[string]string
    Allowed   []string
}

type wgClientData struct {
    ClientIP   string
    ClientPriv string
    ClientPub  string
    ClientPSK  string
    ServerPub  string
    Endpoint   string
    DNS        []string
    Extras     map[string]string
}

func createWGClient(p Protocol, name string) (Client, map[string]string, error) {
    configPath, ok := configPathForContainer(p.Container)
    if !ok {
        return Client{}, nil, fmt.Errorf("unknown config path")
    }
    raw, err := readFileInContainer(p.Container, configPath)
    if err != nil {
        return Client{}, nil, err
    }
    cfg := parseWGConfig(raw)
    if len(cfg.Interface) == 0 {
        return Client{}, nil, fmt.Errorf("invalid server config")
    }

    ifaceName := wgInterfaceName(p.ID)
    tool := wgToolName(p.ID)

    serverPriv := cfg.Interface["PrivateKey"]
    if serverPriv == "" {
        return Client{}, nil, fmt.Errorf("server private key not found")
    }
    serverPub, err := wgPubKey(p.Container, tool, serverPriv)
    if err != nil {
        return Client{}, nil, err
    }

    port := cfg.Interface["ListenPort"]
    if port == "" {
        port = defaultForField(p, "port")
    }
    hostIP, err := hostPublicIP()
    if err != nil {
        return Client{}, nil, err
    }
    endpoint := fmt.Sprintf("%s:%s", hostIP, port)

    clientIP, err := nextClientIP(cfg, protocolIDSubnetKey(p.ID))
    if err != nil {
        return Client{}, nil, err
    }

    clientPriv, clientPub, err := wgKeypair(p.Container, tool)
    if err != nil {
        return Client{}, nil, err
    }
    clientPSK, err := wgPSK(p.Container, tool)
    if err != nil {
        return Client{}, nil, err
    }

    if err := appendPeerToConfig(p.Container, configPath, clientPub, clientPSK, clientIP); err != nil {
        return Client{}, nil, err
    }
    if err := addPeerRuntime(p.Container, ifaceName, tool, clientPub, clientPSK, clientIP); err != nil {
        return Client{}, nil, err
    }

    data := wgClientData{
        ClientIP:   clientIP,
        ClientPriv: clientPriv,
        ClientPub:  clientPub,
        ClientPSK:  clientPSK,
        ServerPub:  serverPub,
        Endpoint:   endpoint,
        DNS:        splitDNS(cfg.Interface["DNS"]),
        Extras:     cfg.Interface,
    }

    config := buildClientConfig(p.ID, data)
    protoKey := "wireguard"
    if p.ID == "awg" || p.ID == "awg2" {
        protoKey = "awg"
    }
    subnet := ""
    if addr := cfg.Interface["Address"]; addr != "" {
        cidr := strings.Split(addr, ",")[0]
        if _, network, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
            subnet = network.IP.String()
        }
    }
    amneziaJSON := buildAmneziaConfigFromWireGuardConfig(config, protoKey, p.Container, nameOrDefault(name, p.Name), subnet)
    if cfg, err := getSplitTunnelConfig(); err == nil {
        amneziaJSON = applySplitTunnelToJSON(amneziaJSON, cfg)
    }
    vpn := buildVPNString(amneziaJSON)

    now := nowTS()
    clientID, err := insertClient(p.ID, name, clientIP, clientPub, clientPriv, clientPSK, now)
    if err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "config", config, now); err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "vpn", vpn, now); err != nil {
        return Client{}, nil, err
    }
    if amneziaJSON != "" {
        _ = insertClientConfig(clientID, "amnezia_json", amneziaJSON, now)
    }

    client := Client{
        ID:         clientID,
        ProtocolID: p.ID,
        Name:       name,
        Address:    clientIP,
        PublicKey:  clientPub,
        CreatedAt:  now,
    }
    exports := map[string]string{
        "config": config,
        "vpn":    vpn,
    }
    return client, exports, nil
}

func insertClient(protocolID, name, address, pub, priv, psk, ts string) (int64, error) {
    if db == nil {
        return 0, fmt.Errorf("db not initialized")
    }
    res, err := db.Exec(`INSERT INTO clients(protocol_id, name, address, public_key, private_key, preshared_key, created_at, updated_at)
        VALUES(?,?,?,?,?,?,?,?)`, protocolID, name, address, pub, priv, psk, ts, ts)
    if err != nil {
        return 0, err
    }
    return res.LastInsertId()
}

func insertClientConfig(clientID int64, format, content, ts string) error {
    if db == nil {
        return fmt.Errorf("db not initialized")
    }
    _, err := db.Exec(`INSERT INTO client_configs(client_id, format, content, created_at) VALUES(?,?,?,?)`, clientID, format, content, ts)
    return err
}

func buildVPNString(config string) string {
    if strings.TrimSpace(config) == "" {
        return ""
    }
    compressed := qCompress([]byte(config))
    return "vpn://" + base64.RawURLEncoding.EncodeToString(compressed)
}

func buildQRPngBase64(text string) (string, error) {
    png, err := qrcode.Encode(text, qrcode.Medium, 256)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(png), nil
}

func qCompress(data []byte) []byte {
    var buf bytes.Buffer
    zw := zlib.NewWriter(&buf)
    _, _ = zw.Write(data)
    _ = zw.Close()
    comp := buf.Bytes()
    out := make([]byte, 4+len(comp))
    binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
    copy(out[4:], comp)
    return out
}

func buildQrChunks(data []byte) []string {
    const chunkSize = 850
    if len(data) == 0 {
        return []string{}
    }
    chunksCount := (len(data) + chunkSize - 1) / chunkSize
    out := make([]string, 0, chunksCount)
    for i := 0; i < len(data); i += chunkSize {
        end := i + chunkSize
        if end > len(data) {
            end = len(data)
        }
        chunkID := i / chunkSize
        var buf bytes.Buffer
        _ = binary.Write(&buf, binary.BigEndian, int16(1984))
        buf.WriteByte(byte(chunksCount))
        buf.WriteByte(byte(chunkID))
        buf.Write(data[i:end])
        out = append(out, base64.RawURLEncoding.EncodeToString(buf.Bytes()))
    }
    return out
}

func buildAmneziaConfigFromWireGuardConfig(config, protoKey, containerName, description, subnetOverride string) string {
    kv := parseKeyValueConfig(config)
    endpoint := kv["Endpoint"]
    host, port := splitEndpoint(endpoint)
    if port == "" {
        port = protocolsDefaultPort(protoKey)
    }

    last := map[string]any{
        "config": config,
    }
    if host != "" {
        last[config_key_hostName] = host
    }
    if port != "" {
        if p, err := strconv.Atoi(port); err == nil {
            last[config_key_port] = p
        }
    }
    if v := kv["PrivateKey"]; v != "" {
        last[config_key_client_priv_key] = v
    }
    if v := kv["Address"]; v != "" {
        last[config_key_client_ip] = v
    }
    if v := kv["PublicKey"]; v != "" {
        last[config_key_server_pub_key] = v
    }
    if v := kv["PresharedKey"]; v != "" {
        last[config_key_psk_key] = v
    } else if v := kv["PreSharedKey"]; v != "" {
        last[config_key_psk_key] = v
    }
    if v := kv["MTU"]; v != "" {
        last[config_key_mtu] = v
    } else {
        last[config_key_mtu] = defaultMtuForProto(protoKey)
    }
    if v := kv["PersistentKeepalive"]; v != "" {
        last[config_key_persistent_keep_alive] = v
    }
    if v := kv["AllowedIPs"]; v != "" {
        last[config_key_allowed_ips] = splitList(v)
    } else {
        last[config_key_allowed_ips] = []string{"0.0.0.0/0", "::/0"}
    }

    protocolVersion := ""
    if protoKey == "awg" {
        required := []string{config_key_junkPacketCount, config_key_junkPacketMinSize, config_key_junkPacketMaxSize,
            config_key_initPacketJunkSize, config_key_responsePacketJunkSize, config_key_initPacketMagicHeader,
            config_key_responsePacketMagicHeader, config_key_underloadPacketMagicHeader, config_key_transportPacketMagicHeader}
        hasAll := true
        for _, k := range required {
            if kv[k] == "" {
                hasAll = false
                break
            }
        }
        if hasAll {
            for _, k := range required {
                last[k] = kv[k]
            }
            optional := []string{config_key_cookieReplyPacketJunkSize, config_key_transportPacketJunkSize,
                config_key_specialJunk1, config_key_specialJunk2, config_key_specialJunk3, config_key_specialJunk4, config_key_specialJunk5}
            hasCookie := kv[config_key_cookieReplyPacketJunkSize] != ""
            hasTransport := kv[config_key_transportPacketJunkSize] != ""
            hasSpecial := false
            for _, k := range optional {
                if kv[k] != "" {
                    last[k] = kv[k]
                    if k == config_key_specialJunk1 || k == config_key_specialJunk2 || k == config_key_specialJunk3 || k == config_key_specialJunk4 || k == config_key_specialJunk5 {
                        hasSpecial = true
                    }
                }
            }
            if hasCookie && hasTransport {
                protocolVersion = "2"
            } else if hasSpecial && !hasCookie && !hasTransport {
                protocolVersion = "1.5"
            }
        }
    }

    lastJSON, _ := json.Marshal(last)
    protoCfg := map[string]any{
        config_key_last_config:       string(lastJSON),
        config_key_isThirdPartyConfig: true,
        config_key_port:              port,
        config_key_transport_proto:   "udp",
    }
    if subnetOverride != "" {
        protoCfg[config_key_subnet_address] = subnetOverride
    }
    if protocolVersion != "" {
        protoCfg[config_key_protocolVersion] = protocolVersion
    }

    container := map[string]any{
        config_key_container: containerName,
        protoKey:             protoCfg,
    }
    top := map[string]any{
        config_key_containers:      []any{container},
        config_key_defaultContainer: containerName,
        config_key_description:      description,
    }
    if host != "" {
        top[config_key_hostName] = host
    }
    if dns := kv["DNS"]; dns != "" {
        parts := splitList(dns)
        if len(parts) > 0 {
            top[config_key_dns1] = parts[0]
        }
        if len(parts) > 1 {
            top[config_key_dns2] = parts[1]
        }
    }
    out, _ := json.Marshal(top)
    return string(out)
}

func buildAmneziaConfigFromOpenVPNConfig(config, description string) string {
    dns1, dns2 := parseOpenVPNDNS(config)
    host := parseOpenVPNHost(config)

    lastCfg := map[string]any{config_key_config: config}
    lastJSON, _ := json.Marshal(lastCfg)
    protoCfg := map[string]any{
        config_key_last_config:       string(lastJSON),
        config_key_isThirdPartyConfig: true,
    }
    containerName := "amnezia-openvpn"
    container := map[string]any{
        config_key_container: containerName,
        config_key_openvpn:   protoCfg,
    }
    top := map[string]any{
        config_key_containers:      []any{container},
        config_key_defaultContainer: containerName,
        config_key_description:      description,
    }
    if host != "" {
        top[config_key_hostName] = host
    }
    if dns1 != "" {
        top[config_key_dns1] = dns1
    }
    if dns2 != "" {
        top[config_key_dns2] = dns2
    }
    out, _ := json.Marshal(top)
    return string(out)
}

func buildAmneziaConfigFromXrayConfig(configJSON, description string) string {
    host := parseXrayHost(configJSON)
    lastCfg := map[string]any{
        config_key_last_config:       configJSON,
        config_key_isThirdPartyConfig: true,
    }
    containerName := "amnezia-xray"
    container := map[string]any{
        config_key_container: containerName,
        config_key_xray:      lastCfg,
    }
    top := map[string]any{
        config_key_containers:      []any{container},
        config_key_defaultContainer: containerName,
        config_key_description:      description,
    }
    if host != "" {
        top[config_key_hostName] = host
    }
    out, _ := json.Marshal(top)
    return string(out)
}

func parseKeyValueConfig(raw string) map[string]string {
    out := map[string]string{}
    for _, line := range strings.Split(raw, "\n") {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
            continue
        }
        if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
            continue
        }
        parts := strings.SplitN(line, "=", 2)
        if len(parts) != 2 {
            continue
        }
        key := strings.TrimSpace(parts[0])
        val := strings.TrimSpace(parts[1])
        if key != "" {
            out[key] = val
        }
    }
    return out
}

func splitList(raw string) []string {
    parts := strings.Split(raw, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p != "" {
            out = append(out, p)
        }
    }
    return out
}

func splitEndpoint(endpoint string) (string, string) {
    endpoint = strings.TrimSpace(endpoint)
    if endpoint == "" {
        return "", ""
    }
    if strings.HasPrefix(endpoint, "[") {
        if host, port, err := net.SplitHostPort(endpoint); err == nil {
            return strings.Trim(host, "[]"), port
        }
    }
    if idx := strings.LastIndex(endpoint, ":"); idx != -1 {
        return endpoint[:idx], endpoint[idx+1:]
    }
    return endpoint, ""
}

func parseOpenVPNDNS(config string) (string, string) {
    dns := []string{}
    for _, line := range strings.Split(config, "\n") {
        fields := strings.Fields(strings.TrimSpace(line))
        if len(fields) >= 3 && fields[0] == "dhcp-option" && strings.EqualFold(fields[1], "DNS") {
            dns = append(dns, fields[2])
        }
    }
    if len(dns) == 0 {
        return "", ""
    }
    if len(dns) == 1 {
        return dns[0], ""
    }
    return dns[0], dns[1]
}

func parseOpenVPNHost(config string) string {
    for _, line := range strings.Split(config, "\n") {
        fields := strings.Fields(strings.TrimSpace(line))
        if len(fields) >= 2 && fields[0] == "remote" {
            return fields[1]
        }
    }
    return ""
}

func parseXrayHost(configJSON string) string {
    var obj map[string]any
    if json.Unmarshal([]byte(configJSON), &obj) != nil {
        return ""
    }
    inbounds, ok := obj["outbounds"].([]any)
    if !ok || len(inbounds) == 0 {
        return ""
    }
    outbound, ok := inbounds[0].(map[string]any)
    if !ok {
        return ""
    }
    settings, ok := outbound["settings"].(map[string]any)
    if !ok {
        return ""
    }
    vnext, ok := settings["vnext"].([]any)
    if !ok || len(vnext) == 0 {
        return ""
    }
    v0, ok := vnext[0].(map[string]any)
    if !ok {
        return ""
    }
    if addr, ok := v0["address"].(string); ok {
        return addr
    }
    return ""
}

func buildXrayClientConfigJSON(host, port, uuid, serverName, pubKey, shortID string) string {
    portNum := 443
    if p, err := strconv.Atoi(strings.TrimSpace(port)); err == nil && p > 0 {
        portNum = p
    }
    if serverName == "" {
        serverName = "example.com"
    }
    cfg := map[string]any{
        "log": map[string]any{"loglevel": "error"},
        "inbounds": []any{
            map[string]any{
                "listen":   "127.0.0.1",
                "port":     10808,
                "protocol": "socks",
                "settings": map[string]any{"udp": true},
            },
        },
        "outbounds": []any{
            map[string]any{
                "protocol": "vless",
                "settings": map[string]any{
                    "vnext": []any{
                        map[string]any{
                            "address": host,
                            "port":    portNum,
                            "users": []any{
                                map[string]any{
                                    "id":         uuid,
                                    "flow":       "xtls-rprx-vision",
                                    "encryption": "none",
                                },
                            },
                        },
                    },
                },
                "streamSettings": map[string]any{
                    "network":  "tcp",
                    "security": "reality",
                    "realitySettings": map[string]any{
                        "fingerprint": "chrome",
                        "serverName":  serverName,
                        "publicKey":   pubKey,
                        "shortId":     shortID,
                        "spiderX":     "",
                    },
                },
            },
        },
    }
    b, _ := json.Marshal(cfg)
    return string(b)
}

const (
    config_key_hostName              = "hostName"
    config_key_port                  = "port"
    config_key_dns1                  = "dns1"
    config_key_dns2                  = "dns2"
    config_key_description           = "description"
    config_key_splitTunnelSites      = "splitTunnelSites"
    config_key_splitTunnelType       = "splitTunnelType"
    config_key_config                = "config"
    config_key_containers            = "containers"
    config_key_container             = "container"
    config_key_defaultContainer      = "defaultContainer"
    config_key_openvpn               = "openvpn"
    config_key_xray                  = "xray"
    config_key_last_config           = "last_config"
    config_key_isThirdPartyConfig    = "isThirdPartyConfig"
    config_key_transport_proto       = "transport_proto"
    config_key_subnet_address        = "subnet_address"
    config_key_protocolVersion       = "protocol_version"
    config_key_client_priv_key       = "client_priv_key"
    config_key_client_ip             = "client_ip"
    config_key_server_pub_key        = "server_pub_key"
    config_key_psk_key               = "psk_key"
    config_key_mtu                   = "mtu"
    config_key_allowed_ips           = "allowed_ips"
    config_key_persistent_keep_alive = "persistent_keep_alive"
    config_key_junkPacketCount       = "Jc"
    config_key_junkPacketMinSize     = "Jmin"
    config_key_junkPacketMaxSize     = "Jmax"
    config_key_initPacketJunkSize    = "S1"
    config_key_responsePacketJunkSize = "S2"
    config_key_cookieReplyPacketJunkSize = "S3"
    config_key_transportPacketJunkSize   = "S4"
    config_key_initPacketMagicHeader     = "H1"
    config_key_responsePacketMagicHeader = "H2"
    config_key_underloadPacketMagicHeader = "H3"
    config_key_transportPacketMagicHeader = "H4"
    config_key_specialJunk1 = "I1"
    config_key_specialJunk2 = "I2"
    config_key_specialJunk3 = "I3"
    config_key_specialJunk4 = "I4"
    config_key_specialJunk5 = "I5"
)

func defaultMtuForProto(protoKey string) string {
    if protoKey == "awg" {
        return "1376"
    }
    return "1376"
}

func protocolsDefaultPort(protoKey string) string {
    switch protoKey {
    case "awg":
        return "51820"
    default:
        return "51820"
    }
}
func buildAmneziaLong(payload string) string {
    raw := []byte(payload)
    var buf bytes.Buffer
    zw := zlib.NewWriter(&buf)
    _, _ = zw.Write(raw)
    _ = zw.Close()
    comp := buf.Bytes()
    block := make([]byte, 4+len(comp))
    binary.BigEndian.PutUint32(block[:4], uint32(len(raw)))
    copy(block[4:], comp)
    return buildAmneziaBinary(0, block)
}

func buildAmneziaShort(payload string) string {
    sum := sha256.Sum256([]byte(payload))
    block := sum[:21]
    return buildAmneziaBinary(1, block)
}

func buildAmneziaBinary(version byte, block []byte) string {
    header := []byte{0x07, 0xC0, 0x02, version}
    out := make([]byte, 0, 8+len(block))
    out = append(out, header...)
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(block)))
    out = append(out, lenBuf...)
    out = append(out, block...)
    return base64.RawURLEncoding.EncodeToString(out)
}

func wgInterfaceName(protocolID string) string {
    switch protocolID {
    case "awg2":
        return "awg0"
    default:
        return "wg0"
    }
}

func wgToolName(protocolID string) string {
    switch protocolID {
    case "awg", "awg2":
        return "awg"
    default:
        return "wg"
    }
}

func readFileInContainer(name, path string) (string, error) {
    return runCmd("docker", "exec", name, "sh", "-c", "cat "+shellEscape(path))
}

func appendPeerToConfig(container, path, pub, psk, ip string) error {
    block := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", pub, psk, ip)
    cmd := exec.Command("docker", "exec", "-i", container, "sh", "-c", "cat >> "+shellEscape(path))
    cmd.Stdin = strings.NewReader(block)
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("append peer: %w: %s", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func addPeerRuntime(container, iface, tool, pub, psk, ip string) error {
    script := fmt.Sprintf("set -e; tmp=$(mktemp); printf '%%s' '%s' > $tmp; %s set %s peer %s preshared-key $tmp allowed-ips %s/32 2>/dev/null || %s set %s peer %s preshared-key $tmp allowed-ips %s/32; rm -f $tmp",
        escapeSingleQuotes(psk), tool, iface, pub, ip, fallbackTool(tool), iface, pub, ip)
    _, err := runCmd("docker", "exec", container, "sh", "-c", script)
    if err != nil {
        return fmt.Errorf("apply peer: %w", err)
    }
    return nil
}

func wgKeypair(container, tool string) (string, string, error) {
    priv, err := runCmd("docker", "exec", container, "sh", "-c", fmt.Sprintf("%s genkey 2>/dev/null || %s genkey", tool, fallbackTool(tool)))
    if err != nil {
        return "", "", err
    }
    priv = strings.TrimSpace(priv)
    pub, err := wgPubKey(container, tool, priv)
    if err != nil {
        return "", "", err
    }
    return priv, pub, nil
}

func wgPubKey(container, tool, priv string) (string, error) {
    cmd := fmt.Sprintf("printf '%%s' '%s' | %s pubkey 2>/dev/null || printf '%%s' '%s' | %s pubkey",
        escapeSingleQuotes(priv), tool, escapeSingleQuotes(priv), fallbackTool(tool))
    out, err := runCmd("docker", "exec", container, "sh", "-c", cmd)
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(out), nil
}

func wgPSK(container, tool string) (string, error) {
    out, err := runCmd("docker", "exec", container, "sh", "-c", fmt.Sprintf("%s genpsk 2>/dev/null || %s genpsk 2>/dev/null || head -c 32 /dev/urandom | base64", tool, fallbackTool(tool)))
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(out), nil
}

func fallbackTool(tool string) string {
    if tool == "awg" {
        return "wg"
    }
    return "awg"
}

func parseWGConfig(raw string) wgConfig {
    cfg := wgConfig{Interface: map[string]string{}}
    section := ""
    lines := strings.Split(raw, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
            continue
        }
        if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
            section = strings.Trim(line, "[]")
            continue
        }
        parts := strings.SplitN(line, "=", 2)
        if len(parts) != 2 {
            continue
        }
        key := strings.TrimSpace(parts[0])
        val := strings.TrimSpace(parts[1])
        if section == "Interface" {
            cfg.Interface[key] = val
        } else if section == "Peer" && key == "AllowedIPs" {
            cfg.Allowed = append(cfg.Allowed, val)
        }
    }
    return cfg
}

func splitDNS(v string) []string {
    if strings.TrimSpace(v) == "" {
        return []string{"1.1.1.1", "8.8.8.8"}
    }
    parts := strings.Split(v, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p != "" {
            out = append(out, p)
        }
    }
    if len(out) == 0 {
        return []string{"1.1.1.1", "8.8.8.8"}
    }
    return out
}

func nextClientIP(cfg wgConfig, subnetKey string) (string, error) {
    addr := cfg.Interface["Address"]
    if addr == "" {
        return "", fmt.Errorf("missing interface address")
    }
    cidr := strings.Split(addr, ",")[0]
    cidr = strings.TrimSpace(cidr)
    _, network, err := net.ParseCIDR(cidr)
    if err != nil {
        return "", fmt.Errorf("invalid cidr: %w", err)
    }

    used := map[string]bool{}
    used[network.IP.String()] = true
    if ipOnly := strings.Split(cidr, "/")[0]; net.ParseIP(ipOnly) != nil {
        used[ipOnly] = true
    }
    for _, allowed := range cfg.Allowed {
        for _, part := range strings.Split(allowed, ",") {
            part = strings.TrimSpace(part)
            ipStr := strings.Split(part, "/")[0]
            if net.ParseIP(ipStr) == nil {
                continue
            }
            used[ipStr] = true
        }
    }

    // include db used addresses for this protocol
    clients, _ := listClients(subnetKey)
    for _, c := range clients {
        if c.Address != "" {
            used[c.Address] = true
        }
    }

    start, size := cidrRange(network)
    if size < 4 {
        return "", fmt.Errorf("cidr too small")
    }
    for i := uint32(2); i < size-1; i++ {
        ip := uint32ToIP(start + i)
        if !used[ip.String()] {
            return ip.String(), nil
        }
    }
    return "", fmt.Errorf("no free addresses")
}

func cidrRange(n *net.IPNet) (uint32, uint32) {
    ip := n.IP.To4()
    if ip == nil {
        return 0, 0
    }
    ones, bits := n.Mask.Size()
    size := uint32(1) << uint32(bits-ones)
    return ipToUint32(ip), size
}

func ipToUint32(ip net.IP) uint32 {
    ip = ip.To4()
    if ip == nil {
        return 0
    }
    return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
    return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func buildClientConfig(protocolID string, data wgClientData) string {
    dns := strings.Join(data.DNS, ", ")
    b := strings.Builder{}
    b.WriteString("[Interface]\n")
    b.WriteString(fmt.Sprintf("Address = %s/32\n", data.ClientIP))
    b.WriteString(fmt.Sprintf("DNS = %s\n", dns))
    b.WriteString(fmt.Sprintf("PrivateKey = %s\n", data.ClientPriv))

    if protocolID == "awg" || protocolID == "awg2" {
        extras := []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"}
        for _, key := range extras {
            if v := strings.TrimSpace(data.Extras[key]); v != "" {
                b.WriteString(fmt.Sprintf("%s = %s\n", key, v))
            }
        }
    }

    b.WriteString("\n[Peer]\n")
    b.WriteString(fmt.Sprintf("PublicKey = %s\n", data.ServerPub))
    b.WriteString(fmt.Sprintf("PresharedKey = %s\n", data.ClientPSK))
    b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
    b.WriteString(fmt.Sprintf("Endpoint = %s\n", data.Endpoint))
    b.WriteString("PersistentKeepalive = 25\n")
    return b.String()
}

func protocolIDSubnetKey(protocolID string) string {
    // use protocol id for DB grouping
    return protocolID
}

func hostPublicIP() (string, error) {
    out, err := runCmd("sh", "-c", "ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'")
    if err == nil && strings.TrimSpace(out) != "" {
        return strings.TrimSpace(out), nil
    }
    out, err = runCmd("sh", "-c", "hostname -I | awk '{print $1}'")
    if err != nil {
        return "", fmt.Errorf("host ip: %w", err)
    }
    ip := strings.TrimSpace(out)
    if ip == "" {
        return "", fmt.Errorf("host ip not found")
    }
    return ip, nil
}

func escapeSingleQuotes(s string) string {
    return strings.ReplaceAll(s, "'", "'\"'\"'")
}

func createOpenVPNClient(p Protocol, name string) (Client, map[string]string, error) {
    cn := sanitizeName(name)
    if cn == "" {
        cn = fmt.Sprintf("ovpn-%d", timeNowUnix())
    }

    // generate certs
    genCmd := fmt.Sprintf("cd /opt/amnezia/openvpn && EASYRSA_BATCH=1 easyrsa gen-req %s nopass >/dev/null && EASYRSA_BATCH=1 easyrsa sign-req client %s <<EOF\nyes\nEOF\n", shellEscape(cn), shellEscape(cn))
    if _, err := runCmd("docker", "exec", p.Container, "sh", "-c", genCmd); err != nil {
        return Client{}, nil, fmt.Errorf("openvpn client gen: %w", err)
    }

    ca, err := readFileInContainer(p.Container, "/opt/amnezia/openvpn/ca.crt")
    if err != nil {
        return Client{}, nil, err
    }
    ta, _ := readFileInContainer(p.Container, "/opt/amnezia/openvpn/ta.key")
    cert, err := readFileInContainer(p.Container, fmt.Sprintf("/opt/amnezia/openvpn/pki/issued/%s.crt", cn))
    if err != nil {
        return Client{}, nil, err
    }
    key, err := readFileInContainer(p.Container, fmt.Sprintf("/opt/amnezia/openvpn/pki/private/%s.key", cn))
    if err != nil {
        return Client{}, nil, err
    }

    serverConf, err := readFileInContainer(p.Container, "/opt/amnezia/openvpn/server.conf")
    if err != nil {
        return Client{}, nil, err
    }
    ovpnSettings := parseOpenVPNServerConfig(serverConf)
    proto := ovpnSettings["proto"]
    if proto == "" {
        proto = "udp"
    }
    port := ovpnSettings["port"]
    if port == "" {
        port = defaultForField(p, "port")
    }
    cipher := ovpnSettings["cipher"]
    if cipher == "" {
        cipher = "AES-256-GCM"
    }
    auth := ovpnSettings["auth"]
    if auth == "" {
        auth = "SHA512"
    }
    ncpDisable := ""
    if ovpnSettings["ncp-disable"] != "" {
        ncpDisable = "ncp-disable"
    }

    hostIP, err := hostPublicIP()
    if err != nil {
        return Client{}, nil, err
    }

    additional := ""
    remoteHost := hostIP
    if p.ID == "cloak" {
        cloakInfo := buildCloakClientInfo(p.Container, hostIP)
        additional = "\n# Amnezia Cloak\n" + cloakInfo + "\n"
        remoteHost = "127.0.0.1"
    } else if p.ID == "shadowsocks" {
        ssInfo := buildShadowsocksClientInfo(p.Container, hostIP)
        additional = "\n# Amnezia Shadowsocks\n" + ssInfo + "\n"
        remoteHost = "127.0.0.1"
    }

    config := buildOpenVPNClientConfig(openvpnClientParams{
        Proto:      proto,
        Port:       port,
        Cipher:     cipher,
        Auth:       auth,
        NcpDisable: ncpDisable,
        RemoteHost: remoteHost,
        DNS1:       "1.1.1.1",
        DNS2:       "8.8.8.8",
        CA:         strings.TrimSpace(ca),
        Cert:       strings.TrimSpace(cert),
        Key:        strings.TrimSpace(key),
        TA:         strings.TrimSpace(ta),
        Additional: strings.TrimSpace(additional),
    })

    amneziaJSON := buildAmneziaConfigFromOpenVPNConfig(config, nameOrDefault(name, cn))
    if cfg, err := getSplitTunnelConfig(); err == nil {
        amneziaJSON = applySplitTunnelToJSON(amneziaJSON, cfg)
    }
    vpn := buildVPNString(amneziaJSON)

    now := nowTS()
    clientID, err := insertClient(p.ID, nameOrDefault(name, cn), "", "", "", "", now)
    if err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "config", config, now); err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "vpn", vpn, now); err != nil {
        return Client{}, nil, err
    }
    if amneziaJSON != "" {
        _ = insertClientConfig(clientID, "amnezia_json", amneziaJSON, now)
    }

    client := Client{
        ID:         clientID,
        ProtocolID: p.ID,
        Name:       nameOrDefault(name, cn),
        Address:    "",
        PublicKey:  "",
        CreatedAt:  now,
    }
    exports := map[string]string{
        "config": config,
        "vpn":    vpn,
    }
    return client, exports, nil
}

func rebuildOpenVPNClientConfig(p Protocol, name string) (string, error) {
    cn := sanitizeName(name)
    if cn == "" {
        cn = name
    }
    if cn == "" {
        return "", fmt.Errorf("client name required")
    }

    ca, err := readFileInContainer(p.Container, "/opt/amnezia/openvpn/ca.crt")
    if err != nil {
        return "", err
    }
    ta, _ := readFileInContainer(p.Container, "/opt/amnezia/openvpn/ta.key")
    cert, err := readFileInContainer(p.Container, fmt.Sprintf("/opt/amnezia/openvpn/pki/issued/%s.crt", cn))
    if err != nil {
        return "", err
    }
    key, err := readFileInContainer(p.Container, fmt.Sprintf("/opt/amnezia/openvpn/pki/private/%s.key", cn))
    if err != nil {
        return "", err
    }

    serverConf, err := readFileInContainer(p.Container, "/opt/amnezia/openvpn/server.conf")
    if err != nil {
        return "", err
    }
    ovpnSettings := parseOpenVPNServerConfig(serverConf)
    proto := ovpnSettings["proto"]
    if proto == "" {
        proto = "udp"
    }
    port := ovpnSettings["port"]
    if port == "" {
        port = defaultForField(p, "port")
    }
    cipher := ovpnSettings["cipher"]
    if cipher == "" {
        cipher = "AES-256-GCM"
    }
    auth := ovpnSettings["auth"]
    if auth == "" {
        auth = "SHA512"
    }
    ncpDisable := ""
    if ovpnSettings["ncp-disable"] != "" {
        ncpDisable = "ncp-disable"
    }

    hostIP, err := hostPublicIP()
    if err != nil {
        return "", err
    }

    additional := ""
    remoteHost := hostIP
    if p.ID == "cloak" {
        cloakInfo := buildCloakClientInfo(p.Container, hostIP)
        additional = "\n# Amnezia Cloak\n" + cloakInfo + "\n"
        remoteHost = "127.0.0.1"
    } else if p.ID == "shadowsocks" {
        ssInfo := buildShadowsocksClientInfo(p.Container, hostIP)
        additional = "\n# Amnezia Shadowsocks\n" + ssInfo + "\n"
        remoteHost = "127.0.0.1"
    }

    config := buildOpenVPNClientConfig(openvpnClientParams{
        Proto:      proto,
        Port:       port,
        Cipher:     cipher,
        Auth:       auth,
        NcpDisable: ncpDisable,
        RemoteHost: remoteHost,
        DNS1:       "1.1.1.1",
        DNS2:       "8.8.8.8",
        CA:         strings.TrimSpace(ca),
        Cert:       strings.TrimSpace(cert),
        Key:        strings.TrimSpace(key),
        TA:         strings.TrimSpace(ta),
        Additional: strings.TrimSpace(additional),
    })

    return config, nil
}

func rebuildClientConfig(p Protocol, c ClientFull) (string, error) {
    switch p.ID {
    case "wireguard", "awg", "awg2":
        if c.PrivateKey == "" || c.PresharedKey == "" || c.Address == "" {
            return "", fmt.Errorf("client keys not stored")
        }
        configPath, ok := configPathForContainer(p.Container)
        if !ok {
            return "", fmt.Errorf("unknown config path")
        }
        raw, err := readFileInContainer(p.Container, configPath)
        if err != nil {
            return "", err
        }
        cfg := parseWGConfig(raw)
        if len(cfg.Interface) == 0 {
            return "", fmt.Errorf("invalid server config")
        }

        tool := wgToolName(p.ID)
        serverPriv := cfg.Interface["PrivateKey"]
        if serverPriv == "" {
            return "", fmt.Errorf("server private key not found")
        }
        serverPub, err := wgPubKey(p.Container, tool, serverPriv)
        if err != nil {
            return "", err
        }
        port := cfg.Interface["ListenPort"]
        if port == "" {
            port = defaultForField(p, "port")
        }
        hostIP, err := hostPublicIP()
        if err != nil {
            return "", err
        }
        endpoint := fmt.Sprintf("%s:%s", hostIP, port)

        data := wgClientData{
            ClientIP:   c.Address,
            ClientPriv: c.PrivateKey,
            ClientPub:  c.PublicKey,
            ClientPSK:  c.PresharedKey,
            ServerPub:  serverPub,
            Endpoint:   endpoint,
            DNS:        splitDNS(cfg.Interface["DNS"]),
            Extras:     cfg.Interface,
        }
        return buildClientConfig(p.ID, data), nil
    case "openvpn", "cloak", "shadowsocks":
        return rebuildOpenVPNClientConfig(p, c.Name)
    default:
        return "", fmt.Errorf("protocol not supported")
    }
}

type openvpnClientParams struct {
    Proto      string
    Port       string
    Cipher     string
    Auth       string
    NcpDisable string
    RemoteHost string
    DNS1       string
    DNS2       string
    CA         string
    Cert       string
    Key        string
    TA         string
    Additional string
}

func buildOpenVPNClientConfig(p openvpnClientParams) string {
    lines := []string{
        "client",
        "dev tun",
        "proto " + p.Proto,
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
    }
    if p.NcpDisable != "" {
        lines = append(lines, p.NcpDisable)
    }
    lines = append(lines,
        "cipher "+p.Cipher,
        "auth "+p.Auth,
        "verb 3",
        "tls-client",
        "tls-version-min 1.2",
        "key-direction 1",
        "remote-cert-tls server",
        "redirect-gateway def1 bypass-dhcp",
        "dhcp-option DNS "+p.DNS1,
        "dhcp-option DNS "+p.DNS2,
        "block-outside-dns",
        fmt.Sprintf("remote %s %s", p.RemoteHost, p.Port),
    )
    if p.Additional != "" {
        lines = append(lines, p.Additional)
    }
    lines = append(lines,
        "",
        "<ca>",
        p.CA,
        "</ca>",
        "<cert>",
        p.Cert,
        "</cert>",
        "<key>",
        p.Key,
        "</key>",
    )
    if p.TA != "" {
        lines = append(lines, "<tls-auth>", p.TA, "</tls-auth>")
    }
    return strings.Join(lines, "\n") + "\n"
}

func parseOpenVPNServerConfig(raw string) map[string]string {
    out := map[string]string{}
    lines := strings.Split(raw, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
            continue
        }
        fields := strings.Fields(line)
        if len(fields) == 0 {
            continue
        }
        key := fields[0]
        if key == "port" && len(fields) >= 2 {
            out["port"] = fields[1]
        } else if key == "proto" && len(fields) >= 2 {
            out["proto"] = fields[1]
        } else if key == "cipher" && len(fields) >= 2 {
            out["cipher"] = fields[1]
        } else if key == "auth" && len(fields) >= 2 {
            out["auth"] = fields[1]
        } else if key == "ncp-disable" {
            out["ncp-disable"] = "1"
        }
    }
    return out
}

func buildCloakClientInfo(container, host string) string {
    pub, _ := readFileInContainer(container, "/opt/amnezia/cloak/cloak_public.key")
    uid, _ := readFileInContainer(container, "/opt/amnezia/cloak/cloak_bypass_uid.key")
    cfgRaw, _ := readFileInContainer(container, "/opt/amnezia/cloak/ck-config.json")
    serverName := ""
    port := "443"
    if cfgRaw != "" {
        var cfg map[string]any
        if json.Unmarshal([]byte(cfgRaw), &cfg) == nil {
            if v, ok := cfg["RedirAddr"].(string); ok && v != "" {
                serverName = v
            }
            if arr, ok := cfg["BindAddr"].([]any); ok && len(arr) > 0 {
                if s, ok := arr[0].(string); ok && strings.Contains(s, ":") {
                    parts := strings.Split(s, ":")
                    port = parts[len(parts)-1]
                }
            }
        }
    }
    return strings.Join([]string{
        "cloak_server=" + host + ":" + port,
        "cloak_server_name=" + serverName,
        "cloak_public_key=" + strings.TrimSpace(pub),
        "cloak_uid=" + strings.TrimSpace(uid),
    }, "\n")
}

func buildShadowsocksClientInfo(container, host string) string {
    cfgRaw, _ := readFileInContainer(container, "/opt/amnezia/shadowsocks/ss-config.json")
    password, _ := readFileInContainer(container, "/opt/amnezia/shadowsocks/shadowsocks.key")
    method := ""
    port := ""
    if cfgRaw != "" {
        var cfg map[string]any
        if json.Unmarshal([]byte(cfgRaw), &cfg) == nil {
            if v, ok := cfg["method"].(string); ok {
                method = v
            }
            if v, ok := cfg["server_port"]; ok {
                port = fmt.Sprintf("%v", v)
            }
        }
    }
    return strings.Join([]string{
        "ss_server=" + host,
        "ss_port=" + port,
        "ss_method=" + method,
        "ss_password=" + strings.TrimSpace(password),
    }, "\n")
}

func createXrayClient(p Protocol, name string) (Client, map[string]string, error) {
    uuid, err := runCmd("docker", "exec", p.Container, "sh", "-c", "xray uuid")
    if err != nil {
        return Client{}, nil, err
    }
    uuid = strings.TrimSpace(uuid)
    if uuid == "" {
        return Client{}, nil, fmt.Errorf("xray uuid empty")
    }

    serverRaw, err := readFileInContainer(p.Container, "/opt/amnezia/xray/server.json")
    if err != nil {
        return Client{}, nil, err
    }
    var cfg map[string]any
    if err := json.Unmarshal([]byte(serverRaw), &cfg); err != nil {
        return Client{}, nil, err
    }

    inbound, ok := firstInbound(cfg)
    if !ok {
        return Client{}, nil, fmt.Errorf("xray inbound missing")
    }
    clients := getMapSlice(inbound, "settings", "clients")
    clients = append(clients, map[string]any{
        "id":   uuid,
        "flow": "xtls-rprx-vision",
    })
    setMapSlice(inbound, clients, "settings", "clients")

    // write back
    updated, _ := json.MarshalIndent(cfg, "", "  ")
    if err := writeFileInContainer(p.Container, "/opt/amnezia/xray/server.json", string(updated)); err != nil {
        return Client{}, nil, err
    }
    _ = runCmdNoOutput("docker", "restart", p.Container)

    hostIP, err := hostPublicIP()
    if err != nil {
        return Client{}, nil, err
    }
    port := fmt.Sprintf("%v", inbound["port"])
    if port == "" {
        port = defaultForField(p, "port")
    }

    serverName, pubKey, shortID := readXrayRealityParams(p.Container, inbound)
    if serverName == "" {
        serverName = "example.com"
    }
    vless := buildVlessLink(uuid, hostIP, port, serverName, pubKey, shortID, nameOrDefault(name, "xray"))

    xrayJSON := buildXrayClientConfigJSON(hostIP, port, uuid, serverName, pubKey, shortID)
    amneziaJSON := buildAmneziaConfigFromXrayConfig(xrayJSON, nameOrDefault(name, "xray"))
    if cfg, err := getSplitTunnelConfig(); err == nil {
        amneziaJSON = applySplitTunnelToJSON(amneziaJSON, cfg)
    }
    vpn := buildVPNString(amneziaJSON)

    now := nowTS()
    clientID, err := insertClient(p.ID, nameOrDefault(name, uuid[:8]), "", uuid, "", "", now)
    if err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "config", vless, now); err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "vpn", vpn, now); err != nil {
        return Client{}, nil, err
    }
    if amneziaJSON != "" {
        _ = insertClientConfig(clientID, "amnezia_json", amneziaJSON, now)
    }

    client := Client{
        ID:         clientID,
        ProtocolID: p.ID,
        Name:       nameOrDefault(name, uuid[:8]),
        Address:    "",
        PublicKey:  uuid,
        CreatedAt:  now,
    }
    exports := map[string]string{
        "config": vless,
        "vpn":    vpn,
    }
    return client, exports, nil
}

func readXrayRealityParams(container string, inbound map[string]any) (serverName, publicKey, shortID string) {
    pub, _ := readFileInContainer(container, "/opt/amnezia/xray/xray_public.key")
    short, _ := readFileInContainer(container, "/opt/amnezia/xray/xray_short_id.key")
    publicKey = strings.TrimSpace(pub)
    shortID = strings.TrimSpace(short)
    if ss, ok := getMap(inbound, "streamSettings", "realitySettings"); ok {
        if v, ok := ss["dest"].(string); ok && v != "" {
            parts := strings.Split(v, ":")
            serverName = parts[0]
        }
        if arr, ok := ss["serverNames"].([]any); ok && len(arr) > 0 {
            if v, ok := arr[0].(string); ok && v != "" {
                serverName = v
            }
        }
    }
    return
}

func buildVlessLink(uuid, host, port, sni, pubKey, shortID, name string) string {
    params := url.Values{}
    params.Set("type", "tcp")
    params.Set("security", "reality")
    params.Set("encryption", "none")
    params.Set("flow", "xtls-rprx-vision")
    if sni != "" {
        params.Set("sni", sni)
    }
    if pubKey != "" {
        params.Set("pbk", pubKey)
    }
    if shortID != "" {
        params.Set("sid", shortID)
    }
    params.Set("fp", "chrome")
    tag := url.PathEscape(name)
    return fmt.Sprintf("vless://%s@%s:%s?%s#%s", uuid, host, port, params.Encode(), tag)
}

func createIPSecClient(p Protocol, name string) (Client, map[string]string, error) {
    user := sanitizeName(name)
    if user == "" {
        user = fmt.Sprintf("ipsec-%d", timeNowUnix())
    }
    pass := randomToken(12)

    psk := ""
    secrets, _ := readFileInContainer(p.Container, "/etc/ipsec.secrets")
    psk = extractPSK(secrets)

    cmd := fmt.Sprintf("set -e; USER=%s; PASS=%s; HASH=$(openssl passwd -1 \"$PASS\"); echo \"$USER l2tpd \\\"$PASS\\\" *\" >> /etc/ppp/chap-secrets; echo \"$USER:$HASH:xauth-psk\" >> /etc/ipsec.d/passwd; ipsec rereadsecrets >/dev/null 2>&1 || true", shellEscape(user), shellEscape(pass))
    if _, err := runCmd("docker", "exec", p.Container, "sh", "-c", cmd); err != nil {
        return Client{}, nil, fmt.Errorf("ipsec user add: %w", err)
    }

    hostIP, err := hostPublicIP()
    if err != nil {
        return Client{}, nil, err
    }
    config := strings.Join([]string{
        "Server: " + hostIP,
        "PSK: " + psk,
        "User: " + user,
        "Password: " + pass,
    }, "\n")

    vpn := ""

    now := nowTS()
    clientID, err := insertClient(p.ID, user, "", "", "", "", now)
    if err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "config", config, now); err != nil {
        return Client{}, nil, err
    }
    if vpn != "" {
        _ = insertClientConfig(clientID, "vpn", vpn, now)
    }

    client := Client{
        ID:         clientID,
        ProtocolID: p.ID,
        Name:       user,
        Address:    "",
        PublicKey:  "",
        CreatedAt:  now,
    }
    exports := map[string]string{
        "config": config,
        "vpn":    vpn,
    }
    return client, exports, nil
}

func createSocksClient(p Protocol, name string) (Client, map[string]string, error) {
    user := sanitizeName(name)
    if user == "" {
        user = fmt.Sprintf("socks-%d", timeNowUnix())
    }
    pass := randomToken(10)

    cfgPath := "/usr/local/3proxy/conf/3proxy.cfg"
    raw, err := readFileInContainer(p.Container, cfgPath)
    if err != nil {
        return Client{}, nil, err
    }
    port := parseSocksPort(raw)
    if port == "" {
        port = defaultForField(p, "port")
    }
    updated := addSocksUser(raw, user, pass)
    if err := writeFileInContainer(p.Container, cfgPath, updated); err != nil {
        return Client{}, nil, err
    }
    _ = runCmdNoOutput("docker", "restart", p.Container)

    hostIP, err := hostPublicIP()
    if err != nil {
        return Client{}, nil, err
    }
    config := strings.Join([]string{
        "Server: " + hostIP,
        "Port: " + port,
        "User: " + user,
        "Pass: " + pass,
    }, "\n")

    telegram := fmt.Sprintf("https://t.me/socks?server=%s&port=%s&user=%s&pass=%s",
        url.QueryEscape(hostIP), url.QueryEscape(port), url.QueryEscape(user), url.QueryEscape(pass))

    vpn := ""

    now := nowTS()
    clientID, err := insertClient(p.ID, user, "", "", "", "", now)
    if err != nil {
        return Client{}, nil, err
    }
    if err := insertClientConfig(clientID, "config", config, now); err != nil {
        return Client{}, nil, err
    }
    if vpn != "" {
        _ = insertClientConfig(clientID, "vpn", vpn, now)
    }
    if err := insertClientConfig(clientID, "telegram", telegram, now); err != nil {
        return Client{}, nil, err
    }

    client := Client{
        ID:         clientID,
        ProtocolID: p.ID,
        Name:       user,
        Address:    "",
        PublicKey:  "",
        CreatedAt:  now,
    }
    exports := map[string]string{
        "config":   config,
        "vpn":      vpn,
        "telegram": telegram,
    }
    return client, exports, nil
}

func parseSocksPort(raw string) string {
    re := regexp.MustCompile(`(?i)socks\\s+[^\\n]*-p\\s*([0-9]+)`)
    if m := re.FindStringSubmatch(raw); len(m) > 1 {
        return m[1]
    }
    re2 := regexp.MustCompile(`(?i)socks\\s+[^\\n]*-p([0-9]+)`)
    if m := re2.FindStringSubmatch(raw); len(m) > 1 {
        return m[1]
    }
    return ""
}

func addSocksUser(raw, user, pass string) string {
    lines := strings.Split(raw, "\n")
    hasAuth := false
    usersIdx := -1
    for i, line := range lines {
        t := strings.TrimSpace(line)
        if strings.HasPrefix(t, "auth ") {
            hasAuth = true
        }
        if strings.HasPrefix(t, "users ") {
            usersIdx = i
        }
    }
    userEntry := fmt.Sprintf("%s:CL:%s", user, pass)
    if usersIdx >= 0 {
        lines[usersIdx] = strings.TrimSpace(lines[usersIdx]) + " " + userEntry
    } else {
        if !hasAuth {
            lines = append(lines, "auth strong")
        }
        lines = append(lines, "users "+userEntry)
    }
    return strings.Join(lines, "\n")
}

func nameOrDefault(name, def string) string {
    if strings.TrimSpace(name) == "" {
        return def
    }
    return name
}

func sanitizeName(name string) string {
    name = strings.TrimSpace(name)
    if name == "" {
        return ""
    }
    re := regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
    out := re.ReplaceAllString(name, "_")
    out = strings.Trim(out, "_")
    if len(out) > 32 {
        out = out[:32]
    }
    return out
}

func randomToken(n int) string {
    buf := make([]byte, n)
    if _, err := rand.Read(buf); err != nil {
        return "changeme"
    }
    return base64.RawURLEncoding.EncodeToString(buf)[:n]
}

func timeNowUnix() int64 {
    return time.Now().Unix()
}

func extractPSK(secrets string) string {
    lines := strings.Split(secrets, "\n")
    re := regexp.MustCompile(`PSK\\s+\"([^\"]+)\"`)
    for _, line := range lines {
        m := re.FindStringSubmatch(line)
        if len(m) > 1 {
            return m[1]
        }
    }
    return ""
}

func firstInbound(cfg map[string]any) (map[string]any, bool) {
    inbounds, ok := cfg["inbounds"].([]any)
    if !ok || len(inbounds) == 0 {
        return nil, false
    }
    m, ok := inbounds[0].(map[string]any)
    return m, ok
}

func getMapSlice(root map[string]any, keys ...string) []map[string]any {
    cur := root
    for i, k := range keys {
        if i == len(keys)-1 {
            arr, ok := cur[k].([]any)
            if !ok {
                return []map[string]any{}
            }
            out := []map[string]any{}
            for _, v := range arr {
                if m, ok := v.(map[string]any); ok {
                    out = append(out, m)
                }
            }
            return out
        }
        next, ok := cur[k].(map[string]any)
        if !ok {
            next = map[string]any{}
            cur[k] = next
        }
        cur = next
    }
    return []map[string]any{}
}

func setMapSlice(root map[string]any, vals []map[string]any, keys ...string) {
    cur := root
    for i, k := range keys {
        if i == len(keys)-1 {
            arr := make([]any, 0, len(vals))
            for _, v := range vals {
                arr = append(arr, v)
            }
            cur[k] = arr
            return
        }
        next, ok := cur[k].(map[string]any)
        if !ok {
            next = map[string]any{}
            cur[k] = next
        }
        cur = next
    }
}

func getMap(root map[string]any, keys ...string) (map[string]any, bool) {
    cur := root
    for _, k := range keys {
        next, ok := cur[k].(map[string]any)
        if !ok {
            return nil, false
        }
        cur = next
    }
    return cur, true
}
