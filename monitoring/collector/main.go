package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type panelResponse struct {
	Success bool            `json:"success"`
	Obj     json.RawMessage `json:"obj"`
}

type clientTraffic struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
}

type inbound struct {
	ID          int64           `json:"id"`
	Protocol    string          `json:"protocol"`
	Settings    json.RawMessage `json:"settings"`
	ClientStats []clientTraffic `json:"clientStats"`
}

type collector struct {
	mu                       sync.Mutex
	panel                    *http.Client
	wdtt                     *http.Client
	base, username, password string
	token                    string
	key                      []byte
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s) + `"`
}

func (c *collector) panelRequest(ctx context.Context, method, path string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return errors.New("invalid panel URL")
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := c.panel.Do(req)
	if err != nil {
		return errors.New("panel request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("panel HTTP %d", response.StatusCode)
	}
	var envelope panelResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&envelope); err != nil {
		return errors.New("invalid panel response")
	}
	if !envelope.Success {
		return errors.New("panel rejected request")
	}
	if out != nil {
		if len(envelope.Obj) == 0 || string(envelope.Obj) == "null" {
			return errors.New("missing panel data")
		}
		if err := json.Unmarshal(envelope.Obj, out); err != nil {
			return errors.New("incompatible panel data")
		}
	}
	return nil
}

func (c *collector) login(ctx context.Context) error {
	return c.panelRequest(ctx, "POST", "/login", url.Values{"username": {c.username}, "password": {c.password}}, nil)
}

func (c *collector) id(email string) string {
	mac := hmac.New(sha256.New, c.key)
	fmt.Fprintf(mac, "vless\x00%s", email)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func (c *collector) vless(ctx context.Context) (string, bool, error) {
	var inbounds []inbound
	if err := c.panelRequest(ctx, "GET", "/panel/api/inbounds/list", nil, &inbounds); err != nil {
		if c.token != "" {
			return "", false, err
		}
		if err := c.login(ctx); err != nil {
			return "", false, err
		}
		if err := c.panelRequest(ctx, "GET", "/panel/api/inbounds/list", nil, &inbounds); err != nil {
			return "", false, err
		}
	}
	var online []string
	onlineOK := c.panelRequest(ctx, "POST", "/panel/api/clients/onlines", nil, &online) == nil
	if !onlineOK {
		onlineOK = c.panelRequest(ctx, "POST", "/panel/api/inbounds/onlines", nil, &online) == nil
	}
	active := make(map[string]bool, len(online))
	for _, email := range online {
		active[email] = true
	}
	type aggregate struct {
		email   string
		records map[string]clientTraffic
	}
	clients := make(map[string]*aggregate)
	for _, in := range inbounds {
		if in.Protocol != "vless" {
			continue
		}
		// Settings also include clients without a traffic record yet. Decode only
		// the non-secret field; never export full inbound settings or UUIDs.
		var settings struct {
			Clients []struct {
				Email string `json:"email"`
			} `json:"clients"`
		}
		settingsJSON := in.Settings
		// v2 returns a JSON-encoded string, v3 returns an object.
		if len(settingsJSON) > 0 && settingsJSON[0] == '"' {
			var encoded string
			if json.Unmarshal(settingsJSON, &encoded) != nil {
				return "", onlineOK, errors.New("invalid encoded inbound settings")
			}
			settingsJSON = []byte(encoded)
		}
		if err := json.Unmarshal(settingsJSON, &settings); err != nil {
			return "", onlineOK, errors.New("invalid inbound settings")
		}
		stats := make(map[string]clientTraffic)
		for _, traffic := range in.ClientStats {
			if traffic.Up < 0 || traffic.Down < 0 {
				return "", onlineOK, errors.New("negative panel traffic")
			}
			stats[traffic.Email] = traffic
		}
		seen := make(map[string]bool)
		for _, client := range settings.Clients {
			if client.Email == "" || seen[client.Email] {
				return "", onlineOK, errors.New("clients require distinct nonempty email labels")
			}
			seen[client.Email] = true
			entry := clients[client.Email]
			if entry == nil {
				entry = &aggregate{email: client.Email, records: make(map[string]clientTraffic)}
				clients[client.Email] = entry
			}
			if traffic, ok := stats[client.Email]; ok {
				recordKey := fmt.Sprintf("inbound:%d", in.ID)
				if traffic.ID > 0 {
					recordKey = fmt.Sprintf("record:%d", traffic.ID)
				}
				if previous, exists := entry.records[recordKey]; exists && previous != traffic {
					return "", onlineOK, errors.New("inconsistent shared client traffic")
				}
				entry.records[recordKey] = traffic
			}
		}
	}
	var result strings.Builder
	for _, entry := range clients {
		labels := `protocol="vless",client_id=` + quote(c.id(entry.email)) + `,client_name=` + quote(entry.email)
		// A shared traffic row can appear on several inbounds in 3x-ui v3.
		// Count each row once; distinct legacy rows for the same email are summed.
		if len(entry.records) > 0 {
			var up, down int64
			for _, traffic := range entry.records {
				up += traffic.Up
				down += traffic.Down
			}
			fmt.Fprintf(&result, "vpn_client_traffic_bytes_total{%s,direction=\"up\"} %d\n", labels, up)
			fmt.Fprintf(&result, "vpn_client_traffic_bytes_total{%s,direction=\"down\"} %d\n", labels, down)
		}
		fmt.Fprintf(&result, "vpn_client_present{%s} 1\n", labels)
		if onlineOK {
			value := 0
			if active[entry.email] {
				value = 1
			}
			fmt.Fprintf(&result, "vpn_client_online{%s} %d\n", labels, value)
		}
	}
	return result.String(), onlineOK, nil
}

func (c *collector) wdttMetrics(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://wdtt/metrics", nil)
	response, err := c.wdtt.Do(req)
	if err != nil {
		return "", errors.New("WDTT socket unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", fmt.Errorf("WDTT HTTP %d", response.StatusCode)
	}
	const max = 16 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil || len(data) > max {
		return "", errors.New("invalid WDTT metrics size")
	}
	var output strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "vpn_client_") || strings.HasPrefix(line, "wdtt_") {
			fmt.Fprintln(&output, line)
		}
	}
	if output.Len() == 0 {
		return "", errors.New("empty WDTT metrics")
	}
	return output.String(), nil
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(w, `# HELP vpn_source_up Client traffic source is available.
# TYPE vpn_source_up gauge
# HELP vpn_source_online_up Client online status source is available.
# TYPE vpn_source_online_up gauge
# HELP vpn_client_traffic_bytes_total Client payload bytes, direction from client perspective.
# TYPE vpn_client_traffic_bytes_total counter
# HELP vpn_client_online Client online according to the source protocol.
# TYPE vpn_client_online gauge
# HELP vpn_client_workers Active authenticated WDTT workers.
# TYPE vpn_client_workers gauge
# HELP vpn_client_present Client exists in the source.
# TYPE vpn_client_present gauge
# HELP wdtt_server_connections Current WDTT transport connections.
# TYPE wdtt_server_connections gauge
# HELP wdtt_handshake_failures_total Failed WDTT handshakes.
# TYPE wdtt_handshake_failures_total counter
# HELP wdtt_handshake_throttles_total Throttled WDTT handshakes.
# TYPE wdtt_handshake_throttles_total counter
# HELP wdtt_worker_limit_rejections_total WDTT worker limit rejections.
# TYPE wdtt_worker_limit_rejections_total counter`)
	// Separate timeouts ensure one failed source does not hide the other.
	wdttCtx, wdttCancel := context.WithTimeout(ctx, 2*time.Second)
	wdtt, err := c.wdttMetrics(wdttCtx)
	wdttCancel()
	if err == nil {
		fmt.Fprint(w, wdtt)
		fmt.Fprintln(w, `vpn_source_up{protocol="wdtt"} 1`+"\n"+`vpn_source_online_up{protocol="wdtt"} 1`)
	} else {
		fmt.Fprintln(w, `vpn_source_up{protocol="wdtt"} 0`+"\n"+`vpn_source_online_up{protocol="wdtt"} 0`)
	}
	vless, onlineOK, err := c.vless(ctx)
	if err == nil {
		fmt.Fprint(w, vless)
		fmt.Fprintln(w, `vpn_source_up{protocol="vless"} 1`)
	} else {
		fmt.Fprintln(w, `vpn_source_up{protocol="vless"} 0`)
		log.Printf("VLESS collection: %v", err) // Errors never include response bodies or credentials.
	}
	onlineValue := 0
	if err == nil && onlineOK {
		onlineValue = 1
	}
	fmt.Fprintf(w, "vpn_source_online_up{protocol=\"vless\"} %d\n", onlineValue)
}

type panelAuth struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func readAuth(path string) (panelAuth, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return panelAuth{}, errors.New("cannot read panel auth file")
	}
	var auth panelAuth
	if json.Unmarshal(value, &auth) != nil {
		return panelAuth{}, errors.New("invalid panel auth JSON")
	}
	if auth.Token != "" && auth.Username == "" && auth.Password == "" {
		return auth, nil
	}
	if auth.Token == "" && auth.Username != "" && auth.Password != "" {
		return auth, nil
	}
	return panelAuth{}, errors.New("provide either token or username and password")
}

func persistentKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("invalid collector ID key")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(key)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	return key, closeErr
}

func main() {
	base := strings.TrimRight(os.Getenv("XUI_BASE_URL"), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		log.Fatal("set XUI_BASE_URL to panel URL including its web base path")
	}
	jar, _ := cookiejar.New(nil)
	key, err := persistentKey("/data/xui-id.key")
	if err != nil {
		log.Fatal("cannot load collector ID key")
	}
	socket := os.Getenv("WDTT_METRICS_SOCKET")
	if socket == "" {
		socket = "/run/wdtt-metrics/metrics.sock"
	}
	auth, err := readAuth("/run/secrets/xui_auth")
	if err != nil {
		log.Fatal(err)
	}
	c := &collector{
		base: base, key: key, username: auth.Username, password: auth.Password, token: auth.Token,
		panel: &http.Client{Jar: jar, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		wdtt: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}, Timeout: 2 * time.Second},
	}
	server := &http.Server{Addr: "127.0.0.1:9810", Handler: c, ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 15 * time.Second}
	log.Fatal(server.ListenAndServe())
}
