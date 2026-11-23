package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestCollector(t *testing.T, onlineFails bool) *collector {
	t.Helper()
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/private/login" {
			if r.Method != "POST" {
				t.Error("login must POST")
			}
			if r.FormValue("username") != "admin" || r.FormValue("password") != "secret" {
				t.Error("bad credentials")
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/private"})
			json.NewEncoder(w).Encode(map[string]any{"success": true})
			return
		}
		if _, err := r.Cookie("session"); err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch r.URL.Path {
		case "/private/panel/api/inbounds/list":
			if r.Method != "GET" {
				t.Error("list must GET")
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": []inbound{
				{ID: 1, Protocol: "vless", Settings: legacySettings(`{"clients":[{"email":"phone","id":"private-uuid"},{"email":"new"}]}`), ClientStats: []clientTraffic{{Email: "phone", Up: 123, Down: 456}}},
				{ID: 2, Protocol: "trojan", Settings: legacySettings(`{"clients":[{"email":"ignored"}]}`)},
			}})
		case "/private/panel/api/clients/onlines":
			http.NotFound(w, r)
		case "/private/panel/api/inbounds/onlines":
			if r.Method != "POST" {
				t.Error("onlines must POST")
			}
			if onlineFails {
				http.Error(w, "unsupported", 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": []string{"phone"}})
		default:
			t.Errorf("unexpected or mutating endpoint: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(panel.Close)
	wdtt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# TYPE vpn_client_online gauge\nvpn_client_online{protocol=\"wdtt\",client_id=\"test\",client_name=\"Phone\"} 1\nwdtt_server_connections 2\n"))
	}))
	t.Cleanup(wdtt.Close)
	jar, _ := cookiejar.New(nil)
	return &collector{base: panel.URL + "/private", username: "admin", password: "secret", key: []byte("key"), panel: &http.Client{Jar: jar}, wdtt: &http.Client{Transport: rewriteTransport{target: wdtt.URL}}}
}

type rewriteTransport struct{ target string }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	rewritten, _ := http.NewRequestWithContext(req.Context(), req.Method, r.target+req.URL.Path, nil)
	clone.URL = rewritten.URL
	return http.DefaultTransport.RoundTrip(clone)
}

func TestPanelSessionBasePathAndClientCounters(t *testing.T) {
	c := newTestCollector(t, false)
	metrics, online, err := c.vless(context.Background())
	if err != nil || !online {
		t.Fatalf("%v online=%v", err, online)
	}
	for _, part := range []string{`direction="up"} 123`, `direction="down"} 456`, `client_name="phone"} 1`, `client_name="new"} 0`} {
		if !strings.Contains(metrics, part) {
			t.Errorf("missing %s in %s", part, metrics)
		}
	}
	for _, secret := range []string{"private-uuid", "ignored", "secret"} {
		if strings.Contains(metrics, secret) {
			t.Fatal("leaked credentials or unrelated protocol")
		}
	}
	if c.id("phone") == c.id("other") {
		t.Fatal("different clients share an ID")
	}
	if strings.Contains(metrics, `client_name="new",direction=`) {
		t.Fatal("missing counter represented as zero")
	}
	// Second scrape reuses the cookie without changing panel configuration.
	if _, _, err := c.vless(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func legacySettings(value string) json.RawMessage { encoded, _ := json.Marshal(value); return encoded }

func TestModernPanelDeduplicatesSharedTrafficRows(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/onlines") {
			json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": []string{"phone"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": []inbound{
			{ID: 1, Protocol: "vless", Settings: json.RawMessage(`{"clients":[{"email":"phone"}]}`), ClientStats: []clientTraffic{{ID: 99, Email: "phone", Up: 256, Down: 512}}},
			{ID: 2, Protocol: "vless", Settings: json.RawMessage(`{"clients":[{"email":"phone"}]}`), ClientStats: []clientTraffic{{ID: 99, Email: "phone", Up: 256, Down: 512}}},
		}})
	}))
	defer server.Close()
	c := &collector{base: server.URL, panel: server.Client(), token: "token", key: []byte("key")}
	metrics, online, err := c.vless(context.Background())
	if err != nil || !online {
		t.Fatal(err)
	}
	if strings.Count(metrics, "vpn_client_online{") != 1 || !strings.Contains(metrics, `direction="down"} 512`) || strings.Contains(metrics, `direction="down"} 1024`) {
		t.Fatal("shared rows double counted:", metrics)
	}
}

func TestOnlineFailurePreservesTrafficButDoesNotInventOffline(t *testing.T) {
	c := newTestCollector(t, true)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, part := range []string{`vpn_source_up{protocol="vless"} 1`, `vpn_source_online_up{protocol="vless"} 0`, `direction="down"} 456`, `vpn_source_up{protocol="wdtt"} 1`} {
		if !strings.Contains(body, part) {
			t.Fatalf("missing %s", part)
		}
	}
	if strings.Contains(body, `vpn_client_online{protocol="vless"`) {
		t.Fatal("invented offline status")
	}
}

func TestFailedSourcesDoNotReturnStaleMetrics(t *testing.T) {
	c := newTestCollector(t, false)
	c.base = "http://127.0.0.1:0"
	c.wdtt = &http.Client{Transport: rewriteTransport{target: "http://127.0.0.1:0"}}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	if !strings.Contains(body, `vpn_source_up{protocol="wdtt"} 0`) || !strings.Contains(body, `vpn_source_up{protocol="vless"} 0`) {
		t.Fatal(body)
	}
	if strings.Contains(body, "vpn_client_online{") {
		t.Fatal("returned stale clients")
	}
}

func TestPersistentIDKeyAndMetricEscaping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	key, err := persistentKey(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := persistentKey(path)
	if err != nil || string(key) != string(again) {
		t.Fatal("ID key changed")
	}
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := persistentKey(path); err == nil {
		t.Fatal("corrupt key accepted")
	}
	if quote("a\n\"b\\c") != `"a\n\"b\\c"` {
		t.Fatal("invalid escaping")
	}
}

func TestMalformedPanelResponseDoesNotLookLikeNoClients(t *testing.T) {
	for _, body := range []string{`{"success":true}`, `{"success":true,"obj":null}`, `{"success":false}`, `not-json`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer server.Close()
			c := &collector{base: server.URL, panel: server.Client()}
			var inbounds []inbound
			if err := c.panelRequest(context.Background(), "GET", "/list", nil, &inbounds); err == nil {
				t.Fatal("accepted missing data")
			}
		})
	}
}

func TestTokenAuthDoesNotLoginOrExposeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			t.Fatal("token auth attempted password login")
		}
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("missing bearer token")
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "obj": []any{}})
	}))
	defer server.Close()
	c := &collector{base: server.URL, panel: server.Client(), token: "private-token"}
	metrics, online, err := c.vless(context.Background())
	if err != nil || !online || strings.Contains(metrics, "private-token") {
		t.Fatalf("token auth failed: %v", err)
	}
}

func TestReadAuthRejectsMixedAndIncompleteCredentials(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"token":"secret"}`, true}, {`{"username":"a","password":"b"}`, true},
		{`{"token":"secret","username":"a"}`, false}, {`{"username":"a"}`, false}, {`{}`, false}, {`bad`, false},
	} {
		path := filepath.Join(t.TempDir(), "auth.json")
		if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readAuth(path)
		if (err == nil) != tc.valid {
			t.Errorf("wrong auth validation for %s", tc.body)
		}
	}
}
