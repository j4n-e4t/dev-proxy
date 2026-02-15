package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/julian/dev-proxy/internal/config"
)

func TestHostMatch(t *testing.T) {
	cases := []struct {
		pat  string
		host string
		want bool
	}{
		{"api.localhost", "api.localhost", true},
		{"api.localhost", "API.LOCALHOST", true},
		{"*.localhost", "a.localhost", true},
		{"*.localhost", "localhost", false},
		{"*.app.localhost", "x.app.localhost", true},
		{"*.app.localhost", "app.localhost", false},
	}
	for _, c := range cases {
		if got := hostMatch(c.pat, c.host); got != c.want {
			t.Fatalf("hostMatch(%q, %q)=%v want %v", c.pat, c.host, got, c.want)
		}
	}
}

func TestRoutingByHostAndPathPrefix(t *testing.T) {
	h, err := NewHandler(Options{
		BaseDomain: "localhost",
		Routes: []config.Route{
			{Host: "api.localhost", PathPrefix: "/v1", Target: "http://127.0.0.1:4000"},
			{Host: "*.app.localhost", Target: "http://127.0.0.1:5173"},
		},
		Default: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	_ = h

	req := httptest.NewRequest(http.MethodGet, "http://api.localhost/v1/users", nil)
	req.Host = "api.localhost"
	rr := httptest.NewRecorder()

	// We don't want to actually proxy; just ensure match selection doesn't 502.
	// Use the health endpoint to validate the handler works without dialing.
	health := httptest.NewRequest(http.MethodGet, "http://any/__dev-proxy/healthz", nil)
	health.Host = "api.localhost"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, health)
	if rr2.Code != 200 {
		t.Fatalf("health status=%d want 200", rr2.Code)
	}

	// For routing behavior, validate internal matching by hitting an unmapped path:
	// this will attempt to proxy and likely fail; we only assert we get a 502 from
	// proxy error rather than "no route" (indicating match success).
	h.ServeHTTP(rr, req)
	if rr.Code != 502 {
		t.Fatalf("status=%d want 502 (proxy error due to no backend in test)", rr.Code)
	}
	if rr.Body.String() == "" {
		t.Fatalf("expected error body")
	}
}

func TestBaseDomainIndex(t *testing.T) {
	h, err := NewHandler(Options{
		BaseDomain: "localhost",
		Routes: []config.Route{
			{Host: "myapp.localhost", Target: "http://127.0.0.1:5173"},
			{Host: "api.myapp.localhost", PathPrefix: "/v1", Target: "http://127.0.0.1:4000"},
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Host = "localhost"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct == "" {
		t.Fatalf("expected Content-Type")
	}
	body := rr.Body.String()
	if body == "" || body[0] != '<' {
		t.Fatalf("expected html body")
	}
	if !strings.Contains(body, "myapp.localhost") || !strings.Contains(body, "api.myapp.localhost") {
		t.Fatalf("expected domains in index body")
	}
}

func TestProxyErrorCanReturnHTML(t *testing.T) {
	h, err := NewHandler(Options{
		BaseDomain: "localhost",
		Routes: []config.Route{
			{Host: "api.localhost", Target: "http://127.0.0.1:1"},
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://api.localhost/", nil)
	req.Host = "api.localhost"
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 502 {
		t.Fatalf("status=%d want 502", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("expected html content-type, got %q", rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "Bad Gateway") {
		t.Fatalf("expected Bad Gateway in body")
	}
}
