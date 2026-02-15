package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/julian/dev-proxy/internal/config"
)

type Options struct {
	BaseDomain   string
	Routes       []config.Route
	Default      string
	PreserveHost bool
	Quiet        bool
	OnEvent      func(Event)
}

type handler struct {
	baseDomain   string
	indexHTML    []byte
	routes       []route
	def          *httputil.ReverseProxy
	defTarget    string
	preserveHost bool
	logRequests  bool
	onEvent      func(Event)
}

type route struct {
	hostPat    string
	pathPrefix string
	target     string
	proxy      *httputil.ReverseProxy
}

type Event struct {
	Time     time.Time
	Kind     string // index|health|proxy|noroute
	Method   string
	Host     string
	Path     string
	Target   string
	Status   int
	Bytes    int64
	Duration time.Duration
}

func NewHandler(opts Options) (http.Handler, error) {
	if len(opts.Routes) == 0 && opts.Default == "" {
		return nil, errors.New("no routes and no default target")
	}

	baseDomain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(opts.BaseDomain)), ".")

	h := &handler{
		baseDomain:   baseDomain,
		preserveHost: opts.PreserveHost,
		logRequests:  !opts.Quiet,
		onEvent:      opts.OnEvent,
	}

	for i := range opts.Routes {
		r := opts.Routes[i]
		p, err := newProxy(r.Target, opts.PreserveHost)
		if err != nil {
			return nil, fmt.Errorf("route[%d] target=%q: %w", i, r.Target, err)
		}
		h.routes = append(h.routes, route{
			hostPat:    r.Host,
			pathPrefix: r.PathPrefix,
			target:     r.Target,
			proxy:      p,
		})
	}

	if opts.Default != "" {
		p, err := newProxy(opts.Default, opts.PreserveHost)
		if err != nil {
			return nil, fmt.Errorf("default target=%q: %w", opts.Default, err)
		}
		h.def = p
		h.defTarget = opts.Default
	}

	if baseDomain != "" {
		h.indexHTML = buildIndexHTML(baseDomain, opts.Routes, opts.Default)
	}

	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	origHost := stripPort(r.Host)
	origPath := requestPath(r)

	// Health endpoint for quick checks.
	if r.Method == http.MethodGet && r.URL.Path == "/__dev-proxy/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
		h.emit(Event{
			Time:     time.Now(),
			Kind:     "health",
			Method:   r.Method,
			Host:     origHost,
			Path:     origPath,
			Status:   http.StatusOK,
			Bytes:    3,
			Duration: time.Since(start),
		})
		return
	}

	// Base-domain index: http://<base_domain>/ shows all configured domains.
	if h.baseDomain != "" &&
		(strings.EqualFold(origHost, h.baseDomain)) &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		(r.URL.Path == "" || r.URL.Path == "/") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		var n int64
		if r.Method != http.MethodHead {
			nn, _ := w.Write(h.indexHTML)
			n = int64(nn)
		}
		h.emit(Event{
			Time:     time.Now(),
			Kind:     "index",
			Method:   r.Method,
			Host:     origHost,
			Path:     origPath,
			Status:   http.StatusOK,
			Bytes:    n,
			Duration: time.Since(start),
		})
		return
	}

	rt := h.match(origHost, r.URL.Path)
	if rt != nil {
		withProxyHeaders(r, origHost)
		cw := &captureWriter{ResponseWriter: w}
		rt.proxy.ServeHTTP(cw, r)
		dur := time.Since(start)
		if h.logRequests {
			log.Printf("%d %s %s host=%q -> %s (%s)", cw.statusCode(), r.Method, origPath, origHost, rt.target, dur.Truncate(time.Millisecond))
		}
		h.emit(Event{
			Time:     time.Now(),
			Kind:     "proxy",
			Method:   r.Method,
			Host:     origHost,
			Path:     origPath,
			Target:   rt.target,
			Status:   cw.statusCode(),
			Bytes:    cw.bytes,
			Duration: dur,
		})
		return
	}
	if h.def != nil {
		withProxyHeaders(r, origHost)
		cw := &captureWriter{ResponseWriter: w}
		h.def.ServeHTTP(cw, r)
		dur := time.Since(start)
		if h.logRequests {
			log.Printf("%d %s %s host=%q -> %s (%s)", cw.statusCode(), r.Method, origPath, origHost, h.defTarget, dur.Truncate(time.Millisecond))
		}
		h.emit(Event{
			Time:     time.Now(),
			Kind:     "proxy",
			Method:   r.Method,
			Host:     origHost,
			Path:     origPath,
			Target:   h.defTarget,
			Status:   cw.statusCode(),
			Bytes:    cw.bytes,
			Duration: dur,
		})
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	n, _ := fmt.Fprintf(w, "no route for host=%q path=%q\n", origHost, r.URL.Path)
	if h.logRequests {
		log.Printf("%d %s %s host=%q -> (no route) (%s)", http.StatusBadGateway, r.Method, origPath, origHost, time.Since(start).Truncate(time.Millisecond))
	}
	h.emit(Event{
		Time:     time.Now(),
		Kind:     "noroute",
		Method:   r.Method,
		Host:     origHost,
		Path:     origPath,
		Status:   http.StatusBadGateway,
		Bytes:    int64(n),
		Duration: time.Since(start),
	})
}

func (h *handler) match(host, path string) *route {
	for i := range h.routes {
		rt := &h.routes[i]
		if !hostMatch(rt.hostPat, host) {
			continue
		}
		if rt.pathPrefix != "" && !strings.HasPrefix(path, rt.pathPrefix) {
			continue
		}
		return rt
	}
	return nil
}

func hostMatch(pat, host string) bool {
	pat = strings.ToLower(stripPort(strings.TrimSpace(pat)))
	host = strings.ToLower(stripPort(strings.TrimSpace(host)))
	if pat == host {
		return true
	}
	if strings.HasPrefix(pat, "*.") {
		suffix := strings.TrimPrefix(pat, "*")
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	return false
}

func stripPort(hostport string) string {
	if hostport == "" {
		return ""
	}
	// If it's IPv6 in brackets, net.SplitHostPort works when there's a port.
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	// If there's no port or it's an invalid host:port, just return the input.
	return hostport
}

func newProxy(target string, preserveHost bool) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("missing scheme (expected http:// or https://)")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origHost := req.Host
		origDirector(req)
		if preserveHost {
			req.Host = origHost
		}
		// Ensure we keep the original path as-is; NewSingleHostReverseProxy already does,
		// but some middleware may mutate it.
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*") || accept == "" {
			writeProxyErrorHTML(w, r, target, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, "proxy error: target=%s err=%v\n", target, err)
	}
	return rp, nil
}

func withProxyHeaders(r *http.Request, host string) {
	// X-Forwarded-For: add the immediate client IP.
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && ip != "" {
		prior := r.Header.Get("X-Forwarded-For")
		if prior == "" {
			r.Header.Set("X-Forwarded-For", ip)
		} else {
			r.Header.Set("X-Forwarded-For", prior+", "+ip)
		}
	}
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	} else {
		r.Header.Set("X-Forwarded-Proto", "http")
	}
	if host != "" {
		r.Header.Set("X-Forwarded-Host", host)
	}
}

type indexItem struct {
	Project    string
	Service    string
	Host       string
	PathPrefix string
	Target     string
}

func buildIndexHTML(baseDomain string, routes []config.Route, defTarget string) []byte {
	items := make([]indexItem, 0, len(routes))
	for _, r := range routes {
		host := strings.TrimSpace(r.Host)
		if host == "" {
			continue
		}
		project, service, ok := projectServiceFromHost(host, baseDomain)
		if !ok {
			// Best-effort fallback: group by the left-most label (or "other").
			project = "other"
			service = ""
		}
		items = append(items, indexItem{
			Project:    project,
			Service:    service,
			Host:       host,
			PathPrefix: r.PathPrefix,
			Target:     r.Target,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Project != items[j].Project {
			return items[i].Project < items[j].Project
		}
		if items[i].Service != items[j].Service {
			return items[i].Service < items[j].Service
		}
		if items[i].Host != items[j].Host {
			return items[i].Host < items[j].Host
		}
		if items[i].PathPrefix != items[j].PathPrefix {
			return items[i].PathPrefix < items[j].PathPrefix
		}
		return items[i].Target < items[j].Target
	})

	var b strings.Builder
	// Minimal, readable page.
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>dev-proxy</title>")
	b.WriteString("<style>")
	b.WriteString("body{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;margin:24px;line-height:1.35}")
	b.WriteString("h1{font-size:20px;margin:0 0 12px}")
	b.WriteString("h2{font-size:14px;margin:18px 0 6px}")
	b.WriteString("table{border-collapse:collapse;width:100%;max-width:1100px}")
	b.WriteString("th,td{border:1px solid #ddd;padding:8px;vertical-align:top}")
	b.WriteString("th{background:#f7f7f7;text-align:left}")
	b.WriteString("a{color:#0040dd;text-decoration:none}a:hover{text-decoration:underline}")
	b.WriteString(".muted{color:#666}")
	b.WriteString("</style></head><body>")
	b.WriteString("<h1>dev-proxy domains</h1>")
	b.WriteString("<div class=\"muted\">Base domain: ")
	b.WriteString(html.EscapeString(baseDomain))
	b.WriteString("</div>")
	if defTarget != "" {
		b.WriteString("<div class=\"muted\">Default target: ")
		b.WriteString(html.EscapeString(defTarget))
		b.WriteString("</div>")
	}

	lastProject := ""
	if len(items) == 0 {
		b.WriteString("<p>No routes configured.</p>")
		b.WriteString("</body></html>")
		return []byte(b.String())
	}

	for _, it := range items {
		if it.Project != lastProject {
			if lastProject != "" {
				b.WriteString("</tbody></table>")
			}
			lastProject = it.Project
			b.WriteString("<h2>")
			b.WriteString(html.EscapeString(it.Project))
			b.WriteString("</h2>")
			b.WriteString("<table><thead><tr><th>Domain</th><th>Path</th><th>Target</th></tr></thead><tbody>")
		}

		link := "http://" + it.Host
		if it.PathPrefix != "" {
			link += it.PathPrefix
		} else {
			link += "/"
		}
		b.WriteString("<tr><td><a href=\"")
		b.WriteString(html.EscapeString(link))
		b.WriteString("\">")
		b.WriteString(html.EscapeString(it.Host))
		if it.Service != "" && it.Service != "root" && it.Service != "@" {
			b.WriteString("</a><div class=\"muted\">service: ")
			b.WriteString(html.EscapeString(it.Service))
			b.WriteString("</div>")
		} else {
			b.WriteString("</a>")
		}
		b.WriteString("</td><td>")
		if it.PathPrefix == "" {
			b.WriteString("<span class=\"muted\">/</span>")
		} else {
			b.WriteString(html.EscapeString(it.PathPrefix))
		}
		b.WriteString("</td><td>")
		b.WriteString(html.EscapeString(it.Target))
		b.WriteString("</td></tr>")
	}
	b.WriteString("</tbody></table>")
	b.WriteString("</body></html>")
	return []byte(b.String())
}

func projectServiceFromHost(host, baseDomain string) (project, service string, ok bool) {
	host = strings.ToLower(stripPort(strings.TrimSpace(host)))
	baseDomain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(baseDomain), "."))
	if host == "" || baseDomain == "" {
		return "", "", false
	}
	hostParts := strings.Split(host, ".")
	baseParts := strings.Split(baseDomain, ".")
	if len(hostParts) <= len(baseParts) {
		return "", "", false
	}
	if strings.Join(hostParts[len(hostParts)-len(baseParts):], ".") != baseDomain {
		return "", "", false
	}
	left := hostParts[:len(hostParts)-len(baseParts)]
	if len(left) == 1 {
		return left[0], "root", true
	}
	if len(left) == 2 {
		return left[1], left[0], true
	}
	// Unexpected shape (e.g. extra subdomains). Treat last label as project and first as service.
	return left[len(left)-1], left[0], true
}

func writeProxyErrorHTML(w http.ResponseWriter, r *http.Request, target string, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)

	host := stripPort(r.Host)
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>dev-proxy: Bad Gateway</title>")
	b.WriteString("<style>")
	b.WriteString("body{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;margin:24px;line-height:1.35}")
	b.WriteString(".card{border:1px solid #ddd;border-radius:10px;padding:16px;max-width:900px}")
	b.WriteString("h1{font-size:18px;margin:0 0 10px}")
	b.WriteString("pre{background:#f7f7f7;border:1px solid #eee;border-radius:8px;padding:12px;overflow:auto}")
	b.WriteString(".muted{color:#666}")
	b.WriteString("</style></head><body>")
	b.WriteString("<div class=\"card\">")
	b.WriteString("<h1>Bad Gateway (proxy dial failed)</h1>")
	b.WriteString("<div class=\"muted\">")
	b.WriteString(html.EscapeString(r.Method))
	b.WriteString(" ")
	b.WriteString(html.EscapeString(host))
	b.WriteString(html.EscapeString(path))
	b.WriteString("</div>")
	b.WriteString("<p>Upstream target:</p><pre>")
	b.WriteString(html.EscapeString(target))
	b.WriteString("</pre>")
	b.WriteString("<p>Error:</p><pre>")
	b.WriteString(html.EscapeString(err.Error()))
	b.WriteString("</pre>")
	b.WriteString("</div></body></html>")

	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(b.String()))
	}
}

func (h *handler) emit(e Event) {
	if h.onEvent != nil {
		h.onEvent(e)
	}
}

func requestPath(r *http.Request) string {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	return path
}

type captureWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *captureWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *captureWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *captureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return h.Hijack()
}

func (w *captureWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
