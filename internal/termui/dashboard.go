package termui

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/julian/dev-proxy/internal/config"
	"github.com/julian/dev-proxy/internal/proxy"
)

type Dashboard struct {
	out           io.Writer
	version       string
	listenAddr    string
	baseDomain    string
	routes        []config.Route
	defaultTarget string

	events <-chan proxy.Event

	start  time.Time
	recent []proxy.Event

	total int
	n2xx  int
	n3xx  int
	n4xx  int
	n5xx  int
}

func New(out io.Writer, version, listenAddr, baseDomain string, routes []config.Route, defaultTarget string, events <-chan proxy.Event) *Dashboard {
	cp := make([]config.Route, len(routes))
	copy(cp, routes)
	return &Dashboard{
		out:           out,
		version:       version,
		listenAddr:    listenAddr,
		baseDomain:    strings.TrimPrefix(strings.ToLower(strings.TrimSpace(baseDomain)), "."),
		routes:        cp,
		defaultTarget: strings.TrimSpace(defaultTarget),
		events:        events,
		start:         time.Now(),
		recent:        make([]proxy.Event, 0, 20),
	}
}

func (d *Dashboard) Run(ctx context.Context) {
	// Best-effort terminal control. If the output isn't a terminal, this will just print.
	fmt.Fprint(d.out, "\x1b[?25l")       // hide cursor
	defer fmt.Fprint(d.out, "\x1b[?25h") // show cursor

	d.render()

	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()

	dirty := false
	for {
		select {
		case <-ctx.Done():
			d.render()
			return
		case e, ok := <-d.events:
			if !ok {
				d.render()
				return
			}
			d.total++
			switch {
			case e.Status >= 200 && e.Status <= 299:
				d.n2xx++
			case e.Status >= 300 && e.Status <= 399:
				d.n3xx++
			case e.Status >= 400 && e.Status <= 499:
				d.n4xx++
			case e.Status >= 500 && e.Status <= 599:
				d.n5xx++
			}
			if len(d.recent) == cap(d.recent) {
				copy(d.recent, d.recent[1:])
				d.recent[len(d.recent)-1] = e
			} else {
				d.recent = append(d.recent, e)
			}
			dirty = true
		case <-t.C:
			if dirty {
				d.render()
				dirty = false
			}
		}
	}
}

func (d *Dashboard) render() {
	width := termWidth()
	baseURL := listenBaseURL(d.listenAddr)

	fmt.Fprint(d.out, "\x1b[2J\x1b[H") // clear + home

	// Header (ngrok-ish).
	fmt.Fprintf(d.out, "dev-proxy %s  online  %s\n", d.version, time.Since(d.start).Truncate(time.Second))
	fmt.Fprint(d.out, strings.Repeat("-", min(width, 80)))
	fmt.Fprint(d.out, "\n")

	fmt.Fprintf(d.out, "Forwarding:  %s\n", baseURL)
	if d.baseDomain != "" {
		fmt.Fprintf(d.out, "Index:       %s/  (Host: %s)\n", baseURL, d.baseDomain)
	}
	fmt.Fprintf(d.out, "Health:      %s/__dev-proxy/healthz\n", baseURL)
	fmt.Fprint(d.out, "Stop:        Ctrl-C\n")
	fmt.Fprint(d.out, "Hint:        cd /path/to/repo && dev-proxy project init -port 5173\n")
	fmt.Fprint(d.out, "\n")

	fmt.Fprintf(d.out, "Requests: total=%d  2xx=%d  3xx=%d  4xx=%d  5xx=%d\n", d.total, d.n2xx, d.n3xx, d.n4xx, d.n5xx)
	fmt.Fprint(d.out, "\n")

	// Routes (sorted).
	fmt.Fprint(d.out, "Routes:\n")
	routes := make([]config.Route, len(d.routes))
	copy(routes, d.routes)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Host != routes[j].Host {
			return routes[i].Host < routes[j].Host
		}
		if routes[i].PathPrefix != routes[j].PathPrefix {
			return routes[i].PathPrefix < routes[j].PathPrefix
		}
		return routes[i].Target < routes[j].Target
	})
	maxRoutes := 12
	for i, r := range routes {
		if i >= maxRoutes {
			fmt.Fprintf(d.out, "  ... (%d more)\n", len(routes)-maxRoutes)
			break
		}
		path := r.PathPrefix
		if path == "" {
			path = "/"
		}
		fmt.Fprintf(d.out, "  %-40s  %-10s  ->  %s\n", trimTo(r.Host, 40), trimTo(path, 10), r.Target)
	}
	if d.defaultTarget != "" {
		fmt.Fprintf(d.out, "  default%33s     ->  %s\n", "", d.defaultTarget)
	}
	fmt.Fprint(d.out, "\n")

	// Recent requests.
	fmt.Fprint(d.out, "Requests (latest):\n")
	if len(d.recent) == 0 {
		fmt.Fprint(d.out, "  (none yet)\n")
		return
	}
	for i := len(d.recent) - 1; i >= 0; i-- {
		e := d.recent[i]
		ts := e.Time.Format("15:04:05")
		status := fmt.Sprintf("%d", e.Status)
		dur := e.Duration.Truncate(time.Millisecond).String()
		target := e.Target
		if target == "" {
			target = "-"
		}
		line := fmt.Sprintf("  %s  %3s  %-4s  %-22s  %-26s  %7s  %s",
			ts, status, e.Method, trimTo(e.Host, 22), trimTo(e.Path, 26), dur, trimTo(target, 28))
		fmt.Fprintln(d.out, trimTo(line, width))
	}
}

func listenBaseURL(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return "http://localhost"
	}
	host := listen
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	if strings.HasPrefix(host, "0.0.0.0:") {
		host = "localhost:" + strings.TrimPrefix(host, "0.0.0.0:")
	}
	if strings.HasPrefix(host, "[::]:") {
		host = "localhost:" + strings.TrimPrefix(host, "[::]:")
	}
	if strings.HasSuffix(host, ":80") || host == "localhost:80" {
		return "http://localhost"
	}
	if strings.Contains(host, ":") {
		return "http://" + host
	}
	return "http://" + host
}

func termWidth() int {
	if v := strings.TrimSpace(getenv("COLUMNS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 40 && n <= 400 {
			return n
		}
	}
	return 120
}

func getenv(k string) string {
	return os.Getenv(k)
}

func trimTo(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
