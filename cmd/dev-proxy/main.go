package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/julian/dev-proxy/internal/config"
	"github.com/julian/dev-proxy/internal/proxy"
	"github.com/julian/dev-proxy/internal/termui"
	"github.com/julian/dev-proxy/internal/version"
	"gopkg.in/yaml.v3"
)

func main() {
	log.SetFlags(0)

	args := os.Args[1:]
	if len(args) == 0 {
		runCmd(args)
		return
	}

	switch args[0] {
	case "run":
		runCmd(args[1:])
	case "init":
		// Back-compat: project init. Requires global init to have been run.
		projectInitCmd(args[1:])
	case "init-global":
		globalInitCmd(args[1:])
	case "global":
		if len(args) >= 2 && args[1] == "init" {
			globalInitCmd(args[2:])
			return
		}
		usage()
	case "project":
		if len(args) >= 2 && args[1] == "init" {
			projectInitCmd(args[2:])
			return
		}
		usage()
	case "version", "--version", "-version":
		fmt.Println(version.String())
	case "help", "--help", "-h":
		usage()
	default:
		// Back-compat: treat unknown as "run" (so flags still work).
		runCmd(args)
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func usage() {
	defaultGlobal := config.DefaultGlobalConfigPath()
	fmt.Fprintf(os.Stderr, `dev-proxy - local reverse proxy for multi-project dev

Usage:
  dev-proxy run [flags]
  dev-proxy global init [flags]
  dev-proxy project init [flags]
  dev-proxy version

Commands:
  run     Load the global config which references per-project configs, then start the proxy.
  global init   Create the global config (one-time machine setup).
  project init  Create .dev-proxy.yaml in the current project and register it into the global config.

Run flags:
`)
	fmt.Fprintf(os.Stderr, `
  -global PATH
        Path to global config (default %q)
  -listen ADDR
        Listen address (overrides global config). Example: :80
  -default-target URL
        Default target when no route matches (overrides global config)
  -route SPEC
        Extra route override. Format: HOST[,/path_prefix]=TARGET. Repeatable.
  -preserve-host
        Preserve original Host header when proxying.
  -ui
        Show a terminal dashboard (TTY only). Use -ui=false to disable.

Init flags:
Global init flags:
  -global PATH
        Path to global config to create (default %q)
  -base-domain DOMAIN
        Base domain to use (default "localhost")
  -listen ADDR
        Listen address to write (default ":80")
  -default-target URL
        Default target when no route matches (optional)
  -force
        Overwrite existing global config file.

Project init flags:
  -file PATH
        Path to write per-project config (default ".dev-proxy.yaml")
  -project NAME
        Project name (used in generated hostnames; default = current dir name)
  -port N
        Convenience: set root service to http://127.0.0.1:N
  -service SPEC
        Add service. Format: NAME=PORT or NAME=URL. Repeatable.
  -global PATH
        Path to global config to update (default %q)
  -force
        Overwrite existing per-project config file.
`, defaultGlobal, defaultGlobal, defaultGlobal)
	fmt.Fprintf(os.Stderr, `
Examples:
  dev-proxy global init -base-domain localhost
  dev-proxy project init -port 5173
  dev-proxy run -listen :8080

Tips:
  - Visit http://<base_domain>:<port>/ to see an index page of all configured domains (for localhost: http://localhost:8080/).
  - Most systems resolve *.localhost to 127.0.0.1 without /etc/hosts changes (e.g. api.myapp.localhost).
`)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		globalPath     string
		listenAddr     string
		defaultTarget  string
		preserveHost   bool
		ui             bool
		routeSpecs     multiFlag
		routeOverrides []config.Route
	)

	fs.StringVar(&globalPath, "global", config.DefaultGlobalConfigPath(), "Path to global config.")
	fs.StringVar(&listenAddr, "listen", "", "Listen address (overrides global config). Example: :80")
	fs.StringVar(&defaultTarget, "default-target", "", "Default target when no route matches (overrides global config).")
	fs.BoolVar(&preserveHost, "preserve-host", false, "Preserve original Host header when proxying.")
	fs.BoolVar(&ui, "ui", isTerminal(os.Stdout), "Show terminal dashboard (TTY only). Use -ui=false to disable.")
	fs.Var(&routeSpecs, "route", "Extra route override. Format: HOST[,/path_prefix]=TARGET. Repeatable.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		log.Fatalf("run: %v", err)
	}

	for _, spec := range routeSpecs {
		r, err := parseRouteSpec(spec)
		if err != nil {
			log.Fatalf("route: %v", err)
		}
		routeOverrides = append(routeOverrides, r)
	}

	rcfg, err := config.ResolveRuntime(globalPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("config: %v (run `dev-proxy global init` first)", err)
		}
		log.Fatalf("config: %v", err)
	}
	if listenAddr != "" {
		rcfg.Listen = listenAddr
	}
	if defaultTarget != "" {
		rcfg.DefaultTarget = defaultTarget
	}
	if len(routeOverrides) > 0 {
		rcfg.Routes = append(rcfg.Routes, routeOverrides...)
	}

	if ui && !isTerminal(os.Stdout) {
		ui = false
	}

	var events chan proxy.Event
	var onEvent func(proxy.Event)
	if ui {
		events = make(chan proxy.Event, 256)
		onEvent = func(e proxy.Event) {
			select {
			case events <- e:
			default:
			}
		}
	}

	h, err := proxy.NewHandler(proxy.Options{
		BaseDomain:   rcfg.BaseDomain,
		PreserveHost: preserveHost,
		Routes:       rcfg.Routes,
		Default:      rcfg.DefaultTarget,
		Quiet:        ui,
		OnEvent:      onEvent,
	})
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}

	srv := &http.Server{
		Addr:              rcfg.Listen,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if !ui {
		log.Printf("dev-proxy %s listening on %s", version.String(), rcfg.Listen)
		for _, r := range rcfg.Routes {
			log.Printf("route host=%q path_prefix=%q -> %s", r.Host, r.PathPrefix, r.Target)
		}
		if rcfg.DefaultTarget != "" {
			log.Printf("default -> %s", rcfg.DefaultTarget)
		}
		log.Printf("index -> http://%s%s/", rcfg.BaseDomain, formatListenPort(rcfg.Listen))
		log.Printf("health -> http://localhost%s/__dev-proxy/healthz", formatListenPort(rcfg.Listen))

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Common case when trying to bind :80 without sufficient privileges.
			log.Fatalf("listen: %v", err)
		}
		return
	}

	// UI mode: run server + dashboard concurrently so bind errors can still exit cleanly.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			cancel()
			return
		}
		errCh <- nil
		cancel()
	}()

	d := termui.New(os.Stdout, version.String(), rcfg.Listen, rcfg.BaseDomain, rcfg.Routes, rcfg.DefaultTarget, events)
	d.Run(runCtx)

	if err := <-errCh; err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func globalInitCmd(args []string) {
	fs := flag.NewFlagSet("global init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		globalPath    string
		baseDomain    string
		listenAddr    string
		defaultTarget string
		force         bool
	)

	fs.StringVar(&globalPath, "global", config.DefaultGlobalConfigPath(), "Path to global config to create.")
	fs.StringVar(&baseDomain, "base-domain", "localhost", "Base domain to use.")
	fs.StringVar(&listenAddr, "listen", ":80", "Listen address to write.")
	fs.StringVar(&defaultTarget, "default-target", "", "Default target when no route matches (optional).")
	fs.BoolVar(&force, "force", false, "Overwrite existing global config file.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		log.Fatalf("global init: %v", err)
	}

	gPath, err := config.ExpandPath(globalPath)
	if err != nil {
		log.Fatalf("global init: %v", err)
	}

	if !force {
		if _, err := os.Stat(gPath); err == nil {
			log.Fatalf("global init: %s already exists (use -force to overwrite)", gPath)
		}
	}

	gcfg := config.GlobalConfig{
		Listen:        listenAddr,
		BaseDomain:    baseDomain,
		DefaultTarget: defaultTarget,
		Projects:      nil,
		Routes:        nil,
	}

	if err := os.MkdirAll(filepath.Dir(gPath), 0o755); err != nil {
		log.Fatalf("global init: %v", err)
	}
	if err := config.WriteYAML(gPath, gcfg); err != nil {
		log.Fatalf("global init: write %s: %v", gPath, err)
	}
	log.Printf("wrote %s", gPath)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func formatListenPort(listen string) string {
	// Best-effort: extract a :port suffix if present, for printing URLs.
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return ""
	}
	if strings.HasPrefix(listen, ":") {
		if listen == ":80" {
			return ""
		}
		return listen
	}
	if i := strings.LastIndex(listen, ":"); i != -1 && i < len(listen)-1 {
		p := listen[i:]
		if p == ":80" {
			return ""
		}
		return p
	}
	return ""
}

func projectInitCmd(args []string) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		filePath   string
		project    string
		port       int
		services   multiFlag
		globalPath string
		force      bool
	)

	fs.StringVar(&filePath, "file", ".dev-proxy.yaml", "Path to write per-project config.")
	fs.StringVar(&project, "project", "", "Project name (default: current directory name).")
	fs.IntVar(&port, "port", 0, "Convenience: set root service to http://127.0.0.1:N")
	fs.Var(&services, "service", "Add service. Format: NAME=PORT or NAME=URL. Repeatable.")
	fs.StringVar(&globalPath, "global", config.DefaultGlobalConfigPath(), "Path to global config to update.")
	fs.BoolVar(&force, "force", false, "Overwrite existing per-project config file.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return
		}
		log.Fatalf("init: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	if project == "" {
		project = filepath.Base(cwd)
	}

	pcfg := config.ProjectConfig{
		Project:  project,
		Services: map[string]config.Service{},
	}

	if port > 0 {
		pcfg.Services["root"] = config.Service{Target: fmt.Sprintf("http://127.0.0.1:%d", port)}
	}
	for _, spec := range services {
		name, value, err := parseKV(spec)
		if err != nil {
			log.Fatalf("init: service: %v", err)
		}
		if value == "" {
			log.Fatalf("init: service %q has empty target", name)
		}
		target := value
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			target = fmt.Sprintf("http://127.0.0.1:%d", n)
		}
		pcfg.Services[name] = config.Service{Target: target}
	}
	if len(pcfg.Services) == 0 {
		log.Fatalf("init: no services configured (use -port or -service)")
	}

	if !force {
		if _, err := os.Stat(filePath); err == nil {
			log.Fatalf("init: %s already exists (use -force to overwrite)", filePath)
		}
	}

	if err := config.WriteYAML(filePath, pcfg); err != nil {
		log.Fatalf("init: write %s: %v", filePath, err)
	}
	log.Printf("wrote %s", filePath)

	if err := registerProject(globalPath, filePath); err != nil {
		log.Fatalf("init: register: %v", err)
	}
}

func registerProject(globalPath, projectConfigPath string) error {
	gPath, err := config.ExpandPath(globalPath)
	if err != nil {
		return err
	}
	pPath, err := filepath.Abs(projectConfigPath)
	if err != nil {
		return err
	}

	var gcfg config.GlobalConfig
	b, err := os.ReadFile(gPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist (run `dev-proxy global init` first)", gPath)
		}
		return err
	}
	if err := yamlUnmarshal(b, &gcfg); err != nil {
		return fmt.Errorf("parse global config %s: %w", gPath, err)
	}

	if strings.TrimSpace(gcfg.BaseDomain) == "" {
		return errors.New("global config: base_domain is required")
	}

	// Ensure it isn't already present.
	for _, ref := range gcfg.Projects {
		if strings.TrimSpace(ref.Path) == pPath {
			log.Printf("global already contains %s", pPath)
			return config.WriteYAML(gPath, gcfg)
		}
	}
	gcfg.Projects = append(gcfg.Projects, config.ProjectRef{Path: pPath})

	// Ensure parent dir exists.
	if err := os.MkdirAll(filepath.Dir(gPath), 0o755); err != nil {
		return err
	}
	if err := config.WriteYAML(gPath, gcfg); err != nil {
		return err
	}
	log.Printf("registered %s in %s", pPath, gPath)
	return nil
}

func parseRouteSpec(spec string) (config.Route, error) {
	spec = strings.TrimSpace(spec)
	left, target, ok := strings.Cut(spec, "=")
	if !ok || strings.TrimSpace(left) == "" || strings.TrimSpace(target) == "" {
		return config.Route{}, fmt.Errorf("invalid route spec %q (expected HOST[,/path_prefix]=TARGET)", spec)
	}
	left = strings.TrimSpace(left)
	target = strings.TrimSpace(target)

	host := left
	pathPrefix := ""
	if h, p, ok := strings.Cut(left, ","); ok {
		host = strings.TrimSpace(h)
		pathPrefix = strings.TrimSpace(p)
	}
	if host == "" {
		return config.Route{}, fmt.Errorf("invalid route spec %q (empty host)", spec)
	}
	if pathPrefix != "" && !strings.HasPrefix(pathPrefix, "/") {
		return config.Route{}, fmt.Errorf("invalid route spec %q (path_prefix must start with /)", spec)
	}
	return config.Route{Host: host, PathPrefix: pathPrefix, Target: target}, nil
}

func parseKV(spec string) (string, string, error) {
	spec = strings.TrimSpace(spec)
	k, v, ok := strings.Cut(spec, "=")
	if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
		return "", "", fmt.Errorf("invalid spec %q (expected NAME=VALUE)", spec)
	}
	return strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v), nil
}

// Kept local to main so config doesn't depend on yaml for partial reads.
func yamlUnmarshal(b []byte, v any) error {
	return yaml.Unmarshal(b, v)
}
