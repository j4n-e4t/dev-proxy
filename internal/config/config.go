package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Route is a concrete host/path_prefix -> target mapping used by the proxy.
type Route struct {
	Host       string `yaml:"host"`
	PathPrefix string `yaml:"path_prefix,omitempty"`
	Target     string `yaml:"target"`
}

// RuntimeConfig is what the proxy server needs after resolving the global and per-project configs.
type RuntimeConfig struct {
	BaseDomain    string
	Listen        string
	DefaultTarget string
	Routes        []Route
}

// GlobalConfig is the machine-global config and references per-project config files.
type GlobalConfig struct {
	Listen        string       `yaml:"listen,omitempty"`
	BaseDomain    string       `yaml:"base_domain"`
	DefaultTarget string       `yaml:"default_target,omitempty"`
	Projects      []ProjectRef `yaml:"projects,omitempty"`

	// Optional extra explicit routes in the global config.
	Routes []Route `yaml:"routes,omitempty"`
}

type ProjectRef struct {
	// Path to a per-project .dev-proxy.yaml.
	Path string `yaml:"path"`

	// Enabled defaults to true when omitted.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// ProjectConfig lives in each project repo as .dev-proxy.yaml.
type ProjectConfig struct {
	Project  string             `yaml:"project"`
	Services map[string]Service `yaml:"services,omitempty"`

	// Optional extra explicit routes for this project.
	Routes []Route `yaml:"routes,omitempty"`
}

type Service struct {
	Target     string `yaml:"target"`
	PathPrefix string `yaml:"path_prefix,omitempty"`
	Host       string `yaml:"host,omitempty"` // Optional override. If empty, host is computed from project+service+base_domain.
}

func LoadGlobal(path string) (GlobalConfig, error) {
	path, err := ExpandPath(path)
	if err != nil {
		return GlobalConfig{}, err
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return GlobalConfig{}, err
	}

	var cfg GlobalConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return GlobalConfig{}, err
	}

	cfg.BaseDomain = strings.TrimSpace(cfg.BaseDomain)
	if cfg.BaseDomain == "" {
		return GlobalConfig{}, errors.New("global config: base_domain is required")
	}
	return cfg, nil
}

func LoadProject(path string) (ProjectConfig, error) {
	path, err := ExpandPath(path)
	if err != nil {
		return ProjectConfig{}, err
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return ProjectConfig{}, err
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return ProjectConfig{}, err
	}
	cfg.Project = strings.TrimSpace(cfg.Project)
	if cfg.Project == "" {
		return ProjectConfig{}, errors.New("project config: project is required")
	}
	if cfg.Services == nil {
		cfg.Services = map[string]Service{}
	}
	for name, svc := range cfg.Services {
		if strings.TrimSpace(name) == "" {
			return ProjectConfig{}, errors.New("project config: services has empty key")
		}
		if strings.TrimSpace(svc.Target) == "" {
			return ProjectConfig{}, fmt.Errorf("project config: services[%q].target is required", name)
		}
		if svc.PathPrefix != "" && !strings.HasPrefix(svc.PathPrefix, "/") {
			return ProjectConfig{}, fmt.Errorf("project config: services[%q].path_prefix must start with /", name)
		}
	}
	for i := range cfg.Routes {
		r := cfg.Routes[i]
		if strings.TrimSpace(r.Host) == "" || strings.TrimSpace(r.Target) == "" {
			return ProjectConfig{}, fmt.Errorf("project config: routes[%d] must include host and target", i)
		}
		if r.PathPrefix != "" && !strings.HasPrefix(r.PathPrefix, "/") {
			return ProjectConfig{}, fmt.Errorf("project config: routes[%d].path_prefix must start with /", i)
		}
	}
	return cfg, nil
}

// ResolveRuntime loads the global config and all enabled project configs, then compiles them into concrete routes.
func ResolveRuntime(globalPath string) (RuntimeConfig, error) {
	g, err := LoadGlobal(globalPath)
	if err != nil {
		return RuntimeConfig{}, err
	}

	baseDomain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(g.BaseDomain)), ".")
	if baseDomain == "" {
		return RuntimeConfig{}, errors.New("global config: base_domain is required")
	}

	var routes []Route
	routes = append(routes, g.Routes...)

	globalDir := filepath.Dir(mustAbs(globalPath))

	for _, ref := range g.Projects {
		enabled := true
		if ref.Enabled != nil {
			enabled = *ref.Enabled
		}
		if !enabled {
			continue
		}
		if strings.TrimSpace(ref.Path) == "" {
			return RuntimeConfig{}, errors.New("global config: projects[].path is required")
		}

		pPath := strings.TrimSpace(ref.Path)
		if strings.HasPrefix(pPath, "~") || filepath.IsAbs(pPath) {
			// ExpandPath will handle ~ and abs.
		} else {
			// Relative paths are relative to the global config directory.
			pPath = filepath.Join(globalDir, pPath)
		}

		pcfg, err := LoadProject(pPath)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("load project %q: %w", pPath, err)
		}
		project := strings.ToLower(strings.TrimSpace(pcfg.Project))

		for svcName, svc := range pcfg.Services {
			svcName = strings.ToLower(strings.TrimSpace(svcName))
			host := strings.TrimSpace(svc.Host)
			if host == "" {
				// Convention:
				// - root service: <project>.<base_domain>
				// - other services: <service>.<project>.<base_domain>
				if svcName == "root" || svcName == "@" {
					host = fmt.Sprintf("%s.%s", project, baseDomain)
				} else {
					host = fmt.Sprintf("%s.%s.%s", svcName, project, baseDomain)
				}
			}
			routes = append(routes, Route{
				Host:       host,
				PathPrefix: svc.PathPrefix,
				Target:     svc.Target,
			})
		}

		routes = append(routes, pcfg.Routes...)
	}

	if len(routes) == 0 && strings.TrimSpace(g.DefaultTarget) == "" {
		return RuntimeConfig{}, errors.New("no routes resolved and no default_target configured")
	}

	listen := strings.TrimSpace(g.Listen)
	if listen == "" {
		listen = ":80"
	}

	return RuntimeConfig{
		BaseDomain:    baseDomain,
		Listen:        listen,
		DefaultTarget: strings.TrimSpace(g.DefaultTarget),
		Routes:        routes,
	}, nil
}

func WriteYAML(path string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func ExpandPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("empty path")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func mustAbs(path string) string {
	p, err := ExpandPath(path)
	if err != nil {
		return path
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}
