package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRuntime_NormalizesWhitespaceInGeneratedHosts(t *testing.T) {
	td := t.TempDir()

	projectPath := filepath.Join(td, "project.dev-proxy.yaml")
	globalPath := filepath.Join(td, "global.dev-proxy.yaml")

	if err := os.WriteFile(projectPath, []byte(`
project: "Open Ports"
services:
  root:
    target: "http://127.0.0.1:5173"
  api v1:
    target: "http://127.0.0.1:4000"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(globalPath, []byte(`
base_domain: "localhost"
projects:
  - path: "`+projectPath+`"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	rcfg, err := ResolveRuntime(globalPath)
	if err != nil {
		t.Fatalf("ResolveRuntime: %v", err)
	}

	var hosts []string
	for _, r := range rcfg.Routes {
		hosts = append(hosts, r.Host)
	}

	// Root service uses <project>.<base_domain>.
	wantRoot := "open-ports.localhost"
	// Non-root services use <service>.<project>.<base_domain>.
	wantSvc := "api-v1.open-ports.localhost"

	foundRoot := false
	foundSvc := false
	for _, h := range hosts {
		if h == wantRoot {
			foundRoot = true
		}
		if h == wantSvc {
			foundSvc = true
		}
	}
	if !foundRoot || !foundSvc {
		t.Fatalf("expected hosts %q and %q, got %v", wantRoot, wantSvc, hosts)
	}
}

