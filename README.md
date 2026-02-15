# dev-proxy

Local reverse proxy for multi-project development.

Note: `/etc/hosts` does not support wildcard hostnames. If you use `*.localhost` (for example `myapp.localhost`, `api.myapp.localhost`), most systems resolve those to `127.0.0.1` without editing hosts.

## Getting Started

### 1) Build (from source)

macOS/Linux:

```bash
go build -o dev-proxy ./cmd/dev-proxy
```

Windows (PowerShell):

```powershell
go build -o dev-proxy.exe .\cmd\dev-proxy
```

### 2) Create the global config (one time per machine)

Pick a non-privileged port to start (recommended):

```bash
./dev-proxy global init -base-domain localhost -listen :8080
```

Windows (PowerShell):

```powershell
.\dev-proxy.exe global init -base-domain localhost -listen :8080
```

### 3) Initialize a project and register it

From inside a project repo:

```bash
./dev-proxy project init -port 5173
```

Now start the proxy:

```bash
./dev-proxy run
```

Visit the index page:
- `http://localhost:8080/` (or whatever `-listen` port you chose)
- your app(s) at `http://<project>.localhost:8080/`, `http://api.<project>.localhost:8080/`, etc.

## Config Model

- Global config:
  - macOS/Linux default: `~/.dev-proxy.yaml`
  - Windows default: `%APPDATA%\\dev-proxy\\config.yaml`
  - sets `base_domain`, `listen`, and lists project config file paths
- Per-project config: `.dev-proxy.yaml` inside each repo
  - defines services and their local ports/targets

You can always override the global config location with `-global PATH`. The CLI help prints the platform default.

Generated hostnames:
- `root` service: `<project>.<base_domain>` (e.g. `myapp.localhost`)
- other services: `<service>.<project>.<base_domain>` (e.g. `api.myapp.localhost`)

## More Examples

Initialize a project with multiple services:

```bash
./dev-proxy project init -service root=5173 -service api=4000
```

To listen on port 80 on macOS you typically need privileges:

```bash
sudo ./dev-proxy run
```

Or choose a different port (recommended):

```bash
./dev-proxy run -listen :8080
```

## Health

`GET /__dev-proxy/healthz` returns `ok`.
