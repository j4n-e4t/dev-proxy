# dev-proxy

Local reverse proxy for multi-project development.

Note: `/etc/hosts` does not support wildcard hostnames. If you use `*.localhost` (for example `myapp.localhost`, `api.myapp.localhost`), most systems resolve those to `127.0.0.1` without editing hosts.

## Install / Build

```bash
go build ./cmd/dev-proxy
```

## Run

```bash
./dev-proxy run
```

## Config Model

- Global config:
  - macOS/Linux default: `~/.dev-proxy.yaml`
  - Windows default: `%APPDATA%\\dev-proxy\\config.yaml`
  - sets `base_domain`, `listen`, and lists project config file paths
- Per-project config: `.dev-proxy.yaml` inside each repo
  - defines services and their local ports/targets

Generated hostnames:
- `root` service: `<project>.<base_domain>` (e.g. `myapp.localhost`)
- other services: `<service>.<project>.<base_domain>` (e.g. `api.myapp.localhost`)

## Init A Project

```bash
./dev-proxy global init -base-domain localhost
./dev-proxy project init -port 5173
```

This writes `.dev-proxy.yaml` in the current directory and registers it into your global config (global must exist first).

Or specify multiple services:

```bash
./dev-proxy project init -service root=5173 -service api=4000
```

To listen on port 80 on macOS you typically need privileges:

```bash
sudo ./dev-proxy run
```

Or choose a different port:

```bash
./dev-proxy run -listen :8080
```

## Health

`GET /__dev-proxy/healthz` returns `ok`.
