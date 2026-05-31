# UpCloud CLI Plus — `upctl-plus`

[![Based on UpCloud CLI](https://img.shields.io/badge/based%20on-UpCloud%20CLI-blue)](https://github.com/UpCloudLtd/upcloud-cli)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

`upctl-plus` is an enhanced command-line interface for [UpCloud](https://upcloud.com/), built on the official [UpCloud Go SDK](https://github.com/UpCloudLtd/upcloud-go-api). It pairs a scriptable CLI with an interactive terminal **dashboard** (a TUI in the spirit of k9s/lazygit) for managing your servers.

> **Status:** v1 focuses on **servers** (browse + lifecycle). Storage and networks are scriptable foundations today and are next in line for the dashboard.

## Highlights

- **Interactive dashboard** — run `upctl-plus` with no arguments to open a master-detail TUI: a server list (with public IPv4), a detail pane (overview, storage, network), and lifecycle actions with confirmation.
- **Scriptable CLI** — every action is also a plain subcommand with `table`/`json`/`yaml` output, safe to pipe and automate. The TUI never hijacks a non-interactive (piped) invocation.
- **Token-first auth** — uses an UpCloud API token by default, and is compatible with your existing `upctl` configuration.
- **Single static binary** — no runtime dependencies.

## Installation

### Build from source (recommended for now)

```bash
git clone https://github.com/shaliru/upcloud-cli-plus.git
cd upcloud-cli-plus
go build -o bin/upctl-plus ./cmd/upctl-plus
./bin/upctl-plus --help
```

Requires Go 1.24+.

### go install

```bash
go install github.com/shaliru/upcloud-cli-plus/cmd/upctl-plus@latest
```

## Configuration

Credentials are resolved **environment-first, then a config file**:

```bash
# Preferred: an UpCloud API token (People → API tokens in the Control Panel)
export UPCLOUD_TOKEN="ucat_…"

# Or sub-account username/password
export UPCLOUD_USERNAME="…"
export UPCLOUD_PASSWORD="…"
```

If no environment variables are set, `upctl-plus` reads the `upctl`-compatible config file at `~/.config/upctl.yaml` (honouring `XDG_CONFIG_HOME`):

```yaml
token: ucat_…
# or:
# username: …
# password: …
```

If you already use `upctl`, your existing configuration works as-is.

## Usage

### Interactive dashboard

```bash
upctl-plus              # open the dashboard (lands on the server list)
upctl-plus server list -i   # open the dashboard, deep-linked to servers
```

Keys:

| Key | Action |
|-----|--------|
| `↑` / `↓` | move the selection |
| `enter` | load the selected server's details |
| `s` / `x` / `r` | start / stop / restart (asks `y`/`n` to confirm) |
| `q` | quit |

A long error stays pinned (in red) at the bottom until you press a key.

### CLI

```bash
upctl-plus server list                  # table of all servers
upctl-plus server list -o json | jq     # scriptable JSON
upctl-plus server show <hostname|uuid>  # details (resolves hostname or title)
upctl-plus server restart web-sg-1      # act by hostname, UUID, or title
upctl-plus server stop web-sg-1 db-sg-1 # act on several at once
```

Servers can be referenced by **UUID, hostname, or title**.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1`–`99` | Number of failed operations (e.g. 1 of 3 restarts failed) |
| `100`+ | Other errors (missing flag, authentication failure, etc.) |

## Development

```bash
go test ./...     # run the test suite
go vet ./...      # static checks
go build ./...    # build everything
```

The codebase is layered so the CLI and the TUI are thin front-ends over one shared service layer (`internal/cloud`): `internal/cli` (Cobra commands), `internal/tui` (Bubble Tea dashboard), `internal/output` (rendering), `internal/config` (credentials).

Dependencies are kept current automatically via [Renovate](./renovate.json) (minor/patch bumps auto-merge when CI is green).

## License

[MIT](./LICENSE). Originally derived from [UpCloud CLI](https://github.com/UpCloudLtd/upcloud-cli); rebuilt on the official UpCloud Go SDK.
