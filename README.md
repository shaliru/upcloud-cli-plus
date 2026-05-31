# UpCloud CLI Plus — `upctl-plus`

[![Based on UpCloud CLI](https://img.shields.io/badge/based%20on-UpCloud%20CLI-blue)](https://github.com/UpCloudLtd/upcloud-cli)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

`upctl-plus` is an enhanced command-line interface for [UpCloud](https://upcloud.com/), built on the official [UpCloud Go SDK](https://github.com/UpCloudLtd/upcloud-go-api). It pairs a scriptable CLI with an interactive terminal **dashboard** (a TUI in the spirit of k9s/lazygit) for managing your servers, storage, and networks.

> **Status:** read + server lifecycle across **servers, storage, and networks**, in both the CLI and the dashboard. Resource creation/deletion and managed services are not in yet (see [Roadmap](#roadmap)).

## Highlights

- **Interactive dashboard** — run `upctl-plus` with no arguments. Full-width lists with a `Servers │ Storage │ Networks` tab bar; press **Enter** to drill into a full-screen detail, **Esc** to return. Colour-coded (blue UUIDs, green/red `●` state), with a highlighted selected row.
- **Scriptable CLI** — every view is also a plain subcommand with `table`/`json`/`yaml` output, safe to pipe and automate. The dashboard never hijacks a non-interactive (piped) invocation.
- **Sensible defaults that cut the noise** — `storage list` shows your real devices (not UpCloud's public templates); `network list` shows your private networks (not the per-zone public/utility infrastructure). The full set is one flag away.
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
upctl-plus                  # open the dashboard (lands on the Servers tab)
upctl-plus storage list -i  # open the dashboard, deep-linked to the Storage tab
upctl-plus network list -i  # …deep-linked to Networks
```

Keys:

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | switch resource tab (Servers / Storage / Networks) |
| `↑` / `↓` | move the selection |
| `Enter` | drill into the selected item's full-screen detail |
| `Esc` | return from detail to the list (`↑↓` scrolls a detail view) |
| `s` / `x` / `r` | start / stop / restart the selected server (asks `y`/`n`) — Servers tab |
| `[` / `]` | switch storage sub-category: Devices / Backups / Custom images — Storage tab |
| `a` | toggle private ⇄ all networks (incl. UpCloud infra) — Networks tab |
| `q` | quit |

A long error stays pinned (in red) at the bottom until you press a key.

### CLI

```bash
# Servers
upctl-plus server list                   # table of all servers
upctl-plus server list -o json | jq      # scriptable JSON
upctl-plus server show <hostname|uuid>   # details (resolves hostname or title)
upctl-plus server restart web-sg-1       # act by hostname, UUID, or title
upctl-plus server stop web-sg-1 db-sg-1  # act on several at once

# Storage (read-only) — default shows your devices; use --type for more
upctl-plus storage list                  # devices only
upctl-plus storage list --type backups   # backups | images | all
upctl-plus storage show <title|uuid>

# Networks (read-only) — default shows your private SDN networks
upctl-plus network list                  # private only
upctl-plus network list --type all       # include UpCloud public/utility nets
upctl-plus network show <name|uuid>
```

Resources can be referenced by **UUID, or by their name/hostname/title**.

**Colour:** table output is coloured on a terminal and plain when piped. Control it with `--color auto|always|never` (default `auto`); `NO_COLOR` is also honoured. `--color always` keeps colour through e.g. `| less -R`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1`–`99` | Number of failed operations (e.g. 1 of 3 restarts failed) |
| `100`+ | Other errors (missing flag, authentication failure, etc.) |

## Roadmap

- [ ] **Dashboard niceties** — in-list `/` filter, a sort toggle, and cross-links (jump from a server's detail to its attached storage/network).
- [ ] Resource **create / delete / modify** (including a guided server-create wizard).
- [ ] Managed services — databases, Kubernetes, load balancers, object storage.
- [ ] **Firewall rules** in the server detail view.

## Development

```bash
go test ./...     # run the test suite
go vet ./...      # static checks
go build ./...    # build everything
```

The codebase is layered so the CLI and the TUI are thin front-ends over one shared service layer (`internal/cloud`): `internal/cli` (Cobra commands), `internal/tui` (Bubble Tea dashboard), `internal/output` (CLI rendering), `internal/palette` (shared colours), `internal/config` (credentials).

Dependencies are kept current automatically via [Renovate](./renovate.json) (minor/patch bumps auto-merge when CI is green).

## License

[MIT](./LICENSE). Originally derived from [UpCloud CLI](https://github.com/UpCloudLtd/upcloud-cli); rebuilt on the official UpCloud Go SDK.
