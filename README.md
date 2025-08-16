# UpCloud CLI Plus - upctl-plus

[![Original upcloud-cli](https://img.shields.io/badge/based%20on-UpCloud%20CLI-blue)](https://github.com/UpCloudLtd/upcloud-cli)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

`upctl-plus` is an enhanced command-line interface to [UpCloud](https://upcloud.com/) services with interactive features. It provides all the functionality of the original UpCloud CLI plus interactive resource selection, visual management, and streamlined workflows.

## ✨ What's New

- **🖱️ Interactive Server Selection** - Navigate servers with arrow keys instead of copying UUIDs
- **📊 Columnar Display** - Clean, aligned tables showing server info including public IP addresses
- **⌨️ Keyboard Navigation** - Use arrow keys, search with `/`, and select with Enter
- **🎯 Context-Aware Actions** - Action menus that adapt based on server state
- **🔄 Backward Compatible** - All original `upctl` functionality preserved

## 🚀 Installation

### Option 1: Download and Build (Recommended)

```bash
# Clone the repository
git clone https://github.com/shaliru/upcloud-cli-plus.git
cd upcloud-cli-plus

# Build the binary
make build

# The binary will be available at ./bin/upctl-plus
./bin/upctl-plus --help
```

### Option 2: Direct Go Install

```bash
go install github.com/shaliru/upcloud-cli-plus/cmd/upctl-plus@latest
```

## ⚙️ Configuration

`upctl-plus` uses the same configuration as the original UpCloud CLI. If you already have `upctl` configured, `upctl-plus` will work immediately.

If not, set your credentials:

```bash
export UPCLOUD_USERNAME="your-username"
export UPCLOUD_PASSWORD="your-password"
```

For detailed configuration options, see the [original UpCloud CLI documentation](https://upcloudltd.github.io/upcloud-cli/).

## 🎮 Quick Start

### Interactive Mode
```bash
# Launch interactive server selection
upctl-plus server list --interactive

# Or use the short form
upctl-plus server list -i
```

### Regular Mode (Same as original upctl)
```bash
# List servers in table format
upctl-plus server list

# Show specific server details
upctl-plus server show <server-uuid>
```

## Exit codes

Exit code communicates success or the type and number of failures. Possible exit codes of `upctl` are:

Exit code | Description
--------- | -----------
0         | Command(s) executed successfully.
1 - 99    | Number of failed executions. For example, if stopping four servers and API returns error for one of the request, exit code will be 1.
100 -     | Other, non-execution related, errors. For example, required flag missing.

## Examples

Every command has a `--help` parameter that can be used to print detailed usage instructions and examples on how to use the command. For example, run `upctl network list --help`, to display usage instructions and examples for `upctl network list` command.

See [examples](./examples/) directory for examples on more complex use-cases.

## Documentation

The detailed documentation is available in [GitHub pages](https://upcloudltd.github.io/upcloud-cli/).

To generate markdown version of command reference, run `make md-docs`. Command reference will then be generated into `docs/commands_reference`.

```sh
make md-docs
```

To run the MkDocs documentation locally, run make docs and start static http server (e.g., `python3 -m http.server 8000`) in `site/` directory or run mkdocs serve in repository root.

```sh
make docs
mkdocs serve
```

## Contributing

Contributions from the community are much appreciated! Please note that all features using our
API should be implemented with [UpCloud Go API SDK](https://github.com/UpCloudLtd/upcloud-go-api).
If something is missing from there, add an issue or PR in that repository instead before implementing it here.

* Check GitHub issues and pull requests before creating new ones
  * If the issue isn't yet reported, you can [create a new issue](https://github.com/UpCloudLtd/upcloud-cli/issues/new).
* Besides bug reports, all improvement ideas and feature requests are more than welcome and can be submitted through GitHub issues.
  * New features and enhancements can be submitted by first forking the repository and then sending your changes back as a pull request.
* Following [semantic versioning](https://semver.org/), we won't accept breaking changes within the major version (1.x.x, 2.x.x etc).
  * Such PRs can be open for some time and are only accepted when the next major version is being created.

## Development

* `upctl` uses [UpCloud Go API SDK](https://github.com/UpCloudLtd/upcloud-go-api)
* `upctl` is built on [Cobra](https://cobra.dev)

You need a Go version 1.20+ installed on your development machine.

Use `make` to build and test the CLI. Makefile help can be found by running `make help`.

```sh
make help
```

### Debugging
Environment variables `UPCLOUD_DEBUG_API_BASE_URL` and `UPCLOUD_DEBUG_SKIP_CERTIFICATE_VERIFY` can be used for HTTP client debugging purposes. More information can be found in the client's [README](https://github.com/UpCloudLtd/upcloud-go-api/blob/986ca6da9ca85ff51ecacc588215641e2e384cfa/README.md#debugging) file.

### Requirements

This repository uses [pre-commit](https://pre-commit.com/#install) and [go-critic](https://github.com/go-critic/go-critic)
for maintaining code quality. Installing them is not mandatory, but it helps in avoiding the problems you'd
otherwise encounter after opening a pull request as they are run by automated tests for all PRs.

### Development quickstart

To begin development, first fork the repository to your own account, clone it and begin making changes.
```bash
git clone git@github.com/username/upcloud-cli.git
cd upcloud-cli
pre-commit install
```

Make the changes with your favorite editor. Once you're done, create a new branch and push it back to GitHub.
```bash
git checkout -b <branch-name>
<add your changes, "git status" helps>
git commit -m "New feature: create a new server in the nearest zone if not specified"
git push --set-upstream <branch-name>
```

After pushing the new branch, browse to your fork of the repository in GitHub and create a pull request from there.
Once the pull request is created, please make changes to your branch based on the comments & discussion in the PR.

## License

[MIT license](LICENSE)
