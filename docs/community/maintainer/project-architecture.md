# Trivy Project Architecture and Developer Reference

This document gives maintainers and coding agents a practical map of Trivy's executable entrypoint, command dispatch, end-to-end scan flow, service boundaries, integrations, commands, and development workflows.

## Project Overview

Trivy is a Go security scanner organized around two dimensions:

- **Targets:** container images, filesystems, Git repositories, VM images, Kubernetes clusters, and SBOMs.
- **Scanners:** vulnerabilities, SBOM/packages, misconfigurations, secrets, licenses, RBAC, crypto assets, and custom WASM analyzers.

The Go module is `github.com/aquasecurity/trivy`. The required Go version is declared in `go.mod`.

## Executable Entrypoint

The executable starts at [`cmd/trivy/main.go`](../../../cmd/trivy/main.go):

```text
main()
  └── run()
       ├── If TRIVY_RUN_AS_PLUGIN is set:
       │    └── plugin.Run(...)
       │
       └── Otherwise:
            ├── commands.NotifyContext(...)
            ├── commands.Run(ctx)
            └── commands.Cleanup()
```

`main()` maps errors to process behavior:

- `types.ExitError` exits with the requested code.
- `types.UserError` is logged as a user-facing error.
- Other errors are logged as fatal errors.

The normal application entrypoint after `main` is [`pkg/commands/run.go`](../../../pkg/commands/run.go). It creates and executes the Cobra application defined in [`pkg/commands/app.go`](../../../pkg/commands/app.go).

## CLI Construction and Dispatch

[`pkg/commands/app.go`](../../../pkg/commands/app.go) defines the Cobra command tree. The main commands are:

```text
image
filesystem / fs
rootfs
repository / repo
config
sbom
vm
kubernetes / k8s
server
client             deprecated and hidden
convert
clean
registry
plugin
module
vex
version
```

A scan command generally follows this sequence:

```text
Cobra command
  ├── Bind command flags
  ├── Load configuration and environment variables through Viper
  ├── Convert flags into flag.Options
  ├── Validate arguments
  └── Call artifact.Run(...)
```

Flags are intentionally bound in `PreRunE`, not at command construction time. Viper must bind flags after Cobra has parsed them. The configuration path is:

```text
CLI flags
  + environment variables
  + YAML config file
        ↓
Viper
        ↓
flag.Flags.ToOptions(...)
        ↓
flag.Options
```

Relevant locations are [`pkg/commands/app.go`](../../../pkg/commands/app.go), [`pkg/flag/`](../../../pkg/flag/), and [`pkg/types/`](../../../pkg/types/).

## Standard End-to-End Scan Flow

For image, filesystem, repository, rootfs, SBOM, and VM scans, the main path is:

```text
cmd/trivy/main.go
  ↓
pkg/commands.Run
  ↓
pkg/commands.NewApp
  ↓
Cobra command RunE
  ↓
flag.Flags.ToOptions
  ↓
pkg/commands/artifact.Run
  ↓
extension.PreRun
  ↓
runner initialization
  ↓
database/cache/module setup
  ↓
artifact inspection
  ↓
scanner backend
  ↓
result filtering
  ↓
report generation
  ↓
exit-code evaluation
  ↓
extension.PostRun
```

The orchestration is in [`pkg/commands/artifact/run.go`](../../../pkg/commands/artifact/run.go).

### `artifact.Run`

`artifact.Run`:

1. Creates a timeout context.
2. Handles `--generate-default-config`.
3. Calls extension pre-run hooks.
4. Runs the scan and report pipeline.
5. Calls extension post-run hooks.
6. Calls `operation.Exit` to determine whether the process returns a non-zero exit code.

### Runner initialization

`NewRunner` initializes:

- HTTP transport and TLS settings.
- The vulnerability database when vulnerability scanning is enabled.
- The Java vulnerability database when required.
- VEX repositories when requested.
- The WASM module manager.
- Background version checking.

Database and policy update operations are implemented in [`pkg/commands/operation/operation.go`](../../../pkg/commands/operation/operation.go). Configuration-only scans normally do not need the vulnerability database.

### Target dispatch

Targets are represented by `TargetKind` values:

```go
TargetContainerImage
TargetFilesystem
TargetRootfs
TargetRepository
TargetSBOM
TargetVM
```

The runner dispatches to `ScanImage`, `ScanFilesystem`, `ScanRootfs`, `ScanRepository`, `ScanSBOM`, or `ScanVM`.

Each target adjusts analyzer behavior. Examples:

- Image scans disable lockfile scanning.
- Filesystem scans disable individual-package and SBOM analyzers.
- Repository scans disable OS-package analyzers and focus on library dependencies.
- Rootfs scans disable lockfile analyzers.
- VM scans disable lockfile analyzers.

## Artifact Inspection and Caching

Artifact construction is defined in [`pkg/commands/artifact/scanner.go`](../../../pkg/commands/artifact/scanner.go), with implementations under [`pkg/fanal/artifact/`](../../../pkg/fanal/artifact/), [`pkg/fanal/walker/`](../../../pkg/fanal/walker/), and [`pkg/fanal/image/`](../../../pkg/fanal/image/).

| Command | Artifact implementation |
| --- | --- |
| `image` | Container image or image archive |
| `fs` | Local filesystem walker |
| `rootfs` | Root filesystem walker |
| `repo` | Git repository artifact |
| `sbom` | SBOM parser |
| `vm` | VM image walker |

Inspection extracts OS data, packages, language dependencies, image layers, repository metadata, IaC configuration, secrets, licenses, and SBOM information. Analysis results are stored through the selected cache.

The dependency injection graph is manually wired in `scanner.go`:

```text
createLocalService
  ├── cache.New
  ├── applier.NewApplier
  ├── ospkg.NewScanner
  ├── langpkg.NewScanner
  ├── vulnerability.NewClient
  ├── local.NewService
  └── scan.NewService

createRemoteService
  ├── cache.NewRemoteCache
  ├── artifact construction
  ├── rpc/client.NewService
  └── scan.NewService
```

## Local Scan Backend

The common coordinator is [`pkg/scan/service.go`](../../../pkg/scan/service.go). It:

1. Inspects the artifact.
2. Delegates scanning to a backend.
3. Builds report metadata.
4. Generates finding fingerprints.
5. Cleans up the artifact.

The standalone backend is [`pkg/scan/local/service.go`](../../../pkg/scan/local/service.go). It:

1. Applies cached artifact layers.
2. Detects the operating system.
3. Collects OS and application packages.
4. Applies package relationship and development-dependency filters.
5. Runs OS and language-package vulnerability scanners.
6. Converts IaC findings into results.
7. Converts secret findings into results.
8. Scans licenses.
9. Adds crypto and custom-resource findings.
10. Fills vulnerability metadata from the vulnerability database.
11. Runs extension pre-scan and post-scan hooks.

Core scanner areas are:

```text
pkg/scan/ospkg/
pkg/scan/langpkg/
pkg/vulnerability/
pkg/misconf/
pkg/fanal/analyzer/
pkg/fanal/secret/
pkg/licensing/
```

## Client/Server Flow

Start a server:

```bash
trivy server --listen 0.0.0.0:4954
```

Run a client scan:

```bash
trivy image --server http://127.0.0.1:4954 alpine:latest
```

The client/server path is:

```text
Client CLI
  ↓
Local artifact inspection
  ↓
Local artifact cache / remote cache
  ↓
Twirp RPC request
  ↓
Trivy server
  ↓
Server-side cache and vulnerability database
  ↓
Server scanner backend
  ↓
RPC response
  ↓
Client result filtering and report writing
```

The client is [`pkg/rpc/client/client.go`](../../../pkg/rpc/client/client.go). The server entrypoint is [`pkg/commands/server/run.go`](../../../pkg/commands/server/run.go). RPC implementation and generated contracts are under [`pkg/rpc/server/`](../../../pkg/rpc/server/), [`rpc/`](../../../rpc/), and [`rpc/scanner/`](../../../rpc/scanner/).

The client sends the target name, artifact ID, blob IDs, package types, package relationships, enabled scanners, license settings, distribution override, and vulnerability severity-source settings.

In client/server mode, misconfiguration and secret scanning remain client-side; the code warns about this behavior.

## Reporting Flow

Reporting is handled by [`pkg/report/writer.go`](../../../pkg/report/writer.go):

```text
types.Report
  ↓
extension.PreReport
  ↓
OutputWriter
  ↓
format-specific writer
  ↓
extension.PostReport
```

Supported formats include:

```text
table
json
github
cyclonedx
spdx
spdx-json
template
sarif
cosign-vuln
```

Format writers live under [`pkg/report/`](../../../pkg/report/), including `table`, `cyclonedx`, `spdx`, and template/SARIF writers.

## Exit Codes

Exit behavior is in [`pkg/commands/operation/operation.go`](../../../pkg/commands/operation/operation.go). Findings only fail the process when an exit code is configured.

```bash
trivy image --exit-code 1 --severity HIGH,CRITICAL alpine:latest
trivy image --exit-on-eol 1 alpine:latest
```

## Command Reference

### Basic information

```bash
trivy --help
trivy image --help
trivy fs --help
trivy version
trivy version --format json
```

### Container images

```bash
trivy image alpine:3.15
trivy image python:3.4-alpine
trivy image --severity HIGH,CRITICAL alpine:3.15
trivy image --ignore-unfixed alpine:3.15
trivy image --scanners vuln alpine:3.15
trivy image --scanners vuln,misconfig,secret alpine:3.15
trivy image --input image.tar
trivy image --image-src docker,containerd,podman alpine:latest
trivy image --format json --output result.json alpine:3.15
```

### Filesystems and root filesystems

```bash
trivy fs .
trivy fs /path/to/project
trivy fs ./package-lock.json
trivy fs --scanners vuln,secret,misconfig .
trivy fs --scanners license .
trivy fs --severity HIGH,CRITICAL .
trivy fs --skip-dirs node_modules,vendor .
trivy fs --skip-files "*.lock" .
trivy rootfs /path/to/rootfs
trivy rootfs --scanners vuln /path/to/rootfs
```

`rootfs` is intended for an extracted operating-system filesystem rather than a normal source repository.

### Git repositories

```bash
trivy repo .
trivy repo https://github.com/aquasecurity/trivy.git
trivy repo --format json --output repo.json .
trivy repo --pkg-relationships root,direct .
```

Repository scans focus on library dependencies and do not scan OS packages.

### IaC and configuration

```bash
trivy config .
trivy config ./infrastructure
trivy config --severity HIGH,CRITICAL ./infrastructure
trivy config --misconfig-scanners terraform,dockerfile .
trivy config --config-check ./checks --namespaces user ./configs
trivy config --tf-vars dev.terraform.tfvars ./terraform
trivy config --cf-params params.json ./cloudformation
trivy config --trace-rego ./configs
```

Common supported configuration areas include Terraform, Kubernetes YAML, Dockerfiles, Helm, CloudFormation, Ansible, JSON, and YAML.

### SBOMs

```bash
trivy sbom ./sbom.cdx.json
trivy sbom ./sbom.spdx.json
trivy sbom ./sbom.cdx.intoto.jsonl
trivy sbom --scanners vuln ./sbom.cdx.json
trivy sbom --scanners license ./sbom.cdx.json
```

Generate SBOMs from an image:

```bash
trivy image --format cyclonedx --output image.cdx.json alpine:3.15
trivy image --format spdx-json --output image.spdx.json alpine:3.15
```

### VM images

```bash
trivy vm --scanners vuln disk.vmdk
trivy vm ./disk.img
trivy vm --aws-region ap-northeast-1 ami:ami-0123456789abcdef0
trivy vm --aws-region ap-northeast-1 ebs:snap-0123456789abcdef0
```

The VM command raises the timeout to at least 30 minutes.

### Kubernetes

```bash
trivy k8s --report summary
trivy k8s kind-kind --report summary
trivy k8s --include-namespaces kube-system --report summary
trivy k8s --format json
```

The Kubernetes command is experimental and uses the default kubeconfig context unless another context is specified.

### Client/server

```bash
trivy server
trivy server --listen 0.0.0.0:4954
trivy image --server http://127.0.0.1:4954 alpine:latest
trivy fs --server http://127.0.0.1:4954 .
```

The old `client` command is hidden and deprecated. Prefer `--server` on normal scan commands.

### Registry authentication

```bash
trivy registry login reg.example.com
cat password.txt | trivy registry login --username user --password-stdin reg.example.com
trivy registry logout reg.example.com
```

### Cache and database management

```bash
trivy clean
trivy clean --all
trivy image --download-db-only alpine:latest
trivy image --download-java-db-only alpine:latest
trivy image --skip-db-update alpine:latest
```

Use command-specific help for the complete current flag set:

```bash
trivy clean --help
trivy image --help
```

### Plugins

```bash
trivy plugin install github.com/aquasecurity/trivy-plugin-attest
trivy plugin list
trivy plugin info PLUGIN_NAME
trivy plugin run PLUGIN_NAME
trivy plugin update
trivy plugin upgrade
trivy plugin uninstall PLUGIN_NAME
```

Installed plugins are dynamically loaded into the Cobra command tree when the plugin directory exists.

### WASM modules

```bash
trivy module install REPOSITORY
trivy module uninstall REPOSITORY
```

WASM modules are initialized and registered by the scan runner before scanning.

### VEX repositories

```bash
trivy vex repo init
trivy vex repo list
trivy vex repo download
trivy vex repo download REPOSITORY_NAME
```

### Result conversion

```bash
trivy convert result.json --format sarif --output result.sarif
trivy convert --help
```

## Developer Workflows

The project uses Mage for most Go workflows. List available targets with:

```bash
mage -l
```

### Build and formatting

```bash
mage build
mage install
mage fmt
mage tidy
```

`mage build` builds the `cmd/trivy` executable with version linker flags. `mage install` installs it with the same version metadata.

### Linting

```bash
mage lint:run
mage lint:fix
```

The configured CI linter version is defined in [`magefiles/magefile.go`](../../../magefiles/magefile.go) and the test workflow.

### Tests

```bash
mage test:unit
mage test:integration
mage test:k8s
mage test:module
mage test:vm
mage test:e2e
```

The unit target generates test modules and fixtures, then runs the short unit suite. Integration targets require their external environments:

- Integration tests use Docker and downloaded fixtures.
- Kubernetes tests create and remove a Kind cluster.
- Module tests compile example WASM modules.
- VM tests use VM image fixtures.
- E2E tests use the testscript framework.

Golden-file updates include:

```bash
mage test:updateGolden
mage test:updateModuleGolden
```

VM golden updates are currently unsupported by the Mage target.

### CLI documentation and generated code

```bash
mage docs:generate
mage protoc:generate
mage protoc:fmt
mage protoc:lint
mage protoc:breaking
```

CI verifies that generated CLI documentation is current. Protobuf generation requires the tools installed by the Mage tool target and should be rerun after RPC schema changes.

The primary workflow definitions are [`magefiles/magefile.go`](../../../magefiles/magefile.go) and [`.github/workflows/test.yaml`](../../../.github/workflows/test.yaml).

## External Integrations

Important integration boundaries include:

- **Cobra/Viper:** CLI parsing and configuration.
- **Trivy vulnerability database:** vulnerability metadata and severity information.
- **Trivy Java DB:** Java vulnerability information.
- **Trivy checks bundle:** downloadable misconfiguration policies.
- **OCI/container registries:** image pulls, database downloads, checks bundles, VEX data, and SBOM sources.
- **Docker/containerd/Podman:** container image access.
- **Twirp/protobuf RPC:** client/server communication.
- **Open Policy Agent/Rego:** built-in and custom IaC checks.
- **Kubernetes APIs:** cluster scanning.
- **AWS SDK:** AMI and EBS scanning.
- **WASM/WASI:** custom analyzers and modules.
- **Git libraries:** local and remote repository scanning.
- **CycloneDX/SPDX/SARIF:** SBOM and security report formats.
- **Sigstore/Rekor/Cosign-compatible output:** attestation and vulnerability predicate support.

## Where to Start When Modifying Code

| Task | Start here |
| --- | --- |
| Add or change a CLI command | [`pkg/commands/app.go`](../../../pkg/commands/app.go) |
| Change command flags | [`pkg/flag/`](../../../pkg/flag/) |
| Change scan orchestration | [`pkg/commands/artifact/run.go`](../../../pkg/commands/artifact/run.go) |
| Add an artifact type | [`pkg/fanal/artifact/`](../../../pkg/fanal/artifact/) and [`pkg/commands/artifact/scanner.go`](../../../pkg/commands/artifact/scanner.go) |
| Change filesystem or image walking | [`pkg/fanal/walker/`](../../../pkg/fanal/walker/) and [`pkg/fanal/image/`](../../../pkg/fanal/image/) |
| Add an analyzer | [`pkg/fanal/analyzer/`](../../../pkg/fanal/analyzer/) |
| Change vulnerability scanning | [`pkg/scan/ospkg/`](../../../pkg/scan/ospkg/), [`pkg/scan/langpkg/`](../../../pkg/scan/langpkg/), and [`pkg/vulnerability/`](../../../pkg/vulnerability/) |
| Change secrets | [`pkg/fanal/secret/`](../../../pkg/fanal/secret/) |
| Change IaC scanning | [`pkg/misconf/`](../../../pkg/misconf/) and [`pkg/iac/`](../../../pkg/iac/) |
| Change the local backend | [`pkg/scan/local/service.go`](../../../pkg/scan/local/service.go) |
| Change client/server behavior | [`pkg/rpc/client/`](../../../pkg/rpc/client/), [`pkg/rpc/server/`](../../../pkg/rpc/server/), and [`rpc/`](../../../rpc/) |
| Change report formats | [`pkg/report/`](../../../pkg/report/) |
| Change cache behavior | [`pkg/cache/`](../../../pkg/cache/) |
| Change DB update behavior | [`pkg/db/`](../../../pkg/db/) and [`pkg/commands/operation/`](../../../pkg/commands/operation/) |
| Change plugin behavior | [`pkg/plugin/`](../../../pkg/plugin/) |
| Change WASM modules | [`pkg/module/`](../../../pkg/module/) |
| Change generated CLI docs | [`magefiles/docs.go`](../../../magefiles/docs.go) and generated docs |
| Change the RPC schema | [`rpc/`](../../../rpc/), then run `mage protoc:generate` |

## Environment Note

The source analysis was performed with a clean Git working tree. If the Go toolchain is not available on `PATH`, install or select the Go version declared by `go.mod` before running the build and test commands above.
