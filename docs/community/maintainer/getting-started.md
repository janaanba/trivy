# Getting Started with Trivy Development

This guide explains Trivy in beginner-friendly terms. It is intended for someone who is new to the project and wants to understand the codebase before making changes.

## What Trivy Does

Trivy is a security scanner. You give it something to inspect, and it finds security-related information and problems.

Trivy has two important concepts:

- **Targets:** the things Trivy scans.
- **Scanners:** the kinds of problems Trivy looks for.

### Targets

| Command | Target |
| --- | --- |
| `trivy image` | Container image |
| `trivy fs` | Local filesystem or project |
| `trivy rootfs` | Extracted operating-system filesystem |
| `trivy repo` | Git repository |
| `trivy config` | Infrastructure-as-code and configuration files |
| `trivy sbom` | Existing SBOM file |
| `trivy vm` | Virtual-machine image |
| `trivy k8s` | Kubernetes cluster |

### Scanners

Trivy can detect:

- Vulnerabilities in operating-system packages and application libraries
- Packages and components for SBOM generation
- Infrastructure misconfigurations
- Secrets and credentials
- Software licenses
- Kubernetes RBAC issues
- Cryptographic assets
- Results from custom WASM analyzers

For example:

```bash
trivy image --scanners vuln,secret alpine:latest
```

This scans the image for vulnerabilities and secrets.

## The Program Entry Point

The executable starts at [`cmd/trivy/main.go`](../../../cmd/trivy/main.go).

The simplified startup flow is:

```text
main()
  ↓
commands.Run()
  ↓
Create the CLI command tree
  ↓
Parse the user's command
  ↓
Run the selected operation
```

`main()` mainly handles startup, plugin mode, signals, cleanup, and process exit codes. The actual CLI command tree is built in [`pkg/commands/app.go`](../../../pkg/commands/app.go).

## Example: What Happens in an Image Scan

When you run:

```bash
trivy image alpine:latest
```

the code follows this general path:

```text
cmd/trivy/main.go
  ↓
pkg/commands/run.go
  ↓
pkg/commands/app.go
  ↓
image command
  ↓
Convert flags into options
  ↓
pkg/commands/artifact/run.go
  ↓
Inspect the image
  ↓
Run scanners
  ↓
Filter results
  ↓
Write the report
```

The important division is:

- [`pkg/commands/app.go`](../../../pkg/commands/app.go) decides which command the user requested.
- [`pkg/commands/artifact/run.go`](../../../pkg/commands/artifact/run.go) runs the common scan workflow.
- [`pkg/commands/artifact/scanner.go`](../../../pkg/commands/artifact/scanner.go) connects an artifact to a local or remote scan service.

## Common Scan Flow

Most artifact scans follow these steps:

```text
Read command-line flags
  ↓
Load configuration and environment variables
  ↓
Create flag.Options
  ↓
Prepare vulnerability databases and policies
  ↓
Create an artifact
  ↓
Inspect the artifact
  ↓
Run analyzers and scanners
  ↓
Filter findings
  ↓
Generate a report
  ↓
Return the configured exit code
```

### 1. Options

Trivy accepts command-line flags, environment variables, and YAML configuration files. They are converted into the common `flag.Options` structure.

Flag definitions are under:

```text
pkg/flag/
```

### 2. Databases and policies

Vulnerability scanning uses downloaded vulnerability data. Misconfiguration scanning uses checks and policies. Java projects can use a separate Java database, and VEX options can load VEX repositories.

The update logic is mainly in:

```text
pkg/commands/operation/operation.go
```

Useful commands include:

```bash
trivy image --skip-db-update alpine:latest
trivy image --download-db-only alpine:latest
```

### 3. Artifacts

An artifact is the object being scanned:

```text
Container image → image artifact
Folder          → filesystem artifact
Git repository  → repository artifact
SBOM file       → SBOM artifact
VM disk         → VM artifact
```

Artifact implementations are under:

```text
pkg/fanal/artifact/
pkg/fanal/walker/
pkg/fanal/image/
```

### 4. Analysis

Trivy inspects the artifact and collects information such as:

- Operating system
- Installed packages
- Application dependencies
- Image layers
- Lock files
- Dockerfiles and IaC files
- Secrets
- Licenses

Analyzers are under:

```text
pkg/fanal/analyzer/
```

Results from expensive analysis are cached. Cache code is under:

```text
pkg/cache/
```

### 5. Scanning

The common scan coordinator is [`pkg/scan/service.go`](../../../pkg/scan/service.go). The standalone backend is [`pkg/scan/local/service.go`](../../../pkg/scan/local/service.go).

The main scanning areas are:

```text
OS packages       → pkg/scan/ospkg/
Language packages → pkg/scan/langpkg/
Vulnerabilities   → pkg/vulnerability/
Misconfigurations → pkg/misconf/
Secrets           → pkg/fanal/secret/
Licenses          → pkg/licensing/
```

### 6. Reports

Reports are written through [`pkg/report/writer.go`](../../../pkg/report/writer.go).

Common output formats are:

```text
table
json
sarif
cyclonedx
spdx
spdx-json
template
github
cosign-vuln
```

Examples:

```bash
trivy image alpine:latest
trivy image --format json --output result.json alpine:latest
trivy image --format sarif --output result.sarif alpine:latest
trivy image --format cyclonedx --output result.cdx.json alpine:latest
```

## Commands to Try

### Container images

```bash
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL nginx:latest
trivy image --ignore-unfixed nginx:latest
trivy image --input image.tar
```

### Local projects

```bash
trivy fs .
trivy fs --scanners vuln,misconfig,secret .
trivy fs --severity HIGH,CRITICAL .
```

### Configuration and IaC

```bash
trivy config ./infrastructure
trivy config --severity HIGH,CRITICAL ./infrastructure
trivy config --misconfig-scanners terraform,dockerfile .
trivy config --trace-rego ./configs
```

### Git repositories

```bash
trivy repo .
trivy repo https://github.com/aquasecurity/trivy.git
trivy repo --format json --output repo.json .
```

Repository scans focus on application dependencies rather than operating-system packages.

### SBOMs

```bash
trivy sbom ./sbom.cdx.json
trivy sbom ./sbom.spdx.json
```

Generate an SBOM first:

```bash
trivy image --format cyclonedx --output image.cdx.json alpine:latest
```

Then scan it:

```bash
trivy sbom image.cdx.json
```

### Kubernetes and VM images

```bash
trivy k8s --report summary
trivy k8s my-context --report summary
trivy vm disk.vmdk
trivy vm --aws-region us-east-1 ami:ami-0123456789abcdef0
```

The Kubernetes and VM commands are marked experimental in the CLI. VM scans use a longer timeout because disk images can be large.

### Client/server mode

Run a server:

```bash
trivy server --listen 0.0.0.0:4954
```

Use it from a scan command:

```bash
trivy image --server http://127.0.0.1:4954 alpine:latest
```

The client/server flow is:

```text
Client inspects the artifact
  ↓
Client sends scan data through RPC
  ↓
Server scans using its database and cache
  ↓
Server returns results
  ↓
Client writes the report
```

Client code is in [`pkg/rpc/client/`](../../../pkg/rpc/client/), server code is in [`pkg/rpc/server/`](../../../pkg/rpc/server/), and RPC contracts are under [`rpc/`](../../../rpc/).

Important: secret and misconfiguration scanning still happens on the client in client/server mode.

## Running the Project Locally

The project uses Go and Mage. First check that the tools are available:

```bash
go version
mage -l
```

The Go version to use is declared in `go.mod`.

Build and install Trivy:

```bash
mage build
mage install
```

Format and tidy the project:

```bash
mage fmt
mage tidy
```

Run linting:

```bash
mage lint:run
mage lint:fix
```

## Tests

Run unit tests:

```bash
mage test:unit
```

Run integration tests:

```bash
mage test:integration
```

Other test suites are:

```bash
mage test:k8s
mage test:module
mage test:vm
mage test:e2e
```

The external requirements differ:

- Integration tests use Docker and test fixtures.
- Kubernetes tests create and remove a Kind cluster.
- Module tests compile WASM modules.
- VM tests use VM image fixtures.
- E2E tests use the testscript framework.

Test code is mainly under:

```text
integration/
e2e/
pkg/*/*_test.go
```

## Where to Edit Code

| If you want to... | Start here |
| --- | --- |
| Add a CLI command | `pkg/commands/app.go` |
| Change flags | `pkg/flag/` |
| Change scan orchestration | `pkg/commands/artifact/run.go` |
| Add an artifact type | `pkg/fanal/artifact/` and `pkg/commands/artifact/scanner.go` |
| Change image handling | `pkg/fanal/image/` |
| Change filesystem walking | `pkg/fanal/walker/` |
| Add an analyzer | `pkg/fanal/analyzer/` |
| Change OS scanning | `pkg/scan/ospkg/` |
| Change language dependency scanning | `pkg/scan/langpkg/` |
| Change vulnerability lookup | `pkg/vulnerability/` |
| Change IaC scanning | `pkg/misconf/` and `pkg/iac/` |
| Change secret scanning | `pkg/fanal/secret/` |
| Change license scanning | `pkg/licensing/` |
| Change local scan behavior | `pkg/scan/local/service.go` |
| Change RPC behavior | `pkg/rpc/client/`, `pkg/rpc/server/`, `rpc/` |
| Change output formats | `pkg/report/` |
| Change cache behavior | `pkg/cache/` |
| Change plugins | `pkg/plugin/` |
| Change WASM modules | `pkg/module/` |

## Recommended Learning Path

Do not try to understand the entire repository at once. Follow one scan from the command line into the code:

1. Read [`cmd/trivy/main.go`](../../../cmd/trivy/main.go).
2. Read [`pkg/commands/run.go`](../../../pkg/commands/run.go).
3. Find `NewImageCommand` in [`pkg/commands/app.go`](../../../pkg/commands/app.go).
4. Read [`pkg/commands/artifact/run.go`](../../../pkg/commands/artifact/run.go).
5. Read [`pkg/commands/artifact/scanner.go`](../../../pkg/commands/artifact/scanner.go).
6. Read [`pkg/scan/service.go`](../../../pkg/scan/service.go).
7. Read [`pkg/scan/local/service.go`](../../../pkg/scan/local/service.go).
8. Read [`pkg/report/writer.go`](../../../pkg/report/writer.go).
9. Try a local filesystem scan:

   ```bash
   trivy fs --scanners vuln .
   ```

10. Repeat it with debug logging:

   ```bash
   trivy fs --debug --scanners vuln .
   ```

The most useful mental model is:

```text
Command
  → Options
  → Artifact
  → Analysis
  → Scanners
  → Results
  → Report
```

Once this path makes sense, other targets mostly reuse the same architecture with different artifact constructors and analyzer settings.
