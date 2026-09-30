# Offline Filesystem-to-CycloneDX Flow

This guide explains what happens when Trivy runs a command like:

```bash
trivy fs --format cyclonedx --offline-scan <input> > <output.json>
```

The explanation follows the implementation in this repository. It covers the shell, command dispatch, filesystem analysis, dependency discovery, caching, CycloneDX conversion, and the limits of offline mode.

## 1. What the command means

The command has four independent pieces:

| Part | Meaning |
| --- | --- |
| `trivy` | Starts the Trivy executable from `cmd/trivy/main.go`. |
| `fs` | Selects the filesystem scan command. It is an alias for `filesystem`. |
| `--format cyclonedx` | Requests CycloneDX JSON as the report format. |
| `--offline-scan` | Prevents API requests used to identify dependencies during artifact analysis. |
| `<input>` | The file or directory to inspect. |
| `>` | Shell output redirection. It is not a Trivy flag. |
| `<output.json>` | The file created by the shell and populated with Trivy's standard output. |

For example:

```bash
./trivy fs --format cyclonedx --offline-scan /work/frontend > /work/frontend.cdx.json
```

The command produces a software inventory from files already present under `/work/frontend`. It does not mean that every possible Trivy network feature is disabled in every configuration. In particular, offline artifact analysis and vulnerability database downloading are separate concerns.

## 2. The shell runs first

In a zsh or Bash shell, the command line is parsed before Trivy starts.

The shell:

1. Resolves `trivy` or `./trivy` as an executable.
2. Passes the remaining arguments to the process.
3. Opens `<output.json>` for standard-output redirection.
4. Starts Trivy with standard output connected to that file.

The `>` operator is therefore outside Trivy's command parser. Trivy does not receive the output filename as an option. It only receives the scan arguments and writes its report to standard output.

This distinction matters because Trivy's machine-readable report is written to standard output, while progress messages, informational messages, warnings, and errors are normally written to standard error. As a result:

```bash
trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json
```

normally keeps the JSON in `app.cdx.json` while leaving human-readable diagnostics visible in the terminal.

To capture both streams, use shell syntax deliberately:

```bash
trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json 2> app.trivy.log
```

Avoid `> app.cdx.json 2>&1` when the file must remain valid JSON, because that combines diagnostics with the JSON report.

Trivy can also open the output file itself:

```bash
trivy fs --format cyclonedx --output app.cdx.json --offline-scan ./app
```

`--output` is a Trivy option. `>` is shell behavior. They are alternative ways to choose the report destination.

## 3. Trivy dispatches the filesystem command

The executable entrypoint is `cmd/trivy/main.go`. Normal execution calls `pkg/commands.Run`, which creates the Cobra command tree and executes the selected command.

The filesystem command is built by `NewFilesystemCommand` in `pkg/commands/app.go`:

1. Cobra matches `fs` to the `filesystem` command alias.
2. The command registers the scan, cache, database, report, package, secret, vulnerability, and other flag groups.
3. Viper-backed flag binding makes CLI flags, configuration values, and supported environment variables available.
4. The command converts the bound values into `flag.Options`.
5. It invokes `artifact.Run(ctx, options, artifact.TargetFilesystem)`.

The target kind is important. It tells the artifact command layer to construct a local filesystem artifact rather than an image, registry, repository, Kubernetes, or VM artifact.

Relevant source locations:

- [`cmd/trivy/main.go`](../../../cmd/trivy/main.go)
- [`pkg/commands/run.go`](../../../pkg/commands/run.go)
- [`pkg/commands/app.go`](../../../pkg/commands/app.go)
- [`pkg/commands/artifact/run.go`](../../../pkg/commands/artifact/run.go)

## 4. The flags become scan options

`--offline-scan` is declared in `pkg/flag/scan_flags.go` as `OfflineScanFlag`:

- CLI name: `offline-scan`
- Configuration name: `scan.offline`
- Type: boolean
- Purpose: do not issue API requests to identify dependencies

During option conversion, its value is stored in `flag.Options.ScanOptions.OfflineScan`.

The artifact command later builds an `artifact.Option`. In `initScannerConfig`, the relevant values include:

```text
Offline:      opts.OfflineScan
FileChecksum: true for CycloneDX and SPDX formats
```

The checksum setting is not caused by `--offline-scan`. It is enabled because CycloneDX and SPDX reports can include hashes for package files. The two settings work independently:

- `Offline` controls dependency-identification requests.
- `FileChecksum` requests digest calculation while analyzing package files.

The filesystem artifact receives both settings through its analysis options.

## 5. CycloneDX changes the scan configuration

`--format cyclonedx` selects `types.FormatCycloneDX`. During scan configuration, Trivy enables file checksums for CycloneDX and SPDX output.

CycloneDX output also has an important scanner-selection behavior. In this version, selecting CycloneDX without explicitly requesting vulnerability scanning disables security scanning for the report. Trivy prints a message similar to:

```text
"--format cyclonedx" disables security scanning. Specify "--scanners vuln" explicitly if you want to include vulnerabilities in the "cyclonedx" report.
```

Therefore, the basic command is primarily an SBOM generation command:

```bash
trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json
```

It discovers packages, applications, files, relationships, licenses, and other inventory metadata supported by the detected analyzers. It should not be interpreted as a vulnerability report unless vulnerability scanning is explicitly enabled.

To request vulnerability data as well:

```bash
trivy fs --format cyclonedx --scanners vuln --offline-scan ./app > app-vuln.cdx.json
```

That is a different operational mode. It requires a vulnerability database that can support matching. See [Database and offline limitations](#database-and-offline-limitations).

## 6. The local filesystem artifact is created

For a standalone filesystem scan, `pkg/commands/artifact/scanner.go` creates a local scan service. The local path uses:

1. A filesystem walker from `pkg/fanal/walker`.
2. A local artifact from `pkg/fanal/artifact/local`.
3. An artifact cache.
4. Fanal's analyzer group.
5. The local scan backend for packages and other scanner results.

`pkg/fanal/artifact/local/fs.go` stores the input path, cache, walker, analyzer group, handlers, and artifact options. It also checks whether the input is a Git repository.

If the path is a clean Git repository, Trivy can use the commit and analyzer versions as part of the cache identity. It also records repository metadata such as the commit, branch, tags, and sanitized remote URL when available. If the repository is dirty or is not a Git repository, Trivy uses a different cache strategy and may analyze the files directly for the current invocation.

This Git inspection is local metadata inspection. It is not a clone or fetch operation.

## 7. Artifact inspection and cache lookup

The scan service first calls `ScanArtifact` in `pkg/scan/service.go`. That causes the artifact to be inspected before the backend turns the analysis into a report.

For a local filesystem artifact, `Inspect` in `pkg/fanal/artifact/local/fs.go` performs these high-level steps:

1. Calculate an artifact cache key.
2. Check for a complete cached result when the input is a clean Git repository.
3. Return the cached reference immediately on a cache hit.
4. Otherwise create a fresh analysis result.
5. Build analysis options containing `Offline`, `FileChecksum`, and Maven mirror settings.
6. Run analyzers over the selected files.
7. Store the analysis result in the artifact cache.
8. Return an artifact reference to the scan service.

The cache is an optimization, not a package source. A cache hit can avoid walking and parsing files again, but the resulting report still goes through the normal reporting path.

The exact cache behavior depends on the cache backend and artifact type. Filesystem commands default to an in-memory cache in the command setup, while explicit cache configuration can provide persistent storage.

## 8. Files are selected and analyzed

The local artifact chooses between two analysis strategies:

- Static paths: if all enabled analyzers advertise fixed paths, Trivy analyzes those paths directly.
- Root traversal: otherwise the walker traverses the input directory and sends files to the analyzer group.

During traversal, each file is passed to `AnalyzeFile` with:

- The root path and relative path.
- File metadata.
- A file opener.
- The analysis options.
- The `Offline` setting.
- The `FileChecksum` setting.

Analyzers are registered from `pkg/fanal/analyzer/all` and selected based on file names, file contents, operating-system metadata, and other detection rules. Different analyzers understand different ecosystems and artifact data. Examples include:

- Debian, Alpine, Red Hat, Ubuntu, and other OS package databases.
- Node.js manifests and lockfiles.
- Go module files and sums.
- Python, Ruby, Rust, Java, PHP, .NET, and other language ecosystems.
- Container and application metadata when present in the scanned filesystem.
- License and file metadata where the selected scanners support it.

The analyzer group may perform post-analysis steps. The local artifact creates a composite analysis filesystem for analyzers that need to inspect a combined view of files after the initial pass.

## 9. What offline mode changes

The option is passed to analyzers as `analyzer.AnalysisOptions.Offline`. The CLI description is intentionally specific: offline mode prevents API requests used to identify dependencies.

In practical terms, local analysis can still:

- Open and parse manifests and lockfiles.
- Read installed package databases.
- Inspect files under the input path.
- Build package and dependency records from local evidence.
- Calculate local file checksums for CycloneDX output.
- Reuse local cache entries.

Offline mode can reduce or remove dependency information that would otherwise require contacting an ecosystem service or looking up metadata remotely. The exact effect varies by ecosystem and by which files are present. A lockfile containing complete versions and relationships is generally more useful offline than a manifest containing only version ranges.

`--offline-scan` should not be described as a universal process sandbox. It controls dependency-identification requests in artifact analysis; it does not automatically disable every other possible network feature in the overall command.

For the plain CycloneDX command, the format behavior normally avoids vulnerability database work because vulnerabilities are not enabled for the report. If vulnerability scanning is explicitly added, database behavior becomes relevant.

## 10. Package discovery and dependency records

Package information comes from local files and package databases, not from a single universal package parser.

For a Node.js project, typical evidence includes:

- `package.json` for project metadata, declared dependencies, development dependencies, optional dependencies, peer dependencies, and license information.
- `package-lock.json` for resolved package versions, package locations, integrity or resolved metadata where available, and dependency relationships.
- `yarn.lock` for Yarn-resolved versions and dependency edges.
- Installed package directories such as `node_modules` when they are present and recognized by the relevant analyzers.

The dependency parsers under `pkg/dependency/parser` convert ecosystem-specific files into Trivy's internal package and dependency types. The parser can classify relationships such as direct, indirect, optional, or development dependencies when the source data supports that distinction.

For each discovered component, Trivy can retain data such as:

- Ecosystem and package name.
- Installed or resolved version.
- Package URL (PURL), for example `pkg:npm/react@18.2.0`.
- Dependency relationship and parent-child edges.
- License information.
- Source file or package file information.
- File digest when checksum calculation is enabled.

The result is an internal graph rather than merely a flat list. That graph is later converted into CycloneDX components and dependency relationships.

A manifest with ranges such as `^18.2.0` does not by itself prove that version `18.2.0` is installed. Lockfiles and installed package metadata provide stronger evidence. If those sources are absent or incomplete, the SBOM can contain fewer or less precise components.

## 10.1 What the Node.js parser actually does

The parser is an intermediate conversion step. It does not read `package-lock.json` and emit CycloneDX directly:

```text
package-lock.json
  -> JSON decoding
  -> []types.Package + []types.Dependency
  -> types.Application
  -> types.Result / types.Report
  -> internal SBOM graph
  -> CycloneDX components and dependencies
```

The npm analyzer is registered as a post-analyzer:

```go
func init() {
  analyzer.RegisterPostAnalyzer(analyzer.TypeNpmPkgLock, newNpmLibraryAnalyzer)
}
```

It keeps root-level `package-lock.json` files for dependency analysis and `package.json` files under `node_modules` for license lookup. Nested lockfiles are deliberately excluded to avoid duplicate application results:

```go
func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
  fileName := filepath.Base(filePath)
  if fileName == types.NpmPkgLock && !xpath.Contains(filePath, "node_modules") {
    return true
  }
  return fileName == types.NpmPkg && xpath.Contains(filePath, "node_modules")
}
```

During post-analysis, the analyzer walks the local analysis filesystem, opens each selected lockfile, and calls:

```go
return language.Parse(ctx, types.Npm, filePath, file, a.lockParser)
```

With `--offline-scan`, `file` is still read normally from disk or the local artifact cache. The parser does not need to contact npm to decode a complete lockfile.

### Lockfile decoding and version selection

The npm parser first decodes JSON into its lockfile model:

```go
var lockFile LockFile
if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
  return nil, nil, xerrors.Errorf("decode error: %w", err)
}

if lockFile.LockfileVersion == 1 {
  pkgs, deps = p.parseV1(lockFile.Dependencies, make(map[string]string))
} else {
  pkgs, deps = p.parseV2(lockFile.Packages)
}
```

Version 1 uses a nested `dependencies` tree. Versions 2 and 3 use a `packages` map keyed by installation paths such as `node_modules/react` and `node_modules/foo/node_modules/bar`.

### Direct dependency detection

For versions 2 and 3, `packages[""]` is the project root. The parser combines its normal, optional, development, and peer dependency maps and checks which names have corresponding `node_modules/<name>` entries:

```go
directDeps := set.New[string]()
for name := range lo.Assign(
  packages[""].Dependencies,
  packages[""].OptionalDependencies,
  packages[""].DevDependencies,
  packages[""].PeerDependencies,
) {
  pkgPath := joinPaths(nodeModulesDir, name)
  if _, ok := packages[pkgPath]; ok {
    directDeps.Append(pkgPath)
  }
}
```

For this input:

```json
{
  "packages": {
  "": {"dependencies": {"react": "18.2.0"}},
  "node_modules/react": {
    "version": "18.2.0",
    "dependencies": {"loose-envify": "^1.1.0"}
  },
  "node_modules/loose-envify": {"version": "1.4.0"}
  }
}
```

`react` is direct because it appears in the root dependency map. `loose-envify` is indirect because it appears only under React's dependency map. The parser does not need to resolve `^1.1.0` against the internet; it finds the installed `1.4.0` entry in the lockfile.

### Package records and IDs

Each `node_modules` entry becomes a `types.Package`. The parser extracts the name, version, license, relationship, development flag, location, and resolved URL when present:

```text
Name:         react
Version:      18.2.0
ID:           react@18.2.0
Relationship: direct
Dev:          false
Location:     node_modules/react
```

The internal npm package ID is created by the shared dependency helper:

```go
func ID(ltype types.LangType, name, version string) string {
  if version == "" {
    return name
  }
  return name + "@" + version
}
```

This ID is used to connect graph edges. It is not necessarily the final CycloneDX `bom-ref`.

### Dependency edge resolution

The lockfile declaration contains a version constraint, but the installed package is resolved by location. For every dependency declaration, the parser calls `findDependsOn`:

```go
for depName, depVersion := range dependencies {
  depID, err := findDependsOn(pkgPath, depName, packages)
  if err != nil {
    p.logger.Debug("Unable to resolve the version",
      log.String("name", depName), log.String("version", depVersion))
    continue
  }
  dependsOn = append(dependsOn, depID)
}
```

The example becomes this internal edge:

```text
react@18.2.0 -> loose-envify@1.4.0
```

Nested `node_modules` paths are handled relative to the package that declares the dependency. If no local lockfile entry can satisfy an edge, Trivy keeps the package but omits that unresolved edge and logs at debug level.

The parser merges repeated occurrences of the same name/version, retaining multiple locations, licenses, and external references. It then removes duplicate packages and dependency edges:

```go
return utils.UniquePackages(pkgs), uniqueDeps(deps), nil
```

## 10.2 How `package.json` participates

`package.json` provides project metadata and declared dependency ranges; it is not a replacement for a resolved lockfile. Its parser decodes JSON and returns a package plus dependency-category maps:

```go
var pkgJSON packageJSON
if err := json.NewDecoder(r).Decode(&pkgJSON); err != nil {
  return Package{}, xerrors.Errorf("JSON decode error: %w", err)
}

return Package{
  Package: ftypes.Package{
    ID:       dependency.ID(ftypes.NodePkg, pkgJSON.Name, pkgJSON.Version),
    Name:     pkgJSON.Name,
    Version:  pkgJSON.Version,
    Licenses: pkgJSON.License.Names(),
  },
  Dependencies:         pkgJSON.Dependencies,
  OptionalDependencies: pkgJSON.OptionalDependencies,
  DevDependencies:      pkgJSON.DevDependencies,
  Workspaces:            ParseWorkspaces(pkgJSON.Workspaces),
}, nil
```

For example, `"react": "^18.2.0"` remains a range at this stage. A lockfile or installed package metadata supplies the concrete installed version. Workspace declarations are also parsed in both supported shapes:

```json
"workspaces": ["packages/*", "frontend"]
```

or:

```json
"workspaces": {"packages": ["packages/*", "frontend"]}
```

Trivy reads these files; it does not run `npm install`, `npm ls`, or another package-manager command as part of this parser.

## 10.3 The language helper creates an application

The parser returns packages and graph edges. `language.Parse` wraps them in a `types.Application`. `toApplication` attaches dependency edges to each package and sets the package file path:

```go
deps := make(map[string][]string)
for _, dep := range depGraph {
  deps[dep.ID] = dep.DependsOn
}

for i := range pkgs {
  pkg := &pkgs[i]
  pkg.FilePath = cmp.Or(pkg.FilePath, libFilePath)
  pkg.DependsOn = deps[pkg.ID]
  pkg.Indirect = isIndirect(pkg.Relationship)
}
```

For a lockfile, `libFilePath` is empty because all libraries came from the same lockfile. For package files where checksum calculation is enabled, the helper reads the local file and calculates a SHA-1 digest:

```go
if checksum {
  d, err := calculateDigest(r)
  // The digest is assigned to packages without an existing digest.
}
```

This checksum is local. It is why CycloneDX sets `FileChecksum: true`; it is not a download from npm.

Conceptually, the application now contains:

```go
types.Application{
  Type:     types.Npm,
  FilePath: "package-lock.json",
  Packages: []types.Package{
    {
      ID:           "react@18.2.0",
      Name:         "react",
      Version:      "18.2.0",
      Relationship: types.RelationshipDirect,
      DependsOn:    []string{"loose-envify@1.4.0"},
    },
    {
      ID:           "loose-envify@1.4.0",
      Name:         "loose-envify",
      Version:      "1.4.0",
      Relationship: types.RelationshipIndirect,
    },
  },
}
```

## 10.4 How packages become CycloneDX

The CycloneDX writer does not iterate over raw lockfile JSON. It first converts the Trivy report into an internal BOM:

```go
bom, err := sbomio.NewEncoder(sbomio.WithBOMRef()).Encode(report)
```

The encoder creates a root component, then processes each result and its packages:

```go
for _, result := range report.Results {
  e.encodeResult(root, report.Metadata, result)
}
```

For a filesystem containing `package-lock.json`, the conceptual graph is:

```text
filesystem application
└── package-lock.json application
  ├── react@18.2.0 library
  └── loose-envify@1.4.0 library

react@18.2.0 dependsOn loose-envify@1.4.0
```

Inside `encodePackages`, each package becomes an internal component and each `DependsOn` ID becomes a graph relationship:

```go
c := e.component(result, pkg)
e.bom.AddComponent(c)

for _, dep := range pkg.DependsOn {
  dependsOn, ok := dependencies[dep]
  if !ok {
    continue
  }
  e.bom.AddRelationship(c, dependsOn, core.RelationshipDependsOn)
}
```

The component conversion carries the package identity, PURL, licenses, properties, suppliers, and file hashes:

```go
cdxComponent := &cdx.Component{
  BOMRef:     component.PkgIdentifier.BOMRef,
  Type:       componentType,
  Name:       component.Name,
  Group:      component.Group,
  Version:    component.Version,
  PackageURL: m.PackageURL(component.PkgIdentifier.PURL),
  Supplier:   m.Supplier(component.Supplier),
  Hashes:     m.Hashes(component.Files),
  Licenses:   m.Licenses(component.Licenses),
  Properties: m.Properties(component.Properties),
}
```

The final npm component is conceptually similar to:

```json
{
  "type": "library",
  "name": "react",
  "version": "18.2.0",
  "purl": "pkg:npm/react@18.2.0",
  "properties": [
  {"name": "aquasecurity:trivy:PkgType", "value": "npm"},
  {"name": "aquasecurity:trivy:PkgID", "value": "react@18.2.0"}
  ]
}
```

The exact `bom-ref` is assigned after package parsing. The internal `Package.ID`, the PURL, and the CycloneDX `bom-ref` are related identifiers, but they are not the same concept.

The final marshaler maps internal component types to CycloneDX types:

```go
case core.TypeApplication, core.TypeFilesystem, core.TypeRepository:
  return cdx.ComponentTypeApplication, nil
case core.TypeLibrary:
  return cdx.ComponentTypeLibrary, nil
case core.TypeOS:
  return cdx.ComponentTypeOS, nil
```

Only after this graph conversion does Trivy encode the pretty CycloneDX JSON that the shell redirects to the output file.

## 10.5 How Go modules are analyzed

Go dependency discovery usually starts with `go.mod` and may also use `go.sum` and the local Go module cache. The built-in analyzer is registered as a post-analyzer:

```go
func init() {
  analyzer.RegisterPostAnalyzer(analyzer.TypeGoMod, newGoModAnalyzer)
}
```

The analyzer walks the filesystem for `go.mod` files. For each module it calls the Go module parser through the common language helper:

```go
return language.Parse(ctx, types.GoModule, path, file, parser)
```

The module parser decodes the `module`, `go`, `toolchain`, `require`, and `replace` directives. Each required module becomes a package with an ID based on module path and version:

```go
pkgs[require.Mod.Path] = ftypes.Package{
  ID:           packageID(require.Mod.Path, require.Mod.Version),
  Name:         require.Mod.Path,
  Version:      require.Mod.Version,
  Relationship: lo.Ternary(require.Indirect,
    ftypes.RelationshipIndirect,
    ftypes.RelationshipDirect),
}
```

The main module is represented as a root package. Its dependency list initially contains the direct requirements:

```text
example.com/myapp
└── github.com/example/library@v1.2.3
```

Go version affects completeness. For modules below Go 1.17, `go.mod` does not necessarily list every transitive dependency. Trivy can therefore merge `go.sum` to add packages that are missing from the older module file:

```text
go.mod  -> direct and available requirements
go.sum  -> additional resolved module versions
         -> merged Go application
```

For each dependency, the analyzer can inspect the corresponding module under `$GOPATH/pkg/mod` to collect its own `go.mod` requirements and build deeper `DependsOn` edges. If the module source is unavailable locally, Trivy can still report the package found in `go.mod` or `go.sum`, but the dependency graph may be less complete.

`replace` directives are handled for the root module. A replacement with a version changes the package identity; a local-path replacement represents local source rather than a downloadable module. The analyzer also collects VCS external references when the module path can be mapped to a repository URL.

A Go application therefore looks conceptually like:

```go
types.Application{
  Type:     types.GoModule,
  FilePath: "go.mod",
  Packages: []types.Package{
    {
      ID:           "example.com/myapp",
      Name:         "example.com/myapp",
      Relationship: types.RelationshipRoot,
      DependsOn:    []string{"github.com/example/library@v1.2.3"},
    },
    {
      ID:           "github.com/example/library@v1.2.3",
      Name:         "github.com/example/library",
      Version:      "v1.2.3",
      Relationship: types.RelationshipDirect,
    },
  },
}
```

For Go binaries, a separate analyzer can read embedded build information. It reports the Go standard library version, the main module, and compiled dependencies from the binary itself. This is different from parsing source manifests: it describes what was compiled into the executable, even when the original `go.mod` is not present.

Relevant source locations:

- [`pkg/fanal/analyzer/language/golang/mod/mod.go`](../../../pkg/fanal/analyzer/language/golang/mod/mod.go)
- [`pkg/dependency/parser/golang/mod/parse.go`](../../../pkg/dependency/parser/golang/mod/parse.go)
- [`pkg/dependency/parser/golang/sum/parse.go`](../../../pkg/dependency/parser/golang/sum/parse.go)
- [`pkg/dependency/parser/golang/binary/parse.go`](../../../pkg/dependency/parser/golang/binary/parse.go)

## 10.6 How Python dependencies are analyzed

Python has several dependency formats, so there is not one universal Python parser. Trivy selects analyzers based on the files found in the scanned path. Common inputs include:

| Input | What it provides | Graph quality |
| --- | --- | --- |
| `requirements.txt` | Declared package names and version constraints | Usually a shallow declared graph |
| `poetry.lock` | Resolved packages and dependency constraints | Resolved package graph; `pyproject.toml` identifies direct dependencies |
| `Pipfile.lock` | Resolved default packages | Package inventory and lockfile relationships where represented |
| `pylock.toml` | PEP 751 locked packages and dependencies | Explicit locked graph; `pyproject.toml` can identify direct dependencies |
| Installed `.dist-info` metadata | Installed package versions and metadata | Actual installed-package evidence; relationships may be limited |

### Poetry

The Poetry analyzer is registered as a post-analyzer and looks for both `poetry.lock` and `pyproject.toml`:

```go
func init() {
  analyzer.RegisterPostAnalyzer(analyzer.TypePoetry, newPoetryAnalyzer)
}
```

It parses every locked package and converts dependency constraints into IDs of installed package versions. Because a dependency declaration can contain a version range, the parser first records all available versions and then resolves each dependency against those versions:

```go
pkgVersions := p.parseVersions(lockfile)

for _, pkg := range lockfile.Packages {
  pkgID := packageID(pkg.Name, pkg.Version)
  // Parse the package's dependency constraints using pkgVersions.
}
```

`pyproject.toml` is then read beside `poetry.lock` to distinguish direct project dependencies from transitive and development dependencies. Trivy walks the dependency graph from the declared production roots to classify packages:

```text
pyproject.toml direct roots
  -> poetry.lock resolved versions
  -> transitive dependency walk
  -> direct / indirect / development relationships
```

If `pyproject.toml` is missing, the lockfile can still provide package versions and some edges, but direct-dependency classification is less precise.

### Pip, Pipenv, and PEP 751 lockfiles

`requirements.txt` generally contains declarations such as `requests==2.31.0` or `Django>=4.2`. It does not normally contain a complete transitive graph, so Trivy can identify the declared package but cannot infer every resolved child solely from that file.

`Pipfile.lock` contains resolved entries under its `default` section. The Pipenv parser converts those entries into Trivy packages. The `develop` section is used to mark development dependencies where supported.

The newer `pylock.toml` format has explicit package dependency entries. Its parser creates package IDs and dependency edges directly, then the analyzer reads `pyproject.toml` beside it to identify direct roots:

```text
pylock.toml
  -> package name/version records
  -> dependency entries
  -> types.Application
  -> CycloneDX components and top-level dependencies
```

### Installed Python packages

The packaging analyzer recognizes `.dist-info` directories and egg metadata. This path is important when scanning an installed environment or container rather than source code. It can provide the installed version and metadata even if the project lockfile was not copied into the image. However, installed metadata alone may not preserve the complete dependency graph that a lockfile contains.

Python applications therefore differ depending on the evidence available:

```text
requirements.txt       -> declared package inventory
poetry.lock / pylock   -> resolved package graph
site-packages metadata -> installed package evidence
```

Relevant source locations:

- [`pkg/fanal/analyzer/language/python/poetry/poetry.go`](../../../pkg/fanal/analyzer/language/python/poetry/poetry.go)
- [`pkg/dependency/parser/python/poetry/parse.go`](../../../pkg/dependency/parser/python/poetry/parse.go)
- [`pkg/fanal/analyzer/language/python/pip/pip.go`](../../../pkg/fanal/analyzer/language/python/pip/pip.go)
- [`pkg/fanal/analyzer/language/python/pipenv/pipenv.go`](../../../pkg/fanal/analyzer/language/python/pipenv/pipenv.go)
- [`pkg/dependency/parser/python/pipenv/parse.go`](../../../pkg/dependency/parser/python/pipenv/parse.go)
- [`pkg/fanal/analyzer/language/python/pylock/pylock.go`](../../../pkg/fanal/analyzer/language/python/pylock/pylock.go)
- [`pkg/dependency/parser/python/pylock/parse.go`](../../../pkg/dependency/parser/python/pylock/parse.go)
- [`pkg/fanal/analyzer/language/python/packaging/packaging.go`](../../../pkg/fanal/analyzer/language/python/packaging/packaging.go)

## 10.7 How .NET and NuGet dependencies are analyzed

The main NuGet lockfile input is `packages.lock.json`. Trivy also supports older `packages.config` files and project/package metadata such as `packages.props`. The NuGet post-analyzer selects the appropriate parser based on the file name:

```go
parser := a.lockParser
if filepath.Base(path) == configFile {
  parser = a.configParser
}

app, err := language.Parse(ctx, types.NuGet, path, r, parser)
```

For `packages.lock.json`, the parser reads each target framework under `targets`. Each resolved package becomes a `types.Package` with the `resolved` version. A package's nested `dependencies` map becomes a dependency edge:

```json
{
  "version": 1,
  "dependencies": {
    ".NETCoreApp,Version=v6.0": {
      "Newtonsoft.Json/13.0.3": {
        "type": "Direct",
        "resolved": "13.0.3",
        "dependencies": {
          "System.Runtime": "4.3.0"
        }
      }
    }
  }
}
```

The internal result is conceptually:

```text
Newtonsoft.Json@13.0.3
└── System.Runtime@4.3.0
```

The parser skips entries whose type is `Project` when constructing library packages. It determines the root project from project entries and target relationships when the file contains enough information to identify exactly one root. Workspace or project packages are not treated as ordinary external libraries.

NuGet can have multiple target frameworks. Trivy reads target sections and de-duplicates package records and dependency edges where the same package is present for multiple targets. The selected package may therefore represent more than one framework occurrence, while source locations retain where the package was found.

If only a `.csproj` or `packages.props` is present, Trivy can identify declared package references and versions, but a project file alone may not provide the fully resolved transitive graph. `packages.lock.json` is the stronger offline source because it contains resolved versions and nested dependency maps.

The NuGet analyzer may also inspect the local NuGet packages directory to find `.nuspec` metadata and licenses. That metadata enrichment is separate from dependency-edge construction:

```text
packages.lock.json -> versions and dependency graph
local NuGet cache  -> licenses and package metadata
```

Relevant source locations:

- [`pkg/fanal/analyzer/language/dotnet/nuget/nuget.go`](../../../pkg/fanal/analyzer/language/dotnet/nuget/nuget.go)
- [`pkg/dependency/parser/nuget/lock/parse.go`](../../../pkg/dependency/parser/nuget/lock/parse.go)
- [`pkg/dependency/parser/nuget/config/parse.go`](../../../pkg/dependency/parser/nuget/config/parse.go)
- [`pkg/fanal/analyzer/language/dotnet/packagesprops/packagesprops.go`](../../../pkg/fanal/analyzer/language/dotnet/packagesprops/packagesprops.go)

## 10.8 How an existing SBOM is analyzed

The `sbom` target is different from `fs`. It does not discover dependencies by walking project manifests. It opens an existing SBOM, detects its format, decodes its components, and reuses its declared relationships.

The SBOM artifact performs format detection before decoding:

```go
format, err := sbom.DetectFormat(f)
bom, err := sbom.Decode(ctx, f, format)
```

Supported inputs include CycloneDX JSON and SPDX representations, including supported attestation forms. For a CycloneDX JSON input, Trivy parses components first and then processes the top-level `dependencies` array:

```go
for _, dep := range lo.FromPtr(bom.Dependencies) {
  ref, ok := components[dep.Ref]
  if !ok {
    continue
  }

  for _, depRef := range lo.FromPtr(dep.Dependencies) {
    dependency, ok := components[depRef]
    if !ok {
      continue
    }
    b.BOM.AddRelationship(ref, dependency,
      core.RelationshipDependsOn)
  }
}
```

This means a CycloneDX file with components but no top-level `dependencies` array contains an inventory without a dependency graph. Trivy cannot reconstruct relationships that the input SBOM omitted. It can still scan the listed components for vulnerabilities or licenses when those scanners are enabled.

SPDX relationships are handled similarly. Trivy converts SPDX package relationships such as `DEPENDS_ON` into its internal graph. The source relationship vocabulary differs, but the normalized result is the same:

```text
CycloneDX: dependencies[].ref + dependencies[].dependsOn
SPDX:      Relationship: DEPENDS_ON
                                |
                                v
                 internal RelationshipDependsOn
```

When an input SBOM was not generated by Trivy, Trivy warns that vulnerability detection may be less accurate. This can happen when the input lacks package URLs, uses ambiguous versions, omits dependency relationships, or represents components differently from Trivy's package model.

The SBOM scan flow is therefore:

```text
existing SBOM
  -> format detection
  -> CycloneDX/SPDX decoding
  -> components + relationships
  -> internal BOM
  -> ScanTarget
  -> optional vulnerability/license matching
  -> requested report format
```

If the input is already CycloneDX and you only want to preserve or inspect it, a converter may be sufficient. Trivy is useful when you want to validate, normalize, enrich, or scan that SBOM using Trivy's vulnerability, license, filtering, VEX, and reporting pipelines.

Relevant source locations:

- [`pkg/fanal/artifact/sbom/sbom.go`](../../../pkg/fanal/artifact/sbom/sbom.go)
- [`pkg/fanal/analyzer/sbom/sbom.go`](../../../pkg/fanal/analyzer/sbom/sbom.go)
- [`pkg/sbom/sbom.go`](../../../pkg/sbom/sbom.go)
- [`pkg/sbom/cyclonedx/unmarshal.go`](../../../pkg/sbom/cyclonedx/unmarshal.go)
- [`pkg/sbom/spdx/unmarshal.go`](../../../pkg/sbom/spdx/unmarshal.go)
- [`docs/guide/target/sbom.md`](../../guide/target/sbom.md)

## 11. Local scan aggregation

After artifact inspection, the local service in `pkg/scan/local/service.go` applies analysis results and builds scan targets. It can combine several classes of information:

- Operating-system packages.
- Language-specific packages and applications.
- Package relationships.
- Vulnerability matches when the vulnerability scanner is enabled.
- Misconfiguration results when enabled.
- Secrets, licenses, crypto assets, and custom resources when enabled and supported.

Package filters can remove excluded packages or development dependencies according to the selected options. The service then constructs a `types.Report` containing the artifact metadata, package/application data, relationships, and any enabled findings.

For a CycloneDX-only SBOM request, the important output is the inventory portion of this report. Other finding types are only included when both the relevant scanner and the CycloneDX mapping support them.

## 12. Database and offline limitations

There are two different kinds of data involved in a scan:

1. **Artifact evidence:** files, manifests, lockfiles, package databases, and local metadata.
2. **Security intelligence:** vulnerability databases, Java vulnerability data, checks bundles, VEX repositories, and similar external data.

`--offline-scan` primarily affects the first category when analyzers would otherwise issue API requests to identify dependencies. It is not the same option as `--skip-db-update`.

The artifact runner's database initialization skips vulnerability database work when vulnerability scanning is disabled. That is the normal behavior for the plain command:

```bash
trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json
```

If `--scanners vuln` is added, Trivy needs a usable local vulnerability database for matching. Depending on the other options and current Trivy configuration, startup may still attempt database initialization or an update. For a genuinely disconnected vulnerability scan, prepare the databases ahead of time and use the database controls appropriate to the deployment, commonly including `--skip-db-update`.

Even with a local database, offline vulnerability results have limits:

- Newly published vulnerabilities are absent until the database is refreshed.
- A package may be identified locally but lack a matching vulnerability record.
- Dependency metadata that could not be resolved offline can reduce match coverage.
- Java scanning may require the separate Java database when Java packages are included.

For a package inventory without vulnerability matching, do not add `--scanners vuln`.

## 13. Report construction and CycloneDX mapping

Once the report is assembled, `pkg/commands/artifact/run.go` applies result filtering and calls `pkg/report.Write`.

`pkg/report/writer.go` selects `pkg/report/cyclonedx.NewWriter` for `types.FormatCycloneDX`. The writer:

1. Creates a CycloneDX marshaler with the Trivy application version.
2. Converts the Trivy report into the internal SBOM representation.
3. Converts the internal SBOM into a CycloneDX BOM.
4. Encodes the BOM as pretty-printed JSON.
5. Writes the JSON to the configured output writer.

The main conversion is implemented in `pkg/sbom/cyclonedx/marshal.go`. It creates:

- A CycloneDX serial number.
- Metadata including the generation timestamp and Trivy tool information.
- An optional root component for the scanned application or artifact.
- Components for discovered packages and applications.
- PURLs, suppliers, licenses, properties, and file hashes when available.
- Dependency entries derived from Trivy's relationship graph.
- Vulnerability entries only when the input report contains vulnerability data.

Components are identified with BOM references. The marshaler records the mapping between Trivy component IDs and CycloneDX BOM references so that dependency edges and vulnerability affects relationships point to the correct components. Components and dependency entries are sorted by BOM reference for stable output.

The result is CycloneDX JSON. In this repository's current implementation and observed output, the BOM uses CycloneDX specification version `1.7`.

Relevant source locations:

- [`pkg/report/writer.go`](../../../pkg/report/writer.go)
- [`pkg/report/cyclonedx/cyclonedx.go`](../../../pkg/report/cyclonedx/cyclonedx.go)
- [`pkg/sbom/cyclonedx/marshal.go`](../../../pkg/sbom/cyclonedx/marshal.go)
- [`pkg/fanal/artifact/local/fs.go`](../../../pkg/fanal/artifact/local/fs.go)

## 14. End-to-end sequence

The complete normal sequence is:

```text
zsh parses the command
  |
  +-- redirects stdout to <output.json>
  |
cmd/trivy/main.go
  |
pkg/commands.Run
  |
NewFilesystemCommand (fs alias)
  |
Viper/Cobra flags -> flag.Options
  |
artifact.Run(..., TargetFilesystem)
  |
runner initialization
  |
filesystemStandaloneScanService
  |
walker.NewFS + local filesystem artifact
  |
artifact.Option.Offline = true
artifact.Option.FileChecksum = true
  |
artifact.Inspect
  |
cache lookup
  |
static-path analysis or filesystem traversal
  |
fanal analyzers and dependency parsers
  |
internal package/application/dependency graph
  |
local scan service -> types.Report
  |
result filtering
  |
CycloneDX report writer
  |
pretty JSON written to stdout
  |
stdout is already redirected to <output.json>
```

If the command includes `--scanners vuln`, the sequence also includes vulnerability database initialization and local vulnerability matching. Without that explicit scanner selection, the intended result is an inventory-focused CycloneDX report.

## 15. Useful commands

Generate an offline inventory using shell redirection:

```bash
./trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json
```

Use Trivy's output option instead:

```bash
./trivy fs --format cyclonedx --offline-scan --output app.cdx.json ./app
```

Capture diagnostics separately:

```bash
./trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json 2> app.trivy.log
```

Inspect the BOM metadata and component count with `jq`:

```bash
jq '{bomFormat, specVersion, serialNumber, metadata, componentCount: (.components | length)}' app.cdx.json
```

List component names, versions, and PURLs:

```bash
jq -r '.components[] | [.name, .version, .purl] | @tsv' app.cdx.json
```

Inspect dependency relationships:

```bash
jq '.dependencies' app.cdx.json
```

Check that the output is valid JSON:

```bash
jq empty app.cdx.json
```

Generate a CycloneDX report with explicit vulnerability scanning only when the local database policy supports it:

```bash
./trivy fs --format cyclonedx --scanners vuln --offline-scan --skip-db-update ./app > app-vuln.cdx.json
```

The last command assumes a suitable local vulnerability database already exists. `--skip-db-update` prevents an update attempt; it does not create or refresh the database.

## 16. Troubleshooting

### The output file is empty or invalid JSON

Check whether the command failed and inspect standard error:

```bash
./trivy fs --format cyclonedx --offline-scan ./app > app.cdx.json 2> app.trivy.log
echo $status
cat app.trivy.log
```

In zsh, `$status` is the exit status of the previous command. A failure can occur before the writer emits a complete report, leaving an empty or partial output file.

### Logs appear in the terminal

That is expected with `>`. Standard output is redirected, but standard error is not. Redirect standard error separately if needed.

### The SBOM has fewer packages than expected

Check whether the project contains complete lockfiles, whether the relevant package files are under the scanned input, and whether skip rules exclude directories or files. Offline mode can also prevent remote dependency identification that would have supplied additional metadata.

### A clean Git repository is unexpectedly fast

Trivy may have returned a cached artifact analysis. Change the input, use a different cache directory, or enable debug logging to understand cache decisions.

### Vulnerabilities are missing

CycloneDX format alone does not guarantee vulnerability scanning. Add `--scanners vuln`, make sure a compatible local database exists, and understand that `--offline-scan` does not refresh security intelligence.

### The command still needs network access

Review more than `--offline-scan`. Check whether vulnerability scanning, Java database initialization, VEX retrieval, SBOM retrieval from external sources, plugins, or other configured integrations are enabled. Offline artifact analysis specifically prevents dependency-identification API requests; it is not a general operating-system network isolation mechanism.

## 17. Source-reading map

The most useful files for following this flow are:

- [`cmd/trivy/main.go`](../../../cmd/trivy/main.go): executable entrypoint.
- [`pkg/commands/app.go`](../../../pkg/commands/app.go): Cobra command and `fs` alias.
- [`pkg/flag/scan_flags.go`](../../../pkg/flag/scan_flags.go): `--offline-scan` definition and option conversion.
- [`pkg/commands/artifact/run.go`](../../../pkg/commands/artifact/run.go): target dispatch, database initialization, artifact options, filtering, and reporting.
- [`pkg/commands/artifact/scanner.go`](../../../pkg/commands/artifact/scanner.go): standalone filesystem service construction.
- [`pkg/fanal/artifact/local/fs.go`](../../../pkg/fanal/artifact/local/fs.go): local artifact inspection, cache lookup, walking, and analyzer invocation.
- [`pkg/fanal/walker`](../../../pkg/fanal/walker): filesystem traversal.
- [`pkg/fanal/analyzer`](../../../pkg/fanal/analyzer): analyzer registration and file analysis.
- [`pkg/dependency/parser`](../../../pkg/dependency/parser): ecosystem-specific dependency parsing.
- [`pkg/scan/service.go`](../../../pkg/scan/service.go): artifact inspection and report assembly.
- [`pkg/scan/local/service.go`](../../../pkg/scan/local/service.go): local package and finding aggregation.
- [`pkg/report/writer.go`](../../../pkg/report/writer.go): report writer selection.
- [`pkg/report/cyclonedx/cyclonedx.go`](../../../pkg/report/cyclonedx/cyclonedx.go): CycloneDX JSON encoding.
- [`pkg/sbom/cyclonedx/marshal.go`](../../../pkg/sbom/cyclonedx/marshal.go): internal report-to-CycloneDX conversion.

The central distinction to keep in mind is:

> The filesystem analyzers discover what is present locally; CycloneDX describes that discovered inventory; vulnerability scanning is an additional operation that requires explicit scanner selection and appropriate security data.

## 18. The whole-project architecture

The offline filesystem command is one path through a larger system. Trivy is better understood as several cooperating subsystems:

```text
CLI and configuration
  |
  v
Target-specific artifact acquisition
  |
  v
Fanal inspection and cache records
  |
  v
Local backend or client/server RPC backend
  |
  v
Normalized scan target and report
  |
  v
Filtering, suppression, and policy decisions
  |
  v
Output writers and exit-code behavior
```

The same middle and reporting layers are reused across different targets, but the first stage changes substantially:

| Target | What Trivy acquires or opens | Typical artifact code |
| --- | --- | --- |
| `image` | OCI image, image archive, Docker/containerd/Podman image | `pkg/fanal/image/`, `pkg/fanal/artifact/image/` |
| `fs` | Local file or directory | `pkg/fanal/artifact/local/`, `pkg/fanal/walker/` |
| `rootfs` | Extracted operating-system root filesystem | `pkg/fanal/artifact/local/` |
| `repo` | Local or remote Git repository | `pkg/fanal/artifact/repository/` |
| `sbom` | Existing CycloneDX, SPDX, or related SBOM | `pkg/fanal/artifact/sbom/` |
| `vm` | VM disk or cloud-backed disk source | `pkg/fanal/artifact/vm/` |
| `config` | IaC/configuration files and Rego checks | `pkg/commands/config/`, `pkg/iac/`, `pkg/misconf/` |
| `k8s` | Kubernetes API objects and workloads | `pkg/commands/kubernetes/` |

The important migration boundary is that an artifact is not yet a vulnerability result. It is an inspected, identified, and often cached representation that later scanners consume.

## 19. Target behavior is not identical

The command tree exposes many targets, but they do not enable exactly the same analyzers. `pkg/commands/artifact/run.go` changes analyzer configuration for each target.

Examples:

- Filesystem scans disable some individual-package and SBOM analyzers because the filesystem path is analyzed through the normal language and OS package paths.
- Image scans disable some lockfile-oriented behavior because an image is primarily an installed filesystem plus image metadata.
- Repository scans focus on source dependency manifests and generally disable OS-package analysis.
- Rootfs scans are optimized for operating-system filesystems rather than normal source trees.
- VM scans use disk-oriented inspection and usually disable lockfile analyzers.
- SBOM scans do not rediscover packages from a filesystem; they parse the existing SBOM and can enrich it with vulnerability or license data.
- Kubernetes scanning has a separate orchestration path and should not be assumed to follow `artifact.Run` exactly.

When migrating a command or adding a new target, compare the target's disabled analyzers, artifact constructor, cache behavior, scanner service, and output restrictions instead of copying the filesystem path blindly.

## 20. The internal data model

The most useful way to understand Trivy is to follow the data structures rather than only the functions.

### 20.1 CLI input becomes `flag.Options`

Command-line flags, environment variables, and configuration files are normalized into the large `flag.Options` structure. This object contains both general runtime settings and nested option groups for:

- Scan behavior and scanner selection.
- Cache and database directories.
- Registry, HTTP, TLS, and client/server settings.
- Package relationship and development-dependency filters.
- Severity and ignore behavior.
- Report format and output destination.
- License, secret, misconfiguration, Rego, module, VEX, and plugin settings.

The conversion is intentionally centralized. If a new flag is added only to Cobra but not to the flag option conversion or generated documentation path, the feature may appear in `--help` but not actually reach the scanner.

### 20.2 Artifact inspection becomes analysis records

Fanal analyzers return `analyzer.AnalysisResult`. It can contain more than packages:

```text
AnalysisResult
├── OS information
├── OS repositories
├── OS packages
├── language applications
├── misconfigurations
├── secrets
├── licenses
├── crypto assets
├── file digests
├── build information
└── custom resources
```

These records are designed to be cached and, in client/server mode, transported. They are not the same thing as the final `types.Report`.

### 20.3 Cached analysis becomes a scan target

The applier reads cached artifact or layer records and merges them into a normalized view. For images, this includes overlay semantics:

```text
base layer
  + child layer packages/files
  - whiteouts and opaque directories
  = effective filesystem/package state
```

The merge can assign originating layer information, merge OS metadata, de-duplicate packages, merge licenses, generate package URLs, and connect dependency UIDs. This is why changing layer merge behavior can change vulnerability and SBOM output even when individual analyzers did not change.

The local scan service then builds a `types.ScanTarget`. This is the scanner-facing model containing the effective packages, applications, OS data, enabled scanners, package relationships, distro override, license settings, and related options.

### 20.4 The scan target becomes `types.Report`

The final report contains more than a list of CVEs:

```text
types.Report
├── schema version
├── artifact name, type, ID, and metadata
├── client/server versions
├── creation time and report ID
├── results grouped by target/class
│   ├── packages and applications
│   ├── vulnerabilities
│   ├── misconfigurations
│   ├── secrets
│   ├── licenses
│   ├── crypto assets
│   └── custom resources
└── optional internal SBOM representation
```

Report fields and JSON tags are compatibility surfaces. Downstream consumers, golden tests, report converters, and plugins can depend on them.

## 21. Cache architecture and migration impact

Caching has multiple layers and should not be described as one generic cache.

### 21.1 Local cache

The local cache is implemented under `pkg/cache/`. The bbolt backend stores serialized analysis records in buckets for artifact-level and blob/layer-level data. The cache is protected by bbolt locking and has a lock timeout.

The conceptual lookup is:

```text
artifact identity
  -> cache key
  -> artifact/blob record
  -> serialized AnalysisResult
  -> applier
  -> ScanTarget
```

Filesystem scans can use an in-memory backend by default, while persistent cache configuration uses the database-backed implementation. Remote cache, Redis, memory, and no-op backends have different lifecycle and consistency properties.

### 21.2 Cache invalidation

Cache validity depends on more than the input path. Cache keys and records include information such as:

- Analyzer versions.
- Post-handler versions.
- Artifact options.
- Image/layer identity or Git commit identity.
- Cache schema/version information.
- Module/analyzer versions where applicable.

Therefore, a migration that changes an analyzer, handler, package model, or merge rule must consider cache invalidation. Reusing old cache records can produce stale or structurally incompatible results.

Useful migration actions include:

```bash
trivy clean --all
```

or isolating the migration with a new cache directory. Do not assume a successful cache read proves that the cached data is semantically compatible with new code.

### 21.3 Cache and RPC are connected

In client/server mode, the client may inspect locally and send artifact identifiers/blob records to the server. The scanner RPC then sends options and references rather than blindly uploading an arbitrary source directory. The server applies its cache and database before scanning.

That means client/server results depend on:

```text
client binary
+ client analyzer/cache behavior
+ uploaded analysis records
+ server binary
+ server cache state
+ server vulnerability database
+ scanner options
```

Version skew between client and server can therefore affect output even when the scanned input is unchanged.

## 22. Database boundaries

Trivy has several kinds of external data, and they have different update and compatibility rules:

| Data | Used for | Typical boundary |
| --- | --- | --- |
| Vulnerability DB | OS/application vulnerability matching | `pkg/db/`, `pkg/commands/operation/` |
| Java DB | Java vulnerability matching | `pkg/javadb/` |
| Checks bundle | IaC/misconfiguration rules | `pkg/iac/`, `pkg/misconf/` |
| VEX repositories | Vulnerability exploitability/suppression context | `pkg/vex/` |
| SBOM sources | Retrieved external SBOM evidence | `pkg/fanal/`, source-specific packages |

The normal artifact runner skips vulnerability DB work when vulnerability scanning is disabled. Server startup has its own database initialization path. Do not infer server behavior solely from filesystem command behavior.

Database compatibility is versioned. A newer local database can be rejected by an older binary, and a missing or incompatible database can fail before the actual artifact scan begins. A migration plan should record:

1. Which DB schemas the old and new binaries support.
2. Whether databases are shared between versions.
3. Whether the update process is online, mirrored, or air-gapped.
4. Whether the Java DB and checks bundle need separate lifecycle management.
5. Whether `--skip-db-update` means “use an already prepared DB,” not “do not need a DB.”

## 23. Local mode versus client/server mode

The two modes share interfaces but have different ownership:

```text
Standalone:
  CLI -> local artifact -> local cache -> local backend -> report

Client/server:
  CLI -> client artifact inspection/cache
      -> RPC request
      -> server cache/database/backend
      -> RPC response
      -> client filtering/report
```

The client/server split is not simply “move the scan to another process.” In particular:

- Artifact inspection and some cache work occur on the client.
- Vulnerability and license processing can occur through the server backend.
- Secret and misconfiguration behavior can remain client-side.
- The client and server must agree on RPC/protobuf contracts and compatible option semantics.
- Server-side DB and cache state can change results without changing the client input.

When migrating, test both standalone and server-backed execution. A change that works locally may fail when its data is serialized through RPC or applied from a remote cache.

## 24. Extension points and registration

Trivy has several extension mechanisms. They are different and should not be conflated.

### Built-in analyzers and handlers

Built-in analyzers are registered during package initialization. Blank imports in analyzer registration packages make those `init()` functions run. Removing or rearranging a blank import can remove analyzer functionality without causing a compile error.

Analyzer and handler versions participate in cache identity. A new analyzer output shape should therefore update its version and account for old cached records.

### Run, scan, and report hooks

`pkg/extension` defines hooks that can modify:

```text
RunHook    -> options/run lifecycle
ScanHook  -> scan target or results
ReportHook -> report before/after writing
```

Hooks are registered globally and ordered. Migration code should check hook ordering and mutation behavior because a hook can change the effective result after the core scanner finishes.

### WASM modules

`pkg/module` loads WASM/WASI modules, checks the module API version, registers analyzers or post-scanners, and controls module filesystem access. Modules are not unrestricted host processes; their available files and interfaces are mediated by the module runtime.

Module analyzer versions and API compatibility affect cache reuse and startup behavior. A module migration should test installation, API-version validation, registration, scan execution, and cache invalidation.

### External executable plugins

`pkg/plugin` manages installed platform binaries and plugin metadata. Plugin commands are added dynamically to the Cobra tree, and plugin arguments may be passed through without normal Trivy flag parsing. Plugin execution inherits process streams and environment behavior, so it is a different boundary from WASM modules.

## 25. Reporting and compatibility contracts

Reporting is not only presentation. It is a public data contract.

The report path normally looks like:

```text
types.Report
  -> pre-report hooks
  -> output writer selection
  -> format writer
  -> post-report hooks
```

There is an important exception: compliance reporting has an early path in `pkg/report/writer.go` and may return before the normal writer/post-report sequence. Do not assume every output format follows the same hook behavior.

Migration-sensitive surfaces include:

- `types.Report` schema version.
- JSON field names and omission behavior.
- CycloneDX/SPDX mapping.
- SARIF and GitHub output contracts.
- Template data shape.
- Finding fingerprints.
- Exit-code behavior.
- Golden files and downstream report consumers.

When changing package IDs, PURLs, relationships, or component ordering, expect changes in SBOM output and golden tests even if vulnerability matching is unchanged.

## 26. Generated files and source-of-truth rules

Several repository outputs are generated and must be kept synchronized:

| Area | Source of truth | Generated/verified output |
| --- | --- | --- |
| CLI docs/config docs | Cobra command and flag definitions | `docs/`, generated config documentation |
| RPC | `.proto` files under `rpc/` | `*.pb.go`, `*.twirp.go` |
| IaC schema | `magefiles/config_schema.go` and schema code | `schema/trivy-config.json` |
| Version/build metadata | Git and Mage build logic | linked binary metadata |
| Golden behavior | test fixtures and code | golden JSON/report files |

Typical checks include:

```bash
mage docs:generate
mage protoc:generate
mage protoc:fmt
mage protoc:lint
mage protoc:breaking
```

Do not manually edit generated protobuf or schema output unless the repository specifically requires it. Update the source and regenerate.

## 27. Migration checklist

Before migrating a scanner, analyzer, backend, or report integration, answer these questions:

### Runtime and target behavior

- Which command constructs the target?
- Is the target standalone, remote, or both?
- Which analyzers are disabled for this target?
- Which database and policy initialization paths run?
- Which hooks and modules run before analysis?

### Data and cache behavior

- What is the input analysis record?
- Which fields are serialized into cache or RPC?
- What creates the artifact/layer cache key?
- Which analyzer, handler, module, and schema versions invalidate old data?
- Does the change affect layer merging, package IDs, PURLs, or dependency UIDs?

### Network and security behavior

- Which operations contact registries, Git servers, package APIs, Rekor, cloud APIs, or Trivy servers?
- Does `--offline-scan` actually cover the operation, or is it a DB/VEX/plugin/module concern?
- Is a local DB required even when updates are disabled?
- Are credentials or secrets crossing a client/server boundary?

### Compatibility

- Does the change alter `types.Report`, JSON, CycloneDX, SPDX, SARIF, or template output?
- Does it alter protobuf/RPC fields or enum values?
- Does it require generated documentation or schema updates?
- Does it change exit codes or finding fingerprints?
- Which unit, integration, E2E, golden, module, VM, or client/server tests cover it?

### Operational rollout

- Can old and new binaries share the same cache directory?
- Can old and new binaries share the same vulnerability DB?
- Can clients and servers be upgraded independently?
- Is there a rollback procedure if cache or DB compatibility fails?
- Can the migration run first with a clean cache and pinned databases?

## 28. Recommended learning path for a newcomer

Read the project in layers instead of opening files randomly:

1. Run `./trivy --help` and identify the target command you care about.
2. Read `cmd/trivy/main.go` and `pkg/commands/run.go` for process lifecycle.
3. Read the relevant command constructor in `pkg/commands/app.go`.
4. Read `pkg/flag/` to see how input becomes `flag.Options`.
5. Read `pkg/commands/artifact/run.go` for shared orchestration and target-specific settings.
6. Read `pkg/commands/artifact/scanner.go` for dependency wiring.
7. Read `pkg/fanal/artifact/` and `pkg/fanal/analyzer/` for inspection.
8. Read `pkg/cache/` and `pkg/fanal/applier/` to understand persistence and layer merging.
9. Read `pkg/scan/service.go`, `pkg/scan/local/service.go`, and `pkg/types/` for normalized scan data.
10. Read `pkg/result/` for filtering and suppression.
11. Read `pkg/report/` and `pkg/sbom/` for output contracts.
12. Read `pkg/rpc/` and `rpc/` before changing client/server behavior.
13. Read `pkg/extension/`, `pkg/module/`, and `pkg/plugin/` before changing extensibility.
14. Read `magefiles/`, CI workflows, and relevant tests before changing generated files or release behavior.

For the current offline CycloneDX example, the shortest useful path is:

```text
NewFilesystemCommand
  -> flag.ScanOptions.ToOptions
  -> artifact.initScannerConfig
  -> filesystemStandaloneScanService
  -> local.Artifact.Inspect
  -> npmLibraryAnalyzer.PostAnalyze
  -> npm.Parser.Parse
  -> language.toApplication
  -> local.Service.ScanTarget
  -> sbom.io.Encoder.Encode
  -> cyclonedx.Marshaler.Marshal
```

The key migration lesson is that Trivy is not one monolithic scanner. It is a target-specific artifact acquisition system, a versioned analysis/cache layer, a local or RPC scanning backend, a policy/filtering stage, and a set of independently evolving report and extension contracts.
