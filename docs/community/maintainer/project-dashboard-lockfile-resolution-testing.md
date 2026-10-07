# npm Lockfile Resolution Testing

## Purpose

This report documents the controlled testing performed with Trivy's offline CycloneDX filesystem scan for the npm package `@babel/helper-validator-identifier`.

The test answers an important question:

> What happens when a package is referenced by dependency maps but its concrete `packages` entry is missing from `package-lock.json`?

The test project was `/Users/krish/Downloads/project_dashboard`. The package was also physically present in `node_modules` at version `7.28.5`, but it was not present as a concrete package record in the original lockfile.

## Command under test

```bash
./trivy fs \
  --format cyclonedx \
  --offline-scan \
  --include-dev-deps \
  /path/to/project > /path/to/output.cdx.json
```

`--include-dev-deps` was used for the controlled comparison so that development dependencies, including Babel packages, were eligible for inclusion. The default production-only scan was tested separately.

The command creates an inventory/SBOM. It does not perform vulnerability matching unless vulnerability scanning is explicitly enabled, for example with `--scanners vuln` and an available vulnerability database.

## Initial evidence

Before creating temporary fixtures, the original project was inspected without modifying it:

| Evidence | Observation |
|---|---|
| `package.json` direct dependencies | `@babel/helper-validator-identifier` was not declared directly |
| `package-lock.json` dependency maps | The package was referenced by Babel package dependency maps |
| `package-lock.json` concrete package records | No `packages["node_modules/@babel/helper-validator-identifier"]` entry existed |
| Installed package | `node_modules/@babel/helper-validator-identifier/package.json` existed at version `7.28.5` |
| Existing production BOM | 42 components; no matching Babel component |
| Existing dev-inclusive BOM | 380 components; no matching Babel component |

The dangling references were found near lines 42, 157, and 518 of the original lockfile. The constraints included `^7.27.1` and `^7.28.5`.

## Fixtures

All controlled tests used temporary copies under `/tmp/trivy-babel-tests`; the source project was not changed.

### 1. No lockfile

The fixture contained only `package.json`. The npm lockfile was intentionally omitted.

```text
/tmp/trivy-babel-tests/no-lock/
└── package.json
```

### 2. Missing lockfile package entry

The fixture contained the original `package.json` and the original `package-lock.json`. The lockfile still referenced `@babel/helper-validator-identifier` from other dependency maps, but the concrete package entry remained absent.

```text
/tmp/trivy-babel-tests/missing-entry/
├── package.json
└── package-lock.json
```

This represents the damaged or incomplete-lockfile case:

```json
{
  "dependencies": {
    "@babel/helper-validator-identifier": "^7.28.5"
  }
}
```

but no corresponding entry:

```json
{
  "packages": {
    "node_modules/@babel/helper-validator-identifier": {
      "version": "7.28.5"
    }
  }
}
```

### 3. Repaired lockfile

This fixture was based on the missing-entry copy. A package record for version `7.28.5` was added to the temporary lockfile only:

```json
"node_modules/@babel/helper-validator-identifier": {
  "version": "7.28.5",
  "resolved": "https://registry.npmjs.org/@babel/helper-validator-identifier/-/helper-validator-identifier-7.28.5.tgz",
  "dev": true,
  "license": "MIT",
  "engines": {
    "node": ">=6.9.0"
  }
}
```

This is a parser fixture, not a package installation test. It demonstrates the effect of restoring the concrete lockfile node.

### 4. Default dependency filtering

The original project was scanned without `--include-dev-deps` to verify the normal production-only behavior.

## Results

| Scenario | Trivy options | Components | Dependency records | Populated relationships | Target package present |
|---|---|---:|---:|---:|---:|
| No `package-lock.json` | `--offline-scan --include-dev-deps` | 0 | 1 | 0 | No |
| References, missing package entry | `--offline-scan --include-dev-deps` | 380 | 381 | 222 | No |
| Repaired package entry | `--offline-scan --include-dev-deps` | 381 | 382 | 222 | Yes, `7.28.5` |
| Original project, default filtering | `--offline-scan` | 42 | 43 | 23 | No |

The repaired fixture produced this CycloneDX component:

```json
{
  "bom-ref": "pkg:npm/%40babel/helper-validator-identifier@7.28.5",
  "type": "library",
  "group": "@babel",
  "name": "helper-validator-identifier",
  "version": "7.28.5",
  "purl": "pkg:npm/%40babel/helper-validator-identifier@7.28.5"
}
```

The original BOM's `package-lock.json` analyzer component had the UUID-like reference `6c7791bf-c109-4d6e-9a8b-c8dc4b840891`. That reference identifies the analyzed lockfile artifact; it is not a reference to `@babel/helper-validator-identifier`.

## Interpretation

### A dependency map is not a package record

The dependency map says that one package requires `@babel/helper-validator-identifier` and supplies a version range. It does not, by itself, provide the complete resolved package object needed to create a component reliably.

For the offline parser, the concrete `packages` entry supplies the resolved package identity and metadata used to construct the application package graph. When that entry is absent, Trivy does not invent a component from the dangling dependency name or version range.

This behavior prevents an unverified range from being represented as an installed, resolved package in the SBOM.

### Installed files do not repair an incomplete lockfile

The target package existed under `node_modules`, but the missing-entry scan still omitted it. In this test, the offline npm result was driven by the lockfile's resolvable package records; the presence of an installed directory did not cause Trivy to synthesize the missing lockfile node.

Consequently, these are separate sources of evidence:

- `package.json`: requested dependency ranges.
- `package-lock.json`: resolved dependency versions and graph.
- `node_modules`: files currently present on disk.

A package can exist in one source and be absent from another.

### Development dependency filtering is a separate behavior

The original lockfile contained many Babel packages marked `"dev": true`. Without `--include-dev-deps`, Trivy emitted 42 production components. With `--include-dev-deps`, it emitted 380 components in the original incomplete-lockfile case.

Therefore, a missing Babel package can have two independent causes:

1. It is a development dependency and the scan did not include development dependencies.
2. Its concrete lockfile package record is missing, even when development dependencies are included.

For `@babel/helper-validator-identifier`, both checks were performed. The package remained absent with `--include-dev-deps` until its concrete lockfile entry was restored.

### CycloneDX graph effect

CycloneDX stores components in `components[]` and edges in top-level `dependencies[]`. A missing package node cannot be emitted as a normal component, and Trivy cannot emit a valid edge to a component it could not resolve. The repaired fixture added one component and one dependency record; it did not change the number of populated relationships in this particular project because the existing Babel dependency paths were not all retained in the selected output graph.

## Reproduction commands

The following commands reproduce the scan phase after creating equivalent fixtures:

```bash
cd /Users/krish/Documents/Project/trivy

./trivy fs --format cyclonedx --offline-scan --include-dev-deps \
  /tmp/trivy-babel-tests/no-lock \
  > /tmp/trivy-babel-tests/no-lock.cdx.json

./trivy fs --format cyclonedx --offline-scan --include-dev-deps \
  /tmp/trivy-babel-tests/missing-entry \
  > /tmp/trivy-babel-tests/missing-entry.cdx.json

./trivy fs --format cyclonedx --offline-scan --include-dev-deps \
  /tmp/trivy-babel-tests/valid-lock \
  > /tmp/trivy-babel-tests/valid-lock.cdx.json

./trivy fs --format cyclonedx --offline-scan \
  /Users/krish/Downloads/project_dashboard \
  > /tmp/trivy-babel-tests/default-prod.cdx.json
```

A compact result check can be performed with:

```bash
python3 - <<'PY'
import json
from pathlib import Path

name = "@babel/helper-validator-identifier"
for path in sorted(Path("/tmp/trivy-babel-tests").glob("*.cdx.json")):
    bom = json.loads(path.read_text())
    components = bom.get("components", [])
    dependencies = bom.get("dependencies", [])
    matches = [component for component in components if name in str(component)]
    populated = sum(bool(item.get("dependsOn")) for item in dependencies)
    print(
        path.name,
        "components=", len(components),
        "dependency_records=", len(dependencies),
        "populated_relationships=", populated,
        "target_matches=", len(matches),
    )
PY
```

## Limitations

- The repaired package record was synthetic and was added only to a temporary copy. It proves parser behavior when a concrete node exists; it does not prove that the package can be installed from the network.
- The scans used `--offline-scan`, so no dependency-resolution fallback should be inferred from these results.
- The report measures SBOM inventory and graph construction. It does not report vulnerability findings because vulnerability scanning was not enabled.
- Component and relationship totals are specific to this Trivy build, project contents, dependency flags, and lockfile state.
- A lockfile should normally be repaired by the package manager, for example by regenerating it from the project manifest, rather than by manually inserting a synthetic entry.

## Conclusion

The tests confirm that Trivy requires a resolvable package record to emit an npm component in this offline CycloneDX flow. A dependency reference such as `@babel/helper-validator-identifier: ^7.28.5` is not enough to create an SBOM component when `packages["node_modules/@babel/helper-validator-identifier"]` is missing.

The practical remediation is to restore or regenerate a valid `package-lock.json`, then rerun the scan. If the package is a development dependency, include it with `--include-dev-deps` when the SBOM is intended to cover development and build tooling.

## Related ecosystem flows

The same distinction between declared dependencies, resolved package records, and local metadata applies to other ecosystems. The repository-wide implementation guide documents these flows:

- [Offline filesystem-to-CycloneDX flow](offline-cyclonedx-scan-flow.md)
- [Go module analysis](offline-cyclonedx-scan-flow.md#105-how-go-modules-are-analyzed)
- [Python dependency analysis](offline-cyclonedx-scan-flow.md#106-how-python-dependencies-are-analyzed)
- [.NET and NuGet analysis](offline-cyclonedx-scan-flow.md#107-how-net-and-nuget-dependencies-are-analyzed)
- [Gradle dependency analysis](offline-cyclonedx-scan-flow.md#108-how-gradle-dependencies-are-analyzed)
- [Maven dependency analysis](offline-cyclonedx-scan-flow.md#109-how-maven-dependencies-are-analyzed)
- [Composer dependency analysis](offline-cyclonedx-scan-flow.md#1010-how-composer-dependencies-are-analyzed)
- [Poetry dependency analysis](offline-cyclonedx-scan-flow.md#1011-how-poetry-dependencies-are-analyzed)
- [Conan dependency analysis](offline-cyclonedx-scan-flow.md#1012-how-conan-dependencies-are-analyzed)
