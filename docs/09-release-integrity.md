# Release size and integrity notes

A smaller ZIP file is not, by itself, evidence that functionality was removed. ZIP size is affected by at least five variables:

1. the uncompressed source bytes included in the package;
2. the compressibility of the changed files;
3. ZIP container metadata such as member timestamps and paths;
4. whether cache/build artefacts were excluded;
5. whether sidecar files are stored outside the ZIP rather than inside it.

For CodeProbe, source files such as Python, JavaScript, HTML, CSS and Markdown compress strongly. A large new JavaScript or Python feature can add many uncompressed bytes but only a few compressed kilobytes. Conversely, a screenshot, DOCX or already-compressed binary contributes almost one-to-one to ZIP size. For that reason, compressed ZIP size is a weak audit signal.

## Canonical comparison procedure

When two releases appear unexpectedly different in size, do not compare only the file size displayed by the operating system or browser. Use this procedure:

```bash
python3 tools/compare_releases.py old_release.zip new_release.zip \
  --json-out release_comparison.json \
  --md-out release_comparison.md
```

Then check:

- ZIP SHA-256;
- file count;
- total uncompressed member bytes;
- total compressed member bytes;
- added paths;
- removed paths;
- changed paths with largest deltas.

A release is acceptable when the membership and hash manifest are coherent. A release is not acceptable merely because its ZIP size looks plausible.

## Source-tree immutability invariant

`python3 tools/check_release.py` is a read-only operation. Run it in both a fresh
Git clone and an exact `git archive` export when preparing a release candidate.
With the same supported toolchain and a byte-preserving checkout configuration,
the semantic results must agree, and a before/after inventory of the complete
source tree, excluding `.git`, must be unchanged. Evidence generation is a
separate explicit maintenance action through `--write-release-evidence`; the ZIP
builder consumes that committed evidence rather than silently replacing it.
The repository does not yet define a cross-platform `.gitattributes`
normalisation policy, so line-ending and other content-changing checkout filters
remain a separate release-hardening concern.

## Canonical v2.1.8 package observed during Phase 9 audit

The canonical Phase 8 package available in the build workspace had the following audit values:

| Field | Value |
|---|---:|
| ZIP size | 438,150 bytes |
| File count | 84 |
| Total uncompressed member bytes | 881,373 bytes |
| Total compressed member bytes | 420,992 bytes |
| SHA-256 | `0c09639a36f4737a53ff0959f7df569a7d3073160b6c585bff5d6c564eb6b1cc` |

In the same workspace, Phase 7 had:

| Field | Value |
|---|---:|
| ZIP size | 425,050 bytes |
| File count | 82 |
| Total uncompressed member bytes | 834,248 bytes |
| Total compressed member bytes | 408,306 bytes |
| SHA-256 | `101c0954556cad767b716180b773bdcf031a739ce7adc462f5fbb9ff67b4773f` |

This means that the canonical v2.1.8 package was larger than v2.1.7 in this workspace: +13,100 ZIP bytes and +47,125 uncompressed member bytes. If a downloaded Phase 8 ZIP appears substantially smaller than another Phase 8 ZIP, treat that as a release-identification problem and verify the SHA-256, not the visible size alone.

## Phase 9 correction

Phase 9 adds deterministic ZIP construction, sidecar package-audit output and explicit GitHub/hosted-ZIP root normalisation. The root normalisation is intentionally conservative: CodeProbe strips a common top-level directory such as `repo-main/` only when every safe candidate file is under one non-source-like wrapper. It does not strip top-level source directories such as `src/`. `tools/build_release.py` now normalises ZIP member timestamps and writes two sidecars next to the generated package:

```text
<release>.zip.sha256.txt
<release>.zip.package_audit.json
```

The sidecar JSON records package-level size, member-level compressed and uncompressed sizes, CRC-32 values, total compressed bytes and ZIP container overhead. This is the defensible way to reconcile any future size discrepancy.
