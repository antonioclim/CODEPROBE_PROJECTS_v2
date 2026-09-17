# CodeProbe v2.3.0 — evidence-contract research integration

> Local release candidate. This file does not assert that a tag, GitHub Release, Zenodo record or DOI exists. Final tag-target and CI identifiers belong in the external release-provenance receipt.

CodeProbe v2.3.0 integrates a bounded evidence-contract route for heuristic source review while retaining the established formative-review application as a compatibility and educational surface. The scientific route separates observation availability, measured values, interpretation policy, source localisation and consumer admission. It is not an empirically validated AI-authorship detector, misconduct detector or authorship-probability estimator.

## Added

- source-level measurement, interpretation, reporting, review-contract and calibration-admission modules;
- machine-readable observation, measurement-kernel, review-bundle and feedback-journal schemas;
- CE04 component and source-localisation contracts;
- explicit claim policy, construct map and measurement-error records;
- a bounded standalone S05 reader surface;
- public provenance, reproducibility and distribution-boundary documentation for the article-facing source-only asset.

## Changed

- strengthened fail-closed input, output, process and runtime-integrity boundaries accumulated since v2.2.0;
- clarified provenance, negative-result preservation and the separation of historical S05 from the locally repaired CE04 identity;
- separated software version `2.3.0` from unchanged report schemas `2.2.0` and `2.2.0-project`;
- removed direct Git process launch from the interpretation component, with commit/tree anchors delegated to an external release-provenance receipt;
- expanded calibration, browser, release and reproducibility controls without treating software tests as external validation evidence.

## Compatibility

- the public Python wrappers remain `analyse_file(payload)` and `analyse_project(payload)`;
- the formerly accepted but ineffective `--min-per-class-for-language` option remains accepted, hidden and ignored for v2.2.0 command compatibility;
- stricter refusal of malformed, ambiguous or unsafe inputs is treated as integrity hardening and is documented explicitly;
- the established aggregate score and 60% provisional trigger remain compatibility constructs, not the current scientific composition rule.

## Distribution boundary

GitHub-generated source archives contain the complete tagged repository snapshot. The separately attached `CodeProbe_Source_Only_v2.3.0.zip` is the bounded article-facing asset and has its own manifest and SHA-256.

The release does not attach the manuscript, editable figures, CE09 package, CE11 executable replay, private continuity archives, Ruff or Radon distributions, Pyodide runtime bytes, crate archives or held reproducibility data. No Zenodo deposit or DOI is implied.

## Verification fields recorded after remote authorisation

- tag target commit: external release-provenance receipt;
- final repository tree: external release-provenance receipt;
- bounded asset SHA-256: release asset sidecar and receipt;
- canonical CI run: release read-back receipt;
- release identity and attached assets: release read-back receipt.
