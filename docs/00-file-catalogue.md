# 00 — File catalogue

This catalogue is generated from `release/file-rename-map.csv` and records the canonical file names for the v2.3.0 release candidate. `Previous path` is shown only for auditable migration history; current documentation and runtime references should use `Current path`.

## Summary

- `added_I04`: 1
- `added_I13`: 3
- `added_audit_phase4`: 7
- `added_audit_phase4b`: 1
- `added_audit_phase4c`: 7
- `added_audit_phase4d`: 4
- `added_audit_phase4f1`: 4
- `added_audit_phase4f2`: 3
- `added_audit_phase4f3`: 8
- `added_audit_phase4h`: 3
- `added_ce20`: 1
- `added_citation_lineage`: 2
- `added_phase13`: 10
- `completed_migration`: 30
- `completed_phase13`: 4
- `integrated_ce19`: 28
- `integrated_ce19_patched`: 1
- `integrated_ce20`: 9
- `keep`: 68

- **Total canonical files:** 194

## Current files

| Current path | Previous path | Area | Role | Action | Phase | Risk |
|---|---|---|---|---|---:|---|
| `.codeprobeignore.example` | `—` | `root` | standard project file | `keep` | current | `low` |
| `.gitattributes` | `—` | `root` | repository checkout policy | `added_audit_phase4` | audit-4 | `high` |
| `.github/CODEOWNERS` | `—` | `.github` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `medium` |
| `.github/workflows/ci.yml` | `—` | `.github` | continuous-integration workflow | `added_audit_phase4` | audit-4 | `high` |
| `.gitignore` | `—` | `root` | standard project file | `keep` | current | `low` |
| `.zenodo.json` | `—` | `root` | optional repository deposit metadata; no deposit authority | `integrated_ce20` | CE20 | `medium` |
| `00-kit-index.md` | `KIT_INDEX.md` | `root` | standard project file | `completed_phase13` | 13 | `low` |
| `CHANGELOG.md` | `—` | `root` | standard project file | `keep` | current | `low` |
| `CITATION.bib` | `—` | `root` | release-specific software citation | `added_citation_lineage` | citation-lineage | `medium` |
| `CITATION.cff` | `—` | `root` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `medium` |
| `CONTRIBUTING.md` | `—` | `root` | standard project file | `keep` | current | `low` |
| `DISTRIBUTION_BOUNDARY.md` | `—` | `root` | public distribution, provenance or third-party boundary | `integrated_ce20` | CE20 | `medium` |
| `LICENSE` | `—` | `root` | standard project file | `keep` | current | `low` |
| `NOTICE.md` | `—` | `root` | public distribution, provenance or third-party boundary | `integrated_ce20` | CE20 | `medium` |
| `README.md` | `—` | `root` | standard project file | `keep` | current | `low` |
| `REPRODUCIBILITY.md` | `—` | `root` | public distribution, provenance or third-party boundary | `integrated_ce20` | CE20 | `medium` |
| `SECURITY.md` | `—` | `root` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `medium` |
| `THIRD_PARTY_NOTICES.md` | `—` | `root` | public distribution, provenance or third-party boundary | `integrated_ce20` | CE20 | `medium` |
| `app/README.md` | `—` | `app` | browser app asset | `keep` | current | `high` |
| `app/analysis-worker.js` | `—` | `app` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `high` |
| `app/codeprobe-ui.js` | `src/index.js` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/codeprobe.css` | `—` | `app` | browser app asset | `keep` | current | `high` |
| `app/index.html` | `src/index.html` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/project-ui.js` | `src/project_index.js` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/project.css` | `src/project_index.css` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/project.html` | `src/project_index.html` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/pyodide-loader.js` | `src/pyodide_loader.js` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/pyodide-provenance.json` | `—` | `app` | browser app asset | `added_audit_phase4c` | audit-4c | `high` |
| `app/resource-integrity.json` | `src/RESOURCE_INTEGRITY_MANIFEST.json` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/runtime-config.example.json` | `src/runtime_config.example.json` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/runtime-config.json` | `src/runtime_config.json` | `app` | browser app asset | `completed_migration` | current | `high` |
| `app/s05/reader.css` | `—` | `app` | bounded evidence-contract reader asset | `integrated_ce20` | CE20 | `high` |
| `app/s05/reader.js` | `—` | `app` | bounded evidence-contract reader asset | `integrated_ce20` | CE20 | `high` |
| `app/vendor/pyodide/README.md` | `—` | `app` | browser app asset | `keep` | current | `high` |
| `calibration/01-corpus-manifest-template.csv` | `calibration/manifest_template.csv` | `calibration` | calibration template or placeholder | `completed_migration` | current | `medium` |
| `calibration/01-corpus-manifest-template.json` | `calibration/manifest_template.json` | `calibration` | calibration template or placeholder | `completed_migration` | current | `medium` |
| `calibration/01-project-corpus-manifest-template.csv` | `—` | `calibration` | project-only calibration manifest template | `added_I13` | I13 | `medium` |
| `calibration/01-project-corpus-manifest-template.json` | `—` | `calibration` | project-only calibration manifest template | `added_I13` | I13 | `medium` |
| `calibration/02-calibration-profile-template.json` | `calibration/profile_template.json` | `calibration` | calibration template or placeholder | `completed_migration` | current | `medium` |
| `calibration/03-example-calibration-profile.json` | `calibration/example_profile.json` | `calibration` | calibration template or placeholder | `completed_migration` | current | `medium` |
| `calibration/04-validation-summary-template.md` | `calibration/validation_summary_template.md` | `calibration` | calibration template or placeholder | `completed_migration` | current | `medium` |
| `calibration/README.md` | `—` | `calibration` | calibration template or placeholder | `keep` | current | `medium` |
| `calibration/profiles/README.md` | `—` | `calibration` | calibration template or placeholder | `keep` | current | `medium` |
| `calibration/reports/.gitkeep` | `—` | `calibration` | calibration template or placeholder | `keep` | current | `medium` |
| `docs/00-file-catalogue.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/01-naming-policy.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/02-architecture.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/03-report-schema.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/04-browser-security.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/05-offline-deployment.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/06-calibration-guide.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/07-ui-extension-guide.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/08-release-process.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/09-release-integrity.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/10-provenance.md` | `AI_ASSISTANCE_AND_PROVENANCE.md` | `docs` | technical documentation or asset | `completed_migration` | current | `medium` |
| `docs/11-design-decisions.md` | `DESIGN_DECISIONS.md` | `docs` | technical documentation or asset | `completed_migration` | current | `medium` |
| `docs/12-release-hash-sheet.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/13-signed-release-workflow.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/14-optimisation-roadmap.md` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/15-final-release-audit.md` | `—` | `docs` | technical documentation or asset | `added_phase13` | 13 | `medium` |
| `docs/16-ci-and-repository-controls.md` | `—` | `docs` | technical documentation or asset | `added_audit_phase4` | audit-4 | `medium` |
| `docs/17-supported-coverage.md` | `—` | `docs` | technical documentation or asset | `added_audit_phase4d` | audit-4d | `medium` |
| `docs/18-runtime-integrity.md` | `—` | `docs` | technical documentation or asset | `added_audit_phase4f1` | audit-4f1 | `medium` |
| `docs/19-release-recovery.md` | `—` | `docs` | technical documentation or asset | `added_audit_phase4f2` | audit-4f2 | `high` |
| `docs/20-worker-resilience.md` | `—` | `docs` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `medium` |
| `docs/21-runtime-lifecycle.md` | `—` | `docs` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `medium` |
| `docs/22-contract-reconciliation.md` | `—` | `docs` | scoring, intake, report and publication contracts | `added_audit_phase4h` | audit-4h | `high` |
| `docs/assets/interface-preview.png` | `—` | `docs` | technical documentation or asset | `keep` | current | `medium` |
| `docs/history/01-stabilisation.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/02-parser-and-metrics.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/03-project-mode.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/04-calibration.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/05-release-metadata.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/06-browser-security.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/07-institutional-packaging.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/08-dynamic-ui-and-review.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/09-release-integrity.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/10-naming-governance.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/11-documentation-resources.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/12-runtime-app-tools.md` | `—` | `docs` | phase-history note | `keep` | current | `medium` |
| `docs/history/13-final-audit.md` | `—` | `docs` | technical documentation or asset | `added_phase13` | 13 | `medium` |
| `docs/history/14-legacy-lineage.md` | `—` | `docs` | fixed-snapshot legacy lineage and retirement assessment | `added_citation_lineage` | citation-lineage | `medium` |
| `educator/01-student-quick-start.md` | `—` | `educator` | educator resource | `keep` | current | `medium` |
| `educator/02-student-announcement.docx` | `educator_resources/AI_FINGERPRINT_SELF_CHECK_ANNOUNCEMENT_REVISED.docx` | `educator` | educator resource | `completed_migration` | current | `medium` |
| `educator/02-student-announcement.md` | `educator_resources/AI_FINGERPRINT_SELF_CHECK_ANNOUNCEMENT_REVISED.md` | `educator` | educator resource | `completed_migration` | current | `medium` |
| `educator/03-student-disclosure-template.md` | `STUDENT_DISCLOSURE_TEMPLATE.md` | `educator` | educator resource | `completed_migration` | current | `medium` |
| `educator/04-instructor-checklist.md` | `—` | `educator` | educator resource | `keep` | current | `medium` |
| `educator/05-review-protocol.md` | `—` | `educator` | educator resource | `keep` | current | `medium` |
| `educator/06-evidence-rubric.md` | `—` | `educator` | educator resource | `keep` | current | `medium` |
| `educator/07-course-integration.md` | `COURSE_INTEGRATION.md` | `educator` | educator resource | `completed_migration` | current | `medium` |
| `educator/08-deployment-one-page.md` | `—` | `educator` | educator resource | `keep` | current | `medium` |
| `educator/09-project-kit-notice.md` | `PROJECT_KIT_NOTICE.md` | `educator` | educator resource | `completed_migration` | current | `medium` |
| `provenance/ACTIVE_NATIVE_FILES_CE04.json` | `—` | `provenance` | source identity and integration provenance record | `integrated_ce19` | CE20 | `high` |
| `provenance/CE04_COMPLETE_SOURCE_IDENTITY.json` | `—` | `provenance` | source identity and integration provenance record | `integrated_ce19` | CE20 | `high` |
| `provenance/CE19_OVERLAY.json` | `—` | `provenance` | source identity and integration provenance record | `integrated_ce19` | CE20 | `high` |
| `provenance/CE20_P01_RELEASE_INTEGRATION.json` | `—` | `provenance` | source identity and integration provenance record | `added_ce20` | CE20 | `high` |
| `release/RELEASE_NOTES_v2.3.0.md` | `release/RELEASE_NOTES_CE19_DRAFT.md` | `release` | release-specific notes and distribution boundary | `integrated_ce20` | CE20 | `medium` |
| `release/file-rename-map.csv` | `release/rename-map.csv` | `release` | release evidence | `completed_phase13` | 13 | `high` |
| `release/final-audit-report.json` | `—` | `release` | release evidence | `added_phase13` | 13 | `medium` |
| `release/final-audit-summary.md` | `—` | `release` | release evidence | `added_phase13` | 13 | `medium` |
| `release/release-manifest.json` | `RELEASE_MANIFEST.json` | `release` | release evidence | `completed_phase13` | 13 | `low` |
| `reproducibility/README.md` | `—` | `reproducibility` | public reproducibility-scope documentation | `integrated_ce20` | CE20 | `medium` |
| `research/ce04/component-inventory.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/ce04/locator-contract.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/claim-policy.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/construct-map.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/measurement-error-register.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/observation-catalogue.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s03/error-register-extension.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s04/acceptance-lock.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s04/calibration-design.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s04/condition-migration.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s04/profiles.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s05/BRIDGE_PRIVACY_ACCESSIBILITY.md` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `research/s05/acceptance-lock.v1.json` | `—` | `research` | machine-readable scientific claim, construct or acceptance contract | `integrated_ce19` | CE20 | `high` |
| `schemas/codeprobe-feedback-journal-v1.schema.json` | `—` | `schemas` | machine-readable evidence-contract schema | `integrated_ce19` | CE20 | `high` |
| `schemas/codeprobe-measurement-kernel-result-v1.schema.json` | `—` | `schemas` | machine-readable evidence-contract schema | `integrated_ce19` | CE20 | `high` |
| `schemas/codeprobe-observation-catalogue-v1.schema.json` | `—` | `schemas` | machine-readable evidence-contract schema | `integrated_ce19` | CE20 | `high` |
| `schemas/codeprobe-review-bundle-v1.schema.json` | `—` | `schemas` | machine-readable evidence-contract schema | `integrated_ce19` | CE20 | `high` |
| `src/codeprobe_calibration_admission.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19` | CE20 | `high` |
| `src/codeprobe_engine/README.md` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/__init__.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/api.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/diagnostic_outputs.py` | `—` | `src` | diagnostic destination admission | `added_I04` | I04 | `high` |
| `src/codeprobe_engine/metrics.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/paths.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/process_control.py` | `—` | `src` | maintainer engine support module | `added_audit_phase4c` | audit-4c | `high` |
| `src/codeprobe_engine/project_io.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/release.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_engine/server.py` | `—` | `src` | maintainer engine support module | `added_audit_phase4c` | audit-4c | `high` |
| `src/codeprobe_engine/version.py` | `—` | `src` | maintainer engine support module | `keep` | current | `high` |
| `src/codeprobe_interpretation.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19_patched` | CE20 | `high` |
| `src/codeprobe_measurement_kernel.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19` | CE20 | `high` |
| `src/codeprobe_report_cli.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19` | CE20 | `high` |
| `src/codeprobe_reporting.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19` | CE20 | `high` |
| `src/codeprobe_review_contract.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19` | CE20 | `high` |
| `src/codeprobe_runtime.py` | `src/engine.py` | `src` | browser-compatible analysis runtime | `completed_migration` | current | `high` |
| `src/codeprobe_s01_observation_adapter.py` | `—` | `src` | bounded evidence-contract implementation module | `integrated_ce19` | CE20 | `high` |
| `tests/s05/view_oracle.py` | `—` | `tests` | support-only evidence-contract view oracle | `integrated_ce19` | CE20 | `high` |
| `tests/test_app_runtime_tools_paths.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_browser_security.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_calibration_profiles.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_calibration_workflow.py` | `—` | `tests` | calibration workflow and document contract regressions | `added_I13` | I13 | `medium` |
| `tests/test_contract_repairs.py` | `—` | `tests` | native replay, provenance and publication regressions | `added_audit_phase4h` | audit-4h | `high` |
| `tests/test_coverage_policy.py` | `—` | `tests` | regression test | `added_audit_phase4d` | audit-4d | `high` |
| `tests/test_dependency_boundary.py` | `—` | `tests` | regression test | `added_audit_phase4` | audit-4 | `high` |
| `tests/test_documentation_resources.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_dynamic_ui_review.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_false_positive_controls.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_final_naming_release.py` | `—` | `tests` | regression test | `added_phase13` | 13 | `medium` |
| `tests/test_final_naming_stability.py` | `—` | `tests` | regression test | `added_phase13` | 13 | `medium` |
| `tests/test_final_package_audit.py` | `—` | `tests` | regression test | `added_phase13` | 13 | `medium` |
| `tests/test_final_release_audit.py` | `—` | `tests` | regression test | `added_phase13` | 13 | `medium` |
| `tests/test_github_zip_roots.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_institutional_packaging.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_javascript_parser.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_local_server.py` | `—` | `tests` | regression test | `added_audit_phase4c` | audit-4c | `high` |
| `tests/test_process_control.py` | `—` | `tests` | regression test | `added_audit_phase4c` | audit-4c | `high` |
| `tests/test_project_mode.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_pyodide_fixture.py` | `—` | `tests` | regression test | `added_audit_phase4f1` | audit-4f1 | `high` |
| `tests/test_pyodide_provenance.py` | `—` | `tests` | regression test | `added_audit_phase4c` | audit-4c | `high` |
| `tests/test_reference_integrity.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_release_crash_driver.py` | `—` | `tests` | automated regression test | `added_audit_phase4f2` | audit-4f2 | `high` |
| `tests/test_release_integrity.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_release_metadata.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_release_recovery.py` | `—` | `tests` | automated regression test | `added_audit_phase4f2` | audit-4f2 | `high` |
| `tests/test_release_reproducibility.py` | `—` | `tests` | regression test | `added_audit_phase4` | audit-4 | `high` |
| `tests/test_report_schema.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_runtime_smoke.py` | `—` | `tests` | regression test | `keep` | current | `high` |
| `tests/test_worker_contract.py` | `—` | `tests` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `high` |
| `tools/README.md` | `—` | `tools` | command-line or release utility | `keep` | current | `high` |
| `tools/analyze_project.py` | `src/analyze_project.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/audit_institutional_pack.py` | `src/institutional_audit.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/build_release.py` | `src/build_release.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/calibrate_corpus.py` | `src/calibrate_corpus.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/calibrate_profile.py` | `src/calibrate_profile.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/check_browser_accessibility.js` | `—` | `tools` | command-line or release utility | `added_audit_phase4b` | audit-4b | `high` |
| `tools/check_browser_functional.js` | `—` | `tools` | command-line or release utility | `added_audit_phase4f1` | audit-4f1 | `high` |
| `tools/check_coverage.py` | `—` | `tools` | command-line or release utility | `added_audit_phase4d` | audit-4d | `high` |
| `tools/check_dependency_boundary.py` | `—` | `tools` | command-line or release utility | `added_audit_phase4` | audit-4 | `high` |
| `tools/check_file_references.py` | `tools/check_references.py` | `tools` | command-line or release utility | `completed_phase13` | 13 | `high` |
| `tools/check_input_contracts.js` | `—` | `tools` | deterministic browser input and export regressions | `added_audit_phase4h` | audit-4h | `high` |
| `tools/check_naming.py` | `—` | `tools` | command-line or release utility | `added_phase13` | 13 | `high` |
| `tools/check_pyodide_provenance.py` | `—` | `tools` | command-line or release utility | `added_audit_phase4c` | audit-4c | `high` |
| `tools/check_release.py` | `src/release_check.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/check_release_reproducibility.py` | `—` | `tools` | command-line or release utility | `added_audit_phase4` | audit-4 | `high` |
| `tools/check_worker_protocol.js` | `—` | `tools` | worker resilience, export privacy or governance metadata | `added_audit_phase4f3` | audit-4f3 | `high` |
| `tools/codeprobe_s05.py` | `—` | `tools` | bounded evidence-contract command-line entry point | `integrated_ce19` | CE20 | `high` |
| `tools/compare_releases.py` | `—` | `tools` | command-line or release utility | `keep` | current | `high` |
| `tools/coverage-policy.json` | `—` | `tools` | command-line or release utility | `added_audit_phase4d` | audit-4d | `high` |
| `tools/final_audit.py` | `—` | `tools` | command-line or release utility | `added_phase13` | 13 | `high` |
| `tools/prepare_pyodide_fixture.py` | `—` | `tools` | command-line or release utility | `added_audit_phase4f1` | audit-4f1 | `high` |
| `tools/run_local_server.py` | `src/run_local_server.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |
| `tools/validate_release.py` | `src/validate_release.py` | `tools` | command-line or release utility | `completed_migration` | current | `high` |

## Interpretation

The catalogue proves path membership and migration history. It does not establish scientific validity, release authority, third-party redistribution rights or completion of held CE09/CE11 evidence packages.
