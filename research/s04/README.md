# S04 — Evidence-bounded interpretation and calibration design

Author and maintainer: Antonio Clim.

S04 adds a native interpretation capsule to the exact S03 source. It does not change the public v2.2.0 application, the measurement kernel, the S01 adapter or their specification versions. The baseline is `5e8036489a830afcf557e8accded80c85eea01bc`; the complete prospective acceptance contract is committed at `fd883a13c705fdddae8814f2759027afb92bd5f5`. The latter is the required direct parent of the implementation candidate.

## What is implemented

Seven candidate dimensions remain visible. Only per-callable structural observations and parser-scope disclosures receive operative interpretations. The other five dimensions explicitly withhold interpretation. In particular, naming counts cannot establish clarity, documentation counts cannot establish implementation alignment and exception counts cannot establish defensive correctness. Even the structural dimension does not estimate project-level dispersion or establish construct validity.

Three versioned profiles are supplied: `observation-only`, `structural-review` and `structural-review-conservative`. The latter two use illustrative policy thresholds, not learned or empirically calibrated cut-offs. Profiles must be selected explicitly with their canonical SHA-256. A profile change is visible and cannot silently alter a transported report.

Every rule remains separate. Evidence from one rule or dimension cannot compensate for another, and no overall score is produced. Optional inspection opportunities are reversible suggestions, not defect determinations, grades or sanctions. An absence of rule triggers is not evidence of good quality.

## Interface

With `src` on the Python import path:

```python
from codeprobe_interpretation import available_profiles, interpret_bytes, verify_capsule

# Select a profile explicitly and retain this digest in the calling application.
selected = next(p for p in available_profiles() if p['profile_id'] == 'structural-review')
source = b'def example(x):\n    return x\n'
report = interpret_bytes(
    source, language='python', profile_id=selected['profile_id'],
    profile_sha256=selected['sha256'], task_family='source_inspection', path='example.py'
)
verify_capsule(
    report, source, language='python', profile_id=selected['profile_id'],
    profile_sha256=selected['sha256'], task_family='source_inspection', path='example.py'
)
```

This is a new capsule, **not** a drop-in S01 v3 report or a completed browser/CLI integration. `INTERPRETATION_CONTRACT.md` defines the admitted API and the S05 integration boundary. A caller must not relabel the capsule as a validated S01 report. No supplied source fixture is executed.

## Evidence and reproduction

From the exact committed checkout, run `python -I -S -B tools/check_s04_interpretation.py --output <directory-outside-source>`. It verifies additive-only changes and the prospective lock, runs the S01/S02 checks, the 19 S03 corrective regressions, the S04 unit tests and the finite interpretation experiment. It does not rerun the historical S03 2,000-case experiment merely for reassurance.

The finite experiment retains 504 analytic boundary cases, 369 interpretation executions and 306 transformation comparisons over 21 base source cases and three profiles. These are dependent synthetic tests, not independent observations or a calibration dataset. Full capsules, input bytes, projections, discrepancies and logs are retained. Two development failures were observed and corrected: an unenforced JSON-depth limit and an inaccurate dimension-level uncertainty qualification. The phase audit retains their negative logs and dispositions.

The checker admits one exact-candidate four-cell CI matrix, matching the declared S03 native runtime cells. The comparison uses actual input-manifest and decision-projection bytes, not just a generic success status. Rich capsule digests are expected to differ across runtimes because runtime identity is retained. The comparison projection is not an authentication API.

## Absences and residual boundaries

Empirical calibration, educational utility, construct validity and fairness remain unestablished. `CALIBRATION_PLAN.md` is a prospective design with an executable split-manifest admission interface, not an approved human-study protocol or a completed evaluation. No dataset, participant, approval, external preregistration, article, release or Zenodo object is created.

S03-F007 and S03-F008 are addressed at the new native boundary through source-qualified condition migration and separated build identity. ME-008 and the additional ME-013 collision are not silently repurposed. Historical bytes and protocols remain unchanged. Deployment-wide migration belongs to S05. The historical 111-entry ledger remains 80 closed and 31 open; A01-F003 is still open. A finite Python exception boundary is not universal process containment.
