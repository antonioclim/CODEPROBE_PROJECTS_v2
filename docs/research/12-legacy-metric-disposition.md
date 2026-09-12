# Legacy metric disposition

S02 adjudicates every metric configured in the v2.2.0 runtime. A metric is not retained merely because it is computable or historically weighted. The disposition catalogue records one of retain, revise, split, defer or retire, together with replacement observation identifiers, measurement problems and unresolved validity questions.

All legacy weights, thresholds and provenance interpretations are explicitly set to `false`. Raw observations may be retained when their entity, attribute, scale, unit and counting rule can be specified. Composite labels and hardware-like names without an adequate measurement relation are revised, deferred or retired.

The CSV and JSON forms are semantically equivalent; the CSV is optimised for audit and the JSON for automated checks.
