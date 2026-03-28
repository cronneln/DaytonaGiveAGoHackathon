# Test Package Classification

## Malicious / Suspicious

- `package-malicious-fail.json`
  - Contains known historical malicious chain (`event-stream@3.3.6` + `flatmap-stream@0.1.1`)
  - Contains typo-squat style names (`lodas`, `expresss`)
  - Expected outcome: should be flagged high risk (or at least suspicious)

- `package-mixed-maybe.json`
  - Mix of common packages and one suspicious dependency (`event-stream@3.3.6`)
  - Expected outcome: mixed results; at least one package should be flagged

## Not Malicious (Baseline)

- `package-safe-pass.json`
  - Popular mainstream packages only
  - Expected outcome: mostly safe/low risk

## Notes

- Final severity can vary depending on sandbox runtime signals and LLM synthesis.
- Sandbox infrastructure errors (quota/limits) are not package-malicious behavior.
