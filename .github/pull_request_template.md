## What & why
Implements: <!-- FR-x / NFR-x / ADR-xxxx -->
Closes: #<!-- issue number -->

## Change-control tier
<!-- 0–3. Tier ≥2 requires the security checklist below. -->

## Evidence
- [ ] Behavior verified by observation, not just "it compiles"
- [ ] Tests written first, at agreed seams

## Security checklist (tier ≥ 2)
- [ ] Escape-attempt tests pass for every control claimed (NFR-5)
- [ ] Fails closed on error/timeout (FR-9)
- [ ] Child cannot touch the log / decision path (ADR-0002)
- [ ] Every `unsafe` has a `// SAFETY:` note

## Docs
- [ ] Spec/ADR/CONTEXT.md updated if this changed a decision or a term
