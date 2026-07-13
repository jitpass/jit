# Security reviews & audits

jit handles secrets, so we review the code for vulnerabilities on a cadence and
publish the results here, including the honest limits, not just the clean parts.
This folder is the running record.

To **report** a vulnerability, see [SECURITY.md](../SECURITY.md) (private disclosure).
For the full threat model (everything jit deliberately does *not* defend against),
see [RFC.md §2](../RFC.md).

## Published reviews

| Date | Type | Report |
|------|------|--------|
| 2026-07 | Internal review: AI-assisted (Claude Opus 4.8) + on-host verification | [2026-07-review.md](./2026-07-review.md) |

An independent third-party audit, if and when one happens, will be listed here and
labeled as such; internal reviews are not a substitute for one.
