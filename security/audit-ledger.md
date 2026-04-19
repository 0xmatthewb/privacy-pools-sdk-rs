# Audit Ledger

This ledger tracks the current audit status of the SDK, internal assurance
reviews, open security findings, and explicitly accepted residual risks.

## Audit Status Summary

- External audits completed: none
- Internal assurance architecture review:
  2026-04-18 uplift pass across PR, nightly, release, mobile, and fuzz lanes
- Current release-trust model:
  verified GitHub artifact attestations, packaged-artifact validation, signed
  manifest binding, SBOMs, and multi-runtime evidence

## External Audits

No external cryptographic or application security audit has completed for this
repository yet.

When an external audit is commissioned, record:

- auditor
- scope
- reviewed commit/tag
- findings summary
- report link or internal storage location
- remediation status

Audit preparation requirements are tracked in
[`security/external-audit-readiness.md`](./external-audit-readiness.md).

## Internal Reviews

| Date | Owner | Scope | Outcome | Follow-Up |
| --- | --- | --- | --- | --- |
| 2026-04-18 | SDK maintainers | Assurance architecture, release evidence, browser/mobile parity, CI shape | Strengthened | Keep dedicated fuzz lane, land stateful wrapper parity, commission external audit |

## Open Security Findings

| Severity | Surface | Finding | Owner | Target Resolution |
| --- | --- | --- | --- | --- |
| high | external assurance | No external cryptographic/application security audit completed yet | maintainers | Before mainnet production promotion |
| medium | fuzz depth | Dedicated fuzz lane exists, but corpus and targets still emphasize parsers/wire boundaries more than long-lived session flows | maintainers | Add session/handle lifecycle targets |

## Resolved Findings

| Date | Surface | Resolution |
| --- | --- | --- |
| 2026-04-18 | CI architecture | Split Rust PR lane into parallel groups with one aggregate required gate |
| 2026-04-18 | browser assurance | Restored signed-manifest-backed prove/verify happy path and moved exact browser artifact identity to canonical release packaging |
| 2026-04-18 | release provenance | Replaced metadata-only provenance with saved verified-attestation evidence validated offline in release assurance |
| 2026-04-18 | mobile evidence | Lifted mobile release evidence to four first-class surfaces across native and React Native |

## Accepted Residual Risks

| Risk | Rationale | Owner | Review Date | Exit Condition |
| --- | --- | --- | --- | --- |
| No external audit yet | Pre-public SDK, still iterating on assurance architecture | maintainers | 2026-04-18 | External audit commissioned and findings addressed |
| Fuzz not on every PR | Keeping PR deterministic and tractable is more valuable than embedding long-running fuzz in merge gates | maintainers | 2026-04-18 | If PR lanes can absorb targeted short fuzz smoke without hiding attribution |

## Coverage Notes

- Browser and mobile release evidence are stronger than typical early-stage SDKs.
- Release evidence is already one of the strongest parts of the repository.
- The next quality frontier is external audit maturity and continued deepening
  of long-lived fuzz/session coverage rather than adding more opaque CI.
