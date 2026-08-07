# Zero-Type Agent Zero-Authority Profile

> **Maximum capability, zero ambient authority.**
>
> A capable AI agent begins with no implicit authority. Every external effect must be explicitly granted, risk-classified, jointly authorized where necessary, bound to a verified execution context, independently recorded, continuously revalidated, closed after use, sealed into tamper-evident evidence, and independently assessable.

---

## Version

**v0.5.0 — Tamper-Evident Evidence, Execution Closure, and Independent Conformance**

Version 0.5 completes the first end-to-end Zero-Type authority lifecycle.

The profile is designed to prevent an AI agent, operator, or runtime from merely claiming that an execution was safe. Instead, the entire lifecycle must produce reproducible evidence showing:

* how authority was created;
* who authorized it;
* where and under what conditions it could be exercised;
* what actually happened during execution;
* whether revocation or containment occurred;
* whether execution was fully closed;
* whether authority returned to zero;
* whether an independent verifier can reproduce the same conclusion.

---

## Core principle

> **Unverifiable authority is no authority.**

The existence of a Grant, approval, Runtime Trace, or Zeroization Record alone does not establish conformance.

A conformant lifecycle requires that authority be:

1. explicitly created;
2. bounded by scope and risk;
3. tied to an authorized execution context;
4. continuously revalidated;
5. independently recorded;
6. revoked or exhausted when appropriate;
7. closed against replay and residual effects;
8. sealed into tamper-evident evidence;
9. independently reassessed.

Missing evidence never defaults to safety.

---

## Security evolution

```text
v0.1  Zero authority by default
       ↓
v0.2  Delegation, renewal, continuity,
      and cascade revocation
       ↓
v0.3  Risk tiers, separated approval roles,
      and irreversible commitment
       ↓
v0.4  Context-bound execution,
      tool attestation,
      data-boundary control,
      and fail-closed runtime interlocks
       ↓
v0.5  Execution closure,
      incident containment,
      tamper-evident evidence chains,
      and independently reproducible conformance
```

The development path can be summarized as:

```text
No ambient authority
        ↓
No silent persistence
        ↓
No unilateral critical authority
        ↓
No portable authority
        ↓
No unverifiable authority
```

---

# Zero-Type authority lifecycle

## v0.5 execution and evidence path

```text
Zero State
    ↓
Capability Grant
    ↓
Risk Classification Assessment
    ↓
Authorization Quorum Receipt
    ↓
Irreversible Action Commitment
    │
    │ when required
    ↓
Execution Context Attestation
    ↓
Tool Identity Attestation
    ↓
Data Egress Authorization
    │
    │ when outbound data effects exist
    ↓
Runtime Interlock Record
    ↓
Action Gate Receipt
    ↓
Execution Continuity Receipt(s)
    ↓
Runtime Trace Record
    ↓
Incident Containment Receipt
    │
    │ when anomaly or revocation occurs
    ↓
Capability Revocation Record
    and/or
Emergency Zeroization Record
    ↓
Execution Closure Receipt
    ↓
Authority Evidence Chain
    ↓
Conformance Assessment Record
    ↓
Zero State
```

The profile therefore distinguishes between:

```text
authority creation
authority exercise
authority observation
authority revocation
authority closure
authority proof
```

An execution is not complete merely because the external action finished.

The authority lifecycle itself must also finish.

---

# New in v0.5

## 1. Incident Containment Receipt

The **Incident Containment Receipt** records the fail-closed response to a detected security or authority anomaly.

Examples include:

* revocation during execution;
* evidence tampering;
* execution-context drift;
* tool substitution;
* unauthorized data egress;
* token replay;
* unexpected credential use;
* loss of a required runtime monitor.

A successfully contained incident confirms that required defensive actions were performed.

Typical containment actions include:

```text
execution suspended
execution tokens invalidated
network access blocked
credentials quarantined
execution context isolated
evidence preserved
revocation initiated
zeroization initiated or completed
```

The executing agent cannot be the sole detector or sole authority for declaring its own incident contained.

---

## 2. Execution Closure Receipt

The **Execution Closure Receipt** formally closes an issued execution token after the Runtime Trace has completed.

It proves that:

* the token was consumed exactly once;
* its nonce was retired;
* replay was blocked;
* no external side effect remains pending;
* external outputs were reconciled;
* data-egress events were reconciled;
* credentials expired or were destroyed;
* child tasks were terminated or closed;
* the Runtime Recorder finalized its evidence.

Example closure semantics:

```text
execution token issued
        ↓
token used once
        ↓
nonce retired
        ↓
replay blocked
        ↓
pending effects = 0
        ↓
active tokens = 0
        ↓
execution closed
```

A zeroized execution must also reference the corresponding:

* Emergency Zeroization Record; and
* final Zero State Record.

Execution completion and authority closure are therefore separate concepts.

---

## 3. Authority Evidence Chain

The **Authority Evidence Chain** seals security-critical lifecycle records into a tamper-evident append-only digest chain.

Each entry contains:

```text
sequence
record_type
record_id
record_digest
previous_entry_digest
observed_at
entry_digest
```

The reference validator uses deterministic sorted JSON with UTF-8 encoding and compact separators.

Conceptually:

```text
record_digest =
SHA-256(
  canonical JSON of referenced record
)
```

and:

```text
entry_digest =
SHA-256(
  canonical JSON of:
    sequence,
    record_type,
    record_id,
    record_digest,
    previous_entry_digest,
    observed_at
)
```

The first entry points to:

```text
genesis
```

Every later entry points to the previous `entry_digest`.

The final entry digest becomes:

```text
chain_root
```

Therefore:

```text
referenced record changes
        ↓
record_digest changes
        ↓
entry_digest changes
        ↓
later links change
        ↓
chain_root changes
```

A silent modification to a sealed lifecycle record invalidates the expected chain root.

The evidence chain must be recorded and signed by identities independent from the executing agent.

The reference validator verifies:

* digest consistency;
* chain continuity;
* identity bindings;
* ordering;
* lifecycle completeness.

Verification of actual detached signature bytes, hardware-backed keys, certificate trust, or external PKI remains deployment-specific and is referenced through `signature_ref`.

---

## 4. Conformance Assessment Record

The **Conformance Assessment Record** allows an independent verifier to reproduce the safety conclusion from a sealed Authority Evidence Chain.

A result of:

```text
conformant
```

requires all required checks to succeed.

These include:

* JSON Schemas are valid;
* primary identifiers are unique;
* record digests match;
* chain links are valid;
* evidence timestamps are monotonic;
* lifecycle ordering is valid;
* authority bindings are complete;
* authorization precedes action;
* execution tokens are single-use;
* revocation is enforced;
* zeroization references are correct;
* execution closure is complete;
* evidence was generated independently from the agent;
* the assessment references the correct chain root.

The executing agent cannot assess its own conformance.

---

# Core v0.5 invariants

## Evidence completeness

At minimum:

```text
Capability Grant
    <
Action Gate Receipt
    <
Runtime Trace Record
    <
Execution Closure Receipt
    <
Authority Evidence Chain
    <
Conformance Assessment Record
```

Every sealed execution lifecycle must contain at least:

* Capability Grant;
* Action Gate Receipt;
* Runtime Trace Record;
* Execution Closure Receipt.

Additional records become mandatory when the lifecycle requires them.

Examples:

```text
critical action
→ Risk Classification
→ Authorization Quorum
→ Irreversible Commitment

outbound data
→ Data Egress Authorization

revocation
→ Capability Revocation Record

emergency stop
→ Emergency Zeroization Record

runtime anomaly
→ Incident Containment Receipt
```

---

## Digest integrity

```text
record
  ↓
record_digest
  ↓
entry_digest
  ↓
next entry
  ↓
...
  ↓
chain_root
```

Any unauthorized mutation in the sealed record set invalidates the chain.

---

## Token finality

```text
execution token issued
        ↓
consumed exactly once
        ↓
nonce retired
        ↓
replay rejected
        ↓
pending effects resolved
        ↓
active token set empty
```

An execution is not considered closed while a reusable token or unresolved external effect remains.

---

## Independent verification

The intended separation is:

```text
executing agent
    ≠
evidence recorder
    ≠
chain signer
    ≠
conformance verifier
```

These functions may exist within the same organization.

However, they must use distinct identities and sufficiently independent enforcement boundaries to prevent agent self-attestation from becoming authoritative evidence.

---

## Fail-closed evidence handling

```text
tamper signal
missing record
broken chain
unknown signature binding
incomplete closure
invalid authority linkage
        ↓
No conformant result
        ↓
Quarantine
Contain
Zeroize
or
Mark indeterminate
```

Absence of evidence is never interpreted as evidence of safety.

---

# Complete record set

Version 0.5 defines twenty record types.

1. Zero State Record
2. Capability Grant
3. Capability Delegation Receipt
4. Capability Renewal Record
5. Capability Revocation Record
6. Risk Classification Assessment
7. Authorization Quorum Receipt
8. Irreversible Action Commitment
9. Execution Context Attestation
10. Tool Identity Attestation
11. Data Egress Authorization
12. Runtime Interlock Record
13. Action Gate Receipt
14. Execution Continuity Receipt
15. Runtime Trace Record
16. Emergency Zeroization Record
17. Incident Containment Receipt
18. Execution Closure Receipt
19. Authority Evidence Chain
20. Conformance Assessment Record

---

# Security properties by version

## v0.1 — Zero Authority

The agent begins without implicit external authority.

```text
Maximum capability
        +
Zero ambient authority
```

External action requires explicit authorization.

---

## v0.2 — Authority Lifetime

Authority cannot silently persist.

v0.2 introduced:

* constrained delegation;
* explicit renewal;
* grant epochs;
* revocation epochs;
* short-lived execution tokens;
* continuous execution checks;
* cascade revocation.

The rule became:

> Permission to start is not permission to continue forever.

---

## v0.3 — Separated Critical Authority

Critical authority cannot be created by a single actor.

v0.3 introduced:

* risk tiers;
* maximum risk ceilings;
* authorization quorum;
* role separation;
* cooling-off periods;
* irreversible-action commitments.

The rule became:

> No single key may create critical authority.

---

## v0.4 — Context-Bound Authority

Authority cannot simply be copied into another execution environment.

v0.4 introduced:

* execution-context attestation;
* tool-identity attestation;
* independent data-egress authorization;
* runtime interlocks;
* context-drift detection;
* fail-closed monitor handling.

The rule became:

> Authority is not portable.

---

## v0.5 — Verifiable Authority

Authority is not considered safely exercised merely because the system claims so.

v0.5 adds:

* execution closure;
* token finality;
* incident containment;
* tamper-evident evidence chains;
* independent conformance assessment.

The rule becomes:

> Unverifiable authority is no authority.

---

# Validator coverage

The reference validator performs:

```text
JSON Schema validation
        +
semantic validation
        +
cross-record validation
        +
evidence-chain validation
```

Version 0.5 additionally rejects:

* modified record content after evidence sealing;
* broken `previous_entry_digest` links;
* incorrect record digests;
* incorrect entry digests;
* incorrect chain roots;
* duplicate evidence records;
* duplicate primary identifiers;
* non-monotonic evidence timestamps;
* incomplete mandatory evidence sets;
* evidence recorded by the executing agent;
* evidence signed by the executing agent;
* reused execution tokens;
* unretired nonces;
* pending external effects at closure;
* zeroized closures without corresponding zeroization evidence;
* zeroized closures without final Zero State evidence;
* fail-open incident containment;
* missing revocation references;
* missing zeroization references;
* agent self-assessment;
* false `conformant` conclusions;
* assessments bound to another chain root.

All v0.1 through v0.4 invariants remain enforced.

---

# Validation

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

Run:

```bash
python scripts/validate_examples.py
```

Expected final line:

```text
All pass examples succeeded and all fail examples were rejected.
```

The v0.5 validation suite contains:

```text
20 JSON Schemas
29 valid examples
34 deliberately invalid examples
```

---

# Repository layout

```text
.github/
└── workflows/
    └── validate.yml

schemas/
├── zero-state-record.schema.json
├── capability-grant.schema.json
├── capability-delegation-receipt.schema.json
├── capability-renewal-record.schema.json
├── capability-revocation-record.schema.json
├── risk-classification-assessment.schema.json
├── authorization-quorum-receipt.schema.json
├── irreversible-action-commitment.schema.json
├── execution-context-attestation.schema.json
├── tool-identity-attestation.schema.json
├── data-egress-authorization.schema.json
├── runtime-interlock-record.schema.json
├── action-gate-receipt.schema.json
├── execution-continuity-receipt.schema.json
├── runtime-trace-record.schema.json
├── emergency-zeroization-record.schema.json
├── incident-containment-receipt.schema.json
├── execution-closure-receipt.schema.json
├── authority-evidence-chain.schema.json
└── conformance-assessment-record.schema.json

examples/
├── pass/
└── fail/

scripts/
└── validate_examples.py

README.md
CHANGELOG.md
MIGRATION.md
MANIFEST.txt
requirements.txt
LICENSE
```

---

# Scope and limitations

This repository defines a portable authority-record profile and reference validator.

It does **not** provide a complete production implementation of:

* policy engines;
* sandboxes;
* credential brokers;
* hardware security modules;
* cryptographic key-management services;
* transparency logs;
* remote-attestation infrastructure;
* trusted timestamping services;
* production incident-response systems.

Production deployments should additionally provide:

* standards-based canonicalization where cross-language byte identity is required;
* verified detached signatures;
* certificate or key-trust infrastructure;
* append-only or transparency-backed evidence storage;
* trusted clocks and timestamping;
* durable nonce-consumption storage;
* durable execution-token state;
* independent audit infrastructure;
* independent incident-response operators;
* hardware- or platform-backed remote attestation where appropriate.

The reference validator verifies the logical bindings required by this profile.

It does not claim to replace deployment-specific cryptographic or infrastructure trust systems.

---

# Design statement

```text
A model may discover a path.

A Grant may authorize one step.

A verified runtime may execute that step.

But only a closed,
tamper-evident,
and independently verifiable evidence chain

may prove that the authority existed,
remained bounded,
was exercised only as permitted,
and finally returned to zero.
```

---

## Zero-Type principle

```text
Capability may expand.

Roles may change.

Tools may evolve.

But authority does not arise
merely because an intelligence
is capable of exercising it.

Authority begins at zero,
exists only within explicit bounds,
and returns to zero
when those bounds expire.
```
