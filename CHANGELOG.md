# Changelog

All notable changes to the **Zero-Type Agent Zero-Authority Profile** are documented in this file.

The project follows a progressive security model:

```text
v0.1  Zero authority
v0.2  Authority lifetime
v0.3  Separated critical authority
v0.4  Context-bound authority
v0.5  Verifiable authority
```

---

## [0.5.0] - 2026-08-06

### Added

* Added **Incident Containment Receipt** for fail-closed handling of runtime anomalies, revocation, evidence tampering, context drift, tool substitution, data-egress violations, and execution replay.
* Added **Execution Closure Receipt** for formal termination of execution authority.
* Added single-use execution-token verification.
* Added nonce retirement and replay-prevention requirements.
* Added reconciliation of pending external effects before execution closure.
* Added verification that credentials expire or are destroyed before closure.
* Added verification that child tasks are closed before authority finalization.
* Added **Authority Evidence Chain** for tamper-evident lifecycle sealing.
* Added deterministic record digests.
* Added chained entry digests using `previous_entry_digest`.
* Added final `chain_root` calculation.
* Added independent evidence-recorder and chain-signer identity requirements.
* Added detached `signature_ref` bindings for deployment-specific signature verification.
* Added **Conformance Assessment Record** for independent and reproducible evaluation of the complete authority lifecycle.
* Added valid lifecycle examples connecting:

  * revocation;
  * incident containment;
  * emergency zeroization;
  * execution closure;
  * evidence sealing;
  * independent conformance assessment.
* Added invalid examples covering:

  * record tampering;
  * broken evidence-chain links;
  * non-monotonic evidence ordering;
  * agent self-signing;
  * agent self-assessment;
  * execution-token replay;
  * unretired nonces;
  * pending side effects;
  * incomplete execution closure;
  * missing zeroization evidence;
  * fail-open incident containment;
  * chain-root mismatch.

### Validator

* Added deterministic SHA-256 digest generation over sorted compact JSON representations.
* Recomputes every referenced record digest.
* Recomputes every evidence entry digest.
* Validates `previous_entry_digest` linkage.
* Validates sequence continuity.
* Validates monotonic evidence timestamps.
* Validates the final `chain_root`.
* Requires mandatory Grant, Gate, Trace, and Closure evidence in every sealed execution lifecycle.
* Rejects evidence recorded by the executing agent.
* Rejects evidence signed by the executing agent.
* Validates independent identity bindings for:

  * evidence recording;
  * chain signing;
  * conformance verification.
* Validates single-use token consumption.
* Validates nonce retirement.
* Rejects token replay.
* Requires zero pending external effects before closure.
* Verifies zeroized closures against:

  * Emergency Zeroization Record;
  * final Zero State Record.
* Verifies Incident Containment Receipt references to affected:

  * Capability Grants;
  * execution tokens;
  * execution contexts;
  * tools;
  * Runtime Trace Records;
  * revocations;
  * zeroization records.
* Rejects agent self-assessment.
* Rejects false `conformant` conclusions.
* Rejects Conformance Assessment Records bound to another evidence-chain root.
* Preserves all semantic and cross-record invariants introduced in v0.1 through v0.4.

### Security model

* Introduced the rule:

> **Unverifiable authority is no authority.**

* Missing evidence never defaults to a safe conclusion.
* An execution token is not considered complete until it has:

  * been consumed exactly once;
  * had its nonce retired;
  * become non-replayable;
  * been formally closed.
* External effects must be reconciled before authority closure.
* Evidence generation is separated from execution.
* Evidence signing is separated from the executing agent.
* Conformance assessment is separated from the executing agent.
* Any content mutation after evidence sealing invalidates the expected chain root.
* Authority lifecycle completion now requires proof of closure, not merely proof of action completion.

---

## [0.4.0] - 2026-08-05

### Added

* Added **Execution Context Attestation** for binding authority to a specific runtime environment.
* Added runtime-image digest bindings.
* Added execution-code digest bindings.
* Added isolation-policy bindings.
* Added network-policy bindings.
* Added credential-broker bindings.
* Added Runtime Recorder bindings.
* Added Policy Engine bindings.
* Added Grant-epoch and revocation-epoch bindings to execution contexts.
* Added **Tool Identity Attestation** for:

  * tool binary digest;
  * manifest digest;
  * supply-chain verification;
  * side-effect declarations;
  * network destinations;
  * allowed execution contexts.
* Added **Data Egress Authorization** for:

  * data classifications;
  * content digests;
  * destinations;
  * byte limits;
  * retention constraints;
  * required transformations;
  * secret removal;
  * PII handling.
* Added **Runtime Interlock Record** with fail-closed health checks for:

  * Policy Engine;
  * Runtime Recorder;
  * Network Guard;
  * Credential Broker;
  * Tool Guard;
  * Egress Guard.
* Added execution-context references to Action Gate Receipts.
* Added tool-identity references to Action Gate Receipts.
* Added runtime-interlock references to Action Gate Receipts.
* Added optional egress-authorization references to Action Gate Receipts.
* Added continuing context, tool, interlock, and egress validity checks to Execution Continuity Receipts.
* Added context-drift observations to Runtime Trace Records.
* Added tool-substitution observations to Runtime Trace Records.
* Added egress-violation observations to Runtime Trace Records.
* Added pass scenarios for:

  * low-risk read-only execution;
  * critical public-release execution under context-bound authority.
* Added fail scenarios for:

  * execution-context replay;
  * tool substitution;
  * ambient credential assumptions;
  * unauthorized data egress;
  * fail-open runtime interlocks;
  * execution continuation after context expiry.

### Validator

* Validates that execution contexts match:

  * Grant owner;
  * authority domain;
  * effective Grant epoch;
  * revocation epoch.
* Rejects agent self-attestation.
* Rejects execution contexts that outlive their effective Grant.
* Validates tool manifests.
* Validates allowed execution contexts.
* Validates tool action types.
* Validates declared side effects.
* Validates trusted tool-validity windows.
* Rejects tool substitution even when the logical tool name remains unchanged.
* Validates authorized data classes.
* Validates egress targets.
* Validates network destinations.
* Validates mandatory transformations.
* Validates byte limits.
* Validates execution-context bindings for egress.
* Validates tool bindings for egress.
* Requires Data Egress Authorization when a tool declares:

  * outbound network writes;
  * public-output side effects.
* Enforces fail-closed Runtime Interlocks.
* Rejects `permit` if any mandatory runtime monitor is unhealthy.
* Revalidates execution context, tool identity, Runtime Interlock, and egress authorization during execution continuity.
* Verifies Runtime Trace bindings to the original Action Gate.
* Requires safe termination after observed context drift, tool substitution, or egress violations.

### Security model

* Introduced the rule:

> **Authority is not portable.**

* A valid Grant cannot automatically be transferred into another runtime.
* Tool authority is bound to verified tool identity rather than tool name alone.
* Data movement is independently authorized from action authorization.
* Runtime monitor failure removes permission rather than weakening enforcement.
* A valid Grant outside its verified execution context is treated as no authority.

---

## [0.3.0] - 2026-08-04

### Added

* Added `maximum_risk_tier` to Capability Grants.
* Added delegated risk ceilings.
* Added non-widening risk checks during delegation.
* Added **Risk Classification Assessment**.
* Added **Authorization Quorum Receipt**.
* Added separated approval roles.
* Added minimum approval counts for elevated-risk actions.
* Added conflict-of-interest checks.
* Added veto handling.
* Added **Irreversible Action Commitment**.
* Added cooling-off periods.
* Added final human confirmation for irreversible operations.
* Added risk bindings to Action Gate Receipts.
* Added quorum bindings to Action Gate Receipts.
* Added irreversible-commitment bindings to Action Gate Receipts.
* Added continuing validation of quorum state.
* Added continuing validation of commitment state.
* Added complete pass scenarios for:

  * low-risk execution;
  * critical-risk execution.
* Added fail examples for:

  * risk escalation;
  * agent self-approval;
  * missing mandatory approval roles;
  * cooling-off bypass;
  * missing irreversible commitment.

### Validator

* Validates risk-tier ceilings against Capability Grants.
* Rejects risk classifications above the authorized ceiling.
* Enforces high-risk approval requirements.
* Enforces critical-risk approval requirements.
* Rejects agent self-approval.
* Rejects conflicting approvers.
* Rejects vetoed approval sets.
* Rejects duplicate approvers.
* Rejects expired approvals.
* Rejects action-digest mismatch between approvers.
* Validates Authorization Quorum policy against risk-required controls.
* Validates irreversible-commitment timing.
* Validates cooling-off periods.
* Requires critical Action Gates to bind a valid commitment.
* Rechecks Quorum validity during Execution Continuity.
* Rechecks Commitment validity during Execution Continuity.
* Converts duplicate primary identifiers into a controlled fatal validation result rather than an uncaught traceback.
* Builds the cross-record registry only from schema-valid pass examples.

### Security model

* Introduced the rule:

> **No single key may create critical authority.**

* Risk authority is explicitly bounded by the Capability Grant.
* Authorization strength increases with risk.
* Critical authority requires multiple independent approval roles.
* Irreversible actions use:

  * prepare;
  * cooling-off;
  * final confirmation;
  * expiring commitment.
* Approval expiry can stop execution independently from Grant expiry.

---

## [0.2.0] - 2026-08-04

### Added

* Added authority-domain identifiers.
* Added monotonic revocation epochs.
* Added root and delegated Capability Grant types.
* Added **Capability Delegation Receipt**.
* Added independently countersigned subset delegation.
* Added **Capability Renewal Record**.
* Added explicit non-automatic reauthorization.
* Added Grant-epoch advancement.
* Added stale-gate invalidation after renewal.
* Added **Capability Revocation Record**.
* Added cascade revocation.
* Added execution-token invalidation on revocation.
* Added short-lived execution tokens to Action Gate Receipts.
* Added **Execution Continuity Receipt** with:

  * `continue`;
  * `suspend`;
  * `zeroize`.
* Added runtime recording of continuity checkpoints.
* Added runtime recording of observed revocation.
* Added runtime recording of execution suspension.
* Added epoch-aware zeroization.
* Added revocation-epoch bindings to Zero State proof.
* Added migration guidance from v0.1.

### Validator

* Validates delegated capability subsets.
* Validates delegated constraint subsets.
* Validates child-Grant linkage to an authorized Delegation Receipt.
* Validates renewal count.
* Validates renewal-extension limits.
* Validates issuer separation.
* Validates effective Grant expiry.
* Validates Grant-epoch progression.
* Rejects stale Action Gates after renewal.
* Validates revocation-epoch progression.
* Validates complete descendant coverage during cascade revocation.
* Ensures cascade revocation invalidates all known execution tokens derived from the revoked authority lineage.
* Rejects `continue` decisions after revocation.
* Rejects successful external actions after revocation.
* Rejects successful external actions after a stop decision.
* Validates final Zero State authority domain.
* Validates final Zero State revocation epoch.

### Security model

* Introduced the rule:

> **Permission to start is not permission to continue forever.**

* Delegation is constrained subset transfer, never authority expansion.
* Renewal is explicit reauthorization, never silent persistence.
* Execution authority is short-lived.
* Execution authority is continuously revalidated.
* Revocation propagates through the authority lineage.
* Revoked or stale execution must stop before any further external effect.

---

## [0.1.0] - 2026-08-04

### Added

* Defined the foundational principle:

> **Maximum capability, zero ambient authority.**

* Defined the minimum Zero-Type authority lifecycle:

```text
Zero State
    ↓
Capability Grant
    ↓
Action Gate Receipt
    ↓
Runtime Trace Record
    ↓
Emergency Zeroization Record
    ↓
Zero State
```

* Added **Zero State Record**.
* Added **Capability Grant**.
* Added **Action Gate Receipt**.
* Added **Runtime Trace Record**.
* Added **Emergency Zeroization Record**.
* Added JSON Schemas for the five foundational record types.
* Added valid lifecycle examples.
* Added deliberately invalid examples.
* Added the Python reference validator.
* Added GitHub Actions validation.

### Security model

* An AI agent begins with no implicit external authority.
* Capability and authority are treated as separate concepts.
* External action requires explicit authorization.
* Authority cannot be assumed from model capability.
* Runtime actions must be independently recorded.
* Revocation or abnormal termination returns the agent to Zero State.

The foundational rule is:

```text
A model may be capable of an action.

That does not mean
it possesses the authority
to perform that action.
```
