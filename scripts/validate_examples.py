#!/usr/bin/env python3
"""Validate Zero-Type Agent Zero-Authority Profile v0.5 examples."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
PASS_DIR = ROOT / "examples" / "pass"
FAIL_DIR = ROOT / "examples" / "fail"

SCHEMA_BY_RECORD_TYPE = {
    "zero_state_record": SCHEMA_DIR / "zero-state-record.schema.json",
    "capability_grant": SCHEMA_DIR / "capability-grant.schema.json",
    "capability_delegation_receipt": SCHEMA_DIR / "capability-delegation-receipt.schema.json",
    "capability_renewal_record": SCHEMA_DIR / "capability-renewal-record.schema.json",
    "capability_revocation_record": SCHEMA_DIR / "capability-revocation-record.schema.json",
    "risk_classification_assessment": SCHEMA_DIR / "risk-classification-assessment.schema.json",
    "authorization_quorum_receipt": SCHEMA_DIR / "authorization-quorum-receipt.schema.json",
    "irreversible_action_commitment": SCHEMA_DIR / "irreversible-action-commitment.schema.json",
    "execution_context_attestation": SCHEMA_DIR / "execution-context-attestation.schema.json",
    "tool_identity_attestation": SCHEMA_DIR / "tool-identity-attestation.schema.json",
    "data_egress_authorization": SCHEMA_DIR / "data-egress-authorization.schema.json",
    "runtime_interlock_record": SCHEMA_DIR / "runtime-interlock-record.schema.json",
    "action_gate_receipt": SCHEMA_DIR / "action-gate-receipt.schema.json",
    "execution_continuity_receipt": SCHEMA_DIR / "execution-continuity-receipt.schema.json",
    "runtime_trace_record": SCHEMA_DIR / "runtime-trace-record.schema.json",
    "emergency_zeroization_record": SCHEMA_DIR / "emergency-zeroization-record.schema.json",
    "incident_containment_receipt": SCHEMA_DIR / "incident-containment-receipt.schema.json",
    "execution_closure_receipt": SCHEMA_DIR / "execution-closure-receipt.schema.json",
    "authority_evidence_chain": SCHEMA_DIR / "authority-evidence-chain.schema.json",
    "conformance_assessment_record": SCHEMA_DIR / "conformance-assessment-record.schema.json",
}

PRIMARY_ID_FIELD = {
    "zero_state_record": "zero_state_id",
    "capability_grant": "grant_id",
    "capability_delegation_receipt": "delegation_id",
    "capability_renewal_record": "renewal_id",
    "capability_revocation_record": "revocation_id",
    "risk_classification_assessment": "risk_assessment_id",
    "authorization_quorum_receipt": "quorum_id",
    "irreversible_action_commitment": "commitment_id",
    "execution_context_attestation": "context_id",
    "tool_identity_attestation": "tool_attestation_id",
    "data_egress_authorization": "egress_id",
    "runtime_interlock_record": "interlock_id",
    "action_gate_receipt": "receipt_id",
    "execution_continuity_receipt": "continuity_id",
    "runtime_trace_record": "trace_id",
    "emergency_zeroization_record": "zeroization_id",
    "incident_containment_receipt": "containment_id",
    "execution_closure_receipt": "closure_id",
    "authority_evidence_chain": "chain_id",
    "conformance_assessment_record": "assessment_id",
}

EXTERNAL_EFFECT_EVENTS = {
    "tool_call", "network_request", "file_write", "credential_use",
    "child_agent_create", "external_output", "process_exec",
}


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("document root must be an object")
    return data


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("schema root must be an object")
    return data


def canonical_json_bytes(value: Any) -> bytes:
    """Return the profile's deterministic JSON representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def primary_identifier(record: dict[str, Any]) -> str | None:
    field = PRIMARY_ID_FIELD.get(record.get("record_type"))
    value = record.get(field) if field else None
    return str(value) if value else None


def evidence_entry_payload(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence": entry.get("sequence"),
        "record_type": entry.get("record_type"),
        "record_id": entry.get("record_id"),
        "record_digest": entry.get("record_digest"),
        "previous_entry_digest": entry.get("previous_entry_digest"),
        "observed_at": entry.get("observed_at"),
    }


def parse_datetime(value: Any, field_name: str) -> tuple[datetime | None, list[str]]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")), []
    except (TypeError, ValueError):
        return None, [f"{field_name}: invalid RFC 3339 date-time"]


def build_registry(records: list[tuple[Path, dict[str, Any]]]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    registry: dict[str, dict[str, Any]] = {}
    sources: dict[str, Path] = {}
    errors: list[str] = []
    for path, record in records:
        record_type = record.get("record_type")
        id_field = PRIMARY_ID_FIELD.get(record_type)
        record_id = record.get(id_field) if id_field else None
        if not record_id:
            continue
        if record_id in registry:
            first = sources[record_id].relative_to(ROOT)
            second = path.relative_to(ROOT)
            errors.append(f"duplicate primary identifier {record_id}: {first} and {second}")
            continue
        registry[record_id] = record
        sources[record_id] = path
    return registry, errors


def schema_errors(record: dict[str, Any], schemas: dict[str, dict[str, Any]]) -> list[str]:
    record_type = record.get("record_type")
    schema = schemas.get(record_type)
    if schema is None:
        return [f"unknown record_type: {record_type!r}"]

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors: list[str] = []
    for error in sorted(validator.iter_errors(record), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "<root>"
        errors.append(f"{location}: {error.message}")
    return errors


def all_true(mapping: dict[str, Any], names: tuple[str, ...], prefix: str) -> list[str]:
    return [f"{prefix}.{name} must be true" for name in names if mapping.get(name) is not True]


def semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "capability_grant":
        valid_from, e1 = parse_datetime(record.get("valid_from"), "valid_from")
        expires_at, e2 = parse_datetime(record.get("expires_at"), "expires_at")
        errors.extend(e1 + e2)
        if valid_from and expires_at and expires_at <= valid_from:
            errors.append("expires_at must be later than valid_from")
        delegation = record.get("delegation", {})
        if delegation.get("delegable") is False:
            if delegation.get("max_depth") != 0:
                errors.append("non-delegable grant requires delegation.max_depth=0")
            if delegation.get("allowed_child_agents"):
                errors.append("non-delegable grant must not list allowed_child_agents")
        renewal = record.get("renewal_policy", {})
        if renewal.get("renewable") is False:
            if renewal.get("max_renewals") != 0 or renewal.get("max_extension_seconds") != 0:
                errors.append("non-renewable grant requires zero renewal limits")

    elif record_type == "capability_delegation_receipt":
        checks = record.get("checks", {})
        if record.get("decision") == "allowed":
            errors.extend(all_true(checks, (
                "parent_grant_active", "capability_subset", "constraints_not_widened",
                "child_agent_allowed", "depth_allowed", "revocation_clear", "risk_tier_not_widened",
            ), "checks"))

    elif record_type == "capability_renewal_record":
        reviewed_at, e1 = parse_datetime(record.get("reviewed_at"), "reviewed_at")
        previous_expires_at, e2 = parse_datetime(record.get("previous_expires_at"), "previous_expires_at")
        requested_expires_at, e3 = parse_datetime(record.get("requested_expires_at"), "requested_expires_at")
        resulting_expires_at, e4 = parse_datetime(record.get("resulting_expires_at"), "resulting_expires_at") if record.get("resulting_expires_at") else (None, [])
        errors.extend(e1 + e2 + e3 + e4)
        if requested_expires_at and previous_expires_at and requested_expires_at <= previous_expires_at:
            errors.append("requested_expires_at must extend previous_expires_at")
        if record.get("decision") == "approved":
            errors.extend(all_true(record.get("checks", {}), (
                "grant_active", "renewal_allowed", "within_renewal_count",
                "extension_within_limit", "origin_unchanged", "revocation_clear", "risk_limit_unchanged",
            ), "checks"))
            if record.get("new_grant_epoch") != record.get("previous_grant_epoch", 0) + 1:
                errors.append("approved renewal must increment grant epoch by one")
            if requested_expires_at and resulting_expires_at and requested_expires_at != resulting_expires_at:
                errors.append("approved renewal resulting_expires_at must equal requested_expires_at")
        issuer = record.get("issuer", {})
        if issuer.get("issuer_id") == record.get("agent_id"):
            errors.append("grantee agent must not issue its own renewal")

    elif record_type == "capability_revocation_record":
        if record.get("new_revocation_epoch") != record.get("previous_revocation_epoch", -1) + 1:
            errors.append("revocation must increment authority-domain epoch by one")
        if record.get("root_grant_id") not in record.get("revoked_grant_ids", []):
            errors.append("root_grant_id must be included in revoked_grant_ids")
        if record.get("scope") == "grant_only" and record.get("descendant_grant_ids"):
            errors.append("grant_only revocation must not list descendant_grant_ids")

    elif record_type == "action_gate_receipt":
        evaluated_at, e1 = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        valid_until, e2 = parse_datetime(record.get("valid_until"), "valid_until")
        errors.extend(e1 + e2)
        if evaluated_at and valid_until and valid_until <= evaluated_at:
            errors.append("valid_until must be later than evaluated_at")
        checks = record.get("checks", {})
        if record.get("decision") == "allowed":
            errors.extend(all_true(checks, (
                "grant_active", "grant_epoch_current", "revocation_clear", "delegation_chain_valid",
                "within_scope", "target_allowed", "tool_allowed", "within_time_window",
                "invocation_budget_available", "recorder_available", "risk_classified",
                "risk_within_grant", "authorization_quorum_satisfied", "commitment_satisfied",
            ), "checks"))
            if checks.get("irreversible_action") is True and not checks.get("human_approval_ref"):
                errors.append("irreversible allowed action requires human_approval_ref")
            token = record.get("execution_token", {})
            issued_at, e3 = parse_datetime(token.get("issued_at"), "execution_token.issued_at")
            expires_at, e4 = parse_datetime(token.get("expires_at"), "execution_token.expires_at")
            errors.extend(e3 + e4)
            if evaluated_at and issued_at and issued_at < evaluated_at:
                errors.append("execution token must not be issued before evaluation")
            if issued_at and expires_at and expires_at <= issued_at:
                errors.append("execution token expires_at must be later than issued_at")
            if valid_until and expires_at and expires_at > valid_until:
                errors.append("execution token must not outlive action gate receipt")
        elif record.get("execution_token"):
            errors.append("non-allowed action gate must not issue execution_token")

    elif record_type == "execution_continuity_receipt":
        checked_at, e1 = parse_datetime(record.get("checked_at"), "checked_at")
        errors.extend(e1)
        checks = record.get("checks", {})
        if record.get("decision") == "continue":
            errors.extend(all_true(checks, (
                "grant_active", "grant_epoch_current", "revocation_clear", "execution_token_valid",
                "execution_token_unrevoked", "within_effective_validity", "budget_remaining", "recorder_healthy",
                "risk_profile_unchanged", "quorum_still_satisfied", "commitment_still_valid",
            ), "checks"))
            next_due, e2 = parse_datetime(record.get("next_check_due_at"), "next_check_due_at")
            errors.extend(e2)
            if checked_at and next_due and next_due <= checked_at:
                errors.append("next_check_due_at must be later than checked_at")

    elif record_type == "runtime_trace_record":
        started_at, e1 = parse_datetime(record.get("started_at"), "started_at")
        completed_at, e2 = parse_datetime(record.get("completed_at"), "completed_at")
        errors.extend(e1 + e2)
        if started_at and completed_at and completed_at < started_at:
            errors.append("completed_at must not be earlier than started_at")
        events = record.get("events", [])
        if [event.get("sequence") for event in events] != list(range(1, len(events) + 1)):
            errors.append("events.sequence must be contiguous and start at 1")
        previous_time: datetime | None = None
        for index, event in enumerate(events):
            timestamp, event_errors = parse_datetime(event.get("timestamp"), f"events[{index}].timestamp")
            errors.extend(event_errors)
            if timestamp and previous_time and timestamp < previous_time:
                errors.append("events must be ordered chronologically")
            if timestamp:
                previous_time = timestamp
            if started_at and timestamp and timestamp < started_at:
                errors.append(f"events[{index}].timestamp is before started_at")
            if completed_at and timestamp and timestamp > completed_at:
                errors.append(f"events[{index}].timestamp is after completed_at")

    elif record_type == "emergency_zeroization_record":
        initiated_at, e1 = parse_datetime(record.get("initiated_at"), "initiated_at")
        completed_at, e2 = parse_datetime(record.get("completed_at"), "completed_at")
        errors.extend(e1 + e2)
        if initiated_at and completed_at and completed_at < initiated_at:
            errors.append("completed_at must not be earlier than initiated_at")

    return errors


def grant_children(registry: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    children: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in registry.values():
        if record.get("record_type") == "capability_grant" and record.get("parent_grant_id"):
            children[record["parent_grant_id"]].append(record)
    return children


def descendants(root_grant_id: str, registry: dict[str, dict[str, Any]]) -> set[str]:
    children = grant_children(registry)
    found: set[str] = set()
    stack = [root_grant_id]
    while stack:
        parent = stack.pop()
        for child in children.get(parent, []):
            child_id = child["grant_id"]
            if child_id not in found:
                found.add(child_id)
                stack.append(child_id)
    return found


def approved_renewals(grant_id: str, registry: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records = [
        record for record in registry.values()
        if record.get("record_type") == "capability_renewal_record"
        and record.get("grant_id") == grant_id
        and record.get("decision") == "approved"
    ]
    return sorted(records, key=lambda item: item.get("reviewed_at", ""))


def effective_grant_state(grant: dict[str, Any], registry: dict[str, dict[str, Any]]) -> tuple[int, datetime | None, list[str]]:
    errors: list[str] = []
    epoch = grant.get("grant_epoch")
    expiry, e1 = parse_datetime(grant.get("expires_at"), "grant.expires_at")
    errors.extend(e1)
    for renewal in approved_renewals(grant["grant_id"], registry):
        if renewal.get("previous_grant_epoch") != epoch:
            errors.append(f"renewal chain has stale previous_grant_epoch: {renewal.get('renewal_id')}")
        if renewal.get("new_grant_epoch") != epoch + 1:
            errors.append(f"renewal chain has invalid new_grant_epoch: {renewal.get('renewal_id')}")
        previous_expiry, e2 = parse_datetime(renewal.get("previous_expires_at"), "renewal.previous_expires_at")
        result_expiry, e3 = parse_datetime(renewal.get("resulting_expires_at"), "renewal.resulting_expires_at")
        errors.extend(e2 + e3)
        if expiry and previous_expiry and previous_expiry != expiry:
            errors.append(f"renewal chain has stale previous_expires_at: {renewal.get('renewal_id')}")
        epoch = renewal.get("new_grant_epoch")
        expiry = result_expiry
    return epoch, expiry, errors


def revocations_for_grant(grant_id: str, registry: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records = [
        record for record in registry.values()
        if record.get("record_type") == "capability_revocation_record"
        and grant_id in record.get("revoked_grant_ids", [])
    ]
    return sorted(records, key=lambda item: item.get("revoked_at", ""))


def current_domain_epoch(domain_id: str, at_time: datetime, registry: dict[str, dict[str, Any]]) -> int:
    epoch = 0
    for record in registry.values():
        if record.get("record_type") != "capability_revocation_record" or record.get("authority_domain_id") != domain_id:
            continue
        revoked_at, _ = parse_datetime(record.get("revoked_at"), "revoked_at")
        if revoked_at and revoked_at <= at_time:
            epoch = max(epoch, record.get("new_revocation_epoch", 0))
    return epoch


def token_receipts(registry: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in registry.values():
        if record.get("record_type") == "action_gate_receipt" and record.get("execution_token"):
            result[record["execution_token"]["token_id"]] = record
    return result


def cross_record_errors(record: dict[str, Any], registry: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "capability_grant" and record.get("grant_kind") == "delegated":
        parent = registry.get(record.get("parent_grant_id"))
        delegation = registry.get(record.get("delegation_receipt_id"))
        if parent is None:
            errors.append(f"parent_grant_id not found: {record.get('parent_grant_id')}")
        if delegation is None:
            errors.append(f"delegation_receipt_id not found: {record.get('delegation_receipt_id')}")
        if parent and parent.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("delegated grant authority_domain_id differs from parent")
        if parent and parent.get("origin_ref") != record.get("origin_ref"):
            errors.append("delegated grant must preserve parent origin_ref")
        if parent:
            child_valid_from, _ = parse_datetime(record.get("valid_from"), "valid_from")
            child_expires_at, _ = parse_datetime(record.get("expires_at"), "expires_at")
            parent_valid_from, _ = parse_datetime(parent.get("valid_from"), "parent.valid_from")
            _, parent_effective_expiry, parent_state_errors = effective_grant_state(parent, registry)
            errors.extend(parent_state_errors)
            if child_valid_from and parent_valid_from and child_valid_from < parent_valid_from:
                errors.append("delegated grant starts before parent grant")
            if child_expires_at and parent_effective_expiry and child_expires_at > parent_effective_expiry:
                errors.append("delegated grant outlives parent grant")
        if delegation:
            if delegation.get("decision") != "allowed":
                errors.append("delegated grant requires an allowed delegation receipt")
            if delegation.get("proposed_child_grant_id") != record.get("grant_id"):
                errors.append("delegation receipt proposed_child_grant_id mismatch")
            if delegation.get("child_agent_id") != record.get("agent_id"):
                errors.append("delegation receipt child_agent_id mismatch")
            if delegation.get("parent_grant_id") != record.get("parent_grant_id"):
                errors.append("delegation receipt parent_grant_id mismatch")
            if delegation.get("delegated_capability") != record.get("capability"):
                errors.append("delegated grant capability differs from approved delegation")
            if delegation.get("delegated_constraints") != record.get("constraints"):
                errors.append("delegated grant constraints differ from approved delegation")

    elif record_type == "capability_delegation_receipt":
        parent = registry.get(record.get("parent_grant_id"))
        if parent is None:
            return [f"parent_grant_id not found: {record.get('parent_grant_id')}"]
        if parent.get("agent_id") != record.get("delegator_agent_id"):
            errors.append("delegator_agent_id does not own parent grant")
        if parent.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("delegation authority_domain_id differs from parent")
        evaluated_at, _ = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        parent_valid_from, _ = parse_datetime(parent.get("valid_from"), "parent.valid_from")
        _, parent_effective_expiry, parent_state_errors = effective_grant_state(parent, registry)
        errors.extend(parent_state_errors)
        if evaluated_at and parent_valid_from and parent_effective_expiry and not parent_valid_from <= evaluated_at < parent_effective_expiry:
            errors.append("delegation evaluated outside parent grant validity")
        if evaluated_at and current_domain_epoch(record.get("authority_domain_id"), evaluated_at, registry) != parent.get("issued_revocation_epoch"):
            errors.append("delegation evaluated after authority-domain revocation")
        delegation = parent.get("delegation", {})
        if not delegation.get("delegable"):
            errors.append("parent grant is not delegable")
        if record.get("child_agent_id") not in delegation.get("allowed_child_agents", []):
            errors.append("child agent is not allowed by parent grant")
        if record.get("delegation_depth", 0) > delegation.get("max_depth", 0):
            errors.append("delegation depth exceeds parent limit")
        parent_cap = parent.get("capability", {})
        child_cap = record.get("delegated_capability", {})
        if child_cap.get("action_type") != parent_cap.get("action_type"):
            errors.append("delegated action_type is not a subset of parent")
        if not set(child_cap.get("targets", [])).issubset(set(parent_cap.get("targets", []))):
            errors.append("delegated targets widen parent scope")
        if not set(child_cap.get("allowed_tools", [])).issubset(set(parent_cap.get("allowed_tools", []))):
            errors.append("delegated tools widen parent scope")
        parent_constraints = parent.get("constraints", {})
        child_constraints = record.get("delegated_constraints", {})
        if child_constraints.get("max_invocations", 0) > parent_constraints.get("max_invocations", 0):
            errors.append("delegated max_invocations exceeds parent")
        for field in ("network_destinations", "data_classes"):
            if not set(child_constraints.get(field, [])).issubset(set(parent_constraints.get(field, []))):
                errors.append(f"delegated {field} widen parent constraints")

    elif record_type == "capability_renewal_record":
        grant = registry.get(record.get("grant_id"))
        if grant is None:
            return [f"grant_id not found: {record.get('grant_id')}"]
        if grant.get("agent_id") != record.get("agent_id"):
            errors.append("renewal agent_id differs from grant")
        if grant.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("renewal authority_domain_id differs from grant")
        policy = grant.get("renewal_policy", {})
        if not policy.get("renewable"):
            errors.append("grant is not renewable")
        prior = [r for r in approved_renewals(grant["grant_id"], registry) if r.get("renewal_id") != record.get("renewal_id") and r.get("reviewed_at", "") < record.get("reviewed_at", "")]
        expected_epoch = grant.get("grant_epoch") + len(prior)
        expected_expiry = grant.get("expires_at") if not prior else prior[-1].get("resulting_expires_at")
        if record.get("previous_grant_epoch") != expected_epoch:
            errors.append("renewal previous_grant_epoch is stale")
        if record.get("previous_expires_at") != expected_expiry:
            errors.append("renewal previous_expires_at is stale")
        if len(prior) + 1 > policy.get("max_renewals", 0):
            errors.append("renewal count exceeds grant policy")
        previous_dt, _ = parse_datetime(record.get("previous_expires_at"), "previous_expires_at")
        result_dt, _ = parse_datetime(record.get("resulting_expires_at"), "resulting_expires_at") if record.get("resulting_expires_at") else (None, [])
        if previous_dt and result_dt:
            extension = int((result_dt - previous_dt).total_seconds())
            if extension > policy.get("max_extension_seconds", 0):
                errors.append("renewal extension exceeds grant policy")
        reviewed_at, _ = parse_datetime(record.get("reviewed_at"), "reviewed_at")
        if reviewed_at:
            domain_epoch = current_domain_epoch(record.get("authority_domain_id"), reviewed_at, registry)
            if domain_epoch != grant.get("issued_revocation_epoch"):
                errors.append("renewal occurred after authority-domain revocation")
            previous_expiry_dt, _ = parse_datetime(record.get("previous_expires_at"), "previous_expires_at")
            if previous_expiry_dt and reviewed_at >= previous_expiry_dt:
                errors.append("renewal must be reviewed before current expiry")
        if grant.get("grant_kind") == "delegated" and record.get("resulting_expires_at"):
            parent = registry.get(grant.get("parent_grant_id"))
            if parent:
                _, parent_expiry, parent_errors = effective_grant_state(parent, registry)
                errors.extend(parent_errors)
                resulting_expiry, _ = parse_datetime(record.get("resulting_expires_at"), "resulting_expires_at")
                if parent_expiry and resulting_expiry and resulting_expiry > parent_expiry:
                    errors.append("renewed delegated grant outlives parent grant")

    elif record_type == "capability_revocation_record":
        root = registry.get(record.get("root_grant_id"))
        if root is None:
            return [f"root_grant_id not found: {record.get('root_grant_id')}"]
        if root.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("revocation authority_domain_id differs from root grant")
        expected_descendants = descendants(root["grant_id"], registry)
        if record.get("scope") == "cascade":
            if set(record.get("descendant_grant_ids", [])) != expected_descendants:
                errors.append("cascade revocation descendant_grant_ids are incomplete")
            expected_revoked = expected_descendants | {root["grant_id"]}
            if set(record.get("revoked_grant_ids", [])) != expected_revoked:
                errors.append("cascade revocation revoked_grant_ids are incomplete")
        revoked_at, _ = parse_datetime(record.get("revoked_at"), "revoked_at")
        if revoked_at:
            prior_epoch = 0
            for other in registry.values():
                if other.get("record_type") != "capability_revocation_record" or other.get("revocation_id") == record.get("revocation_id"):
                    continue
                if other.get("authority_domain_id") != record.get("authority_domain_id"):
                    continue
                other_time, _ = parse_datetime(other.get("revoked_at"), "other.revoked_at")
                if other_time and other_time < revoked_at:
                    prior_epoch = max(prior_epoch, other.get("new_revocation_epoch", 0))
            if record.get("previous_revocation_epoch") != prior_epoch:
                errors.append("revocation previous_revocation_epoch is stale")
        expected_agents = {registry[g]["agent_id"] for g in record.get("revoked_grant_ids", []) if g in registry}
        if not expected_agents.issubset(set(record.get("propagation", {}).get("acknowledged_agent_ids", []))):
            errors.append("revocation propagation lacks agent acknowledgements")
        tokens = token_receipts(registry)
        expected_tokens = {
            token_id for token_id, receipt in tokens.items()
            if receipt.get("grant_id") in record.get("revoked_grant_ids", [])
            and receipt.get("decision") == "allowed"
        }
        if not expected_tokens.issubset(set(record.get("invalidated_execution_token_ids", []))):
            errors.append("revocation does not invalidate all active execution tokens")

    elif record_type == "action_gate_receipt":
        grant = registry.get(record.get("grant_id"))
        if grant is None:
            return [f"grant_id not found: {record.get('grant_id')}"]
        if grant.get("agent_id") != record.get("agent_id"):
            errors.append("action gate agent_id differs from grant")
        if grant.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("action gate authority_domain_id differs from grant")
        current_epoch, effective_expiry, state_errors = effective_grant_state(grant, registry)
        errors.extend(state_errors)
        if record.get("grant_epoch") != current_epoch:
            errors.append("action gate uses stale grant_epoch")
        evaluated_at, _ = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        valid_from, _ = parse_datetime(grant.get("valid_from"), "grant.valid_from")
        if evaluated_at:
            domain_epoch = current_domain_epoch(record.get("authority_domain_id"), evaluated_at, registry)
            if record.get("observed_revocation_epoch") != domain_epoch:
                errors.append("action gate observed_revocation_epoch is stale")
            if revocations_for_grant(grant["grant_id"], registry) and any(
                parse_datetime(r.get("revoked_at"), "revoked_at")[0] <= evaluated_at for r in revocations_for_grant(grant["grant_id"], registry)
            ):
                errors.append("action gate evaluated after grant revocation")
            if valid_from and effective_expiry and not valid_from <= evaluated_at < effective_expiry:
                errors.append("action gate evaluation is outside effective grant validity")
            token_expiry, _ = parse_datetime(record.get("execution_token", {}).get("expires_at"), "execution_token.expires_at") if record.get("execution_token") else (None, [])
            if token_expiry and effective_expiry and token_expiry > effective_expiry:
                errors.append("execution token outlives effective grant validity")
        requested = record.get("requested_action", {})
        capability = grant.get("capability", {})
        if requested.get("action_type") != capability.get("action_type"):
            errors.append("requested action_type is outside capability grant")
        if requested.get("target") not in capability.get("targets", []):
            errors.append("requested target is outside capability grant")
        if requested.get("tool") not in capability.get("allowed_tools", []):
            errors.append("requested tool is outside capability grant")

    elif record_type == "execution_continuity_receipt":
        grant = registry.get(record.get("grant_id"))
        gate = registry.get(record.get("receipt_id"))
        if grant is None:
            errors.append(f"grant_id not found: {record.get('grant_id')}")
        if gate is None:
            errors.append(f"receipt_id not found: {record.get('receipt_id')}")
        if not grant or not gate:
            return errors
        if gate.get("decision") != "allowed":
            errors.append("continuity receipt requires an allowed action gate")
        if gate.get("grant_id") != record.get("grant_id"):
            errors.append("continuity grant_id differs from action gate")
        token = gate.get("execution_token", {})
        if token.get("token_id") != record.get("execution_token_id"):
            errors.append("continuity execution_token_id differs from action gate")
        if record.get("grant_epoch") != gate.get("grant_epoch"):
            errors.append("continuity grant_epoch differs from action gate")
        checked_at, _ = parse_datetime(record.get("checked_at"), "checked_at")
        token_expiry, _ = parse_datetime(token.get("expires_at"), "execution_token.expires_at")
        if checked_at:
            domain_epoch = current_domain_epoch(record.get("authority_domain_id"), checked_at, registry)
            if record.get("observed_revocation_epoch") != domain_epoch:
                errors.append("continuity observed_revocation_epoch is stale")
            revoked = any(
                parse_datetime(r.get("revoked_at"), "revoked_at")[0] <= checked_at
                for r in revocations_for_grant(record.get("grant_id"), registry)
            )
            if revoked and record.get("decision") == "continue":
                errors.append("continuity must not continue after revocation")
            if token_expiry and checked_at >= token_expiry and record.get("decision") == "continue":
                errors.append("continuity must not continue with expired execution token")
            if record.get("decision") == "continue":
                next_due, _ = parse_datetime(record.get("next_check_due_at"), "next_check_due_at")
                interval = gate.get("continuity", {}).get("interval_seconds")
                if next_due and interval is not None and next_due != checked_at + timedelta(seconds=interval):
                    errors.append("continuity next_check_due_at does not match action-gate interval")

    elif record_type == "runtime_trace_record":
        grant = registry.get(record.get("grant_id"))
        gate = registry.get(record.get("receipt_id"))
        if grant is None:
            errors.append(f"grant_id not found: {record.get('grant_id')}")
        if gate is None:
            errors.append(f"receipt_id not found: {record.get('receipt_id')}")
        if not grant or not gate:
            return errors
        if gate.get("decision") != "allowed":
            errors.append("runtime trace requires an allowed action gate")
        if gate.get("execution_token", {}).get("token_id") != record.get("execution_token_id"):
            errors.append("runtime trace execution_token_id differs from action gate")
        if gate.get("grant_epoch") != record.get("grant_epoch"):
            errors.append("runtime trace grant_epoch differs from action gate")
        continuity_records: list[dict[str, Any]] = []
        for continuity_id in record.get("continuity_receipt_ids", []):
            continuity = registry.get(continuity_id)
            if continuity is None:
                errors.append(f"continuity receipt not found: {continuity_id}")
            else:
                continuity_records.append(continuity)
                if continuity.get("receipt_id") != record.get("receipt_id"):
                    errors.append(f"continuity receipt belongs to another action gate: {continuity_id}")
        allowed_destinations = set(grant.get("constraints", {}).get("network_destinations", []))
        allowed_tools = set(grant.get("capability", {}).get("allowed_tools", []))
        for event in record.get("events", []):
            if event.get("event_type") == "network_request" and event.get("target") not in allowed_destinations:
                errors.append(f"network target outside grant: {event.get('target')}")
            if event.get("event_type") == "tool_call" and event.get("target") not in allowed_tools:
                errors.append(f"tool target outside grant: {event.get('target')}")
        revocations = revocations_for_grant(record.get("grant_id"), registry)
        revocation_times = [parse_datetime(r.get("revoked_at"), "revoked_at")[0] for r in revocations]
        revocation_times = [t for t in revocation_times if t]
        earliest_revocation = min(revocation_times) if revocation_times else None
        stop_times = []
        for continuity in continuity_records:
            if continuity.get("decision") in {"suspend", "zeroize"}:
                t, _ = parse_datetime(continuity.get("checked_at"), "checked_at")
                if t:
                    stop_times.append(t)
        stop_candidates = list(stop_times)
        if earliest_revocation:
            stop_candidates.append(earliest_revocation)
        stop_time = min(stop_candidates) if stop_candidates else None
        if earliest_revocation and not record.get("revocation_observed"):
            errors.append("runtime trace failed to mark revocation_observed")
        if earliest_revocation and record.get("final_status") == "completed":
            errors.append("revoked execution must not finish as completed")
        started_at, _ = parse_datetime(record.get("started_at"), "started_at")
        completed_at, _ = parse_datetime(record.get("completed_at"), "completed_at")
        continuity_times = []
        for continuity in continuity_records:
            checked_at, _ = parse_datetime(continuity.get("checked_at"), "continuity.checked_at")
            if checked_at:
                continuity_times.append(checked_at)
        continuity_times.sort()
        max_unchecked = gate.get("continuity", {}).get("max_unchecked_seconds")
        if max_unchecked is not None and started_at and continuity_times:
            checkpoints = [started_at, *continuity_times]
            if completed_at:
                checkpoints.append(completed_at)
            for left, right in zip(checkpoints, checkpoints[1:]):
                if (right - left).total_seconds() > max_unchecked:
                    errors.append("runtime exceeded max_unchecked_seconds between continuity checkpoints")
                    break
        if stop_time:
            for event in record.get("events", []):
                event_time, _ = parse_datetime(event.get("timestamp"), "event.timestamp")
                if event_time and event_time > stop_time and event.get("event_type") in EXTERNAL_EFFECT_EVENTS and event.get("outcome") == "succeeded":
                    errors.append(f"successful external action occurred after execution stop: sequence {event.get('sequence')}")

    elif record_type == "emergency_zeroization_record":
        for grant_id in record.get("revoked_grant_ids", []):
            grant = registry.get(grant_id)
            if grant is None:
                errors.append(f"revoked grant not found: {grant_id}")
            elif grant.get("agent_id") != record.get("agent_id"):
                errors.append(f"zeroization grant belongs to another agent: {grant_id}")
        newest_epoch = 0
        for revocation_id in record.get("revocation_record_ids", []):
            revocation = registry.get(revocation_id)
            if revocation is None:
                errors.append(f"revocation record not found: {revocation_id}")
            else:
                if revocation.get("authority_domain_id") != record.get("authority_domain_id"):
                    errors.append("zeroization revocation record has different authority domain")
                newest_epoch = max(newest_epoch, revocation.get("new_revocation_epoch", 0))
        tokens = token_receipts(registry)
        expected_agent_tokens = {
            token_id for token_id, gate in tokens.items()
            if gate.get("agent_id") == record.get("agent_id")
            and gate.get("grant_id") in record.get("revoked_grant_ids", [])
            and gate.get("decision") == "allowed"
        }
        if not expected_agent_tokens.issubset(set(record.get("invalidated_execution_token_ids", []))):
            errors.append("zeroization does not invalidate every active token for revoked grants")
        for token_id in record.get("invalidated_execution_token_ids", []):
            gate = tokens.get(token_id)
            if gate is None:
                errors.append(f"invalidated execution token not found: {token_id}")
            elif gate.get("agent_id") != record.get("agent_id"):
                errors.append(f"invalidated execution token belongs to another agent: {token_id}")
        zero_state_id = record.get("final_state", {}).get("zero_state_record_id")
        zero_state = registry.get(zero_state_id)
        if zero_state is None:
            errors.append(f"final zero state not found: {zero_state_id}")
        else:
            if zero_state.get("agent_id") != record.get("agent_id"):
                errors.append("final zero state belongs to another agent")
            if zero_state.get("authority_domain_id") != record.get("authority_domain_id"):
                errors.append("final zero state has different authority domain")
            if zero_state.get("revocation_epoch") != record.get("final_state", {}).get("revocation_epoch"):
                errors.append("zeroization final_state revocation_epoch differs from zero state")
        if record.get("revocation_record_ids") and record.get("final_state", {}).get("revocation_epoch") != newest_epoch:
            errors.append("zeroization final_state uses stale revocation_epoch")
        initiated_at, _ = parse_datetime(record.get("initiated_at"), "initiated_at")
        for revocation_id in record.get("revocation_record_ids", []):
            revocation = registry.get(revocation_id)
            if revocation and initiated_at:
                revoked_at, _ = parse_datetime(revocation.get("revoked_at"), "revoked_at")
                if revoked_at and initiated_at < revoked_at:
                    errors.append("zeroization initiated before referenced revocation")

    return errors



RISK_RANK = {"low": 0, "moderate": 1, "high": 2, "critical": 3}


def v03_semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "risk_classification_assessment":
        if record.get("decision") == "classified":
            errors.extend(all_true(record.get("checks", {}), (
                "grant_scope_known", "target_identified", "effects_bounded",
                "rollback_evaluated", "conflicts_screened",
            ), "checks"))
        if record.get("assessor", {}).get("assessor_id") == record.get("agent_id"):
            errors.append("agent must not classify its own action risk")
        tier = record.get("risk_tier")
        controls = record.get("required_controls", {})
        roles = set(controls.get("required_roles", []))
        minimum = controls.get("minimum_approvals", 0)
        if tier == "high":
            if minimum < 2:
                errors.append("high risk requires at least two approvals")
            if not {"human_origin", "safety_authority"}.issubset(roles):
                errors.append("high risk requires human_origin and safety_authority roles")
            if not controls.get("human_approval_required") or not controls.get("independent_safety_approval_required"):
                errors.append("high risk requires human and independent safety approval")
        if tier == "critical":
            if minimum < 3:
                errors.append("critical risk requires at least three approvals")
            if not {"human_origin", "safety_authority", "domain_owner"}.issubset(roles):
                errors.append("critical risk requires human_origin, safety_authority, and domain_owner roles")
            if not controls.get("human_approval_required") or not controls.get("independent_safety_approval_required"):
                errors.append("critical risk requires human and independent safety approval")
            if controls.get("cooling_off_seconds", 0) < 60:
                errors.append("critical risk requires a cooling-off period of at least 60 seconds")
            if controls.get("commitment_required") is not True:
                errors.append("critical risk requires irreversible action commitment")
        if record.get("impact", {}).get("reversibility") == "irreversible":
            if tier not in {"high", "critical"}:
                errors.append("irreversible action must be classified high or critical")
            if controls.get("commitment_required") is not True:
                errors.append("irreversible action requires commitment")

    elif record_type == "authorization_quorum_receipt":
        assembled_at, e1 = parse_datetime(record.get("assembled_at"), "assembled_at")
        errors.extend(e1)
        approvals = record.get("approvals", [])
        approve_entries = [a for a in approvals if a.get("decision") == "approve"]
        approvers = [a.get("approver_id") for a in approve_entries]
        roles = {a.get("role") for a in approve_entries}
        policy = record.get("policy", {})
        checks = record.get("checks", {})
        if record.get("decision") == "satisfied":
            errors.extend(all_true(checks, (
                "minimum_approvals_met", "required_roles_present", "distinct_approvers",
                "no_self_approval", "no_conflict_of_interest", "no_veto",
                "approvals_unexpired", "action_digest_consistent",
            ), "checks"))
            if len(set(approvers)) < policy.get("minimum_approvals", 0):
                errors.append("authorization quorum has too few distinct approvals")
            if not set(policy.get("required_roles", [])).issubset(roles):
                errors.append("authorization quorum is missing required approval roles")
            if record.get("agent_id") in approvers:
                errors.append("agent self-approval is forbidden")
            if any(a.get("conflict_of_interest") for a in approvals):
                errors.append("authorization quorum contains a conflicted approver")
            if any(a.get("decision") == "veto" for a in approvals):
                errors.append("authorization quorum cannot be satisfied when a veto exists")
            if len(approvers) != len(set(approvers)):
                errors.append("authorization quorum approvers must be distinct")
            for index, approval in enumerate(approvals):
                approved_at, e2 = parse_datetime(approval.get("approved_at"), f"approvals[{index}].approved_at")
                expires_at, e3 = parse_datetime(approval.get("expires_at"), f"approvals[{index}].expires_at")
                errors.extend(e2 + e3)
                if approved_at and expires_at and expires_at <= approved_at:
                    errors.append(f"approvals[{index}].expires_at must be later than approved_at")
                if assembled_at and expires_at and assembled_at >= expires_at:
                    errors.append(f"approvals[{index}] is expired at quorum assembly")
                if approval.get("action_digest") != record.get("action_digest"):
                    errors.append(f"approvals[{index}].action_digest differs from quorum")

    elif record_type == "irreversible_action_commitment":
        prepared_at, e1 = parse_datetime(record.get("prepared_at"), "prepared_at")
        not_before, e2 = parse_datetime(record.get("not_before"), "not_before")
        expires_at, e3 = parse_datetime(record.get("expires_at"), "expires_at")
        confirmed_at, e4 = parse_datetime(record.get("final_confirmation", {}).get("confirmed_at"), "final_confirmation.confirmed_at")
        errors.extend(e1 + e2 + e3 + e4)
        if prepared_at and not_before and not_before < prepared_at:
            errors.append("not_before must not precede prepared_at")
        if not_before and expires_at and expires_at <= not_before:
            errors.append("commitment expires_at must be later than not_before")
        if record.get("decision") == "committed":
            errors.extend(all_true(record.get("checks", {}), (
                "quorum_satisfied", "cooling_off_elapsed", "action_unchanged",
                "final_human_confirmation", "rollback_or_compensation_defined", "revocation_clear",
            ), "checks"))
            if confirmed_at and not_before and confirmed_at < not_before:
                errors.append("final confirmation occurred before cooling-off elapsed")
            if confirmed_at and expires_at and confirmed_at >= expires_at:
                errors.append("final confirmation occurred after commitment expiry")
            confirmation = record.get("final_confirmation", {})
            if confirmation.get("confirmer_id") == record.get("agent_id"):
                errors.append("agent must not confirm its own irreversible commitment")
            if confirmation.get("action_digest") != record.get("action_digest"):
                errors.append("final confirmation action_digest differs from commitment")

    return errors


def approval_expiry(quorum: dict[str, Any]) -> datetime | None:
    expiries: list[datetime] = []
    for approval in quorum.get("approvals", []):
        expiry, _ = parse_datetime(approval.get("expires_at"), "approval.expires_at")
        if expiry:
            expiries.append(expiry)
    return min(expiries) if expiries else None


def same_action(left: dict[str, Any], right: dict[str, Any]) -> bool:
    names = ("action_type", "target", "tool", "parameters_digest")
    return all(left.get(name) == right.get(name) for name in names)


def v03_cross_record_errors(record: dict[str, Any], registry: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "capability_grant" and record.get("grant_kind") == "delegated":
        parent = registry.get(record.get("parent_grant_id"))
        delegation = registry.get(record.get("delegation_receipt_id"))
        if parent and RISK_RANK.get(record.get("maximum_risk_tier"), 99) > RISK_RANK.get(parent.get("maximum_risk_tier"), -1):
            errors.append("delegated grant widens parent maximum_risk_tier")
        if delegation and delegation.get("delegated_maximum_risk_tier") != record.get("maximum_risk_tier"):
            errors.append("delegated grant maximum_risk_tier differs from delegation receipt")

    elif record_type == "capability_delegation_receipt":
        parent = registry.get(record.get("parent_grant_id"))
        if parent and RISK_RANK.get(record.get("delegated_maximum_risk_tier"), 99) > RISK_RANK.get(parent.get("maximum_risk_tier"), -1):
            errors.append("delegated maximum_risk_tier widens parent risk authority")

    elif record_type == "risk_classification_assessment":
        grant = registry.get(record.get("grant_id"))
        if grant is None:
            return [f"grant_id not found: {record.get('grant_id')}"]
        if grant.get("agent_id") != record.get("agent_id"):
            errors.append("risk assessment agent_id differs from grant")
        if grant.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("risk assessment authority_domain_id differs from grant")
        if RISK_RANK.get(record.get("risk_tier"), 99) > RISK_RANK.get(grant.get("maximum_risk_tier"), -1):
            errors.append("risk assessment exceeds grant maximum_risk_tier")
        action = record.get("requested_action", {})
        capability = grant.get("capability", {})
        if action.get("action_type") != capability.get("action_type"):
            errors.append("risk-assessed action_type is outside capability grant")
        if action.get("target") not in capability.get("targets", []):
            errors.append("risk-assessed target is outside capability grant")
        if action.get("tool") not in capability.get("allowed_tools", []):
            errors.append("risk-assessed tool is outside capability grant")

    elif record_type == "authorization_quorum_receipt":
        risk = registry.get(record.get("risk_assessment_id"))
        if risk is None:
            return [f"risk_assessment_id not found: {record.get('risk_assessment_id')}"]
        for field in ("authority_domain_id", "agent_id", "grant_id", "action_digest"):
            if record.get(field) != risk.get(field):
                errors.append(f"authorization quorum {field} differs from risk assessment")
        controls = risk.get("required_controls", {})
        policy = record.get("policy", {})
        if policy.get("minimum_approvals") != controls.get("minimum_approvals"):
            errors.append("authorization quorum minimum_approvals differs from risk controls")
        if set(policy.get("required_roles", [])) != set(controls.get("required_roles", [])):
            errors.append("authorization quorum required_roles differ from risk controls")
        if risk.get("decision") != "classified" and record.get("decision") == "satisfied":
            errors.append("quorum cannot be satisfied for an unclassified risk")
        assessed_at, _ = parse_datetime(risk.get("assessed_at"), "risk.assessed_at")
        assembled_at, _ = parse_datetime(record.get("assembled_at"), "assembled_at")
        if assessed_at and assembled_at and assembled_at < assessed_at:
            errors.append("authorization quorum assembled before risk assessment")

    elif record_type == "irreversible_action_commitment":
        risk = registry.get(record.get("risk_assessment_id"))
        quorum = registry.get(record.get("quorum_id"))
        if risk is None:
            errors.append(f"risk_assessment_id not found: {record.get('risk_assessment_id')}")
        if quorum is None:
            errors.append(f"quorum_id not found: {record.get('quorum_id')}")
        if not risk or not quorum:
            return errors
        for field in ("authority_domain_id", "agent_id", "grant_id", "action_digest"):
            if record.get(field) != risk.get(field):
                errors.append(f"commitment {field} differs from risk assessment")
            if record.get(field) != quorum.get(field):
                errors.append(f"commitment {field} differs from authorization quorum")
        if quorum.get("decision") != "satisfied":
            errors.append("commitment requires a satisfied authorization quorum")
        if risk.get("required_controls", {}).get("commitment_required") is not True:
            errors.append("commitment supplied for risk profile that does not require commitment")
        prepared_at, _ = parse_datetime(record.get("prepared_at"), "prepared_at")
        not_before, _ = parse_datetime(record.get("not_before"), "not_before")
        cooling = risk.get("required_controls", {}).get("cooling_off_seconds", 0)
        if prepared_at and not_before and not_before < prepared_at + timedelta(seconds=cooling):
            errors.append("commitment not_before does not satisfy required cooling-off period")

    elif record_type == "action_gate_receipt":
        risk = registry.get(record.get("risk_assessment_id"))
        quorum = registry.get(record.get("authorization_quorum_id"))
        commitment_id = record.get("commitment_id")
        commitment = registry.get(commitment_id) if commitment_id else None
        if risk is None:
            errors.append(f"risk_assessment_id not found: {record.get('risk_assessment_id')}")
        if quorum is None:
            errors.append(f"authorization_quorum_id not found: {record.get('authorization_quorum_id')}")
        if not risk or not quorum:
            return errors
        for other, label in ((risk, "risk assessment"), (quorum, "authorization quorum")):
            for field in ("authority_domain_id", "agent_id", "grant_id", "action_digest"):
                if record.get(field) != other.get(field):
                    errors.append(f"action gate {field} differs from {label}")
        if not same_action(record.get("requested_action", {}), risk.get("requested_action", {})):
            errors.append("action gate requested_action differs from risk assessment")
        if risk.get("decision") != "classified":
            errors.append("action gate requires classified risk")
        if quorum.get("decision") != "satisfied":
            errors.append("action gate requires satisfied authorization quorum")
        evaluated_at, _ = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        q_expiry = approval_expiry(quorum)
        if evaluated_at and q_expiry and evaluated_at >= q_expiry:
            errors.append("authorization quorum expired before action gate evaluation")
        commitment_required = risk.get("required_controls", {}).get("commitment_required") is True
        if commitment_required and commitment is None:
            errors.append("risk profile requires an irreversible action commitment")
        if not commitment_required and commitment_id is not None:
            errors.append("action gate must not attach commitment when risk profile does not require it")
        if commitment:
            if commitment.get("decision") != "committed":
                errors.append("action gate commitment is not committed")
            for field in ("authority_domain_id", "agent_id", "grant_id", "action_digest"):
                if record.get(field) != commitment.get(field):
                    errors.append(f"action gate {field} differs from commitment")
            expires_at, _ = parse_datetime(commitment.get("expires_at"), "commitment.expires_at")
            if evaluated_at and expires_at and evaluated_at >= expires_at:
                errors.append("irreversible action commitment expired before action gate evaluation")
        if record.get("decision") == "allowed" and risk.get("impact", {}).get("reversibility") == "irreversible" and not record.get("checks", {}).get("irreversible_action"):
            errors.append("irreversible risk must set checks.irreversible_action=true")

    elif record_type == "execution_continuity_receipt":
        gate = registry.get(record.get("receipt_id"))
        if gate:
            for field in ("risk_assessment_id", "authorization_quorum_id", "commitment_id"):
                if record.get(field) != gate.get(field):
                    errors.append(f"continuity {field} differs from action gate")
            checked_at, _ = parse_datetime(record.get("checked_at"), "checked_at")
            quorum = registry.get(record.get("authorization_quorum_id"))
            if quorum and checked_at:
                q_expiry = approval_expiry(quorum)
                if q_expiry and checked_at >= q_expiry and record.get("decision") == "continue":
                    errors.append("continuity must not continue after authorization quorum expiry")
            commitment_id = record.get("commitment_id")
            commitment = registry.get(commitment_id) if commitment_id else None
            if commitment and checked_at:
                expiry, _ = parse_datetime(commitment.get("expires_at"), "commitment.expires_at")
                if expiry and checked_at >= expiry and record.get("decision") == "continue":
                    errors.append("continuity must not continue after commitment expiry")

    return errors



EGRESS_SIDE_EFFECTS = {"network_write", "public_output"}


def v04_semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "execution_context_attestation":
        attested_at, e1 = parse_datetime(record.get("attested_at"), "attested_at")
        valid_until, e2 = parse_datetime(record.get("valid_until"), "valid_until")
        errors.extend(e1 + e2)
        if attested_at and valid_until and valid_until <= attested_at:
            errors.append("execution context valid_until must be later than attested_at")
        if record.get("attestor", {}).get("attestor_id") == record.get("agent_id"):
            errors.append("agent must not attest its own execution context")
        if record.get("status") == "trusted":
            errors.extend(all_true(record.get("checks", {}), (
                "runtime_identity_verified", "image_digest_verified", "code_digest_verified",
                "isolation_enforced", "network_policy_loaded", "credential_broker_bound",
                "recorder_bound", "policy_engine_bound", "revocation_epoch_current",
            ), "checks"))

    elif record_type == "tool_identity_attestation":
        attested_at, e1 = parse_datetime(record.get("attested_at"), "attested_at")
        valid_until, e2 = parse_datetime(record.get("valid_until"), "valid_until")
        errors.extend(e1 + e2)
        if attested_at and valid_until and valid_until <= attested_at:
            errors.append("tool attestation valid_until must be later than attested_at")
        if record.get("attestor", {}).get("attestor_id") == record.get("tool_id"):
            errors.append("tool must not attest itself")
        if record.get("status") == "trusted":
            errors.extend(all_true(record.get("checks", {}), (
                "identity_verified", "binary_digest_verified", "manifest_verified",
                "supply_chain_verified", "permissions_minimized", "no_ambient_credentials",
            ), "checks"))
        manifest = record.get("manifest", {})
        if manifest.get("credential_access") == "brokered" and record.get("checks", {}).get("no_ambient_credentials") is not True:
            errors.append("brokered credential access still requires no ambient credentials")
        if EGRESS_SIDE_EFFECTS.intersection(set(manifest.get("side_effects", []))) and manifest.get("data_egress_capable") is not True:
            errors.append("tool with outbound write/public output side effects must declare data_egress_capable")

    elif record_type == "data_egress_authorization":
        authorized_at, e1 = parse_datetime(record.get("authorized_at"), "authorized_at")
        valid_until, e2 = parse_datetime(record.get("valid_until"), "valid_until")
        errors.extend(e1 + e2)
        if authorized_at and valid_until and valid_until <= authorized_at:
            errors.append("data egress valid_until must be later than authorized_at")
        if record.get("issuer", {}).get("issuer_id") == record.get("agent_id"):
            errors.append("agent must not authorize its own data egress")
        required = set(record.get("transformations", {}).get("required", []))
        applied = set(record.get("transformations", {}).get("applied", []))
        if not required.issubset(applied):
            errors.append("required data transformations were not all applied")
        if record.get("source_data", {}).get("estimated_bytes", 0) > record.get("limits", {}).get("max_bytes", -1):
            errors.append("estimated egress size exceeds max_bytes")
        if record.get("decision") == "allowed":
            errors.extend(all_true(record.get("checks", {}), (
                "data_classes_within_grant", "destination_within_grant", "content_digest_bound",
                "transformations_applied", "secrets_absent", "pii_policy_satisfied",
                "size_within_limit", "retention_bounded", "human_review_satisfied",
            ), "checks"))

    elif record_type == "runtime_interlock_record":
        checked_at, e1 = parse_datetime(record.get("checked_at"), "checked_at")
        valid_until, e2 = parse_datetime(record.get("valid_until"), "valid_until")
        errors.extend(e1 + e2)
        if checked_at and valid_until and valid_until <= checked_at:
            errors.append("runtime interlock valid_until must be later than checked_at")
        checks = record.get("checks", {})
        monitors = record.get("monitors", {})
        if record.get("decision") == "permit":
            errors.extend(all_true(checks, (
                "context_valid", "policy_engine_healthy", "recorder_healthy",
                "network_guard_healthy", "credential_broker_healthy", "tool_guard_healthy",
                "egress_guard_healthy", "revocation_clear", "grant_epoch_current",
            ), "checks"))
            unhealthy = [name for name, state in monitors.items() if state != "healthy"]
            if unhealthy:
                errors.append(f"runtime interlock cannot permit with unhealthy monitors: {unhealthy}")
            if record.get("triggers"):
                errors.append("runtime interlock cannot permit while triggers are active")

    elif record_type == "action_gate_receipt" and record.get("decision") == "allowed":
        errors.extend(all_true(record.get("checks", {}), (
            "execution_context_valid", "context_bound_to_agent", "authority_domain_bound",
            "tool_identity_valid", "tool_digest_current", "tool_allowed_in_context",
            "runtime_interlock_armed", "interlock_fail_closed", "data_boundary_satisfied",
        ), "checks"))

    elif record_type == "execution_continuity_receipt" and record.get("decision") == "continue":
        errors.extend(all_true(record.get("checks", {}), (
            "execution_context_still_valid", "tool_identity_unchanged",
            "runtime_interlock_still_armed", "data_boundary_still_satisfied",
        ), "checks"))

    elif record_type == "runtime_trace_record":
        if record.get("final_status") == "completed":
            if record.get("context_drift_observed"):
                errors.append("completed runtime trace must not contain context drift")
            if record.get("tool_substitution_observed"):
                errors.append("completed runtime trace must not contain tool substitution")
            if record.get("data_egress_violation_observed"):
                errors.append("completed runtime trace must not contain a data egress violation")

    return errors


def _active_at(record: dict[str, Any], start_field: str, end_field: str, moment: datetime | None) -> bool:
    if moment is None:
        return False
    start, _ = parse_datetime(record.get(start_field), start_field)
    end, _ = parse_datetime(record.get(end_field), end_field)
    return bool(start and end and start <= moment < end)


def v04_cross_record_errors(record: dict[str, Any], registry: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "execution_context_attestation":
        grant = registry.get(record.get("grant_id"))
        if grant is None:
            return [f"grant_id not found: {record.get('grant_id')}"]
        if grant.get("agent_id") != record.get("agent_id"):
            errors.append("execution context agent_id differs from grant")
        if grant.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("execution context authority_domain_id differs from grant")
        effective_epoch, effective_expiry, state_errors = effective_grant_state(grant, registry)
        errors.extend(state_errors)
        if record.get("grant_epoch") != effective_epoch:
            errors.append("execution context uses stale grant_epoch")
        attested_at, _ = parse_datetime(record.get("attested_at"), "attested_at")
        valid_until, _ = parse_datetime(record.get("valid_until"), "valid_until")
        grant_start, _ = parse_datetime(grant.get("valid_from"), "grant.valid_from")
        if attested_at and grant_start and attested_at < grant_start:
            errors.append("execution context attested before grant validity")
        if valid_until and effective_expiry and valid_until > effective_expiry:
            errors.append("execution context outlives effective grant")
        if attested_at and current_domain_epoch(record.get("authority_domain_id"), attested_at, registry) != record.get("observed_revocation_epoch"):
            errors.append("execution context observed_revocation_epoch is stale")

    elif record_type == "tool_identity_attestation":
        for context_id in record.get("allowed_context_ids", []):
            context = registry.get(context_id)
            if context is None:
                errors.append(f"allowed execution context not found: {context_id}")
            elif context.get("authority_domain_id") != record.get("authority_domain_id"):
                errors.append("tool attestation context has different authority domain")

    elif record_type == "data_egress_authorization":
        grant = registry.get(record.get("grant_id"))
        context = registry.get(record.get("context_id"))
        tool = registry.get(record.get("tool_attestation_id"))
        if grant is None:
            errors.append(f"grant_id not found: {record.get('grant_id')}")
        if context is None:
            errors.append(f"context_id not found: {record.get('context_id')}")
        if tool is None:
            errors.append(f"tool_attestation_id not found: {record.get('tool_attestation_id')}")
        if not grant or not context or not tool:
            return errors
        for other, label in ((grant, "grant"), (context, "execution context")):
            for field in ("agent_id", "authority_domain_id", "grant_id"):
                if field in other and record.get(field) != other.get(field):
                    errors.append(f"data egress {field} differs from {label}")
        if context.get("grant_id") != record.get("grant_id"):
            errors.append("data egress context is bound to another grant")
        if tool.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("data egress tool has different authority domain")
        if record.get("context_id") not in tool.get("allowed_context_ids", []):
            errors.append("data egress tool is not authorized in execution context")
        if tool.get("manifest", {}).get("data_egress_capable") is not True:
            errors.append("data egress authorization references a non-egress-capable tool")
        constraints = grant.get("constraints", {})
        if not set(record.get("source_data", {}).get("data_classes", [])).issubset(set(constraints.get("data_classes", []))):
            errors.append("data egress classes exceed grant constraints")
        if record.get("destination", {}).get("network_destination") not in constraints.get("network_destinations", []):
            errors.append("data egress destination is outside grant constraints")
        if record.get("destination", {}).get("target") not in grant.get("capability", {}).get("targets", []):
            errors.append("data egress target is outside grant capability")
        authorized_at, _ = parse_datetime(record.get("authorized_at"), "authorized_at")
        if authorized_at and not _active_at(context, "attested_at", "valid_until", authorized_at):
            errors.append("data egress authorized outside execution context validity")
        if authorized_at and not _active_at(tool, "attested_at", "valid_until", authorized_at):
            errors.append("data egress authorized outside tool attestation validity")

    elif record_type == "runtime_interlock_record":
        grant = registry.get(record.get("grant_id"))
        context = registry.get(record.get("context_id"))
        if grant is None:
            errors.append(f"grant_id not found: {record.get('grant_id')}")
        if context is None:
            errors.append(f"context_id not found: {record.get('context_id')}")
        if not grant or not context:
            return errors
        for field in ("agent_id", "authority_domain_id", "grant_id", "grant_epoch", "observed_revocation_epoch"):
            if field in context and record.get(field) != context.get(field):
                errors.append(f"runtime interlock {field} differs from execution context")
        checked_at, _ = parse_datetime(record.get("checked_at"), "checked_at")
        valid_until, _ = parse_datetime(record.get("valid_until"), "valid_until")
        if checked_at and not _active_at(context, "attested_at", "valid_until", checked_at):
            errors.append("runtime interlock checked outside execution context validity")
        context_expiry, _ = parse_datetime(context.get("valid_until"), "context.valid_until")
        if valid_until and context_expiry and valid_until > context_expiry:
            errors.append("runtime interlock outlives execution context")
        if record.get("decision") == "permit" and context.get("status") != "trusted":
            errors.append("runtime interlock cannot permit an untrusted execution context")

    elif record_type == "action_gate_receipt":
        context = registry.get(record.get("execution_context_id"))
        tool = registry.get(record.get("tool_attestation_id"))
        interlock = registry.get(record.get("runtime_interlock_id"))
        egress_id = record.get("data_egress_authorization_id")
        egress = registry.get(egress_id) if egress_id else None
        for value, label in ((context, "execution_context_id"), (tool, "tool_attestation_id"), (interlock, "runtime_interlock_id")):
            if value is None:
                errors.append(f"{label} not found: {record.get(label)}")
        if not context or not tool or not interlock:
            return errors
        for other, label in ((context, "execution context"), (interlock, "runtime interlock")):
            for field in ("agent_id", "authority_domain_id", "grant_id", "grant_epoch"):
                if record.get(field) != other.get(field):
                    errors.append(f"action gate {field} differs from {label}")
        if tool.get("authority_domain_id") != record.get("authority_domain_id"):
            errors.append("action gate tool attestation has different authority domain")
        if record.get("execution_context_id") not in tool.get("allowed_context_ids", []):
            errors.append("action gate tool is not authorized in execution context")
        if tool.get("tool_id") != record.get("requested_action", {}).get("tool"):
            errors.append("action gate requested tool differs from attested tool identity")
        if record.get("requested_action", {}).get("action_type") not in tool.get("manifest", {}).get("action_types", []):
            errors.append("action gate action_type is absent from tool manifest")
        evaluated_at, _ = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        if evaluated_at and not _active_at(context, "attested_at", "valid_until", evaluated_at):
            errors.append("execution context is not valid at action gate evaluation")
        if evaluated_at and not _active_at(tool, "attested_at", "valid_until", evaluated_at):
            errors.append("tool attestation is not valid at action gate evaluation")
        if evaluated_at and not _active_at(interlock, "checked_at", "valid_until", evaluated_at):
            errors.append("runtime interlock is not valid at action gate evaluation")
        if context.get("status") != "trusted":
            errors.append("action gate requires trusted execution context")
        if tool.get("status") != "trusted":
            errors.append("action gate requires trusted tool identity")
        if interlock.get("decision") != "permit":
            errors.append("action gate requires permitting runtime interlock")
        requires_egress = bool(EGRESS_SIDE_EFFECTS.intersection(set(tool.get("manifest", {}).get("side_effects", []))))
        if requires_egress and egress is None:
            errors.append("outbound write/public output action requires data egress authorization")
        if not requires_egress and egress_id is not None:
            errors.append("non-egress action must not attach data egress authorization")
        if egress:
            if egress.get("decision") != "allowed":
                errors.append("action gate data egress authorization is not allowed")
            for field in ("agent_id", "authority_domain_id", "grant_id", "action_digest"):
                if record.get(field) != egress.get(field):
                    errors.append(f"action gate {field} differs from data egress authorization")
            if record.get("execution_context_id") != egress.get("context_id"):
                errors.append("action gate execution context differs from data egress authorization")
            if record.get("tool_attestation_id") != egress.get("tool_attestation_id"):
                errors.append("action gate tool attestation differs from data egress authorization")
            if evaluated_at and not _active_at(egress, "authorized_at", "valid_until", evaluated_at):
                errors.append("data egress authorization is not valid at action gate evaluation")

    elif record_type == "execution_continuity_receipt":
        gate = registry.get(record.get("receipt_id"))
        if gate:
            for field in ("execution_context_id", "tool_attestation_id", "runtime_interlock_id", "data_egress_authorization_id"):
                if record.get(field) != gate.get(field):
                    errors.append(f"continuity {field} differs from action gate")
            if record.get("decision") == "continue":
                checked_at, _ = parse_datetime(record.get("checked_at"), "checked_at")
                context = registry.get(record.get("execution_context_id"))
                tool = registry.get(record.get("tool_attestation_id"))
                interlock = registry.get(record.get("runtime_interlock_id"))
                egress_id = record.get("data_egress_authorization_id")
                egress = registry.get(egress_id) if egress_id else None
                if context and checked_at and not _active_at(context, "attested_at", "valid_until", checked_at):
                    errors.append("continuity must not continue after execution context expiry")
                if tool and checked_at and not _active_at(tool, "attested_at", "valid_until", checked_at):
                    errors.append("continuity must not continue after tool attestation expiry")
                if interlock and checked_at and not _active_at(interlock, "checked_at", "valid_until", checked_at):
                    errors.append("continuity must not continue after runtime interlock expiry")
                if interlock and interlock.get("decision") != "permit":
                    errors.append("continuity requires permitting runtime interlock")
                if egress and checked_at and not _active_at(egress, "authorized_at", "valid_until", checked_at):
                    errors.append("continuity must not continue after data egress authorization expiry")

    elif record_type == "runtime_trace_record":
        gate = registry.get(record.get("receipt_id"))
        if gate:
            for field in ("execution_context_id", "tool_attestation_id", "runtime_interlock_id", "data_egress_authorization_id"):
                if record.get(field) != gate.get(field):
                    errors.append(f"runtime trace {field} differs from action gate")
        if record.get("context_drift_observed") and record.get("final_status") not in {"blocked", "failed", "zeroized"}:
            errors.append("context drift requires blocked, failed, or zeroized final status")
        if record.get("tool_substitution_observed") and record.get("final_status") not in {"blocked", "failed", "zeroized"}:
            errors.append("tool substitution requires blocked, failed, or zeroized final status")
        if record.get("data_egress_violation_observed") and record.get("final_status") not in {"blocked", "failed", "zeroized"}:
            errors.append("data egress violation requires blocked, failed, or zeroized final status")

    return errors


def v05_semantic_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "authority_evidence_chain":
        entries = record.get("entries", [])
        sequences = [entry.get("sequence") for entry in entries]
        if sequences != list(range(1, len(entries) + 1)):
            errors.append("entries.sequence must be contiguous and start at 1")
        record_ids = [entry.get("record_id") for entry in entries]
        if len(record_ids) != len(set(record_ids)):
            errors.append("authority evidence chain must not contain duplicate record_id values")
        previous_time: datetime | None = None
        for index, entry in enumerate(entries):
            observed_at, date_errors = parse_datetime(entry.get("observed_at"), f"entries[{index}].observed_at")
            errors.extend(date_errors)
            if observed_at and previous_time and observed_at < previous_time:
                errors.append("authority evidence entries must be ordered chronologically")
            if observed_at:
                previous_time = observed_at
        if record.get("recorder", {}).get("recorder_id") == record.get("agent_id"):
            errors.append("agent must not record its own authority evidence chain")
        signature = record.get("signature", {})
        if signature.get("signer_id") == record.get("agent_id"):
            errors.append("agent must not sign its own authority evidence chain")
        if signature.get("signed_chain_root") != record.get("chain_root"):
            errors.append("signature.signed_chain_root must equal chain_root")

    elif record_type == "execution_closure_receipt":
        closed_at, e1 = parse_datetime(record.get("closed_at"), "closed_at")
        first, e2 = parse_datetime(record.get("token_consumption", {}).get("first_consumed_at"), "token_consumption.first_consumed_at")
        last, e3 = parse_datetime(record.get("token_consumption", {}).get("last_consumed_at"), "token_consumption.last_consumed_at")
        errors.extend(e1 + e2 + e3)
        if first and last and last < first:
            errors.append("token_consumption.last_consumed_at must not precede first_consumed_at")
        if closed_at and last and closed_at < last:
            errors.append("closed_at must not precede token consumption")
        if record.get("decision") == "closed":
            errors.extend(all_true(record.get("checks", {}), (
                "trace_finalized", "token_single_use", "no_pending_external_effects",
                "outputs_accounted", "egress_reconciled", "credentials_expired_or_destroyed",
                "child_tasks_closed", "recorder_finalized", "evidence_ready_for_sealing",
            ), "checks"))
            token = record.get("token_consumption", {})
            if token.get("consumed_count") != 1:
                errors.append("closed execution requires token_consumption.consumed_count=1")
            if token.get("replay_blocked") is not True:
                errors.append("closed execution requires replay_blocked=true")
            if token.get("nonce_retired") is not True:
                errors.append("closed execution requires nonce_retired=true")
            if record.get("pending_external_effect_count") != 0:
                errors.append("closed execution requires pending_external_effect_count=0")
        if record.get("final_execution_status") == "zeroized":
            if not record.get("zeroization_id"):
                errors.append("zeroized execution closure requires zeroization_id")
            if not record.get("zero_state_record_id"):
                errors.append("zeroized execution closure requires zero_state_record_id")
            if record.get("authority_after_closure", {}).get("grant_status") != "revoked":
                errors.append("zeroized execution closure requires grant_status=revoked")

    elif record_type == "conformance_assessment_record":
        if record.get("verifier", {}).get("verifier_id") == record.get("agent_id"):
            errors.append("agent must not verify its own conformance")
        if record.get("result") == "conformant":
            errors.extend(all_true(record.get("checks", {}), (
                "schemas_valid", "identifiers_unique", "record_digests_match",
                "chain_links_valid", "timestamps_monotonic", "bindings_complete",
                "authorization_precedes_action", "token_single_use", "revocation_enforced",
                "closure_complete", "evidence_independent",
            ), "checks"))
            serious = [finding for finding in record.get("findings", []) if finding.get("severity") in {"error", "critical"}]
            if serious:
                errors.append("conformant assessment must not contain error or critical findings")

    elif record_type == "incident_containment_receipt":
        detected_at, e1 = parse_datetime(record.get("detected_at"), "detected_at")
        contained_at, e2 = parse_datetime(record.get("contained_at"), "contained_at")
        errors.extend(e1 + e2)
        if detected_at and contained_at and contained_at < detected_at:
            errors.append("contained_at must not precede detected_at")
        if record.get("detector", {}).get("detector_id") == record.get("agent_id"):
            errors.append("agent must not be the sole detector of its own incident")
        if record.get("status") == "contained":
            errors.extend(all_true(record.get("immediate_actions", {}), (
                "execution_suspended", "tokens_invalidated", "network_blocked",
                "credentials_quarantined", "context_quarantined",
                "evidence_snapshot_preserved", "revocation_initiated",
            ), "immediate_actions"))

    return errors


def authority_chain_errors(record: dict[str, Any], registry: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    entries = record.get("entries", [])
    previous_digest = "genesis"
    previous_time: datetime | None = None
    seen_types: list[str] = []
    for index, entry in enumerate(entries):
        referenced = registry.get(entry.get("record_id"))
        if referenced is None:
            errors.append(f"evidence entry record_id not found: {entry.get('record_id')}")
            continue
        if referenced.get("record_type") != entry.get("record_type"):
            errors.append(f"evidence entry record_type mismatch: {entry.get('record_id')}")
        if primary_identifier(referenced) != entry.get("record_id"):
            errors.append(f"evidence entry primary identifier mismatch: {entry.get('record_id')}")
        expected_record_digest = sha256_digest(referenced)
        if entry.get("record_digest") != expected_record_digest:
            errors.append(f"record digest mismatch: {entry.get('record_id')}")
        if entry.get("previous_entry_digest") != previous_digest:
            errors.append(f"broken evidence chain link at sequence {entry.get('sequence')}")
        expected_entry_digest = sha256_digest(evidence_entry_payload(entry))
        if entry.get("entry_digest") != expected_entry_digest:
            errors.append(f"entry digest mismatch at sequence {entry.get('sequence')}")
        previous_digest = entry.get("entry_digest")
        observed_at, date_errors = parse_datetime(entry.get("observed_at"), f"entries[{index}].observed_at")
        errors.extend(date_errors)
        if observed_at and previous_time and observed_at < previous_time:
            errors.append("authority evidence timestamps are not monotonic")
        if observed_at:
            previous_time = observed_at
        seen_types.append(str(entry.get("record_type")))
        for field in ("agent_id", "authority_domain_id"):
            if field in referenced and referenced.get(field) != record.get(field):
                errors.append(f"evidence entry {field} differs from chain: {entry.get('record_id')}")
    if entries and record.get("chain_root") != entries[-1].get("entry_digest"):
        errors.append("chain_root must equal the final entry_digest")
    required_types = {"capability_grant", "action_gate_receipt", "runtime_trace_record", "execution_closure_receipt"}
    missing = sorted(required_types.difference(seen_types))
    if missing:
        errors.append(f"authority evidence chain missing required record types: {missing}")
    order = {record_type: index for index, record_type in enumerate(seen_types)}
    if "action_gate_receipt" in order and "runtime_trace_record" in order and order["action_gate_receipt"] > order["runtime_trace_record"]:
        errors.append("action authorization must precede runtime trace")
    if "runtime_trace_record" in order and "execution_closure_receipt" in order and order["runtime_trace_record"] > order["execution_closure_receipt"]:
        errors.append("runtime trace must precede execution closure")
    return errors


def v05_cross_record_errors(record: dict[str, Any], registry: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "authority_evidence_chain":
        errors.extend(authority_chain_errors(record, registry))

    elif record_type == "execution_closure_receipt":
        gate = registry.get(record.get("receipt_id"))
        trace = registry.get(record.get("trace_id"))
        if gate is None:
            errors.append(f"receipt_id not found: {record.get('receipt_id')}")
        if trace is None:
            errors.append(f"trace_id not found: {record.get('trace_id')}")
        if gate:
            for field in ("agent_id", "authority_domain_id", "grant_id", "grant_epoch"):
                if record.get(field) != gate.get(field):
                    errors.append(f"execution closure {field} differs from action gate")
            if gate.get("execution_token", {}).get("token_id") != record.get("execution_token_id"):
                errors.append("execution closure token differs from action gate")
        if trace:
            for field in ("agent_id", "authority_domain_id", "grant_id", "grant_epoch", "receipt_id", "execution_token_id"):
                if record.get(field) != trace.get(field):
                    errors.append(f"execution closure {field} differs from runtime trace")
            if record.get("final_execution_status") != trace.get("final_status"):
                errors.append("execution closure final status differs from runtime trace")
            closed_at, _ = parse_datetime(record.get("closed_at"), "closed_at")
            trace_completed, _ = parse_datetime(trace.get("completed_at"), "trace.completed_at")
            if closed_at and trace_completed and closed_at < trace_completed:
                errors.append("execution closure occurs before runtime trace completion")
        if record.get("incident_containment_id") and registry.get(record.get("incident_containment_id")) is None:
            errors.append(f"incident_containment_id not found: {record.get('incident_containment_id')}")
        zeroization = registry.get(record.get("zeroization_id")) if record.get("zeroization_id") else None
        zero_state = registry.get(record.get("zero_state_record_id")) if record.get("zero_state_record_id") else None
        if record.get("final_execution_status") == "zeroized":
            if zeroization is None:
                errors.append(f"zeroization_id not found: {record.get('zeroization_id')}")
            if zero_state is None:
                errors.append(f"zero_state_record_id not found: {record.get('zero_state_record_id')}")
            if zeroization and zeroization.get("final_state", {}).get("zero_state_record_id") != record.get("zero_state_record_id"):
                errors.append("execution closure zero state differs from zeroization record")
            if zero_state and zero_state.get("authority_domain_id") != record.get("authority_domain_id"):
                errors.append("execution closure zero state has different authority domain")

    elif record_type == "incident_containment_receipt":
        for revocation_id in record.get("revocation_record_ids", []):
            revocation = registry.get(revocation_id)
            if revocation is None:
                errors.append(f"revocation record not found: {revocation_id}")
            elif revocation.get("authority_domain_id") != record.get("authority_domain_id"):
                errors.append("incident revocation has different authority domain")
        zeroization = registry.get(record.get("zeroization_id"))
        if zeroization is None:
            errors.append(f"zeroization_id not found: {record.get('zeroization_id')}")
        else:
            if zeroization.get("agent_id") != record.get("agent_id"):
                errors.append("incident zeroization has different agent")
            if zeroization.get("authority_domain_id") != record.get("authority_domain_id"):
                errors.append("incident zeroization has different authority domain")
            contained_at, _ = parse_datetime(record.get("contained_at"), "contained_at")
            completed_at, _ = parse_datetime(zeroization.get("completed_at"), "zeroization.completed_at")
            if contained_at and completed_at and contained_at > completed_at:
                errors.append("incident marked contained after referenced zeroization completion")
        token_map = token_receipts(registry)
        for token_id in record.get("affected", {}).get("execution_token_ids", []):
            if token_id not in token_map:
                errors.append(f"affected execution token not found: {token_id}")
        for field, expected_type in (
            ("grant_ids", "capability_grant"),
            ("execution_context_ids", "execution_context_attestation"),
            ("tool_attestation_ids", "tool_identity_attestation"),
            ("trace_ids", "runtime_trace_record"),
        ):
            for record_id in record.get("affected", {}).get(field, []):
                referenced = registry.get(record_id)
                if referenced is None:
                    errors.append(f"affected record not found: {record_id}")
                elif referenced.get("record_type") != expected_type:
                    errors.append(f"affected record has wrong type: {record_id}")

    elif record_type == "conformance_assessment_record":
        chain = registry.get(record.get("chain_id"))
        if chain is None:
            return [f"chain_id not found: {record.get('chain_id')}"]
        if record.get("chain_root") != chain.get("chain_root"):
            errors.append("conformance chain_root differs from evidence chain")
        for field in ("agent_id", "authority_domain_id"):
            if record.get(field) != chain.get(field):
                errors.append(f"conformance {field} differs from evidence chain")
        if record.get("scope", {}).get("entry_count") != len(chain.get("entries", [])):
            errors.append("conformance scope.entry_count differs from evidence chain")
        chain_types = sorted({entry.get("record_type") for entry in chain.get("entries", [])})
        if sorted(record.get("scope", {}).get("record_types", [])) != chain_types:
            errors.append("conformance scope.record_types differs from evidence chain")
        assessed_at, _ = parse_datetime(record.get("assessed_at"), "assessed_at")
        generated_at, _ = parse_datetime(chain.get("generated_at"), "chain.generated_at")
        if assessed_at and generated_at and assessed_at < generated_at:
            errors.append("conformance assessment predates evidence chain generation")
        chain_errors = authority_chain_errors(chain, registry)
        if record.get("result") == "conformant" and chain_errors:
            errors.append("conformant assessment references an invalid evidence chain")

    return errors


def validate_record(path: Path, schemas: dict[str, dict[str, Any]], registry: dict[str, dict[str, Any]]) -> list[str]:
    try:
        record = load_yaml(path)
    except Exception as exc:  # noqa: BLE001
        return [f"load error: {exc}"]
    errors = schema_errors(record, schemas)
    if errors:
        return errors
    errors.extend(semantic_errors(record))
    errors.extend(v03_semantic_errors(record))
    errors.extend(v04_semantic_errors(record))
    errors.extend(v05_semantic_errors(record))
    errors.extend(cross_record_errors(record, registry))
    errors.extend(v03_cross_record_errors(record, registry))
    errors.extend(v04_cross_record_errors(record, registry))
    errors.extend(v05_cross_record_errors(record, registry))
    return errors


def main() -> int:
    print("=== Zero-Type Agent Zero-Authority Profile v0.5 Validation ===")
    try:
        schemas = {record_type: load_json(path) for record_type, path in SCHEMA_BY_RECORD_TYPE.items()}
    except Exception as exc:  # noqa: BLE001
        print(f"[fatal] failed to load schema: {exc}")
        return 1
    for record_type, path in SCHEMA_BY_RECORD_TYPE.items():
        print(f"schema [{record_type}]: {path.relative_to(ROOT)}")

    pass_paths = sorted(PASS_DIR.glob("*.yaml"))
    fail_paths = sorted(FAIL_DIR.glob("*.yaml"))
    loaded_pass: list[tuple[Path, dict[str, Any]]] = []
    preflight_failed = False
    for path in pass_paths:
        try:
            record = load_yaml(path)
        except Exception as exc:  # noqa: BLE001
            print(f"[fatal] {path.relative_to(ROOT)}: load error: {exc}")
            preflight_failed = True
            continue
        errors = schema_errors(record, schemas)
        if errors:
            print(f"[fatal] {path.relative_to(ROOT)} is not schema-valid for registry construction")
            for error in errors:
                print(f"  - {error}")
            preflight_failed = True
            continue
        loaded_pass.append((path, record))
    if preflight_failed:
        print("Validation failed.")
        return 1

    registry, registry_errors = build_registry(loaded_pass)
    if registry_errors:
        for error in registry_errors:
            print(f"[fatal] {error}")
        print("Validation failed.")
        return 1

    failed = False
    for path in pass_paths:
        print(f"\n[validate-pass] {path.relative_to(ROOT)}")
        errors = validate_record(path, schemas, registry)
        if errors:
            failed = True
            for error in errors:
                print(f"  - {error}")
        else:
            print("[schema-ok]")
            print("[semantic-ok]")
            print("[cross-record-ok]")

    for path in fail_paths:
        print(f"\n[validate-fail] {path.relative_to(ROOT)}")
        errors = validate_record(path, schemas, registry)
        if errors:
            print("[expected-fail]")
            for error in errors:
                print(f"  - {error}")
        else:
            failed = True
            print("  - invalid example unexpectedly passed")

    print()
    if failed:
        print("Validation failed.")
        return 1
    print("All pass examples succeeded and all fail examples were rejected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
