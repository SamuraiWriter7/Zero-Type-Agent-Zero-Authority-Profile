#!/usr/bin/env python3
"""Validate Zero-Type Agent Zero-Authority Profile v0.2 examples."""

from __future__ import annotations

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
    "action_gate_receipt": SCHEMA_DIR / "action-gate-receipt.schema.json",
    "execution_continuity_receipt": SCHEMA_DIR / "execution-continuity-receipt.schema.json",
    "runtime_trace_record": SCHEMA_DIR / "runtime-trace-record.schema.json",
    "emergency_zeroization_record": SCHEMA_DIR / "emergency-zeroization-record.schema.json",
}

PRIMARY_ID_FIELD = {
    "zero_state_record": "zero_state_id",
    "capability_grant": "grant_id",
    "capability_delegation_receipt": "delegation_id",
    "capability_renewal_record": "renewal_id",
    "capability_revocation_record": "revocation_id",
    "action_gate_receipt": "receipt_id",
    "execution_continuity_receipt": "continuity_id",
    "runtime_trace_record": "trace_id",
    "emergency_zeroization_record": "zeroization_id",
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


def parse_datetime(value: Any, field_name: str) -> tuple[datetime | None, list[str]]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")), []
    except (TypeError, ValueError):
        return None, [f"{field_name}: invalid RFC 3339 date-time"]


def build_registry(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for record in records:
        record_type = record.get("record_type")
        id_field = PRIMARY_ID_FIELD.get(record_type)
        record_id = record.get(id_field) if id_field else None
        if record_id:
            if record_id in registry:
                raise ValueError(f"duplicate primary identifier: {record_id}")
            registry[record_id] = record
    return registry


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
                "child_agent_allowed", "depth_allowed", "revocation_clear",
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
                "extension_within_limit", "origin_unchanged", "revocation_clear",
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
                "invocation_budget_available", "recorder_available",
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


def validate_record(path: Path, schemas: dict[str, dict[str, Any]], registry: dict[str, dict[str, Any]]) -> list[str]:
    try:
        record = load_yaml(path)
    except Exception as exc:  # noqa: BLE001
        return [f"load error: {exc}"]
    errors = schema_errors(record, schemas)
    if errors:
        return errors
    errors.extend(semantic_errors(record))
    errors.extend(cross_record_errors(record, registry))
    return errors


def main() -> int:
    print("=== Zero-Type Agent Zero-Authority Profile v0.2 Validation ===")
    schemas = {record_type: load_json(path) for record_type, path in SCHEMA_BY_RECORD_TYPE.items()}
    for record_type, path in SCHEMA_BY_RECORD_TYPE.items():
        print(f"schema [{record_type}]: {path.relative_to(ROOT)}")

    pass_paths = sorted(PASS_DIR.glob("*.yaml"))
    fail_paths = sorted(FAIL_DIR.glob("*.yaml"))
    pass_records = [load_yaml(path) for path in pass_paths]
    registry = build_registry(pass_records)
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
