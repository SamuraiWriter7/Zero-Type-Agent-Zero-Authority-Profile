#!/usr/bin/env python3
"""Validate Zero-Type Agent Zero-Authority Profile v0.1 examples."""

from __future__ import annotations

import json
import sys
from datetime import datetime
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
    "action_gate_receipt": SCHEMA_DIR / "action-gate-receipt.schema.json",
    "runtime_trace_record": SCHEMA_DIR / "runtime-trace-record.schema.json",
    "emergency_zeroization_record": SCHEMA_DIR / "emergency-zeroization-record.schema.json",
}

PRIMARY_ID_FIELD = {
    "zero_state_record": "zero_state_id",
    "capability_grant": "grant_id",
    "action_gate_receipt": "receipt_id",
    "runtime_trace_record": "trace_id",
    "emergency_zeroization_record": "zeroization_id",
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


def parse_datetime(value: str, field_name: str) -> tuple[datetime | None, list[str]]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")), []
    except (TypeError, ValueError):
        return None, [f"{field_name}: invalid RFC 3339 date-time"]


def semantic_errors(record: dict[str, Any]) -> list[str]:
    record_type = record.get("record_type")
    errors: list[str] = []

    if record_type == "capability_grant":
        valid_from, e1 = parse_datetime(record.get("valid_from"), "valid_from")
        expires_at, e2 = parse_datetime(record.get("expires_at"), "expires_at")
        errors.extend(e1 + e2)
        if valid_from and expires_at and expires_at <= valid_from:
            errors.append("expires_at must be later than valid_from")

    elif record_type == "action_gate_receipt":
        evaluated_at, e1 = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        valid_until, e2 = parse_datetime(record.get("valid_until"), "valid_until")
        errors.extend(e1 + e2)
        if evaluated_at and valid_until and valid_until <= evaluated_at:
            errors.append("valid_until must be later than evaluated_at")

        decision = record.get("decision")
        checks = record.get("checks", {})
        required_true = (
            "grant_active",
            "within_scope",
            "target_allowed",
            "tool_allowed",
            "within_time_window",
            "invocation_budget_available",
        )
        if decision == "allowed":
            for check_name in required_true:
                if checks.get(check_name) is not True:
                    errors.append(f"allowed decision requires checks.{check_name}=true")
            if checks.get("irreversible_action") is True and not checks.get("human_approval_ref"):
                errors.append("irreversible allowed action requires human_approval_ref")
        else:
            if record.get("execution_token"):
                errors.append("non-allowed decision must not issue execution_token")

    elif record_type == "runtime_trace_record":
        started_at, e1 = parse_datetime(record.get("started_at"), "started_at")
        completed_at, e2 = parse_datetime(record.get("completed_at"), "completed_at")
        errors.extend(e1 + e2)
        if started_at and completed_at and completed_at < started_at:
            errors.append("completed_at must not be earlier than started_at")

        events = record.get("events", [])
        expected_sequences = list(range(1, len(events) + 1))
        actual_sequences = [event.get("sequence") for event in events]
        if actual_sequences != expected_sequences:
            errors.append("events.sequence must be contiguous and start at 1")

        previous_time: datetime | None = None
        for index, event in enumerate(events):
            timestamp, event_errors = parse_datetime(
                event.get("timestamp"), f"events[{index}].timestamp"
            )
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

        actions = record.get("actions", {})
        for action_name, result in actions.items():
            if result is not True:
                errors.append(f"zeroization action {action_name} must be true")

    return errors


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


def build_registry(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for record in records:
        record_type = record.get("record_type")
        id_field = PRIMARY_ID_FIELD.get(record_type)
        if id_field and record.get(id_field):
            registry[record[id_field]] = record
    return registry


def cross_record_errors(
    record: dict[str, Any], registry: dict[str, dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    record_type = record.get("record_type")

    if record_type == "action_gate_receipt":
        grant = registry.get(record.get("grant_id"))
        if grant is None:
            return [f"grant_id not found: {record.get('grant_id')}"]

        if grant.get("agent_id") != record.get("agent_id"):
            errors.append("agent_id does not match referenced capability grant")

        requested = record.get("requested_action", {})
        capability = grant.get("capability", {})
        if requested.get("action_type") != capability.get("action_type"):
            errors.append("requested action_type is outside capability grant")
        if requested.get("target") not in capability.get("targets", []):
            errors.append("requested target is outside capability grant")
        if requested.get("tool") not in capability.get("allowed_tools", []):
            errors.append("requested tool is outside capability grant")

        evaluated_at, e1 = parse_datetime(record.get("evaluated_at"), "evaluated_at")
        valid_from, e2 = parse_datetime(grant.get("valid_from"), "grant.valid_from")
        expires_at, e3 = parse_datetime(grant.get("expires_at"), "grant.expires_at")
        errors.extend(e1 + e2 + e3)
        if evaluated_at and valid_from and expires_at:
            if not valid_from <= evaluated_at < expires_at:
                errors.append("action gate evaluation is outside grant validity window")

    elif record_type == "runtime_trace_record":
        grant = registry.get(record.get("grant_id"))
        receipt = registry.get(record.get("receipt_id"))
        if grant is None:
            errors.append(f"grant_id not found: {record.get('grant_id')}")
        if receipt is None:
            errors.append(f"receipt_id not found: {record.get('receipt_id')}")

        if grant and grant.get("agent_id") != record.get("agent_id"):
            errors.append("trace agent_id does not match capability grant")
        if receipt and receipt.get("agent_id") != record.get("agent_id"):
            errors.append("trace agent_id does not match action gate receipt")
        if receipt and receipt.get("decision") != "allowed":
            errors.append("runtime trace may execute only from an allowed receipt")
        if receipt and receipt.get("grant_id") != record.get("grant_id"):
            errors.append("trace grant_id does not match action gate receipt")

        if grant:
            allowed_destinations = set(grant.get("constraints", {}).get("network_destinations", []))
            allowed_tools = set(grant.get("capability", {}).get("allowed_tools", []))
            for event in record.get("events", []):
                if event.get("event_type") == "network_request" and event.get("target") not in allowed_destinations:
                    errors.append(
                        f"network target outside grant: {event.get('target')}"
                    )
                if event.get("event_type") == "tool_call" and event.get("target") not in allowed_tools:
                    errors.append(f"tool target outside grant: {event.get('target')}")

    elif record_type == "emergency_zeroization_record":
        for grant_id in record.get("revoked_grant_ids", []):
            grant = registry.get(grant_id)
            if grant is None:
                errors.append(f"revoked grant not found: {grant_id}")
            elif grant.get("agent_id") != record.get("agent_id"):
                errors.append(f"revoked grant belongs to another agent: {grant_id}")

        zero_state_id = record.get("final_state", {}).get("zero_state_record_id")
        zero_state = registry.get(zero_state_id)
        if zero_state is None:
            errors.append(f"final zero state not found: {zero_state_id}")
        elif zero_state.get("agent_id") != record.get("agent_id"):
            errors.append("final zero state belongs to another agent")

    return errors


def validate_record(
    path: Path,
    schemas: dict[str, dict[str, Any]],
    registry: dict[str, dict[str, Any]],
) -> list[str]:
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
    print("=== Zero-Type Agent Zero-Authority Profile v0.1 Validation ===")

    schemas = {
        record_type: load_json(path)
        for record_type, path in SCHEMA_BY_RECORD_TYPE.items()
    }
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
