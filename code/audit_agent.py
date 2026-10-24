"""Evidence-driven deletion audit pipeline for Ghost Data Still Exists.

The implementation is deterministic and offline. It parses the supplied
participant-facing evidence, keeps provenance on every observation, applies
the deletion policy, and emits the challenge's constrained step schema.
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import logging
import re
import sqlite3
import unicodedata
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping, Sequence


LOGGER = logging.getLogger("ghost_data_audit")

OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}
VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

CATEGORY_SYSTEM = {
    "USER_PROFILE": "account_service",
    "SECONDARY_IDENTIFIER": "account_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "CACHE_ENTRY": "cache_service",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "analytics_platform",
    "USER_EXPORT": "export_service",
    "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "notification_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "finance_service",
    "BACKUP_ARCHIVE": "backup_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
    "DATA_FLOW": "integration_service",
}

TABLE_CATEGORY = {
    "customer_profiles": "USER_PROFILE",
    "customer_profiles_primary": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "analytics_profiles": "ANALYTICS_PROFILE",
    "profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "tickets": "SUPPORT_MESSAGE",
    "customer_exports": "USER_EXPORT",
    "exports": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW",
    "connectors": "DATA_FLOW",
    "connector_configurations": "DATA_FLOW",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "restore_entries": "BACKUP_ARCHIVE",
    "backup_catalog": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "audit_records": "SECURITY_AUDIT_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "account_tombstones": "ACCOUNT_TOMBSTONE",
    "tombstones": "ACCOUNT_TOMBSTONE",
    "profile_lookups": "USER_PROFILE",
    "index_queries": "SEARCH_INDEX_ENTRY",
    "search_documents": "SEARCH_INDEX_ENTRY",
    "marketing_profiles": "MARKETING_PROFILE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    "product_telemetry": "PRODUCT_TELEMETRY",
    "cache_entries": "CACHE_ENTRY",
}

RESOURCE_CATEGORY = {
    "account": "USER_PROFILE",
    "secondary_identifier": "SECONDARY_IDENTIFIER",
    "search": "SEARCH_INDEX_ENTRY",
    "cache": "CACHE_ENTRY",
    "support_attachment": "SUPPORT_ATTACHMENT",
    "support": "SUPPORT_MESSAGE",
    "analytics": "ANALYTICS_PROFILE",
    "export": "USER_EXPORT",
    "marketing": "MARKETING_PROFILE",
    "email_log": "EMAIL_DELIVERY_LOG",
    "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "backup": "BACKUP_ARCHIVE",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "data_flow": "DATA_FLOW",
}

IDENTIFIER_KEYS = {
    "user_id", "customer_reference", "subject_reference", "subject_ref",
    "subject_selector", "lookup_key", "match_key", "correlation_key",
    "email", "owner_email", "customer_email", "requester_email",
    "email_hash", "phone", "owner_phone", "requester_phone",
    "customer_phone", "full_name", "requester_name", "display_name", "matched_value",
    "name", "customer_name", "subject",
}
DIRECT_PII_KEYS = {
    "email", "owner_email", "customer_email", "requester_email",
    "email_hash", "phone", "owner_phone", "requester_phone",
    "customer_phone", "full_name", "requester_name", "display_name", "matched_value",
    "name", "customer_name",
}
NULL_WORDS = {"", "null", "none", "unknown", "n/a", "not applicable", "-", "—"}


class AuditInputError(ValueError):
    """Raised when a mandatory input is missing or malformed."""


@dataclass(frozen=True)
class EvidenceSource:
    evidence_id: str
    path: Path
    relative_path: str
    origin: str
    captured_at: str


@dataclass
class Observation:
    evidence_id: str
    relative_path: str
    captured_at: str
    observed_at: str
    system_id: str
    resource_id: str
    category: str
    fields: dict[str, Any] = field(default_factory=dict)
    explicit_state: str = ""
    record_key: str = ""


@dataclass
class Activity:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass
class Identity:
    user_id: str
    values: set[str]
    current_email: str
    ambiguous: bool = False


@dataclass
class CaseAnalysis:
    case_id: str
    deletion_status: str
    steps: list[dict[str, Any]]
    user_id: str = ""
    observation_count: int = 0
    findings_count: int = 0
    uncertainty: list[str] = field(default_factory=list)


def read_csv(path: Path, required: Sequence[str] = ()) -> list[dict[str, str]]:
    if not path.is_file():
        raise AuditInputError(f"Required CSV does not exist: {path}")
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            missing = [column for column in required if column not in headers]
            if missing:
                raise AuditInputError(f"{path.name} is missing columns: {', '.join(missing)}")
            return [
                {str(key): (value if value is not None else "") for key, value in row.items()}
                for row in reader
            ]
    except (OSError, UnicodeError, csv.Error) as exc:
        raise AuditInputError(f"Could not read {path}: {exc}") from exc


def parse_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        text = str(value).strip().replace("Z", "+00:00")
        parsed = dt.datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def _time_le(left: str, right: str) -> bool:
    a, b = parse_time(left), parse_time(right)
    return a is not None and b is not None and a <= b


def _normalize(value: Any) -> str:
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    return re.sub(r"\s+", " ", text)


def _normalize_email(value: Any) -> str:
    return _normalize(value).strip("<>()[]{} \t\r\n.,;\"'")


def _is_value(value: Any) -> bool:
    return value is not None and _normalize(value) not in NULL_WORDS


def load_policy(path: Path) -> dict[str, str]:
    rows = read_csv(path, ["data_category", "condition", "required_action"])
    policy: dict[str, str] = {}
    for row in rows:
        category = row["data_category"].strip().upper()
        action = row["required_action"].strip().upper()
        if category in policy and policy[category] != action:
            raise AuditInputError(f"Conflicting policy actions for {category}")
        policy[category] = action
    if not policy:
        raise AuditInputError("deletion_rules.csv contains no policy rules")
    return policy


def load_sources(dataset: Path) -> tuple[list[EvidenceSource], list[Path]]:
    manifest_path = dataset / "evidence_files.csv"
    rows = read_csv(manifest_path, ["file_id", "file_path", "origin", "captured_at"])
    sources: list[EvidenceSource] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for row in rows:
        evidence_id = row["file_id"].strip()
        relative = PurePosixPath(row["file_path"].replace("\\", "/")).as_posix()
        if not evidence_id or evidence_id in seen_ids or relative in seen_paths:
            raise AuditInputError("evidence_files.csv contains a blank or duplicate file reference")
        seen_ids.add(evidence_id)
        seen_paths.add(relative)
        file_path = dataset / Path(*PurePosixPath(relative).parts)
        if not file_path.is_file():
            LOGGER.warning("Evidence listed in manifest is missing: %s", relative)
            continue
        sources.append(EvidenceSource(evidence_id, file_path, relative, row["origin"], row["captured_at"]))
    discovered = sorted(
        path for path in (dataset / "evidence").rglob("*")
        if path.is_file() and path.relative_to(dataset).as_posix() not in seen_paths
    )
    return sources, discovered


def _flatten_fields(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, Mapping):
                result.update(_flatten_fields(child, name))
            elif isinstance(child, list):
                for index, item in enumerate(child):
                    if isinstance(item, (Mapping, list)):
                        result.update(_flatten_fields(item, f"{name}[{index}]"))
                    else:
                        result[f"{name}[{index}]"] = item
            else:
                result[name] = child
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.update(_flatten_fields(child, f"{prefix}[{index}]"))
    else:
        result[prefix or "value"] = value
    return result


def _field_value(fields: Mapping[str, Any], name: str) -> Any:
    target = name.casefold()
    for key, value in fields.items():
        if key.rsplit(".", 1)[-1].split("[", 1)[0].casefold() == target:
            return value
    return None


def _guess_category(path: str, context: Mapping[str, Any], fields: Mapping[str, Any]) -> str:
    explicit = str(
        _field_value(fields, "data_category")
        or _field_value(fields, "record_type")
        or _field_value(fields, "category")
        or ""
    ).strip().upper()
    if explicit in CATEGORY_SYSTEM or explicit in {"USER_PROFILE", "DATA_FLOW", "SECURITY_AUDIT_LOG"}:
        return explicit
    # Prefer exact table/collection/endpoint names. Substring matching the full
    # filename misread every ``service_resource_export`` row as a USER_EXPORT.
    context_names = [str(value).casefold() for value in context.values() if isinstance(value, (str, int))]
    for name in context_names:
        if name in TABLE_CATEGORY:
            return TABLE_CATEGORY[name]
    path_parts = [part.casefold() for part in re.split(r"[./\\]+", path) if part]
    for name in reversed(path_parts):
        if name in TABLE_CATEGORY:
            return TABLE_CATEGORY[name]
    joined = " ".join([*context_names, *(str(value).casefold() for value in fields.values() if isinstance(value, (str, int))), path.casefold()])
    if "legacy_contact_index" in joined:
        return "SECONDARY_IDENTIFIER"
    resource_id = str(_field_value(fields, "resource_id") or "").casefold()
    resource_prefix = re.match(r"([a-z_]+)_\d+$", resource_id)
    if resource_prefix and resource_prefix.group(1) in RESOURCE_CATEGORY:
        return RESOURCE_CATEGORY[resource_prefix.group(1)]
    if "tombstone" in joined:
        return "ACCOUNT_TOMBSTONE"
    if "support_attachment" in joined or "attachment" in joined and "support" in joined:
        return "SUPPORT_ATTACHMENT"
    if "support" in joined or "ticket" in joined:
        return "SUPPORT_MESSAGE"
    if "analytics" in joined or "telemetry" in joined:
        return "ANALYTICS_PROFILE"
    if "search" in joined or "index" in joined:
        return "SEARCH_INDEX_ENTRY"
    if "backup" in joined or "archive" in joined or "restore" in joined:
        return "BACKUP_ARCHIVE"
    if "export" in joined:
        return "USER_EXPORT"
    if "security" in joined or "audit" in joined:
        return "SECURITY_AUDIT_LOG"
    if "marketing" in joined:
        return "MARKETING_PROFILE"
    if "email" in joined and ("delivery" in joined or "notification" in joined):
        return "EMAIL_DELIVERY_LOG"
    if "profile" in joined or "account" in joined:
        return "USER_PROFILE"
    return ""


def _guess_system(category: str, fields: Mapping[str, Any], context: Mapping[str, Any], path: str) -> str:
    explicit = _field_value(fields, "system_id") or _field_value(fields, "system") or _field_value(fields, "origin_system")
    if explicit:
        raw = str(explicit).strip().casefold()
        if raw in CATEGORY_SYSTEM.values():
            return raw
        if raw in set(CATEGORY_SYSTEM.values()):
            return raw
        mapped = {
            "identity_service": "identity_service", "account_platform": "account_service",
            "analytics": "analytics_platform", "search": "search_service",
            "support": "support_platform", "support_replica": "support_platform", "integrations": "integration_service",
            "backup": "backup_service", "security": "security_service",
        }.get(raw)
        if mapped:
            return mapped
    path_lower = path.casefold()
    for system in sorted(set(CATEGORY_SYSTEM.values()), key=len, reverse=True):
        if system in path_lower:
            return system
    for key, value in context.items():
        name = str(key).casefold()
        if name in {"system", "origin", "source", "service"} and isinstance(value, str):
            raw = value.casefold()
            if raw.endswith(("_service", "_platform")):
                return raw
            if raw in {"account", "account_platform"}:
                return "account_service"
    return CATEGORY_SYSTEM.get(category, "")


def _json_records(value: Any, path: str, evidence: EvidenceSource) -> Iterator[Observation]:
    def visit(node: Any, context: dict[str, Any], route: str) -> Iterator[Observation]:
        if isinstance(node, Mapping):
            next_context = dict(context)
            for key in ("origin", "source", "system", "origin_system", "data_store", "collection", "collection_name", "captured_at", "exported_at", "observed_at", "record_type", "data_category"):
                if key in node and not isinstance(node[key], (Mapping, list)):
                    next_context[key] = node[key]
            fields = _flatten_fields(node)
            # Do not promote nested records to the parent container. Several
            # evidence bundles contain hundreds of unrelated resource rows; a
            # flattened root would falsely attach every email to its first id.
            resource = str(node.get("resource_id") or "").strip()
            if resource:
                category = _guess_category(route, next_context, fields)
                system = _guess_system(category, fields, next_context, route)
                observed = str(
                    _field_value(fields, "observed_at")
                    or _field_value(fields, "updated_at")
                    or _field_value(fields, "recorded_at")
                    or next_context.get("captured_at")
                    or next_context.get("exported_at")
                    or evidence.captured_at
                )
                explicit = str(
                    _field_value(fields, "state")
                    or _field_value(fields, "status")
                    or _field_value(fields, "result")
                    or ""
                ).strip().upper()
                yield Observation(evidence.evidence_id, evidence.relative_path, evidence.captured_at, observed, system, resource, category, dict(fields), explicit, route)
            for key, child in node.items():
                if isinstance(child, (Mapping, list)):
                    yield from visit(child, next_context, f"{route}.{key}" if route else str(key))
        elif isinstance(node, list):
            for item in node:
                yield from visit(item, context, route)
    yield from visit(value, {}, path)


def _sqlite_observations(source: EvidenceSource) -> list[Observation]:
    text = source.path.read_text(encoding="utf-8-sig", errors="replace")
    connection = sqlite3.connect(":memory:")
    allowed = {
        sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_REINDEX,
        sqlite3.SQLITE_TRANSACTION,
    }
    def authorize(action: int, arg1: str | None, arg2: str | None, db: str | None, trigger: str | None) -> int:
        if action == sqlite3.SQLITE_PRAGMA and arg1 in {"table_info", "foreign_keys"}:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and arg1 in {"sqlite_master", "sqlite_schema"} and db == "main":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and (arg2 or arg1) == "json_valid":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
    connection.set_authorizer(authorize)
    try:
        connection.executescript(text)
        result: list[Observation] = []
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for table in tables:
            escaped = table.replace('"', '""')
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{escaped}")')]
            # SQLite's table_info is a read-only metadata query; allow it separately on known fixture tables.
            for row in connection.execute(f'SELECT * FROM "{escaped}"'):
                record = dict(zip(columns, row))
                raw_json = record.get("record_json")
                if isinstance(raw_json, str):
                    try:
                        nested = json.loads(raw_json)
                        if isinstance(nested, Mapping):
                            record.update(nested)
                    except json.JSONDecodeError:
                        pass
                fields = _flatten_fields(record)
                resource = str(_field_value(fields, "resource_id") or "").strip()
                if not resource:
                    continue
                category = _guess_category(table, {"table": table, **record}, fields)
                system = _guess_system(category, fields, {"table": table}, table)
                if not system:
                    system = CATEGORY_SYSTEM.get(category, "")
                observed = str(_field_value(fields, "updated_at") or source.captured_at)
                explicit = str(_field_value(fields, "state") or _field_value(fields, "status") or "").strip().upper()
                result.append(Observation(source.evidence_id, source.relative_path, source.captured_at, observed, system, resource, category, fields, explicit, table))
        return result
    finally:
        connection.close()


_KV = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*)=(?:\"((?:[^\"\\]|\\.)*)\"|([^\s|]+))")
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])")
_USER = re.compile(r"\buser_\d+\b", re.I)
_RESOURCE = re.compile(r"\b(?:account|secondary_identifier|search|analytics|support_attachment|support|export|data_flow|backup|audit_record|legal_hold|tombstone|marketing|cache|email_log)_\d+\b", re.I)


def _line_fields(line: str) -> tuple[dict[str, Any], str]:
    fields: dict[str, Any] = {}
    match = re.search(r"\{.*\}\s*$", line)
    if match:
        try:
            decoded = json.loads(match.group(0))
            if isinstance(decoded, Mapping):
                fields.update(decoded)
        except json.JSONDecodeError:
            pass
    for key, quoted, unquoted in _KV.findall(line):
        fields[key] = quoted.replace('\\"', '"') if quoted else unquoted
    timestamp = re.match(r"^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)", line)
    if timestamp:
        fields.setdefault("timestamp", timestamp.group(1))
    if "service" not in fields:
        pipe = [part.strip() for part in line.split("|")]
        if len(pipe) >= 5:
            fields.setdefault("service", pipe[2])
            fields.setdefault("event", pipe[4])
            fields.setdefault("trace_id", pipe[3])
    return fields, (timestamp.group(1) if timestamp else "")


def _line_observations(source: EvidenceSource) -> list[Observation]:
    text = source.path.read_text(encoding="utf-8-sig", errors="replace")
    if source.path.suffix.casefold() == ".txt" and " | " in text and "CUSTOMER PLATFORM - SHIFT HANDOVER" in text:
        result: list[Observation] = []
        for line in text.splitlines():
            match = re.match(r"\s*-\s*(\S+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*(.*?)\s*$", line)
            if not match:
                continue
            observed, system, resource, category, state, subject = [value.strip() for value in match.groups()]
            result.append(Observation(
                source.evidence_id, source.relative_path, source.captured_at, observed,
                system, resource, category.upper(), {"subject_reference": subject, "subject": subject},
                state.upper(), "handover",
            ))
        return result

    # Documents that include prose and a resource key are represented as one observation per key.
    if source.path.suffix.casefold() == ".txt":
        result = []
        if "account_handover" not in source.path.name.casefold():
            for resource in sorted(set(m.group(0) for m in _RESOURCE.finditer(text))):
                category = _guess_category(source.relative_path, {}, {"text": text})
                system = CATEGORY_SYSTEM.get(category, "")
                result.append(Observation(source.evidence_id, source.relative_path, source.captured_at, source.captured_at, system, resource, category, {"text": text}, "FOUND", "text"))
        return result

    lines = text.splitlines()
    grouped: dict[str, dict[str, Any]] = {}
    for index, line in enumerate(lines):
        fields, timestamp = _line_fields(line)
        resource = str(fields.get("resource_id") or "").strip()
        if not resource:
            found = _RESOURCE.search(line)
            resource = found.group(0) if found else ""
        trace = str(fields.get("trace_id") or fields.get("traceId") or fields.get("requestId") or "").strip()
        if not resource and not trace:
            continue
        key = f"trace:{trace}" if trace else f"line:{index}"
        current = grouped.setdefault(key, {"fields": {}, "timestamp": "", "lines": [], "resource_id": ""})
        current["fields"].update(fields)
        if resource:
            current["resource_id"] = resource
        current["timestamp"] = max(current["timestamp"], timestamp or str(fields.get("timestamp") or ""))
        current["lines"].append(line)
    result = []
    for value in grouped.values():
        fields = value["fields"]
        resource = str(fields.get("resource_id") or value["resource_id"])
        event = str(fields.get("event") or fields.get("event_type") or "").casefold()
        system = str(fields.get("service") or fields.get("function") or fields.get("system") or "").strip().casefold()
        category = _guess_category(source.relative_path, {"system": system, "event": event}, fields)
        if event.startswith("profile_lookup"):
            category = "USER_PROFILE"
        elif event.startswith("index_query") or event.startswith("search"):
            category = "SEARCH_INDEX_ENTRY"
        elif event.startswith("analytics_profile"):
            category = "ANALYTICS_PROFILE"
        elif str(fields.get("source", "")).casefold() == "legacy_contact_index":
            category = "SECONDARY_IDENTIFIER"
        elif event.startswith("support_ticket") or event.startswith("message_scan") or event.startswith("contact_query"):
            category = "SUPPORT_MESSAGE"
        elif event.startswith("connector_config"):
            category = "DATA_FLOW"
        elif event.startswith("restore_policy"):
            category = "BACKUP_ARCHIVE"
        elif event.startswith("audit_record"):
            category = "SECURITY_AUDIT_LOG"
        system_aliases = {"support_replica": "support_platform"}
        system = system_aliases.get(system, system)
        system = system if system in set(CATEGORY_SYSTEM.values()) else CATEGORY_SYSTEM.get(category, "")
        if not category:
            continue
        explicit = ""
        rows_value = str(fields.get("rows") or "")
        if category == "USER_PROFILE" and rows_value in {"0", "1"}:
            explicit = "NOT_FOUND" if rows_value == "0" else "FOUND"
        elif category == "SEARCH_INDEX_ENTRY" and str(fields.get("result", "")).casefold() in {"hit", "found"}:
            explicit = "FOUND"
        elif category == "SEARCH_INDEX_ENTRY" and str(fields.get("result", "")).casefold() in {"miss", "not_found", "none"}:
            explicit = "NOT_FOUND"
        elif category == "DATA_FLOW" and str(fields.get("enabled", "")).casefold() in {"true", "1", "yes"}:
            explicit = "ACTIVE"
        elif category == "DATA_FLOW" and str(fields.get("enabled", "")).casefold() in {"false", "0", "no"}:
            explicit = "DISABLED"
        elif category == "BACKUP_ARCHIVE" and str(fields.get("restore_allowed", "")).casefold() in {"true", "1", "yes"}:
            explicit = "ACTIVE"
        elif category == "BACKUP_ARCHIVE" and str(fields.get("restore_allowed", "")).casefold() in {"false", "0", "no"}:
            explicit = "BLOCKED"
        elif category == "SECURITY_AUDIT_LOG" and rows_value == "1":
            explicit = "FOUND"
        result.append(Observation(source.evidence_id, source.relative_path, source.captured_at, value["timestamp"] or source.captured_at, system, resource, category, dict(fields), explicit, event))
    return result


def _pdf_observations(source: EvidenceSource) -> tuple[list[Observation], str]:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except ImportError:
        return [], "pypdf is unavailable; PDF text was not extracted"
    try:
        reader = PdfReader(str(source.path))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception as exc:  # Parser errors must be surfaced, not converted into evidence.
        return [], f"PDF extraction failed: {type(exc).__name__}"
    category = _guess_category(source.relative_path, {}, {"text": text})
    if "delivery_correction_attachment" in source.path.name.casefold():
        category = "SUPPORT_ATTACHMENT"
    elif "retention" in source.path.name.casefold() or "legal" in source.path.name.casefold():
        category = "LEGAL_HOLD_RECORD"
    elif "security" in source.path.name.casefold():
        category = "SECURITY_AUDIT_LOG"
    system = CATEGORY_SYSTEM.get(category, "")
    resource_ids = sorted(set(match.group(0) for match in _RESOURCE.finditer(text)))
    if not resource_ids:
        refs = re.findall(r"\b(?:statement|order|ticket|reference|record)\s+([A-Z]{2,5}[-_]\d{3,}|\d{4,})", text, re.I)
        resource_ids = [ref for ref in refs if ref]
    result = [
        Observation(source.evidence_id, source.relative_path, source.captured_at, source.captured_at, system, resource, category, {"text": text}, "FOUND", "pdf_text")
        for resource in resource_ids
    ]
    return result, ""


_OCR_ENGINE: Any = None


def _image_observations(source: EvidenceSource) -> tuple[list[Observation], str]:
    """Read screenshot text with RapidOCR and keep identifiers scoped to visual rows."""
    try:
        import cv2  # type: ignore[import-not-found]
        from rapidocr_onnxruntime import RapidOCR  # type: ignore[import-not-found]
        global _OCR_ENGINE
        if _OCR_ENGINE is None:
            _OCR_ENGINE = RapidOCR()
        image = cv2.imread(str(source.path))
        if image is None:
            return [], "image could not be decoded by OpenCV"
        boxes, _elapsed = _OCR_ENGINE(image)
        if not boxes:
            return [], "OCR completed but found no readable text"
    except Exception as exc:
        return [], f"image OCR unavailable: {type(exc).__name__}"

    # OCR polygons are grouped into visual text rows. This prevents an email in
    # one result row from being attached to every other resource on the screen.
    row_items: list[dict[str, Any]] = []
    for polygon, text, confidence in boxes:
        if not str(text).strip():
            continue
        xs = [float(point[0]) for point in polygon]
        ys = [float(point[1]) for point in polygon]
        row_items.append({
            "text": str(text).strip(), "confidence": float(confidence),
            "x0": min(xs), "x1": max(xs), "y0": min(ys), "y1": max(ys),
            "cy": (min(ys) + max(ys)) / 2,
        })
    row_items.sort(key=lambda item: (item["cy"], item["x0"]))
    rows: list[list[dict[str, Any]]] = []
    row_centers: list[float] = []
    for item in row_items:
        if rows and abs(item["cy"] - row_centers[-1]) <= 15:
            rows[-1].append(item)
            row_centers[-1] = sum(part["cy"] for part in rows[-1]) / len(rows[-1])
        else:
            rows.append([item])
            row_centers.append(item["cy"])
    for row in rows:
        row.sort(key=lambda item: item["x0"])

    all_text = "\n".join(" | ".join(item["text"] for item in row) for row in rows)
    instances: list[tuple[str, int, int]] = []
    for row_index, row in enumerate(rows):
        for item_index, item in enumerate(row):
            instances.extend((match.group(0), row_index, item_index) for match in _RESOURCE.finditer(item["text"]))
    if not instances:
        return [], "OCR completed but did not identify a resource id"

    result: list[Observation] = []
    single_resource = len(instances) == 1
    for resource, row_index, item_index in instances:
        row = rows[row_index]
        row_text = " | ".join(item["text"] for item in row)
        resource_box = row[item_index]
        # For the selected-record pane, attach the detail lines in that pane to
        # its header resource. Table rows stay isolated from one another.
        if resource_box["x0"] >= 0.72 * image.shape[1]:
            panel_lines = [
                " | ".join(item["text"] for item in candidate)
                for candidate, center in zip(rows, row_centers)
                if row_centers[row_index] <= center <= row_centers[row_index] + 300
                and min(item["x0"] for item in candidate) >= 0.72 * image.shape[1]
            ]
            row_text = "\n".join(panel_lines)
        elif single_resource:
            row_text = all_text

        category = _guess_category(source.relative_path, {}, {"resource_id": resource, "text": row_text})
        system = CATEGORY_SYSTEM.get(category, "")
        normalized_text = _normalize(row_text)
        state = "PRESENT"
        if category == "DATA_FLOW":
            if re.search(r"\b(disabled|inactive|paused|off)\b", normalized_text):
                state = "DISABLED"
            elif re.search(r"\b(enabled|healthy|active|continuous)\b", normalized_text):
                state = "ACTIVE"
        result.append(Observation(
            source.evidence_id, source.relative_path, source.captured_at, source.captured_at,
            system, resource, category, {"text": row_text}, state, "ocr",
        ))
    return result, ""


def extract_evidence(sources: Sequence[EvidenceSource], discovered: Sequence[Path], dataset: Path) -> tuple[list[Observation], list[str]]:
    observations: list[Observation] = []
    limitations: list[str] = []
    for source in sources:
        suffix = source.path.suffix.casefold()
        try:
            if suffix == ".json":
                value = json.loads(source.path.read_text(encoding="utf-8-sig"))
                observations.extend(_json_records(value, "", source))
            elif suffix == ".sql":
                observations.extend(_sqlite_observations(source))
            elif suffix in {".log", ".txt"}:
                observations.extend(_line_observations(source))
            elif suffix == ".pdf":
                found, problem = _pdf_observations(source)
                observations.extend(found)
                if problem:
                    limitations.append(f"{source.evidence_id}: {problem}")
            elif suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff"}:
                found, problem = _image_observations(source)
                observations.extend(found)
                if problem:
                    limitations.append(f"{source.evidence_id}: {problem}")
            else:
                limitations.append(f"{source.evidence_id}: unsupported evidence type {suffix or '(none)'}")
        except Exception as exc:
            limitations.append(f"{source.evidence_id}: extraction failed ({type(exc).__name__})")
            LOGGER.warning("Could not extract %s: %s", source.relative_path, type(exc).__name__)
    if discovered:
        limitations.extend(f"Unmanifested evidence parsed only as undiscoverable provenance: {p.relative_to(dataset).as_posix()}" for p in discovered)
    return observations, limitations


def load_activities(path: Path) -> list[Activity]:
    rows = read_csv(path, ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"])
    return [Activity(**{key: row[key] for key in Activity.__dataclass_fields__}) for row in rows]


def _activity_assignments(case_context: Sequence[Mapping[str, str]], activities: Sequence[Activity], window_seconds: int = 90 * 60) -> dict[str, list[Activity]]:
    """Assign each nearby activity only when one authorized request is uniquely closest."""
    authorized_cases = [item for item in case_context if is_deletion_authorized(item.get("request_text", ""))]
    grouped_cases: dict[dt.datetime, list[str]] = defaultdict(list)
    for item in authorized_cases:
        event_time = parse_time(item.get("reported_at", ""))
        if event_time:
            grouped_cases[event_time].append(item.get("case_id", ""))
    case_times = sorted(grouped_cases)
    assignments: dict[str, list[Activity]] = defaultdict(list)
    allowed_events = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS"}
    for activity in activities:
        if activity.source_system.casefold() != "deletion_worker" or activity.event_type.upper() not in allowed_events:
            continue
        event_time = parse_time(activity.event_time)
        if event_time is None:
            continue
        position = bisect_left(case_times, event_time)
        nearest_times = case_times[max(0, position - 1):min(len(case_times), position + 1)]
        if not nearest_times:
            continue
        distances = sorted((abs((event_time - candidate).total_seconds()), candidate) for candidate in nearest_times)
        if distances[0][0] > window_seconds:
            continue
        if len(distances) > 1 and distances[0][0] == distances[1][0]:
            continue
        closest_time = distances[0][1]
        case_ids = grouped_cases[closest_time]
        if len(case_ids) == 1:
            assignments[case_ids[0]].append(activity)
    return assignments


def _nearby_case_activities(case: Mapping[str, str], case_context: Sequence[Mapping[str, str]], activities: Sequence[Activity], window_seconds: int = 90 * 60) -> list[Activity]:
    """Convenience wrapper for a single case; activity results stay claims."""
    context = list(case_context)
    if not any(item.get("case_id") == case.get("case_id") for item in context):
        context.append(case)
    return _activity_assignments(context, activities, window_seconds).get(case.get("case_id", ""), [])


def _sqlite_profile_tables(source: EvidenceSource) -> set[str]:
    text = source.path.read_text(encoding="utf-8-sig", errors="replace")
    names = {
        match.group(1).strip('"`[]').casefold()
        for match in re.finditer(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\"`\[]?[A-Za-z_][A-Za-z0-9_]*[\"`\]]?)", text, re.I)
    }
    return {name for name in names if TABLE_CATEGORY.get(name) == "USER_PROFILE" and name.startswith("customer_profiles")}


class IdentityResolver:
    def __init__(self, identities: Sequence[Mapping[str, str]], history: Sequence[Mapping[str, str]], activities: Sequence[Activity]):
        self.identities = {row["user_id"]: dict(row) for row in identities}
        self.history_by_user: dict[str, list[Mapping[str, str]]] = defaultdict(list)
        for row in history:
            self.history_by_user[row["user_id"]].append(row)
        self.current_email_users: dict[str, set[str]] = defaultdict(set)
        for user_id, row in self.identities.items():
            email = _normalize_email(row.get("email"))
            if email:
                self.current_email_users[email].add(user_id)
        self.history_email_users: dict[str, set[str]] = defaultdict(set)
        for row in history:
            if row.get("field_name", "").casefold() == "email":
                for value in (row.get("old_value", ""), row.get("new_value", "")):
                    email = _normalize_email(value)
                    if email:
                        self.history_email_users[email].add(row["user_id"])
        self.resource_users: dict[str, set[str]] = defaultdict(set)
        for activity in activities:
            if activity.event_type != "LINK_RESOURCE_IDENTITY":
                continue
            values = set(_USER.findall(activity.details))
            if values:
                uid = next(iter(values)).casefold()
                self.resource_users[activity.resource_id].add(uid)
                for resource in _RESOURCE.findall(activity.details):
                    self.resource_users[resource].add(uid)

    def resolve(self, email: str, requested_at: str, audit_at: str) -> tuple[str, bool]:
        key = _normalize_email(email)
        candidates: set[str] = set()
        for user_id in self.current_email_users.get(key, set()):
            row = self.identities[user_id]
            if _time_le(row.get("updated_at", ""), audit_at):
                candidates.add(user_id)
        for user_id in self.history_email_users.get(key, set()):
            if any(
                row.get("field_name", "").casefold() == "email"
                and key in {_normalize_email(row.get("old_value")), _normalize_email(row.get("new_value"))}
                and _time_le(row.get("event_time", ""), audit_at)
                for row in self.history_by_user.get(user_id, [])
            ):
                candidates.add(user_id)
        if not candidates:
            # The request address is itself a strong identifier. The snapshot is usable
            # only if it predates the request; historical log rows remain time-bounded.
            for user_id, row in self.identities.items():
                if _normalize_email(row.get("email")) == key and _time_le(row.get("updated_at", ""), requested_at):
                    candidates.add(user_id)
        if len(candidates) == 1:
            return next(iter(candidates)), False
        return "", len(candidates) > 1

    def identifiers(self, user_id: str, audit_at: str, request_email: str = "") -> set[str]:
        if not user_id or user_id not in self.identities:
            return {_normalize_email(request_email)} if request_email else set()
        result = {user_id.casefold(), _normalize_email(request_email)}
        current = self.identities[user_id]
        if _time_le(current.get("updated_at", ""), audit_at):
            for key in ("email", "email_hash", "phone"):
                if _is_value(current.get(key)):
                    result.add(_normalize(current[key]))
                    if key == "email":
                        result.add(_normalize_email(current[key]))
        for row in self.history_by_user.get(user_id, []):
            if not _time_le(row.get("event_time", ""), audit_at):
                continue
            if row.get("field_name", "").casefold() in {"email", "email_hash", "phone"}:
                for key in ("old_value", "new_value"):
                    if _is_value(row.get(key)):
                        result.add(_normalize(row[key]))
                        if row["field_name"].casefold() == "email":
                            result.add(_normalize_email(row[key]))
        return {item for item in result if item}


def is_deletion_authorized(text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    # Explicit negation and non-deletion requests take precedence over a quoted
    # mention of deletion (for example, “I do not want the account deleted”).
    negations = (
        r"\bdo not (?:delete|erase|remove|close)\b",
        r"\bdon't (?:delete|erase|remove|close)\b",
        r"\bdo not want (?:my |the )?(?:account|profile)\s+(?:deleted|erased|removed|closed)\b",
        r"\bdon't want (?:my |the )?(?:account|profile)\s+(?:deleted|erased|removed|closed)\b",
        r"\bnot (?:requesting|asking for) (?:a )?(?:deletion|erasure)\b",
        r"\bnot a deletion request\b",
        r"\b(?:only|just) (?:want|request) (?:access|a correction|an export|a copy)\b",
        r"\bkeep (?:my|the) account\b",
        r"\bwithout deleting\b",
        r"\bno deletion (?:request|is requested)\b",
    )
    if any(re.search(pattern, normalized) for pattern in negations):
        return False
    deletion = (
        r"\bdelet(?:e|ed|ing|ion|ions)\b", r"\beras(?:e|ed|ing|ure)\b",
        r"\bpurge\b", r"\bremove\s+(?:my|the|this|associated|personal|all|any)?\s*(?:account|profile|personal data|data|information)\b",
        r"\bremove\w*\b.{0,45}\b(?:records?|copies|search results?|exports?|attachments?|contact details|identifiers|personal details|personal information|my name)\b",
        r"\b(?:has|have|was|were|already)\s+(?:been\s+)?removed\b",
        r"\bclose\s+(?:my|the|this)?\s*account\b", r"\bdelete\s+my\s+account\b",
        r"\belimin\w*\b", r"\bborr\w*\b", r"\bsuprim\w*\b", r"\bsupprim\w*\b",
        r"\beffac\w*\b", r"\bexclu\w*\b", r"\bapag\w*\b", r"\bdeletar\w*\b",
        r"\bcancell\w*\b", r"\bsuppression\w*\b", r"\blösch\w*\b", r"\bloesch\w*\b", r"\bverwijder\w*\b",
        r"\b(?:check|confirm|verify)\b.{0,60}\b(?:profile|account|personal data)\b.{0,35}\b(?:gone|deleted|erased|removed)\b",
        r"\bremaining records?\b.{0,35}\b(?:cannot|can't|can no longer)\b.{0,25}\bidentify\b",
        r"削除|消去|退会|삭제|탈퇴|删除|刪除|حذف",
    )
    if any(re.search(pattern, normalized) for pattern in deletion):
        return True
    # Redacted replacement characters in supplied multilingual text can break
    # inflection endings. Common privacy request phrases remain recognizable.
    if "solicito a la" in normalized and "permanent" in normalized:
        return True
    return False


def _observation_matches(observation: Observation, identifiers: set[str], user_id: str, resource_users: Mapping[str, set[str]]) -> bool:
    if user_id and user_id.casefold() in resource_users.get(observation.resource_id, set()):
        return True
    if user_id and user_id.casefold() in resource_users.get(observation.resource_id.casefold(), set()):
        return True
    fields = observation.fields
    values: set[str] = set()
    for key, value in fields.items():
        leaf = key.rsplit(".", 1)[-1].split("[", 1)[0].casefold()
        if leaf not in IDENTIFIER_KEYS and leaf not in {"text", "message_excerpt", "details", "document"}:
            continue
        if isinstance(value, (str, int, float)):
            raw = _normalize(value)
            if raw:
                values.add(raw)
                if "email" in leaf:
                    values.add(_normalize_email(value))
    if values & identifiers:
        return True
    # Evidence text can contain a subject identifier inside a single prose field.
    for key, value in fields.items():
        if key.rsplit(".", 1)[-1].casefold() in {"text", "message_excerpt", "details"} and isinstance(value, str):
            haystack = _normalize(value)
            if any(len(identifier) >= 5 and identifier in haystack for identifier in identifiers):
                return True
    return False


def _truthy_field(fields: Mapping[str, Any], names: Iterable[str]) -> bool:
    wanted = {name.casefold() for name in names}
    return any(
        key.rsplit(".", 1)[-1].split("[", 1)[0].casefold() in wanted and _is_value(value)
        for key, value in fields.items()
    )


def _is_directly_identifiable(observation: Observation) -> bool:
    if _truthy_field(observation.fields, DIRECT_PII_KEYS):
        return True
    for key, value in observation.fields.items():
        leaf = key.rsplit(".", 1)[-1].split("[", 1)[0].casefold()
        if leaf in IDENTIFIER_KEYS and isinstance(value, str):
            if _EMAIL.search(value) or re.search(r"\+\s*\d[\d ()-]{6,}\d", value):
                return True
    text = " ".join(
        str(value) for key, value in observation.fields.items()
        if key.rsplit(".", 1)[-1].casefold() in {"text", "message_excerpt", "details", "document"}
        and isinstance(value, str)
    )
    return bool(_EMAIL.search(text) or re.search(r"\+\s*\d[\d ()-]{6,}\d", text))


def _is_attributable(observation: Observation, user_id: str) -> bool:
    if _is_directly_identifiable(observation):
        return True
    for name in ("user_id", "customer_reference", "subject_reference", "subject_ref", "subject_selector", "audit_subject_reference"):
        value = _field_value(observation.fields, name)
        if value and user_id and _normalize(value) == user_id.casefold():
            return True
    if user_id:
        for key, value in observation.fields.items():
            if key.rsplit(".", 1)[-1].casefold() in {"text", "message_excerpt", "details", "document"} and isinstance(value, str):
                if user_id.casefold() in _normalize(value):
                    return True
    return False


def _resolved_state(observation: Observation) -> str:
    raw = observation.explicit_state.strip().upper()
    state_aliases = {
        "NOT_FOUND": "ABSENT", "ABSENT": "ABSENT", "404": "ABSENT", "MISS": "ABSENT",
        "FOUND": "PRESENT", "PRESENT": "PRESENT", "200": "PRESENT", "HIT": "PRESENT",
        "IDENTIFIABLE": "IDENTIFIABLE", "EXPOSED": "IDENTIFIABLE",
        "ANONYMIZED": "ANONYMIZED", "ANONYMIZED_RECORD": "ANONYMIZED",
        "REDACTED": "REDACTED", "ACTIVE": "ACTIVE", "DISABLED": "DISABLED",
        "BLOCKED": "BLOCKED", "INACTIVE": "DISABLED", "ENABLED": "ACTIVE",
    }
    if raw in state_aliases:
        return state_aliases[raw]
    status_code = _field_value(observation.fields, "status_code")
    if str(status_code) == "404":
        return "ABSENT"
    if str(status_code) in {"200", "201"}:
        return "PRESENT"
    rows = str(_field_value(observation.fields, "rows") or "")
    if observation.category == "USER_PROFILE" and rows in {"0", "1"}:
        return "ABSENT" if rows == "0" else "PRESENT"
    if observation.category == "DATA_FLOW":
        raw_enabled = _field_value(observation.fields, "enabled")
        enabled = "" if raw_enabled is None else str(raw_enabled).casefold()
        if enabled in {"true", "1", "yes"}:
            return "ACTIVE"
        if enabled in {"false", "0", "no"}:
            return "DISABLED"
    if observation.category == "BACKUP_ARCHIVE":
        raw_allowed = _field_value(observation.fields, "restore_allowed")
        allowed = "" if raw_allowed is None else str(raw_allowed).casefold()
        if allowed in {"true", "1", "yes"}:
            return "ACTIVE"
        if allowed in {"false", "0", "no"}:
            return "BLOCKED"
    return "PRESENT"


def _policy_for(observation: Observation, policy: Mapping[str, str]) -> str:
    category = observation.category
    action = policy.get(category, "")
    if category == "SUPPORT_MESSAGE" and action == "REDACT":
        return action
    if category == "SUPPORT_ATTACHMENT":
        return policy.get(category, "DELETE")
    if category == "BACKUP_ARCHIVE":
        return policy.get(category, "RETAIN")
    return action


def _observation_is_violation(observation: Observation, user_id: str, policy: Mapping[str, str]) -> tuple[bool, str, str]:
    state = _resolved_state(observation)
    action = _policy_for(observation, policy)
    category = observation.category
    if state == "ABSENT":
        return False, "", ""
    if category == "DATA_FLOW":
        return (state == "ACTIVE", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW") if state == "ACTIVE" else (False, "", "")
    if category == "BACKUP_ARCHIVE":
        return (state == "ACTIVE", "REPORT_RESTORE_RISK", "BLOCK_RESTORE") if state == "ACTIVE" else (False, "", "")
    if action == "DELETE" and state not in {"ABSENT"}:
        return True, "REPORT_REMAINING_RECORD", "DELETE_RECORD"
    if action == "REDACT":
        explicit = observation.explicit_state.upper()
        identifiable = state == "IDENTIFIABLE" or _is_directly_identifiable(observation)
        if explicit in {"REDACTED", "ANONYMIZED"}:
            identifiable = False
        if category == "ACCOUNT_TOMBSTONE":
            # Stable user_id may remain; direct fields may not.
            identifiable = state == "IDENTIFIABLE" or _is_directly_identifiable(observation)
        return (identifiable, "REPORT_EXPOSED_PII", "REDACT_RECORD") if identifiable else (False, "", "")
    if action == "ANONYMIZE":
        explicit = observation.explicit_state.upper()
        attributable = state == "IDENTIFIABLE" or _is_attributable(observation, user_id)
        if explicit in {"ANONYMIZED", "REDACTED"}:
            attributable = False
        return (attributable, "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD") if attributable else (False, "", "")
    return False, "", ""


def _make_step(phase: str, system: str, resource: str, operation: str, state: str, evidence_id: str) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def _ordered_steps(steps: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(step: Mapping[str, Any]) -> tuple[Any, ...]:
        phase = str(step["phase"])
        if phase == "FINDING":
            operation = FINDING_ORDER[str(step["operation"])]
        elif phase == "REMEDIATION":
            operation = REMEDIATION_ORDER[str(step["operation"])]
        else:
            operation = VERIFICATION_ORDER[str(step["operation"])]
        return (PHASE_ORDER[phase], operation, str(step["system_id"]), str(step["resource_id"]))
    result = sorted(steps, key=key)
    for index, step in enumerate(result, start=1):
        step["step_no"] = index
    return result


def _latest_observations(observations: Sequence[Observation]) -> list[Observation]:
    grouped: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    for obs in observations:
        grouped[(obs.system_id, obs.resource_id)].append(obs)
    result = []
    for values in grouped.values():
        values.sort(key=lambda obs: (parse_time(obs.observed_at) or parse_time(obs.captured_at) or dt.datetime.min.replace(tzinfo=dt.timezone.utc), obs.evidence_id))
        latest = values[-1]
        merged = dict(latest.fields)
        # A readback often separates its completed result from the lookup-key start line.
        for earlier in values[:-1]:
            if earlier.evidence_id == latest.evidence_id:
                merged = {**earlier.fields, **merged}
        if merged != latest.fields:
            latest = Observation(latest.evidence_id, latest.relative_path, latest.captured_at, latest.observed_at, latest.system_id, latest.resource_id, latest.category, merged, latest.explicit_state, latest.record_key)
        result.append(latest)
    return result


def _analysis_steps(
    case: Mapping[str, str],
    user_id: str,
    observations: Sequence[Observation],
    policy: Mapping[str, str],
    primary_resource_id: str = "",
) -> CaseAnalysis:
    cutoff = case["audit_at"]
    all_steps: list[dict[str, Any]] = []
    relevant: list[Observation] = []
    for obs in observations:
        if not obs.evidence_id:
            continue
        if not _time_le(obs.captured_at, cutoff) or not _time_le(obs.observed_at or obs.captured_at, cutoff):
            continue
        relevant.append(obs)
    relevant = _latest_observations(relevant)
    findings: dict[tuple[str, str, str], Observation] = {}
    actions: dict[tuple[str, str, str], Observation] = {}
    required_verifications: dict[tuple[str, str, str], Observation] = {}
    account_absence: Observation | None = None
    uncertainty: list[str] = []

    for obs in relevant:
        state = _resolved_state(obs)
        category = obs.category
        if category == "USER_PROFILE" and state == "ABSENT" and _time_le(case.get("reported_at", ""), obs.observed_at) and account_absence is None:
            account_absence = obs
        violation, finding_op, remediation_op = _observation_is_violation(obs, user_id, policy)
        key = (obs.system_id, obs.resource_id, remediation_op)
        if violation:
            actions[key] = obs
            findings[(obs.system_id, obs.resource_id, finding_op)] = obs
        else:
            action = _policy_for(obs, policy)
            verify_op = ""
            verify_state = ""
            if state == "ABSENT" and category in {"USER_PROFILE", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER"}:
                verify_op, verify_state = "VERIFY_RECORD_ABSENT", "ABSENT"
            elif category == "BACKUP_ARCHIVE" and state == "BLOCKED":
                verify_op, verify_state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
            elif category == "DATA_FLOW" and state == "DISABLED":
                verify_op, verify_state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            elif action == "RETAIN" and state not in {"ABSENT"}:
                verify_op, verify_state = "VERIFY_RECORD_PRESENT", "PRESENT"
            elif action == "REDACT" and state not in {"ABSENT"} and not _is_directly_identifiable(obs):
                verify_op, verify_state = "VERIFY_RECORD_REDACTED", "REDACTED"
            elif action == "ANONYMIZE" and state not in {"ABSENT"} and not _is_attributable(obs, user_id):
                verify_op, verify_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            if verify_op:
                required_verifications[(obs.system_id, obs.resource_id, verify_op)] = obs

    for (system, resource, finding_op), obs in findings.items():
        state = "ACTIVE" if finding_op in {"REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"} else "PRESENT"
        all_steps.append(_make_step("FINDING", system, resource, finding_op, state, obs.evidence_id))

    for (system, resource, remediation_op), obs in actions.items():
        state = {
            "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
            "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
        }[remediation_op]
        all_steps.append(_make_step("REMEDIATION", system, resource, remediation_op, state, ""))
        verify_op = {
            "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
            "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
            "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
        }[remediation_op]
        required_verifications[(system, resource, verify_op)] = obs

    if actions:
        # The post-remediation plan must reconfirm the primary profile is absent.
        if account_absence:
            required_verifications[(account_absence.system_id, account_absence.resource_id, "VERIFY_RECORD_ABSENT")] = account_absence
        elif primary_resource_id:
            planned_account = Observation("", "", "", "", "account_service", primary_resource_id, "USER_PROFILE", {}, "", "planned")
            required_verifications[("account_service", primary_resource_id, "VERIFY_RECORD_ABSENT")] = planned_account
        # If the current evidence contains a policy-required retained security record,
        # carry its presence check into the future verification plan.
        for (system, resource, verify_op), obs in list(required_verifications.items()):
            if verify_op == "VERIFY_RECORD_PRESENT":
                continue
        for obs in relevant:
            if obs.category == "SECURITY_AUDIT_LOG" and _resolved_state(obs) != "ABSENT":
                required_verifications[(obs.system_id, obs.resource_id, "VERIFY_RECORD_PRESENT")] = obs
    elif not findings:
        # A positive deletion request is complete only when the evidence establishes
        # the relevant policy states. A scoped account readback is the minimum proof.
        if account_absence is None:
            uncertainty.append("No time-bounded account absence observation was found")

    has_violation = bool(findings)
    status = "INCOMPLETE" if has_violation or uncertainty else "COMPLETE"
    if not has_violation:
        for (system, resource, verify_op), obs in required_verifications.items():
            state = {
                "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
                "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
            }[verify_op]
            evidence_id = obs.evidence_id if status == "COMPLETE" else ""
            all_steps.append(_make_step("VERIFICATION", system, resource, verify_op, state, evidence_id))
    else:
        for (system, resource, verify_op), obs in required_verifications.items():
            state = {
                "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
                "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
            }[verify_op]
            all_steps.append(_make_step("VERIFICATION", system, resource, verify_op, state, ""))

    if uncertainty and not findings:
        # Unknown coverage is not evidence of a violation. Keep the outcome
        # conservative and expose why in the internal audit report.
        status = "INCOMPLETE"
    return CaseAnalysis(case["case_id"], status, _ordered_steps(all_steps), user_id, len(relevant), len(findings), uncertainty)


class DeletionAuditAgent:
    def __init__(self, dataset: Path):
        self.dataset = dataset.resolve()
        self.requests = read_csv(self.dataset / "deletion_requests.csv", [
            "case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text",
        ])
        if len(self.requests) != len({row["case_id"] for row in self.requests}):
            raise AuditInputError("deletion_requests.csv contains duplicate case_id values")
        self.policy = load_policy(self.dataset / "deletion_rules.csv")
        identities = read_csv(self.dataset / "user_identities.csv", ["user_id", "email", "updated_at"])
        history = read_csv(self.dataset / "user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"])
        self.activities = load_activities(self.dataset / "system_activity.csv")
        self.resolver = IdentityResolver(identities, history, self.activities)
        self.sources, self.unmanifested = load_sources(self.dataset)
        self.observations, self.extraction_limitations = extract_evidence(self.sources, self.unmanifested, self.dataset)
        self.case_contexts: Sequence[Mapping[str, str]] = self.requests
        self.activity_by_case = _activity_assignments(self.case_contexts, self.activities)
        self.profile_snapshots: list[EvidenceSource] = []
        for source in self.sources:
            if source.path.suffix.casefold() == ".sql" and _sqlite_profile_tables(source):
                self.profile_snapshots.append(source)
        self._evidence_by_user: dict[str, list[Observation]] = defaultdict(list)

    def set_case_context(self, cases: Sequence[Mapping[str, str]]) -> None:
        """Set the request batch used to disambiguate activity timestamps."""
        self.case_contexts = cases
        self.activity_by_case = _activity_assignments(self.case_contexts, self.activities)

    def analyze_case(self, case: Mapping[str, str]) -> CaseAnalysis:
        if not is_deletion_authorized(case.get("request_text", "")):
            return CaseAnalysis(case["case_id"], "NOT_APPLICABLE", [], observation_count=0)
        user_id, ambiguous = self.resolver.resolve(case.get("email", ""), case.get("requested_at", ""), case.get("audit_at", ""))
        uncertainty: list[str] = []
        if ambiguous:
            uncertainty.append("Request email maps to more than one identity in time-bounded identity history")
        elif not user_id:
            uncertainty.append("Request email did not resolve to a unique current or historical user_id")
        identifiers = self.resolver.identifiers(user_id, case["audit_at"], case.get("email", ""))
        matched: list[Observation] = []
        for obs in self.observations:
            if not _observation_matches(obs, identifiers, user_id, self.resolver.resource_users):
                continue
            if user_id and obs.category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                fields = dict(obs.fields)
                fields["audit_subject_reference"] = user_id
                obs = Observation(
                    obs.evidence_id, obs.relative_path, obs.captured_at, obs.observed_at,
                    obs.system_id, obs.resource_id, obs.category, fields, obs.explicit_state, obs.record_key,
                )
            matched.append(obs)

        nearby = [
            activity for activity in self.activity_by_case.get(case.get("case_id", ""), [])
            if _time_le(activity.event_time, case.get("audit_at", ""))
        ]
        primary_candidates: list[tuple[float, str]] = []
        known_resources = {obs.resource_id.casefold() for obs in matched}
        for activity in nearby:
            distance = abs((parse_time(activity.event_time) - parse_time(case["reported_at"])).total_seconds())
            if activity.resource_id.casefold().startswith("account_"):
                primary_candidates.append((distance, activity.resource_id))
            resource_observations = [obs for obs in self.observations if obs.resource_id.casefold() == activity.resource_id.casefold()]
            for obs in resource_observations:
                if not _time_le(obs.captured_at, case["audit_at"]) or not _time_le(obs.observed_at or obs.captured_at, case["audit_at"]):
                    continue
                has_subject_key = any(
                    key.rsplit(".", 1)[-1].split("[", 1)[0].casefold() in IDENTIFIER_KEYS and _is_value(value)
                    for key, value in obs.fields.items()
                )
                if has_subject_key and not _observation_matches(obs, identifiers, user_id, self.resolver.resource_users):
                    continue
                matched.append(obs)
                known_resources.add(obs.resource_id.casefold())

        # A deletion-worker event can identify the primary profile resource,
        # while a full SQL snapshot captured after the reported operation
        # establishes whether that profile was present in both replicas.
        if primary_candidates:
            _, primary_resource = min(primary_candidates)
            if primary_resource.casefold() not in known_resources:
                snapshots = [
                    source for source in self.profile_snapshots
                    if _time_le(source.captured_at, case["audit_at"])
                    and _time_le(case.get("reported_at", ""), source.captured_at)
                ]
                snapshots.sort(key=lambda source: parse_time(source.captured_at) or dt.datetime.min.replace(tzinfo=dt.timezone.utc))
                if snapshots:
                    snapshot = snapshots[-1]
                    existing_rows = [
                        obs for obs in self.observations
                        if obs.evidence_id == snapshot.evidence_id and obs.resource_id.casefold() == primary_resource.casefold()
                        and obs.category == "USER_PROFILE"
                    ]
                    if not existing_rows:
                        matched.append(Observation(
                            snapshot.evidence_id, snapshot.relative_path, snapshot.captured_at, snapshot.captured_at,
                            "account_service", primary_resource, "USER_PROFILE", {"rows": "0", "snapshot_tables": sorted(_sqlite_profile_tables(snapshot))},
                            "NOT_FOUND", "snapshot_absence",
                        ))
                        known_resources.add(primary_resource.casefold())

        primary_resource_id = min(primary_candidates)[1] if primary_candidates else ""
        result = _analysis_steps(case, user_id, matched, self.policy, primary_resource_id)
        result.uncertainty[:0] = uncertainty
        if uncertainty and result.deletion_status == "COMPLETE":
            result.deletion_status = "INCOMPLETE"
        return result

    def analyze_all(self) -> list[CaseAnalysis]:
        self.case_contexts = self.requests
        self.activity_by_case = _activity_assignments(self.case_contexts, self.activities)
        outputs: list[CaseAnalysis] = []
        for case in self.requests:
            try:
                outputs.append(self.analyze_case(case))
            except Exception as exc:
                LOGGER.exception("Case analysis failed for %s", case.get("case_id", "(missing)"))
                outputs.append(CaseAnalysis(case.get("case_id", ""), "INCOMPLETE", [], uncertainty=[f"Analysis error: {type(exc).__name__}"]))
        return outputs

    def write_output(self, results: Sequence[CaseAnalysis], output_path: Path) -> None:
        by_id = {result.case_id: result for result in results}
        request_ids = {row["case_id"] for row in self.requests}
        if set(by_id) != request_ids:
            raise AuditInputError("Inference did not produce exactly one result per request")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
            writer.writeheader()
            for case_id in sorted(request_ids):
                result = by_id[case_id]
                writer.writerow({
                    "case_id": case_id,
                    "deletion_status": result.deletion_status,
                    "steps_json": json.dumps(result.steps, ensure_ascii=False, separators=(",", ":")),
                })

    def audit_summary(self, results: Sequence[CaseAnalysis]) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for result in results:
            status_counts[result.deletion_status] += 1
        return {
            "requests": len(self.requests),
            "results": len(results),
            "statuses": dict(sorted(status_counts.items())),
            "evidence_sources": len(self.sources),
            "observations_extracted": len(self.observations),
            "unmanifested_files": len(self.unmanifested),
            "extraction_limitations": len(self.extraction_limitations),
            "unresolved_identities": sum(bool(r.uncertainty and any("identity" in msg.lower() for msg in r.uncertainty)) for r in results),
            "incomplete_without_findings": sum(r.deletion_status == "INCOMPLETE" and r.findings_count == 0 for r in results),
        }


def validate_output(output_path: Path, expected_requests: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    rows = read_csv(output_path, OUTPUT_COLUMNS)
    expected_ids = [row["case_id"] for row in expected_requests]
    actual_ids = [row["case_id"] for row in rows]
    if len(rows) != len(expected_ids) or sorted(actual_ids) != sorted(expected_ids):
        raise AuditInputError(f"Output coverage mismatch: expected {len(expected_ids)} rows, got {len(rows)}")
    if actual_ids != sorted(actual_ids):
        raise AuditInputError("Output rows are not sorted by case_id")
    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    allowed_steps = {
        "FINDING": {
            "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
            "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
        },
        "REMEDIATION": {
            "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
            "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
        },
        "VERIFICATION": {
            "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
            "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
        },
    }
    steps_total = 0
    for row in rows:
        if row["deletion_status"] not in allowed_statuses:
            raise AuditInputError(f"Invalid status for {row['case_id']}: {row['deletion_status']}")
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            raise AuditInputError(f"Invalid steps_json for {row['case_id']}") from exc
        if not isinstance(steps, list):
            raise AuditInputError(f"steps_json is not an array for {row['case_id']}")
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise AuditInputError(f"NOT_APPLICABLE row has steps for {row['case_id']}")
        previous_order = (-1, -1)
        for expected_number, step in enumerate(steps, start=1):
            if set(step) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}:
                raise AuditInputError(f"Invalid step fields for {row['case_id']} step {expected_number}")
            if step["step_no"] != expected_number:
                raise AuditInputError(f"Non-consecutive steps for {row['case_id']}")
            if step["phase"] not in PHASE_ORDER:
                raise AuditInputError(f"Invalid phase for {row['case_id']}")
            expected_state = allowed_steps[step["phase"]].get(step["operation"])
            if expected_state is None or step["state"] != expected_state:
                raise AuditInputError(f"Invalid operation or state for {row['case_id']} step {expected_number}")
            if not all(isinstance(step[key], str) for key in ("system_id", "resource_id", "evidence_id")):
                raise AuditInputError(f"Invalid step identifier type for {row['case_id']} step {expected_number}")
            order = (PHASE_ORDER[step["phase"]], {
                **FINDING_ORDER, **REMEDIATION_ORDER, **VERIFICATION_ORDER,
            }[step["operation"]])
            if order < previous_order:
                raise AuditInputError(f"Steps are out of phase or operation order for {row['case_id']}")
            previous_order = order
            if row["deletion_status"] == "COMPLETE" and (step["phase"] != "VERIFICATION" or not step["evidence_id"]):
                raise AuditInputError(f"COMPLETE row contains a non-evidence-backed verification for {row['case_id']}")
            if row["deletion_status"] == "INCOMPLETE" and step["phase"] != "FINDING" and step["evidence_id"]:
                raise AuditInputError(f"INCOMPLETE plan cites evidence for a future step for {row['case_id']}")
        steps_total += len(steps)
    return {"rows": len(rows), "steps": steps_total, "header": OUTPUT_COLUMNS, "sorted": True}


def write_audit_report(path: Path, agent: DeletionAuditAgent, results: Sequence[CaseAnalysis]) -> None:
    summary = agent.audit_summary(results)
    lines = [
        "# Audit Run Summary", "",
        "This report contains aggregate counts only. Per-case identifiers and evidence contents remain in the generated prediction file and participant dataset.", "",
        f"- Requests processed: {summary['requests']}",
        f"- Evidence manifest files: {summary['evidence_sources']}",
        f"- Extracted resource observations: {summary['observations_extracted']}",
        f"- Status counts: {json.dumps(summary['statuses'], sort_keys=True)}",
        f"- Cases with unresolved identity: {summary['unresolved_identities']}",
        f"- Incomplete cases with no finding: {summary['incomplete_without_findings']}",
        f"- Extraction limitations: {summary['extraction_limitations']}",
        "", "## Extraction limitations", "",
    ]
    if agent.extraction_limitations:
        lines.extend(f"- {item}" for item in agent.extraction_limitations)
    else:
        lines.append("- None reported.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

