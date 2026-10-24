from __future__ import annotations

import csv
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from audit_agent import (  # noqa: E402
    DeletionAuditAgent,
    Activity,
    EvidenceSource,
    IdentityResolver,
    Observation,
    _analysis_steps,
    _image_observations,
    _line_observations,
    _nearby_case_activities,
    _observation_matches,
    _resolved_state,
    _sqlite_observations,
    is_deletion_authorized,
    load_sources,
    validate_output,
)


def obs(system: str, resource: str, category: str, state: str, *, fields=None, evidence="evidence_01", observed="2026-05-01T00:00:00Z") -> Observation:
    return Observation(evidence, "evidence/mock.json", "2026-05-01T00:00:00Z", observed, system, resource, category, fields or {}, state, "test")


def case(*, audit="2026-05-02T00:00:00Z"):
    return {
        "case_id": "synthetic_1", "email": "person@example.test", "requested_at": "2026-04-30T00:00:00Z",
        "reported_status": "COMPLETE", "reported_at": "2026-05-01T00:00:00Z", "audit_at": audit,
        "request_text": "Please permanently delete my account.",
    }


class AuthorizationTests(unittest.TestCase):
    def test_english_delete_and_verify_requests_are_authorized(self):
        self.assertTrue(is_deletion_authorized("Please erase my account and verify it was deleted."))

    def test_multilingual_deletion_phrases_are_authorized(self):
        self.assertTrue(is_deletion_authorized("Intenté eliminar mi cuenta ayer."))
        self.assertTrue(is_deletion_authorized("Je demande la suppression définitive du compte."))
        self.assertTrue(is_deletion_authorized("このアカウントの完全な削除を依頼します。"))

    def test_non_deletion_and_explicit_negation_are_not_authorized(self):
        self.assertFalse(is_deletion_authorized("Please export my data and correct my email."))
        self.assertFalse(is_deletion_authorized("I do not want the account deleted; update my phone."))


class IdentityTests(unittest.TestCase):
    def test_historical_email_resolves_only_when_the_change_predates_audit(self):
        identities = [{"user_id": "user_1", "email": "new@example.test", "updated_at": "2026-01-02T00:00:00Z"}]
        history = [{
            "audit_id": "audit_1", "user_id": "user_1", "event_time": "2025-12-01T00:00:00Z",
            "field_name": "email", "old_value": "old@example.test", "new_value": "new@example.test",
        }]
        resolver = IdentityResolver(identities, history, [])
        self.assertEqual(resolver.resolve("old@example.test", "2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z"), ("user_1", False))
        self.assertEqual(resolver.resolve("old@example.test", "2025-11-01T00:00:00Z", "2025-11-20T00:00:00Z"), ("", False))

    def test_exact_identifiers_do_not_match_a_similar_email_or_name(self):
        record = obs("search_service", "search_1", "SEARCH_INDEX_ENTRY", "PRESENT", fields={"email": "other@example.test", "display_name": "Same Name"})
        self.assertFalse(_observation_matches(record, {"person@example.test", "user_1"}, "user_1", {}))

    def test_activity_resource_discovery_requires_a_unique_nearest_report_time(self):
        first = {**case(), "case_id": "first", "reported_at": "2026-05-01T12:00:00Z"}
        second = {**case(), "case_id": "second", "reported_at": "2026-05-01T12:05:00Z"}
        activity = Activity("activity_1", "2026-05-01T12:00:30Z", "DELETE_RECORD", "deletion_worker", "account_service", "account_1", "SUCCESS", "Target resource account_1")
        self.assertEqual(_nearby_case_activities(first, [first, second], [activity]), [activity])
        tied = Activity("activity_2", "2026-05-01T12:02:30Z", "DELETE_RECORD", "deletion_worker", "account_service", "account_2", "SUCCESS", "Target resource account_2")
        self.assertEqual(_nearby_case_activities(first, [first, second], [tied]), [])


class PlanningTests(unittest.TestCase):
    def test_active_flow_is_disabled_before_dependent_record_deletion(self):
        observations = [
            obs("account_service", "account_1", "USER_PROFILE", "ABSENT"),
            obs("search_service", "search_1", "SEARCH_INDEX_ENTRY", "PRESENT", fields={"email": "person@example.test"}),
            obs("integration_service", "data_flow_1", "DATA_FLOW", "ACTIVE", fields={"enabled": True, "subject_selector": "user_1"}),
        ]
        result = _analysis_steps(case(), "user_1", observations, {"USER_PROFILE": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE"})
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        operations = [(step["phase"], step["operation"]) for step in result.steps]
        self.assertEqual(operations[:2], [("FINDING", "REPORT_REMAINING_RECORD"), ("FINDING", "REPORT_ACTIVE_DATA_FLOW")])
        remediation = [step["operation"] for step in result.steps if step["phase"] == "REMEDIATION"]
        self.assertEqual(remediation, ["DISABLE_DATA_FLOW", "DELETE_RECORD"])
        self.assertEqual([step["step_no"] for step in result.steps], list(range(1, len(result.steps) + 1)))
        self.assertTrue(all(step["evidence_id"] == "" for step in result.steps if step["phase"] != "FINDING"))

    def test_retained_security_and_anonymized_analytics_are_compliant(self):
        observations = [
            obs("account_service", "account_1", "USER_PROFILE", "ABSENT"),
            obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", "PRESENT", fields={"subject_reference": "user_1"}),
            obs("analytics_platform", "analytics_1", "ANALYTICS_PROFILE", "ANONYMIZED", fields={"email": None, "email_hash": None, "user_id": None}),
        ]
        result = _analysis_steps(case(), "user_1", observations, {"USER_PROFILE": "DELETE", "SECURITY_AUDIT_LOG": "RETAIN", "ANALYTICS_PROFILE": "ANONYMIZE"})
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual([step["operation"] for step in result.steps], ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_ANONYMIZED"])
        self.assertTrue(all(step["phase"] == "VERIFICATION" for step in result.steps))

    def test_incomplete_verification_steps_are_future_checks_without_evidence_ids(self):
        result = _analysis_steps(case(), "user_1", [
            obs("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", "PRESENT", fields={"subject_reference": "user_1"}),
        ], {"SECURITY_AUDIT_LOG": "RETAIN"})
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        self.assertTrue(result.steps)
        self.assertTrue(all(step["evidence_id"] == "" for step in result.steps))

    def test_backup_restore_risk_is_blocked_without_deleting_the_archive(self):
        observations = [
            obs("account_service", "account_1", "USER_PROFILE", "ABSENT"),
            obs("backup_service", "backup_1", "BACKUP_ARCHIVE", "ACTIVE", fields={"restore_allowed": True, "subject_reference": "user_1"}),
        ]
        result = _analysis_steps(case(), "user_1", observations, {"USER_PROFILE": "DELETE", "BACKUP_ARCHIVE": "RETAIN"})
        remediation = [step for step in result.steps if step["phase"] == "REMEDIATION"]
        self.assertEqual([(s["operation"], s["state"]) for s in remediation], [("BLOCK_RESTORE", "BLOCKED")])

    def test_false_boolean_values_are_preserved_and_blocked_backups_get_restore_checks(self):
        flow = obs("integration_service", "data_flow_1", "DATA_FLOW", "", fields={"enabled": False})
        backup = obs("backup_service", "backup_1", "BACKUP_ARCHIVE", "", fields={"restore_allowed": False})
        self.assertEqual(_resolved_state(flow), "DISABLED")
        self.assertEqual(_resolved_state(backup), "BLOCKED")
        result = _analysis_steps(case(), "user_1", [
            obs("account_service", "account_1", "USER_PROFILE", "ABSENT"), flow, backup,
        ], {"USER_PROFILE": "DELETE", "BACKUP_ARCHIVE": "RETAIN"})
        operations = [(step["resource_id"], step["operation"]) for step in result.steps]
        self.assertIn(("data_flow_1", "VERIFY_DATA_FLOW_DISABLED"), operations)
        self.assertIn(("backup_1", "VERIFY_RESTORE_BLOCKED"), operations)

    def test_tombstone_keeps_stable_reference_but_redacts_direct_identifiers(self):
        observations = [
            obs("account_service", "account_1", "USER_PROFILE", "ABSENT"),
            obs("identity_service", "tombstone_1", "ACCOUNT_TOMBSTONE", "PRESENT", fields={"user_id": "user_1", "email": "person@example.test", "phone": "+15555550100"}),
        ]
        result = _analysis_steps(case(), "user_1", observations, {"USER_PROFILE": "DELETE", "ACCOUNT_TOMBSTONE": "REDACT"})
        self.assertEqual(result.deletion_status, "INCOMPLETE")
        finding = next(step for step in result.steps if step["phase"] == "FINDING")
        self.assertEqual((finding["operation"], finding["resource_id"]), ("REPORT_EXPOSED_PII", "tombstone_1"))
        self.assertEqual(next(step for step in result.steps if step["phase"] == "REMEDIATION")["operation"], "REDACT_RECORD")

    def test_future_evidence_is_excluded_by_audit_cutoff(self):
        observations = [
            obs("account_service", "account_1", "USER_PROFILE", "ABSENT", observed="2026-05-01T00:00:00Z"),
            obs("search_service", "search_1", "SEARCH_INDEX_ENTRY", "PRESENT", fields={"email": "person@example.test"}, observed="2026-05-03T00:00:00Z"),
        ]
        result = _analysis_steps(case(audit="2026-05-02T00:00:00Z"), "user_1", observations, {"USER_PROFILE": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE"})
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertEqual([step["resource_id"] for step in result.steps], ["account_1"])


class EvidenceAndOutputTests(unittest.TestCase):
    def test_trace_grouping_keeps_lookup_key_from_the_request_start_line(self):
        root = Path(__file__).resolve().parents[2]
        path = root / "dataset/evidence/logs/support_replica.log"
        source = EvidenceSource("evidence_61", path, "evidence/logs/support_replica.log", "support replica", "2026-09-17T22:00:00Z")
        records = _line_observations(source)
        support = next(record for record in records if record.resource_id == "support_002")
        self.assertEqual(support.category, "SECONDARY_IDENTIFIER")
        self.assertEqual(support.system_id, "support_platform")
        self.assertEqual(support.fields.get("lookup_key"), "nadia.ionescu@yahoo.com")

    def test_screenshot_ocr_keeps_search_result_rows_separate(self):
        root = Path(__file__).resolve().parents[2]
        path = root / "dataset/evidence/images/search_index_inspector_20260901.png"
        source = EvidenceSource("evidence_09", path, "evidence/images/search_index_inspector_20260901.png", "search console", "2026-09-01T06:00:00Z")
        records, problem = _image_observations(source)
        self.assertEqual(problem, "")
        primary = next(record for record in records if record.resource_id == "search_428")
        decoy = next(record for record in records if record.resource_id == "search_1874")
        self.assertIn("g.silva76@gmail.com", primary.fields["text"])
        self.assertNotIn("g.silva76.jr@gmail.com", primary.fields["text"])
        self.assertIn("g.silva76.jr@gmail.com", decoy.fields["text"])
        self.assertNotIn("g.silva76@gmail.com", decoy.fields["text"])

    def test_manifest_scanner_discovers_new_evidence_without_hardcoded_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            dataset = Path(temp)
            (dataset / "evidence").mkdir()
            (dataset / "evidence_files.csv").write_text("file_id,file_path,origin,captured_at\n", encoding="utf-8")
            new_file = dataset / "evidence" / "new_source.txt"
            new_file.write_text("new evidence", encoding="utf-8")
            sources, discovered = load_sources(dataset)
            self.assertEqual(sources, [])
            self.assertEqual(discovered, [new_file])

    def test_sql_inventory_is_read_and_destructive_sql_is_rejected(self):
        root = Path(__file__).resolve().parents[2]
        source = EvidenceSource("evidence_54", root / "dataset/evidence/databases/customer_accounts_failover_replica_20260902.sql", "evidence/databases/customer_accounts_failover_replica_20260902.sql", "fixture", "2026-09-02T23:00:00Z")
        parsed = _sqlite_observations(source)
        self.assertGreaterEqual(len(parsed), 4)
        self.assertTrue(any(record.category == "USER_PROFILE" for record in parsed))
        with tempfile.TemporaryDirectory() as temp:
            bad = Path(temp) / "bad.sql"
            bad.write_text("DROP TABLE sqlite_master;", encoding="utf-8")
            malicious = EvidenceSource("evidence_x", bad, "bad.sql", "fixture", "2026-01-01T00:00:00Z")
            with self.assertRaises(sqlite3.DatabaseError):
                _sqlite_observations(malicious)

    def test_output_writer_and_validator_preserve_exact_contract_and_sort(self):
        root = Path(__file__).resolve().parents[2]
        agent = DeletionAuditAgent(root / "dataset")
        selected = agent.analyze_all()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output.csv"
            expected = agent.requests
            agent.write_output(selected, output)
            result = validate_output(output, expected)
            self.assertEqual(result["rows"], 518)
            with output.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([row["case_id"] for row in rows], sorted(row["case_id"] for row in expected))
            self.assertEqual(list(rows[0]), ["case_id", "deletion_status", "steps_json"])
            for row in rows:
                if row["deletion_status"] == "NOT_APPLICABLE":
                    self.assertEqual(json.loads(row["steps_json"]), [])


if __name__ == "__main__":
    unittest.main()

