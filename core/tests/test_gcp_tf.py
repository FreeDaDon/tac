import json

import pytest

from core.gcp_sre import tfgcp


def _report(fixtures):
    return tfgcp.analyze_file(fixtures / "gcp_sre" / "state.tfstate.json")


def _rules(report):
    return {(f.rule_id, f.resource) for f in report.findings}


def test_state_fixture_findings(fixtures):
    got = _rules(_report(fixtures))
    expected = {
        ("GCP-IAM-PRIMITIVE", "google_project_iam_member.app_owner"),
        ("GCP-IAM-PRIMITIVE", "google_project_iam_member.dev_editor"),
        ("GCP-IAM-USER-DIRECT", "google_project_iam_member.dev_editor"),
        ("GCP-IAM-ESCALATION", "google_project_iam_member.app_sa_admin"),
        ("GCP-IAM-PUBLIC", "google_storage_bucket_iam_member.public"),
        ("GCP-SA-KEY", "google_service_account_key.app"),
        ("GCP-STATE-SECRET", "google_service_account_key.app"),
        ("GCP-SA-DEFAULT", "google_compute_instance.web"),
        ("GCP-NET-FW-OPEN", "google_compute_firewall.ssh_any"),
        ("GCP-DATA-SQL-PUBLIC", "google_sql_database_instance.db"),
        ("GCP-DATA-BUCKET-PAP", "google_storage_bucket.exports"),
        ("GCP-GKE-ABAC", "google_container_cluster.main"),
        ("GCP-GKE-MASTER-OPEN", "google_container_cluster.main"),
        ("GCP-SA-OVERPRIVILEGED", "serviceAccount:app@acme-prod.iam.gserviceaccount.com"),
    }
    assert expected <= got
    # clean resources stay clean: viewer group binding, private firewall, hardened bucket in a child module
    assert not any(r in ("google_project_iam_member.viewer", "google_compute_firewall.internal",
                         "module.data.google_storage_bucket.ok") for _, r in got)


def test_severities_and_secret_hygiene(fixtures):
    report = _report(fixtures)
    sev = {(f.rule_id, f.resource): f.severity for f in report.findings}
    assert sev[("GCP-IAM-PRIMITIVE", "google_project_iam_member.app_owner")] == "critical"  # owner to a service account
    assert sev[("GCP-IAM-PRIMITIVE", "google_project_iam_member.dev_editor")] == "high"
    assert sev[("GCP-IAM-PUBLIC", "google_storage_bucket_iam_member.public")] == "critical"
    assert "REDACTED-BY-FIXTURE" not in json.dumps([f.model_dump() for f in report.findings])
    assert report.metrics["source"] == "state" and report.metrics["google_resources"] == 14
    assert report.metrics["identity_matrix"]["serviceAccount:app@acme-prod.iam.gserviceaccount.com"] == [
        "roles/iam.serviceAccountAdmin", "roles/owner"]


def test_firewall_rules():
    def fw(**values):
        return tfgcp.check_network({"address": "fw", "type": "google_compute_firewall",
                                    "values": {"source_ranges": ["0.0.0.0/0"], **values}})

    [all_open] = fw(allow=[{"protocol": "all"}])
    assert all_open.severity == "critical"
    [db] = fw(allow=[{"protocol": "tcp", "ports": ["5432"]}])
    assert db.severity == "critical" and db.evidence["ports"] == {"5432": "postgres"}
    [web] = fw(allow=[{"protocol": "tcp", "ports": ["443"]}])
    assert web.rule_id == "GCP-NET-FW-PUBLIC" and web.severity == "low"
    assert fw(allow=[{"protocol": "tcp", "ports": ["22"]}], disabled=True) == []
    assert fw(allow=[{"protocol": "tcp", "ports": ["22"]}], direction="EGRESS") == []
    assert fw(allow=[{"protocol": "tcp", "ports": ["22"]}], source_ranges=["35.235.240.0/20"]) == []
    [rng] = fw(allow=[{"protocol": "tcp", "ports": ["3000-3400"]}])
    assert "mysql" in rng.title


def test_iam_policy_and_binding_forms():
    policy = {"address": "p", "type": "google_project_iam_policy",
              "values": {"policy_data": json.dumps({"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]})}}
    rules = {f.rule_id for f in tfgcp.check_iam(policy)}
    assert {"GCP-IAM-PUBLIC", "GCP-IAM-AUTHORITATIVE"} <= rules
    binding = {"address": "b", "type": "google_folder_iam_binding",
               "values": {"role": "roles/iam.serviceAccountTokenCreator", "members": ["group:g@x.example"]}}
    assert [f.rule_id for f in tfgcp.check_iam(binding)] == ["GCP-IAM-ESCALATION", "GCP-IAM-AUTHORITATIVE"]
    assert tfgcp.check_iam({"address": "x", "type": "google_project_iam_custom_role", "values": {}}) == []


def test_plan_input_uses_resource_changes(tmp_path):
    plan = {"resource_changes": [
        {"address": "google_project_iam_member.a", "type": "google_project_iam_member", "name": "a",
         "change": {"actions": ["create"], "after": {"role": "roles/owner", "member": "user:x@y.example"}}},
        {"address": "google_project_iam_member.gone", "type": "google_project_iam_member", "name": "gone",
         "change": {"actions": ["delete"], "before": {"role": "roles/owner", "member": "allUsers"}, "after": None}}]}
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    report = tfgcp.analyze_file(path)
    assert {f.resource for f in report.findings} == {"google_project_iam_member.a"}
    assert report.metrics["source"] == "plan"


def test_rejects_non_terraform_json(tmp_path):
    path = tmp_path / "x.json"
    path.write_text('{"hello": 1}')
    with pytest.raises(ValueError):
        tfgcp.analyze_file(path)
