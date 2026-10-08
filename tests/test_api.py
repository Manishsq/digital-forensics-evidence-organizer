"""
Tests for FastAPI routes (integration tests).
"""

import io
import pytest


def _login(client, username="test_admin", password="TestPass123!"):
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 302
    return client


def test_dashboard_loads(client):
    _login(client)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"Dashboard" in resp.content


def test_cases_page_loads(client):
    _login(client)
    resp = client.get("/cases")
    assert resp.status_code == 200


def test_create_case_api(client):
    _login(client)
    resp = client.post("/cases/new", data={
        "case_id": "API-TEST-001",
        "name": "API Test Case",
        "description": "Created by API test",
        "organization": "",
        "notes": "",
    })
    assert resp.status_code == 302  # redirect to case detail


def test_duplicate_case_rejected(client):
    _login(client)
    # Create first
    client.post("/cases/new", data={
        "case_id": "DEDUP-001",
        "name": "First", "description": "", "organization": "", "notes": ""
    })
    # Try duplicate
    resp = client.post("/cases/new", data={
        "case_id": "DEDUP-001",
        "name": "Second", "description": "", "organization": "", "notes": ""
    })
    # Should return the form with error (200)
    assert resp.status_code == 200
    assert b"already exists" in resp.content


def test_evidence_list_page(client):
    _login(client)
    resp = client.get("/evidence")
    assert resp.status_code == 200


def test_evidence_import_page(client):
    _login(client)
    resp = client.get("/evidence/import")
    assert resp.status_code == 200


def test_evidence_upload(client, sample_case):
    _login(client)
    file_content = b"forensic evidence file content for api test"
    resp = client.post(
        "/evidence/import",
        data={
            "case_id": sample_case["id"],
            "evidence_category": "Document",
            "description": "API upload test",
            "source": "", "device": "", "suspect_reference": "",
            "acquisition_method": "", "evidence_type": "", "tags_input": "api,test",
        },
        files={"files": ("api_test.txt", io.BytesIO(file_content), "text/plain")},
    )
    # Should redirect to evidence detail
    assert resp.status_code == 302


def test_evidence_detail_page(client, db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="detail_test.txt",
        file_data=b"detail test",
        created_by=admin_user["id"],
    )
    _login(client)
    resp = client.get(f"/evidence/{ev.id}")
    assert resp.status_code == 200
    assert b"SHA-256" in resp.content


def test_evidence_search(client):
    _login(client)
    resp = client.get("/evidence?q=test")
    assert resp.status_code == 200


def test_audit_log_page(client):
    _login(client)
    resp = client.get("/audit")
    assert resp.status_code == 200


def test_custody_page(client):
    _login(client)
    resp = client.get("/custody")
    assert resp.status_code == 200


def test_reports_page(client):
    _login(client)
    resp = client.get("/reports")
    assert resp.status_code == 200


def test_generate_case_report(client, sample_case, db_session, admin_user):
    # Ensure at least one evidence item exists
    from app.services.evidence_service import import_evidence_file
    import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="report_ev.txt",
        file_data=b"report evidence",
        created_by=admin_user["id"],
    )
    _login(client)
    resp = client.post(f"/reports/generate/case/{sample_case['id']}")
    assert resp.status_code == 302  # redirect to report view


def test_verify_evidence_endpoint(client, db_session, admin_user, sample_case):
    from app.services.evidence_service import import_evidence_file
    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="verify_ep.txt",
        file_data=b"verify endpoint test",
        created_by=admin_user["id"],
    )
    _login(client)
    resp = client.post(f"/evidence/{ev.id}/verify")
    assert resp.status_code == 200
    assert b"INTEGRITY VERIFIED" in resp.content


def test_reviewer_cannot_import(client, db_session):
    """REVIEWER role should be blocked from importing evidence."""
    from app.database.models import User, UserRole, gen_uuid
    from app.auth import hash_password

    reviewer = db_session.query(User).filter(User.username == "test_reviewer").first()
    if not reviewer:
        reviewer = User(
            id=gen_uuid(),
            username="test_reviewer",
            email="reviewer@test.local",
            full_name="Test Reviewer",
            hashed_password=hash_password("ReviewPass123!"),
            role=UserRole.REVIEWER,
        )
        db_session.add(reviewer)
        db_session.commit()

    # Login as reviewer
    resp = client.post("/login", data={"username": "test_reviewer", "password": "ReviewPass123!"})
    assert resp.status_code == 302

    resp = client.post(
        "/evidence/import",
        data={"case_id": "x", "evidence_category": "Other",
              "description": "", "source": "", "device": "", "suspect_reference": "",
              "acquisition_method": "", "evidence_type": "", "tags_input": ""},
        files={"files": ("x.txt", io.BytesIO(b"data"), "text/plain")},
    )
    assert resp.status_code == 302
    assert "permission" in resp.headers.get("location", "")


def test_report_generation_includes_hash(client, db_session, admin_user, sample_case):
    import hashlib
    from app.services.evidence_service import import_evidence_file

    content = b"report hash check content"
    ev = import_evidence_file(
        db=db_session,
        case_id=sample_case["id"],
        original_filename="report_hash.bin",
        file_data=content,
        created_by=admin_user["id"],
    )
    _login(client)
    gen_resp = client.post(f"/reports/generate/evidence/{ev.id}")
    assert gen_resp.status_code == 302
    report_url = gen_resp.headers["location"]

    view_resp = client.get(report_url)
    assert view_resp.status_code == 200

    expected_sha = hashlib.sha256(content).hexdigest()
    assert expected_sha.encode() in view_resp.content
