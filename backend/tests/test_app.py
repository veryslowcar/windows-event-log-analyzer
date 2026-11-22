from io import BytesIO

import pytest

from backend.app import create_app


@pytest.fixture
def test_app(tmp_path):
    return create_app({"TESTING": True, "UPLOAD_FOLDER": str(tmp_path)})


def test_health_endpoint_returns_ok(test_app):
    response = test_app.test_client().get("/api/health")

    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_upload_saves_evtx_file(test_app, tmp_path):
    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"event log contents"), "System.EVTX")},
    )

    assert response.status_code == 201
    assert response.json["filename"] == "System.EVTX"
    assert response.json["message"] == "File uploaded successfully."
    assert (tmp_path / f"{response.json['upload_id']}.evtx").read_bytes() == b"event log contents"


def test_upload_rejects_unsupported_file_format(test_app):
    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"not an event log"), "events.txt")},
    )

    assert response.status_code == 400
    assert "Unsupported file format" in response.json["error"]


def test_upload_rejects_pdf_file(test_app):
    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"not an event log"), "events.pdf")},
    )

    assert response.status_code == 400
    assert "Unsupported file format" in response.json["error"]


def test_upload_requires_file(test_app):
    response = test_app.test_client().post("/api/upload", data={})

    assert response.status_code == 400
    assert "Choose an .evtx file" in response.json["error"]


def test_upload_reports_file_too_large(test_app):
    test_app.config["MAX_UPLOAD_SIZE"] = 64

    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"x" * 100), "large.evtx")},
    )

    assert response.status_code == 413
    assert "100 MB limit" in response.json["error"]


def test_upload_reports_request_too_large(test_app):
    test_app.config["MAX_CONTENT_LENGTH"] = 64

    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"x" * 100), "large.evtx")},
    )

    assert response.status_code == 413
    assert "100 MB limit" in response.json["error"]
