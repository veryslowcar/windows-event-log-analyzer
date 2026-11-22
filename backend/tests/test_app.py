from io import BytesIO

import pytest

from backend.app import create_app
from logprocessor.evtx_parser import EvtxProcessingError


@pytest.fixture
def test_app(tmp_path):
    return create_app({"TESTING": True, "UPLOAD_FOLDER": str(tmp_path)})


def test_health_endpoint_returns_ok(test_app):
    response = test_app.test_client().get("/api/health")

    assert response.status_code == 200
    assert response.json == {"status": "ok"}


def test_upload_processes_evtx_file_and_returns_events(test_app, tmp_path, monkeypatch):
    expected_events = [
        {
            "event_id": 4624,
            "timestamp": "2026-11-22T12:00:00.000Z",
            "source": "Microsoft-Windows-Security-Auditing",
            "severity": "Information",
            "message": "A user logged on.",
        }
    ]
    monkeypatch.setattr("backend.app.parse_evtx", lambda _path: expected_events)

    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"event log contents"), "System.EVTX")},
    )

    assert response.status_code == 201
    assert response.json["filename"] == "System.EVTX"
    assert response.json["message"] == "Log uploaded and processed successfully."
    assert response.json["event_count"] == 1
    assert response.json["events"] == expected_events
    assert (tmp_path / f"{response.json['upload_id']}.evtx").read_bytes() == b"event log contents"


def test_upload_rejects_log_when_an_event_cannot_be_decoded(test_app, tmp_path, monkeypatch):
    def reject_malformed_event(_path):
        raise EvtxProcessingError("An event record could not be decoded.")

    monkeypatch.setattr("backend.app.parse_evtx", reject_malformed_event)
    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"valid log with a malformed record"), "partially-malformed.evtx")},
    )

    assert response.status_code == 422
    assert response.json["error"] == "An event record could not be decoded."
    assert list(tmp_path.iterdir()) == []


def test_upload_returns_processing_error_for_invalid_evtx(test_app, tmp_path):
    response = test_app.test_client().post(
        "/api/upload",
        data={"file": (BytesIO(b"not an event log"), "corrupt.evtx")},
    )

    assert response.status_code == 422
    assert "not a valid EVTX log" in response.json["error"]
    assert list(tmp_path.iterdir()) == []


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
