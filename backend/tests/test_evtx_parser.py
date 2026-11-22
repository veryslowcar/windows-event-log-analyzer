import pytest

from logprocessor.evtx_parser import EvtxProcessingError
from logprocessor.evtx_parser import parse_evtx
from logprocessor.evtx_parser import summarize_event_xml


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"


def test_summarize_event_xml_extracts_event_fields_and_rendered_message():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>4624</EventID>
        <Level>4</Level>
        <TimeCreated SystemTime="2026-11-22T12:00:00.000Z" />
      </System>
      <RenderingInfo>
        <Message>A user logged on.</Message>
      </RenderingInfo>
    </Event>
    """

    assert summarize_event_xml(event_xml) == {
        "event_id": 4624,
        "timestamp": "2026-11-22T12:00:00.000Z",
        "source": "Microsoft-Windows-Security-Auditing",
        "severity": "Information",
        "message": "A user logged on.",
    }


def test_summarize_event_xml_builds_message_from_event_data_when_unrendered():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <EventID>4625</EventID>
        <Level>2</Level>
      </System>
      <EventData>
        <Data Name="TargetUserName">alice</Data>
        <Data Name="LogonType">3</Data>
      </EventData>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["severity"] == "Error"
    assert result["message"] == "TargetUserName: alice; LogonType: 3"
    assert result["timestamp"] is None
    assert result["source"] is None


def test_parse_evtx_rejects_non_evtx_content(tmp_path):
    invalid_file = tmp_path / "invalid.evtx"
    invalid_file.write_bytes(b"not an event log")

    with pytest.raises(EvtxProcessingError, match="not a valid EVTX log"):
        parse_evtx(str(invalid_file))


def test_parse_evtx_accepts_newer_minor_version_without_strict_verification(tmp_path, monkeypatch):
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Provider Name="Example-Provider" />
        <EventID>1001</EventID>
        <Level>3</Level>
        <TimeCreated SystemTime="2026-11-22T12:00:00.000Z" />
      </System>
      <RenderingInfo>
        <Message>Example warning.</Message>
      </RenderingInfo>
    </Event>
    """

    class FakeHeader:
        def check_magic(self):
            return True

        def major_version(self):
            return 0x3

        def minor_version(self):
            return 0x2

        def header_chunk_size(self):
            return 0x1000

        def verify(self):
            return False

    class FakeRecord:
        def xml(self):
            return event_xml

    class FakeLog:
        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

        def get_file_header(self):
            return FakeHeader()

        def records(self):
            return iter([FakeRecord()])

    event_file = tmp_path / "valid.evtx"
    event_file.write_bytes(b"ElfFile\x00")
    monkeypatch.setattr("logprocessor.evtx_parser.Evtx", lambda _path: FakeLog())

    assert parse_evtx(str(event_file)) == [
        {
            "event_id": 1001,
            "timestamp": "2026-11-22T12:00:00.000Z",
            "source": "Example-Provider",
            "severity": "Warning",
            "message": "Example warning.",
        }
    ]


def test_parse_evtx_rejects_log_when_any_event_record_is_malformed(tmp_path, monkeypatch):
    valid_event = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <EventID>4624</EventID>
      </System>
    </Event>
    """

    class FakeHeader:
        def check_magic(self):
            return True

        def major_version(self):
            return 0x3

        def header_chunk_size(self):
            return 0x1000

    class FakeRecord:
        def __init__(self, event_xml):
            self.event_xml = event_xml

        def xml(self):
            return self.event_xml

    class FakeLog:
        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            return False

        def get_file_header(self):
            return FakeHeader()

        def records(self):
            return iter([FakeRecord(valid_event), FakeRecord("<Event>")])

    event_file = tmp_path / "partially-malformed.evtx"
    event_file.write_bytes(b"ElfFile\x00")
    monkeypatch.setattr("logprocessor.evtx_parser.Evtx", lambda _path: FakeLog())

    with pytest.raises(EvtxProcessingError, match="An event record could not be decoded"):
        parse_evtx(str(event_file))
