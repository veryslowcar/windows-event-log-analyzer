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
        "channel": None,
        "keywords": None,
        "task_category": None,
        "message": "A user logged on.",
    }


def test_summarize_event_xml_uses_general_metadata_when_message_is_unrendered():
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
    assert result["channel"] is None
    assert result["keywords"] is None
    assert result["task_category"] is None
    assert result["message"] == (
        "Rendered message unavailable. General event information:\n"
        "Event ID: 4625\n"
        "Level: Error"
    )
    assert "alice" not in result["message"]
    assert result["timestamp"] is None
    assert result["source"] is None


def test_summarize_event_xml_uses_rendered_level_when_present():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Channel>Application</Channel>
        <Level>0</Level>
      </System>
      <RenderingInfo>
        <Level>Information</Level>
      </RenderingInfo>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["severity"] == "Information"


def test_summarize_security_spp_16384_formats_message_data():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Provider Name="Microsoft-Windows-Security-SPP" />
        <EventID>16384</EventID>
        <Channel>Application</Channel>
        <Level>4</Level>
      </System>
      <EventData>
        <Data>&lt;string&gt;2126-10-30T01:03:39Z&lt;/string&gt;
        &lt;string&gt;RulesEngine&lt;/string&gt;</Data>
        <Data />
      </EventData>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["message"] == (
        "Successfully scheduled Software Protection service for re-start at "
        "2126-10-30T01:03:39Z. Reason: RulesEngine."
    )


def test_summarize_security_spp_1003_uses_readable_message():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Provider Name="Microsoft-Windows-Security-SPP" />
        <EventID>1003</EventID>
        <Channel>Application</Channel>
        <Level>4</Level>
      </System>
      <EventData>
        <Data Name="ApplicationId">example</Data>
        <Data Name="LicensingStatus">example</Data>
      </EventData>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["message"] == (
        "The Software Protection service has completed licensing status check."
    )


@pytest.mark.parametrize(
    ("channel", "expected_severity"),
    [
        ("Application", "Information"),
        ("Setup", "Information"),
        ("System", "Information"),
        ("ForwardedEvents", "LogAlways"),
    ],
)
def test_summarize_level_zero_uses_channel_appropriate_label(channel, expected_severity):
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Channel>{channel}</Channel>
        <Level>0</Level>
      </System>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["severity"] == expected_severity


def test_summarize_event_xml_extracts_log_specific_metadata():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Channel>Security</Channel>
        <Keywords>0x8020000000000000</Keywords>
        <Task>12544</Task>
      </System>
      <RenderingInfo>
        <Keywords>
          <Keyword>Audit Success</Keyword>
          <Keyword>Classic</Keyword>
        </Keywords>
        <Task>Logon</Task>
      </RenderingInfo>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["channel"] == "Security"
    assert result["keywords"] == "Audit Success"
    assert result["task_category"] == "Logon"


def test_summarize_event_xml_falls_back_to_system_keywords_and_task():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Keywords>0x8020000000000000</Keywords>
        <Task>12544</Task>
      </System>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["keywords"] == "0x8020000000000000"
    assert result["task_category"] is None


@pytest.mark.parametrize(
    ("keyword_mask", "expected_keywords"),
    [
        ("0x8020000000000000", "Audit Success"),
        ("0x8010000000000000", "Audit Failure"),
    ],
)
def test_summarize_security_event_resolves_keyword_and_task_display_names(keyword_mask, expected_keywords):
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <EventID>5379</EventID>
        <Channel>Security</Channel>
        <Keywords>{keyword_mask}</Keywords>
        <Task>13824</Task>
      </System>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["keywords"] == expected_keywords
    assert result["task_category"] == "User Account Management"
    if expected_keywords == "Audit Success":
        assert "Keywords: Audit Success" in result["message"]
        assert "Task Category: User Account Management" in result["message"]


def test_summarize_security_event_does_not_display_unknown_task_id_as_category():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" />
        <Channel>Security</Channel>
        <Task>99999</Task>
      </System>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["task_category"] is None


def test_summarize_event_xml_cleans_rendered_string_wrappers():
    event_xml = f"""\
    <Event xmlns="{EVENT_NAMESPACE}">
      <System>
        <EventID>1003</EventID>
      </System>
      <RenderingInfo>
        <Message>&lt;string&gt;First status&lt;/string&gt;&lt;string&gt;Second status&lt;/string&gt;</Message>
      </RenderingInfo>
    </Event>
    """

    result = summarize_event_xml(event_xml)

    assert result["message"] == "First status\nSecond status"


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
            "channel": None,
            "keywords": None,
            "task_category": None,
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
