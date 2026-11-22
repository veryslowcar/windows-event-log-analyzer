import struct
import xml.etree.ElementTree as ET
from typing import TypedDict

from Evtx.BinaryParser import ParseException
from Evtx.Evtx import Evtx


EVTX_MAGIC = b"ElfFile\x00"
SEVERITY_LEVELS = {
    "0": "LogAlways",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}


class EventSummary(TypedDict):
    event_id: int | None
    timestamp: str | None
    source: str | None
    severity: str
    message: str | None


class EvtxProcessingError(ValueError):
    pass


def _find_child(element: ET.Element | None, name: str) -> ET.Element | None:
    if element is None:
        return None

    return next(
        (child for child in element if child.tag.rsplit("}", 1)[-1] == name),
        None,
    )


def _text(element: ET.Element | None) -> str | None:
    if element is None:
        return None

    value = "".join(element.itertext()).strip()
    return value or None


def _event_message(root: ET.Element) -> str | None:
    rendering_info = _find_child(root, "RenderingInfo")
    rendered_message = _text(_find_child(rendering_info, "Message"))
    if rendered_message:
        return rendered_message

    event_data = _find_child(root, "EventData")
    values = []
    if event_data is not None:
        for data in event_data:
            if data.tag.rsplit("}", 1)[-1] != "Data":
                continue
            value = _text(data)
            if value:
                name = data.attrib.get("Name")
                values.append(f"{name}: {value}" if name else value)

    if values:
        return "; ".join(values)

    user_data = _find_child(root, "UserData")
    return _text(user_data)


def summarize_event_xml(event_xml: str) -> EventSummary:
    try:
        root = ET.fromstring(event_xml)
    except ET.ParseError as error:
        raise EvtxProcessingError("An event record could not be decoded.") from error

    system = _find_child(root, "System")
    if system is None:
        raise EvtxProcessingError("An event record is missing system metadata.")

    event_id_text = _text(_find_child(system, "EventID"))
    try:
        event_id = int(event_id_text) if event_id_text is not None else None
    except ValueError:
        event_id = None

    provider = _find_child(system, "Provider")
    time_created = _find_child(system, "TimeCreated")
    level = _text(_find_child(system, "Level"))

    return {
        "event_id": event_id,
        "timestamp": time_created.attrib.get("SystemTime") if time_created is not None else None,
        "source": provider.attrib.get("Name") if provider is not None else None,
        "severity": SEVERITY_LEVELS.get(level, "Unknown"),
        "message": _event_message(root),
    }


def parse_evtx(file_path: str) -> list[EventSummary]:
    try:
        with open(file_path, "rb") as event_file:
            if event_file.read(len(EVTX_MAGIC)) != EVTX_MAGIC:
                raise EvtxProcessingError("The uploaded file is not a valid EVTX log.")

        with Evtx(file_path) as log:
            header = log.get_file_header()
            if (
                not header.check_magic()
                or header.major_version() != 0x3
                or header.header_chunk_size() != 0x1000
            ):
                raise EvtxProcessingError("The EVTX file header is invalid or unsupported.")

            return [summarize_event_xml(record.xml()) for record in log.records()]
    except EvtxProcessingError:
        raise
    except (OSError, ValueError, ParseException, UnicodeError, ET.ParseError, struct.error, IndexError) as error:
        raise EvtxProcessingError("The EVTX file could not be processed; it may be damaged or malformed.") from error
