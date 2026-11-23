import re
import struct
import xml.etree.ElementTree as ET
from typing import TypedDict

from Evtx.BinaryParser import ParseException
from Evtx.Evtx import Evtx


EVTX_MAGIC = b"ElfFile\x00"
STRING_BOUNDARY_RE = re.compile(r"</\s*string\s*>\s*<\s*string(?:\s+[^>]*)?\s*>", re.IGNORECASE)
STRING_TAG_RE = re.compile(r"</?\s*string(?:\s+[^>]*)?\s*>", re.IGNORECASE)
SECURITY_AUDIT_SUCCESS = 0x0020000000000000
SECURITY_AUDIT_FAILURE = 0x0010000000000000
SECURITY_TASK_CATEGORIES = {
    "13824": "User Account Management",
}
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
    channel: str | None
    keywords: str | None
    task_category: str | None
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


def _clean_message_value(value: str | None) -> str | None:
    if value is None:
        return None

    value = STRING_BOUNDARY_RE.sub("\n", value)
    value = STRING_TAG_RE.sub("", value).strip()
    return value or None


def _event_keywords(system: ET.Element, rendering_info: ET.Element | None, channel: str | None) -> str | None:
    rendered_keywords = _find_child(rendering_info, "Keywords")
    keyword_labels: list[str] = []
    if rendered_keywords is not None:
        for keyword in rendered_keywords:
            if keyword.tag.rsplit("}", 1)[-1] == "Keyword":
                value = _text(keyword)
                if value:
                    keyword_labels.append(value)

    system_keywords = _text(_find_child(system, "Keywords"))
    if channel is not None and channel.casefold() == "security":
        if system_keywords:
            try:
                keyword_mask = int(system_keywords, 0)
            except ValueError:
                keyword_mask = 0

            audit_keywords = []
            if keyword_mask & SECURITY_AUDIT_SUCCESS:
                audit_keywords.append("Audit Success")
            if keyword_mask & SECURITY_AUDIT_FAILURE:
                audit_keywords.append("Audit Failure")
            if audit_keywords:
                return ", ".join(audit_keywords)

        security_labels = [label for label in keyword_labels if label.casefold() != "classic"]
        if security_labels:
            return ", ".join(security_labels)

    return (
        ", ".join(keyword_labels)
        or _text(rendered_keywords)
        or system_keywords
    )


def _event_task_category(
    system: ET.Element,
    rendering_info: ET.Element | None,
    provider_name: str | None,
    channel: str | None,
) -> str | None:
    rendered_task = _text(_find_child(rendering_info, "Task"))
    if rendered_task and not rendered_task.isdecimal():
        return rendered_task

    if (
        provider_name == "Microsoft-Windows-Security-Auditing"
        and channel is not None
        and channel.casefold() == "security"
    ):
        task_id = rendered_task or _text(_find_child(system, "Task"))
        return SECURITY_TASK_CATEGORIES.get(task_id or "")

    return None


def _event_severity(
    system: ET.Element,
    rendering_info: ET.Element | None,
    channel: str | None,
) -> str:
    rendered_level = _text(_find_child(rendering_info, "Level"))
    if rendered_level and not rendered_level.isdecimal():
        return rendered_level

    level = rendered_level or _text(_find_child(system, "Level"))
    if (
        level == "0"
        and channel is not None
        and channel.casefold() in {"application", "setup", "system"}
    ):
        return "Information"

    return SEVERITY_LEVELS.get(level or "", "Unknown")


def _general_event_message(
    event_id: int | None,
    timestamp: str | None,
    source: str | None,
    severity: str,
    channel: str | None,
    keywords: str | None,
    task_category: str | None,
) -> str:
    fields = [
        ("Channel", channel),
        ("Event ID", str(event_id) if event_id is not None else None),
        ("Date and Time", timestamp),
        ("Source", source),
        (
            "Keywords" if channel and channel.casefold() == "security" else "Level",
            keywords if channel and channel.casefold() == "security" else (
                severity if severity != "Unknown" else None
            ),
        ),
        ("Task Category", task_category),
    ]
    lines = ["Rendered message unavailable. General event information:"]
    lines.extend(f"{label}: {value}" for label, value in fields if value)
    return "\n".join(lines)


def _event_message(root: ET.Element) -> str | None:
    rendering_info = _find_child(root, "RenderingInfo")
    rendered_message = _clean_message_value(_text(_find_child(rendering_info, "Message")))
    return rendered_message


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
    provider_name = provider.attrib.get("Name") if provider is not None else None
    time_created = _find_child(system, "TimeCreated")
    rendering_info = _find_child(root, "RenderingInfo")
    channel = _text(_find_child(system, "Channel"))
    timestamp = time_created.attrib.get("SystemTime") if time_created is not None else None
    severity = _event_severity(system, rendering_info, channel)
    keywords = _event_keywords(system, rendering_info, channel)
    task_category = _event_task_category(system, rendering_info, provider_name, channel)
    message = _event_message(root) or _general_event_message(
        event_id,
        timestamp,
        provider_name,
        severity,
        channel,
        keywords,
        task_category,
    )

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": provider_name,
        "severity": severity,
        "channel": channel,
        "keywords": keywords,
        "task_category": task_category,
        "message": message,
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
