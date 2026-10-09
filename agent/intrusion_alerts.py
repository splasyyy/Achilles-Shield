"""Alert-only collection of high-signal Windows intrusion events."""

import os
import re
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime

WINDOWS_EVENT_IDS = {
    "Security": (4625, 4624, 4740, 4672, 4698),
    "System": (7045,),
}
MAX_EVENTS_PER_QUERY = 100


def _local_name(tag):
    return tag.rsplit("}", 1)[-1]


def _parse_events(xml_text, channel="Security"):
    if (channel not in WINDOWS_EVENT_IDS
            or not isinstance(xml_text, str) or not xml_text.strip()):
        return []
    xml_text = re.sub(r"<\?xml[^?]*\?>", "", xml_text.lstrip("\ufeff"))
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    xml_events = []
    for child in root:
        if _local_name(child.tag) == "Event":
            xml_events.append(child)
        elif _local_name(child.tag) == "Events":
            xml_events.extend(child)

    events = []
    for event in xml_events:
        system = next(
            (node for node in event if _local_name(node.tag) == "System"), None
        )
        if system is None:
            continue
        record_id = None
        event_id = None
        timestamp = None
        for node in system:
            if _local_name(node.tag) == "EventRecordID" and node.text:
                record_id = int(node.text)
            elif _local_name(node.tag) == "EventID" and node.text:
                event_id = int(node.text)
            elif _local_name(node.tag) == "TimeCreated":
                raw_time = node.attrib.get("SystemTime")
                if raw_time:
                    timestamp = datetime.fromisoformat(
                        raw_time.replace("Z", "+00:00")
                    ).timestamp()
        if record_id is None or event_id not in WINDOWS_EVENT_IDS[channel]:
            continue
        result = {
            "channel": channel,
            "record_id": record_id,
            "event_id": event_id,
            "ts": timestamp,
        }
        if event_id in {4625, 4624}:
            event_data = {}
            for section in event:
                if _local_name(section.tag) != "EventData":
                    continue
                for item in section:
                    if _local_name(item.tag) == "Data":
                        name = item.attrib.get("Name", "")
                        if name in {
                            "IpAddress", "IpPort", "WorkstationName", "LogonType",
                            "Status", "SubStatus", "TargetLogonId", "SubjectLogonId",
                        }:
                            event_data[name] = item.text or ""
            source_ip = event_data.get("IpAddress", "").strip()
            if source_ip in {"", "-", "::1", "127.0.0.1"}:
                source_ip = None
            result["source_ip"] = source_ip
            result["logon_type"] = event_data.get("LogonType")
            result["source_port"] = event_data.get("IpPort")
            result["workstation_name"] = event_data.get("WorkstationName")
            result["status_code"] = event_data.get("Status")
            result["substatus_code"] = event_data.get("SubStatus")
            if event_data.get("TargetLogonId"):
                result["logon_id"] = event_data["TargetLogonId"]
        elif event_id == 4672:
            for section in event:
                if _local_name(section.tag) != "EventData":
                    continue
                for item in section:
                    if (item.attrib.get("Name") == "SubjectLogonId"
                            and item.text):
                        result["logon_id"] = item.text
                        break
        events.append(result)
    return events


class WindowsIntrusionMonitor:
    """Poll selected Security and System events; never authorize response actions."""

    def __init__(
        self, state_db, poll_seconds=15, platform_name=None, source_id="default"
    ):
        self.state_db = state_db
        self.poll_seconds = poll_seconds
        self.platform_name = platform_name or os.name
        self.source_id = source_id
        self.state_key = f"windows_security:{source_id}"
        self.last_poll = 0.0
        self.status = "starting"
        self.detail = ""
        self.channels = {}
        self._init_state()

    def _init_state(self):
        directory = os.path.dirname(os.path.abspath(self.state_db))
        os.makedirs(directory, exist_ok=True)
        with closing(sqlite3.connect(self.state_db, timeout=5)) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS intrusion_monitor_state (
                       source TEXT PRIMARY KEY,
                       last_record_id INTEGER NOT NULL
                   )"""
            )
            connection.commit()

    def _channel_key(self, channel):
        return self.state_key if channel == "Security" else f"windows_system:{self.source_id}"

    def _last_record_id(self, channel="Security"):
        with closing(sqlite3.connect(self.state_db, timeout=5)) as connection:
            row = connection.execute(
                "SELECT last_record_id FROM intrusion_monitor_state WHERE source = ?",
                (self._channel_key(channel),),
            ).fetchone()
        return row[0] if row else None

    def _save_record_id(self, record_id, channel="Security"):
        with closing(sqlite3.connect(self.state_db, timeout=5)) as connection:
            connection.execute(
                """INSERT INTO intrusion_monitor_state(source, last_record_id)
                   VALUES (?, ?)
                   ON CONFLICT(source) DO UPDATE SET last_record_id = excluded.last_record_id""",
                (self._channel_key(channel), record_id),
            )
            connection.commit()

    def _query(self, channel, arguments=None):
        if arguments is None:
            channel, arguments = "Security", channel
        result = subprocess.run(
            ["wevtutil.exe", "qe", channel, *arguments],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            timeout=8,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            raise RuntimeError(f"Windows {channel} log query failed")
        return _parse_events(result.stdout, channel)

    def collect(self, now=None):
        now = time.time() if now is None else now
        empty_result = {
            "source": "windows_intrusion_events",
            "status": self.status,
            "detail": self.detail,
            "channels": dict(self.channels),
            "events": [],
        }
        if self.platform_name != "nt":
            self.status = "unsupported"
            self.detail = "Windows event-log collection is not supported on this OS."
            self.channels = {channel: "unsupported" for channel in WINDOWS_EVENT_IDS}
            return {
                **empty_result,
                "status": self.status,
                "detail": self.detail,
                "channels": dict(self.channels),
            }
        if now - self.last_poll < self.poll_seconds:
            return {**empty_result, "status": self.status, "detail": self.detail}

        self.last_poll = now
        events = []
        checkpoints = {}
        channels = {}
        failures = []
        for channel, event_ids in WINDOWS_EVENT_IDS.items():
            try:
                last_record_id = self._last_record_id(channel)
                event_filter = " or ".join(
                    f"EventID={event_id}" for event_id in event_ids
                )
                if last_record_id is None:
                    baseline = self._query(channel, [
                        f"/q:*[System[({event_filter})]]",
                        "/rd:true",
                        "/c:1",
                        "/f:xml",
                    ])
                    checkpoint = max(
                        (event["record_id"] for event in baseline), default=0
                    )
                    self._save_record_id(checkpoint, channel)
                    channels[channel] = "ready"
                    continue

                channel_events = self._query(channel, [
                    f"/q:*[System[({event_filter}) and "
                    f"(EventRecordID > {last_record_id})]]",
                    "/rd:false",
                    f"/c:{MAX_EVENTS_PER_QUERY}",
                    "/f:xml",
                ])
                events.extend(channel_events)
                channels[channel] = "ready"
                if channel_events:
                    checkpoints[channel] = max(
                        event["record_id"] for event in channel_events
                    )
            except (
                OSError, RuntimeError, ET.ParseError, ValueError,
                subprocess.SubprocessError,
            ) as error:
                channels[channel] = "unavailable"
                failures.append(f"{channel}: {type(error).__name__}")

        if failures and len(failures) == len(WINDOWS_EVENT_IDS):
            self.status = "unavailable"
            self.detail = "Windows event logs could not be read; " + "; ".join(failures)
        elif failures:
            self.status = "degraded"
            self.detail = "Some Windows event logs could not be read; " + "; ".join(failures)
        else:
            self.status = "ready"
            self.detail = "Monitoring selected Windows Security and System events."
        self.channels = channels
        result = {
            "source": "windows_intrusion_events",
            "status": self.status,
            "detail": self.detail,
            "channels": channels,
            "events": events,
        }
        if checkpoints:
            result["checkpoints"] = checkpoints
        return result

    def acknowledge(self, payload):
        """Advance each channel cursor only after telemetry is accepted."""
        monitor = payload.get("auth_monitor") if isinstance(payload, dict) else None
        checkpoints = monitor.get("checkpoints") if isinstance(monitor, dict) else None
        if not isinstance(checkpoints, dict):
            return
        for channel, checkpoint in checkpoints.items():
            if (channel not in WINDOWS_EVENT_IDS
                    or not isinstance(checkpoint, int)
                    or isinstance(checkpoint, bool)
                    or checkpoint < 0):
                continue
            last_record_id = self._last_record_id(channel)
            if last_record_id is None or checkpoint > last_record_id:
                self._save_record_id(checkpoint, channel)
