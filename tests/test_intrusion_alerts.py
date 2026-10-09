import os
import tempfile
import unittest
from unittest.mock import patch

from agent.intrusion_alerts import (
    WINDOWS_EVENT_IDS,
    WindowsIntrusionMonitor,
    _parse_events,
)


def event_xml(event_id, record_id, data=""):
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>{event_id}</EventID>
        <EventRecordID>{record_id}</EventRecordID>
        <TimeCreated SystemTime="2026-10-09T00:00:00.000Z" />
      </System>
      <EventData>{data}</EventData>
    </Event>"""


class WindowsIntrusionMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.state_db = os.path.join(self.temp_directory.name, "agent-state.db")
        self.addCleanup(self.temp_directory.cleanup)

    def test_parses_selected_events_and_omits_sensitive_event_data(self):
        xml = "\n".join([
            event_xml(4625, 42, """
              <Data Name="TargetUserName">private-account</Data>
              <Data Name="IpAddress">203.0.113.9</Data>
              <Data Name="IpPort">53124</Data>
              <Data Name="WorkstationName">source-workstation</Data>
              <Data Name="LogonType">10</Data>
              <Data Name="Status">0xC000006D</Data>
              <Data Name="SubStatus">0xC000006A</Data>"""),
            event_xml(4624, 43, """
              <Data Name="IpAddress">203.0.113.9</Data>
              <Data Name="LogonType">10</Data>
              <Data Name="TargetLogonId">0x123</Data>"""),
            event_xml(4740, 44, '<Data Name="TargetUserName">private-account</Data>'),
            event_xml(4672, 45, """
              <Data Name="SubjectLogonId">0x123</Data>
              <Data Name="PrivilegeList">SensitivePrivilege</Data>"""),
            event_xml(4698, 46, '<Data Name="TaskContent">private task XML</Data>'),
            event_xml(9999, 47),
        ])

        events = _parse_events(xml, "Security")

        self.assertEqual([4625, 4624, 4740, 4672, 4698],
                         [event["event_id"] for event in events])
        self.assertEqual("203.0.113.9", events[0]["source_ip"])
        self.assertEqual("10", events[0]["logon_type"])
        self.assertEqual("53124", events[0]["source_port"])
        self.assertEqual("source-workstation", events[0]["workstation_name"])
        self.assertEqual("0xC000006D", events[0]["status_code"])
        self.assertEqual("0xC000006A", events[0]["substatus_code"])
        self.assertEqual("0x123", events[1]["logon_id"])
        self.assertEqual("0x123", events[3]["logon_id"])
        self.assertEqual({"channel", "record_id", "event_id", "ts"},
                         set(events[2]))
        self.assertNotIn(
            "private-account SensitivePrivilege private task XML", str(events)
        )
        self.assertEqual([{"channel": "System", "record_id": 50, "event_id": 7045,
                          "ts": events[0]["ts"]}],
                         _parse_events(event_xml(7045, 50), "System"))

    def test_channels_have_independent_cursors_and_acknowledge_after_delivery(self):
        monitor = WindowsIntrusionMonitor(
            self.state_db, poll_seconds=15, platform_name="nt", source_id="host-a"
        )
        security_event = {
            "channel": "Security", "record_id": 25, "event_id": 4625,
            "ts": 1_791_494_400, "source_ip": "203.0.113.9", "logon_type": "10",
        }
        system_event = {
            "channel": "System", "record_id": 35, "event_id": 7045,
            "ts": 1_791_494_401,
        }

        def query(channel, arguments):
            if "/rd:true" in arguments:
                return [{"record_id": 20 if channel == "Security" else 30}]
            if channel == "Security":
                return [security_event]
            return [system_event]

        with patch.object(monitor, "_query", side_effect=query) as mocked:
            baseline = monitor.collect(now=100)
            batch = monitor.collect(now=116)
            before_ack = (
                monitor._last_record_id("Security"),
                monitor._last_record_id("System"),
            )
            monitor.acknowledge({"auth_monitor": batch})
            after_ack = (
                monitor._last_record_id("Security"),
                monitor._last_record_id("System"),
            )
            cached = monitor.collect(now=117)

        self.assertEqual("ready", baseline["status"])
        self.assertEqual([], baseline["events"])
        self.assertEqual([security_event, system_event], batch["events"])
        self.assertEqual({"Security": 25, "System": 35}, batch["checkpoints"])
        self.assertEqual((20, 30), before_ack)
        self.assertEqual((25, 35), after_ack)
        self.assertEqual({"Security": "ready", "System": "ready"},
                         cached["channels"])
        self.assertEqual([], cached["events"])
        self.assertEqual(4, mocked.call_count)
        self.assertIn("EventID=4698", mocked.call_args_list[0].args[1][0])
        self.assertEqual(WINDOWS_EVENT_IDS["System"], (7045,))

    def test_partial_channel_access_is_reported_and_accessible_channel_still_collects(self):
        monitor = WindowsIntrusionMonitor(
            self.state_db, platform_name="nt"
        )

        def query(channel, arguments):
            if channel == "Security":
                raise PermissionError
            if "/rd:true" in arguments:
                return [{"record_id": 5}]
            return [{"channel": "System", "record_id": 6, "event_id": 7045,
                     "ts": 1_791_494_400}]

        with patch.object(monitor, "_query", side_effect=query):
            monitor.collect(now=100)
            result = monitor.collect(now=116)

        self.assertEqual("degraded", result["status"])
        self.assertEqual("unavailable", result["channels"]["Security"])
        self.assertEqual("ready", result["channels"]["System"])
        self.assertEqual([7045], [event["event_id"] for event in result["events"]])
        self.assertIn("Security", result["detail"])

    def test_other_operating_systems_report_unsupported(self):
        monitor = WindowsIntrusionMonitor(self.state_db, platform_name="posix")
        result = monitor.collect(now=100)

        self.assertEqual("unsupported", result["status"])
        self.assertEqual([], result["events"])
        self.assertEqual(
            {"Security": "unsupported", "System": "unsupported"},
            result["channels"],
        )
