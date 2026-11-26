#!/usr/bin/env python3
# Copyright (c) 2026 Fernando Areias
#
# SPDX-License-Identifier: GPL-2.0-only
"""Tests of validate_qlog.py: well formed files give no violation and each rule fires.

Run with: python3 -m unittest contrib/quic/test/tools/test_validate_qlog.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import validate_qlog as v  # noqa: E402

GROUP = "0102030405060708"


def header(vantage, group=GROUP):
    return {
        "file_schema": "urn:ietf:params:qlog:file:sequential",
        "serialization_format": "application/qlog+json-seq",
        "trace": {
            "common_fields": {
                "group_id": group,
                "time_format": "relative_to_epoch",
                "reference_time": {"clock_type": "monotonic", "epoch": "unknown"},
            },
            "vantage_point": {"name": "node", "type": vantage},
            "event_schemas": ["urn:ietf:params:qlog:events:quic-14"],
        },
    }


def packet_header(number, ptype="1RTT"):
    h = {"packet_type": ptype, "packet_number": number, "packet_number_length": 2}
    if ptype == "1RTT":
        h.update({"spin_bit": False, "key_phase_bit": False})
    else:
        h.update({"version": "00000001", "scil": 4, "dcil": 4, "scid": "01020304",
                  "dcid": "05060708"})
    return h


def event(time, name, data):
    return {"time": time, "name": "quic:" + name, "data": data}


def sent(time, number, frames=None):
    return event(time, "packet_sent", {"header": packet_header(number),
                                       "frames": frames if frames is not None else
                                       [{"frame_type": "ping"}],
                                       "raw": {"length": 40, "payload_length": 20}})


def received(time, number, frames=None):
    return event(time, "packet_received", {"header": packet_header(number),
                                           "frames": frames if frames is not None else
                                           [{"frame_type": "ping"}]})


def text(head, events, raw=False):
    parts = [head] + events
    return "".join(v.RS + (p if isinstance(p, str) else json.dumps(p)) + "\n" for p in parts)


class ValidateQlogTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def run_files(self, *contents):
        paths = []
        for k, content in enumerate(contents):
            path = os.path.join(self.dir.name, "f%d.sqlog" % k)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            paths.append(path)
        report = v.Report()
        traces = [v.validate_file(p, report) for p in paths]
        v.cross_check(report, traces)
        return report

    def good_client(self):
        return text(header("client"), [
            event(1.0, "connection_started", {"local": {"address_v4": {"ip": "1.1.1.1", "port": 1}}}),
            sent(1.1, 1),
            sent(1.2, 2),
            event(21.0, "recovery_metrics_updated", {"smoothed_rtt": 20.0, "congestion_window": 14000}),
            event(30.0, "timer_updated", {"timer_type": "pto", "event_type": "set", "delta": 75.0}),
            event(31.0, "packet_lost", {"header": {"packet_type": "1RTT", "packet_number": 1},
                                        "trigger": "time_threshold"}),
            event(40.0, "connection_closed", {"initiator": "local", "trigger": "idle_timeout"}),
        ])

    def good_server(self):
        return text(header("server"), [
            event(11.0, "connection_started", {"local": {"address_v4": {"ip": "1.1.1.2", "port": 2}}}),
            received(11.1, 1),
            received(11.2, 2),
        ])

    def test_good_files(self):
        self.assertEqual(self.run_files(self.good_client(), self.good_server()).count(), 0)

    def rules(self, report):
        return set(report.violations)

    def test_framing(self):
        good = self.good_client()
        self.assertIn("R-frame-seq", self.rules(self.run_files(good.replace(v.RS, "", 1))))
        self.assertIn("R-frame-seq", self.rules(self.run_files(good[:-1])))
        self.assertIn("R-json", self.rules(self.run_files(good + v.RS + "{not json}\n")))
        self.assertIn("R-frame-seq", self.rules(self.run_files("")))

    def test_header_record(self):
        head = header("client")
        head["file_schema"] = "x"
        head["trace"]["vantage_point"]["type"] = "peer"
        head["trace"]["event_schemas"] = []
        self.assertIn("R-header", self.rules(self.run_files(text(head, []))))

    def test_events(self):
        head = header("client")
        for bad in (
            event(1.0, "no_such_event", {}),
            event(1.0, "packet_lost", {"header": packet_header(1), "trigger": "bad"}),
            event(1.0, "timer_updated", {"timer_type": "pto", "event_type": "set"}),
            event(1.0, "timer_updated", {"timer_type": "pto", "event_type": "expired", "delta": 1.0}),
            event(1.0, "recovery_metrics_updated", {}),
            event(1.0, "recovery_metrics_updated", {"congestion_window": -1}),
            event(1.0, "connection_closed", {"initiator": "local", "trigger": "bad"}),
            event(1.0, "udp_datagrams_sent", {"count": 2, "raw": [{"length": 1}]}),
        ):
            self.assertNotEqual(self.run_files(text(head, [bad])).count(), 0, bad)

    def test_time_and_numbers(self):
        head = header("client")
        back = text(head, [sent(5.0, 1), sent(4.0, 2)])
        self.assertIn("R-time", self.rules(self.run_files(back)))
        repeated = text(head, [sent(1.0, 2), sent(2.0, 2)])
        self.assertIn("R-pn", self.rules(self.run_files(repeated)))

    def test_headers_and_frames(self):
        head = header("client")
        bad_header = packet_header(1)
        bad_header["packet_type"] = "short"
        self.assertIn("R-hdr", self.rules(self.run_files(
            text(head, [event(1.0, "packet_sent", {"header": bad_header, "frames": []})]))))
        long_header = packet_header(1, "initial")
        long_header["dcil"] = 9
        self.assertIn("R-hdr", self.rules(self.run_files(
            text(head, [event(1.0, "packet_sent", {"header": long_header, "frames": []})]))))
        for frame in ({"frame_type": "teleport"},
                      {"frame_type": "stream", "stream_id": 4, "offset": 0, "fin": False},
                      {"frame_type": "max_data"},
                      {"frame_type": "max_streams", "stream_type": "sideways", "maximum": 3},
                      {"frame_type": "connection_close", "error_space": "everywhere"}):
            self.assertNotEqual(self.run_files(text(head, [sent(1.0, 1, [frame])])).count(), 0,
                                frame)

    def test_ack_ranges(self):
        head = header("client")
        ok = {"frame_type": "ack", "ack_delay": 1.0, "acked_ranges": [[4, 9], [1, 2]]}
        stream = text(head, [sent(1.0, 10), received(2.0, 1, [ok])])
        self.assertEqual(self.run_files(stream).count(), 0)
        for ranges in ([[9, 4]], [[1, 2], [4, 9]], [[4, 9], [2, 5]]):
            frame = {"frame_type": "ack", "ack_delay": 1.0, "acked_ranges": ranges}
            self.assertIn("R-ack-range",
                          self.rules(self.run_files(text(head, [sent(1.0, 10),
                                                                received(2.0, 1, [frame])]))))
        never_sent = {"frame_type": "ack", "ack_delay": 1.0, "acked_ranges": [[40, 50]]}
        self.assertIn("R-ack-range",
                      self.rules(self.run_files(text(head, [sent(1.0, 10),
                                                            received(2.0, 1, [never_sent])]))))

    def test_both_ends(self):
        client = text(header("client"), [sent(1.0, 1)])
        early = text(header("server"), [received(0.5, 1)])
        self.assertIn("R-cross", self.rules(self.run_files(client, early)))
        unknown = text(header("server"), [received(2.0, 7)])
        self.assertIn("R-cross", self.rules(self.run_files(client, unknown)))
        ok = text(header("server"), [received(2.0, 1)])
        self.assertEqual(self.run_files(client, ok).count(), 0)


if __name__ == "__main__":
    unittest.main()
