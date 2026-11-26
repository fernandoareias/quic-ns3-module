#!/usr/bin/env python3
# Copyright (c) 2026 Fernando Areias
#
# SPDX-License-Identifier: GPL-2.0-only
"""Independent validation of the qlog files that the QUIC module writes.

The checker does not share code with the C++ module. It reads .sqlog files (JSON text sequences,
draft-ietf-quic-qlog-main-schema-15) and checks the framing, the file header, the fields that
draft-ietf-quic-qlog-quic-events-14 requires of each event, and the consistency of what the events
say: times that do not go back, packet numbers that grow, acknowledged ranges that are well
formed. When both files of a connection are given, it also compares the two ends: a packet is
received after it was sent, never received without having been sent, and both files have the same
group id.

Usage:
    validate_qlog.py [--json] file.sqlog...

The exit status is 0 when there is no violation, and 1 otherwise.
"""

import argparse
import collections
import json
import re
import sys

RS = "\x1e"

PACKET_TYPES = {
    "initial",
    "handshake",
    "0RTT",
    "1RTT",
    "retry",
    "version_negotiation",
    "stateless_reset",
    "unknown",
}
LONG_TYPES = {"initial", "handshake", "0RTT", "retry", "version_negotiation"}
NUMBERED_TYPES = {"initial", "handshake", "0RTT", "1RTT"}
DROP_TRIGGERS = {
    "internal_error",
    "rejected",
    "unsupported",
    "invalid",
    "duplicate",
    "connection_unknown",
    "decryption_failure",
    "keys_unavailable",
    "general",
}
LOST_TRIGGERS = {"reordering_threshold", "time_threshold", "pto_expired"}
CLOSE_TRIGGERS = {
    "idle_timeout",
    "application",
    "error",
    "version_mismatch",
    "stateless_reset",
    "aborted",
    "unspecified",
}
TIMER_TYPES = {"ack", "pto", "loss_timeout", "path_validation", "handshake_timeout", "idle_timeout"}
TIMER_EVENTS = {"set", "expired", "cancelled"}
HEX = re.compile(r"^([0-9a-f]{2})*$")

# frame type -> {field: kind}; kind is "uint", "bool", "hex", "text", "ranges", "float", "object"
FRAME_FIELDS = {
    "padding": {},
    "ping": {},
    "ack": {"acked_ranges": "ranges", "ack_delay": "float"},
    "reset_stream": {"stream_id": "uint", "final_size": "uint"},
    "stop_sending": {"stream_id": "uint"},
    "crypto": {"offset": "uint"},
    "new_token": {"token": "object"},
    "stream": {"stream_id": "uint", "offset": "uint", "fin": "bool"},
    "max_data": {"maximum": "uint"},
    "max_stream_data": {"stream_id": "uint", "maximum": "uint"},
    "max_streams": {"stream_type": "text", "maximum": "uint"},
    "data_blocked": {"limit": "uint"},
    "stream_data_blocked": {"stream_id": "uint", "limit": "uint"},
    "streams_blocked": {"stream_type": "text", "limit": "uint"},
    "new_connection_id": {
        "sequence_number": "uint",
        "retire_prior_to": "uint",
        "connection_id": "hex",
    },
    "retire_connection_id": {"sequence_number": "uint"},
    "path_challenge": {"data": "hex"},
    "path_response": {"data": "hex"},
    "connection_close": {"error_space": "text"},
    "handshake_done": {},
    "datagram": {},
    "unknown": {"frame_type_bytes": "uint"},
}
FRAMES_WITH_RAW_LENGTH = {"stream", "crypto"}

EVENTS = {
    "connection_started",
    "connection_closed",
    "connection_id_updated",
    "spin_bit_updated",
    "version_information",
    "alpn_information",
    "parameters_set",
    "packet_sent",
    "packet_received",
    "packet_dropped",
    "packet_buffered",
    "packets_acked",
    "udp_datagrams_sent",
    "udp_datagrams_received",
    "udp_datagram_dropped",
    "recovery_metrics_updated",
    "congestion_state_updated",
    "timer_updated",
    "stream_state_updated",
    "packet_lost",
}


def is_uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def space_of(packet_type):
    return {"initial": "initial", "handshake": "handshake"}.get(packet_type, "app")


class Report:
    def __init__(self):
        self.violations = collections.OrderedDict()

    def add(self, rule, where, message):
        self.violations.setdefault(rule, []).append("%s: %s" % (where, message))

    def count(self):
        return sum(len(v) for v in self.violations.values())


class Trace:
    """What the validator keeps of one file for the checks across files."""

    def __init__(self, path):
        self.path = path
        self.group_id = None
        self.vantage = None
        self.sent = {}  # (space, number) -> time of the first transmission
        self.received = {}  # (space, number) -> time


def check_kind(report, where, rule, name, value, kind):
    ok = True
    if kind == "uint":
        ok = is_uint(value)
    elif kind == "bool":
        ok = isinstance(value, bool)
    elif kind == "hex":
        ok = isinstance(value, str) and HEX.match(value) is not None
    elif kind == "text":
        ok = isinstance(value, str)
    elif kind == "float":
        ok = is_num(value) and value >= 0
    elif kind == "object":
        ok = isinstance(value, dict)
    elif kind == "ranges":
        ok = isinstance(value, list) and len(value) > 0
        previous_low = None
        for pair in value if ok else []:
            if not (isinstance(pair, list) and len(pair) == 2 and all(is_uint(x) for x in pair)):
                ok = False
                break
            low, high = pair
            if low > high:
                report.add("R-ack-range", where, "range %r has its ends reversed" % pair)
            if previous_low is not None and high >= previous_low:
                report.add("R-ack-range", where, "range %r overlaps or follows the one before" % pair)
            previous_low = low
    if not ok:
        report.add(rule, where, "%s has a wrong value: %r" % (name, value))


def check_header(report, where, header, trace=None):
    if not isinstance(header, dict):
        report.add("R-hdr", where, "header is not an object")
        return None
    ptype = header.get("packet_type")
    if ptype not in PACKET_TYPES:
        report.add("R-hdr", where, "packet_type %r is not in the draft" % (ptype,))
        return None
    if ptype in NUMBERED_TYPES:
        if not is_uint(header.get("packet_number")):
            report.add("R-hdr", where, "%s packet without packet_number" % ptype)
        length = header.get("packet_number_length")
        if length is not None and length not in (1, 2, 3, 4):
            report.add("R-hdr", where, "packet_number_length %r" % (length,))
    if ptype == "1RTT":
        for name in ("spin_bit", "key_phase_bit"):
            if name in header and not isinstance(header[name], bool):
                report.add("R-hdr", where, "%s is not a bool" % name)
        for name in ("version", "scid", "scil"):
            if name in header:
                report.add("R-hdr", where, "short header packet with %s" % name)
    if ptype in LONG_TYPES:
        version = header.get("version")
        if not (isinstance(version, str) and re.match(r"^[0-9a-f]{8}$", version)):
            report.add("R-hdr", where, "version %r is not four bytes in hex" % (version,))
    for cid, length in (("scid", "scil"), ("dcid", "dcil")):
        if cid in header:
            value = header[cid]
            if not (isinstance(value, str) and HEX.match(value)):
                report.add("R-hdr", where, "%s is not hex" % cid)
            elif length in header and header[length] != len(value) // 2:
                report.add("R-hdr", where, "%s says %r but the id has %d bytes" %
                           (length, header[length], len(value) // 2))
            elif len(value) // 2 > 20:
                report.add("R-hdr", where, "%s longer than 20 bytes" % cid)
    return ptype


def check_frames(report, where, frames):
    if not isinstance(frames, list):
        report.add("R-frame", where, "frames is not a list")
        return
    for k, frame in enumerate(frames):
        here = "%s frame %d" % (where, k)
        if not isinstance(frame, dict):
            report.add("R-frame", here, "not an object")
            continue
        ftype = frame.get("frame_type")
        if ftype not in FRAME_FIELDS:
            report.add("R-frame", here, "frame_type %r is not in the draft" % (ftype,))
            continue
        for name, kind in FRAME_FIELDS[ftype].items():
            if name not in frame:
                report.add("R-frame", here, "%s frame without %s" % (ftype, name))
            else:
                check_kind(report, here, "R-frame", name, frame[name], kind)
        if ftype in FRAMES_WITH_RAW_LENGTH:
            raw = frame.get("raw")
            if not (isinstance(raw, dict) and is_uint(raw.get("length")) and
                    is_uint(raw.get("payload_length")) and raw["payload_length"] <= raw["length"]):
                report.add("R-frame", here, "%s frame needs raw.length >= raw.payload_length" % ftype)
        if ftype == "connection_close" and frame.get("error_space") not in ("transport", "application"):
            report.add("R-frame", here, "error_space %r" % (frame.get("error_space"),))
        if ftype in ("max_streams", "streams_blocked") and \
                frame.get("stream_type") not in ("bidirectional", "unidirectional"):
            report.add("R-frame", here, "stream_type %r" % (frame.get("stream_type"),))


def check_event(report, where, name, data, state, trace):
    if name == "packet_sent" or name == "packet_received":
        ptype = check_header(report, where, data.get("header"))
        if "frames" in data:
            check_frames(report, where, data["frames"])
        raw = data.get("raw")
        if raw is not None and not (isinstance(raw, dict) and is_uint(raw.get("length"))):
            report.add("R-event", where, "raw.length missing")
        header = data.get("header") or {}
        if ptype in NUMBERED_TYPES and is_uint(header.get("packet_number")):
            key = (space_of(ptype), header["packet_number"])
            if name == "packet_sent":
                last = state["last_sent"].get(space_of(ptype))
                if last is not None and key[1] <= last:
                    report.add("R-pn", where, "packet number %d does not follow %d" % (key[1], last))
                state["last_sent"][space_of(ptype)] = key[1]
                trace.sent.setdefault(key, state["time"])
                state["max_sent"] = max(state["max_sent"], key[1])
            else:
                trace.received.setdefault(key, state["time"])
        if name == "packet_received":
            for frame in data.get("frames", []):
                if isinstance(frame, dict) and frame.get("frame_type") == "ack":
                    ranges = frame.get("acked_ranges")
                    if isinstance(ranges, list) and ranges and isinstance(ranges[0], list):
                        if ranges[0][1] > state["max_sent"]:
                            report.add("R-ack-range", where,
                                       "acknowledges packet %d that was never sent" % ranges[0][1])
    elif name == "packet_lost":
        check_header(report, where, data.get("header"))
        if data.get("trigger") not in LOST_TRIGGERS:
            report.add("R-event", where, "trigger %r" % (data.get("trigger"),))
    elif name == "packet_dropped":
        if data.get("trigger") not in DROP_TRIGGERS:
            report.add("R-event", where, "trigger %r" % (data.get("trigger"),))
        if "header" in data:
            check_header(report, where, data["header"])
    elif name in ("udp_datagrams_sent", "udp_datagrams_received"):
        raw = data.get("raw")
        if not (is_uint(data.get("count")) and isinstance(raw, list) and
                len(raw) == data["count"] and all(is_uint(r.get("length")) for r in raw)):
            report.add("R-event", where, "count and raw do not agree")
    elif name == "recovery_metrics_updated":
        if not data:
            report.add("R-event", where, "an event without any metric")
        for key, value in data.items():
            if key in ("pto_count", "congestion_window", "bytes_in_flight", "ssthresh",
                       "packets_in_flight"):
                if not is_uint(value):
                    report.add("R-event", where, "%s is not an unsigned integer" % key)
            elif key in ("min_rtt", "smoothed_rtt", "latest_rtt", "rtt_variance"):
                if not (is_num(value) and value >= 0):
                    report.add("R-event", where, "%s is not a duration" % key)
    elif name == "timer_updated":
        if data.get("timer_type") not in TIMER_TYPES:
            report.add("R-event", where, "timer_type %r" % (data.get("timer_type"),))
        event = data.get("event_type")
        if event not in TIMER_EVENTS:
            report.add("R-event", where, "event_type %r" % (event,))
        if (event == "set") != ("delta" in data):
            report.add("R-event", where, "delta belongs to the set event only")
    elif name == "parameters_set":
        if data.get("initiator") not in ("local", "remote"):
            report.add("R-event", where, "initiator %r" % (data.get("initiator"),))
    elif name == "connection_closed":
        if data.get("trigger") not in CLOSE_TRIGGERS:
            report.add("R-event", where, "trigger %r" % (data.get("trigger"),))
        if data.get("initiator") not in ("local", "remote"):
            report.add("R-event", where, "initiator %r" % (data.get("initiator"),))
        state["closed"] += 1
    elif name == "connection_started":
        state["started"] += 1
        for side in ("local", "remote"):
            endpoint = data.get(side)
            if endpoint is not None and not (isinstance(endpoint, dict) and
                                             ("address_v4" in endpoint or "address_v6" in endpoint)):
                report.add("R-event", where, "%s endpoint has no address" % side)
    elif name == "version_information":
        chosen = data.get("chosen_version")
        if not (isinstance(chosen, str) and re.match(r"^[0-9a-f]{8}$", chosen)):
            report.add("R-event", where, "chosen_version %r" % (chosen,))
    elif name == "congestion_state_updated":
        if not isinstance(data.get("new"), str):
            report.add("R-event", where, "new state missing")


def validate_file(path, report):
    trace = Trace(path)
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        report.add("R-frame-seq", path, "not UTF-8")
        return trace
    if not text:
        report.add("R-frame-seq", path, "empty file")
        return trace
    if not text.endswith("\n"):
        report.add("R-frame-seq", path, "the last record does not end with LF")
    records = text.split(RS)
    if records[0] != "":
        report.add("R-frame-seq", path, "the file does not start with RS")
    records = records[1:]
    state = {"time": 0.0, "last_sent": {}, "max_sent": -1, "started": 0, "closed": 0}
    for number, record in enumerate(records):
        where = "%s record %d" % (path, number)
        if not record.endswith("\n"):
            report.add("R-frame-seq", where, "a record does not end with LF")
            record += "\n"
        try:
            obj = json.loads(record)
        except ValueError as error:
            report.add("R-json", where, "invalid JSON: %s" % error)
            continue
        if number == 0:
            check_header_record(report, where, obj, trace)
            continue
        if not isinstance(obj, dict):
            report.add("R-event", where, "an event is not an object")
            continue
        time = obj.get("time")
        name = obj.get("name")
        data = obj.get("data")
        if not is_num(time):
            report.add("R-event", where, "time is not a number")
            continue
        if time < state["time"]:
            report.add("R-time", where, "time %s goes back from %s" % (time, state["time"]))
        state["time"] = max(time, state["time"])
        if not (isinstance(name, str) and name.startswith("quic:") and name[5:] in EVENTS):
            report.add("R-event", where, "unknown event name %r" % (name,))
            continue
        if not isinstance(data, dict):
            report.add("R-event", where, "data is not an object")
            continue
        check_event(report, where, name[5:], data, state, trace)
    if state["started"] > 1:
        report.add("R-event", path, "connection_started %d times" % state["started"])
    if state["closed"] > 1:
        report.add("R-event", path, "connection_closed %d times" % state["closed"])
    return trace


def check_header_record(report, where, obj, trace):
    if not isinstance(obj, dict):
        report.add("R-header", where, "the header is not an object")
        return
    if obj.get("file_schema") != "urn:ietf:params:qlog:file:sequential":
        report.add("R-header", where, "file_schema %r" % (obj.get("file_schema"),))
    if obj.get("serialization_format") != "application/qlog+json-seq":
        report.add("R-header", where, "serialization_format %r" % (obj.get("serialization_format"),))
    tr = obj.get("trace")
    if not isinstance(tr, dict):
        report.add("R-header", where, "no trace")
        return
    schemas = tr.get("event_schemas")
    if not (isinstance(schemas, list) and schemas and
            all(isinstance(s, str) and s.startswith("urn:ietf:params:qlog:events:") for s in schemas)):
        report.add("R-header", where, "event_schemas %r" % (schemas,))
    common = tr.get("common_fields", {})
    group = common.get("group_id")
    if group is not None and not (isinstance(group, str) and HEX.match(group)):
        report.add("R-header", where, "group_id %r" % (group,))
    trace.group_id = group
    if common.get("time_format", "relative_to_epoch") not in ("relative_to_epoch",
                                                              "relative_to_previous_event"):
        report.add("R-header", where, "time_format %r" % (common.get("time_format"),))
    reference = common.get("reference_time")
    if reference is not None and not (isinstance(reference, dict) and "clock_type" in reference and
                                      "epoch" in reference):
        report.add("R-header", where, "reference_time needs clock_type and epoch")
    vantage = tr.get("vantage_point", {})
    if vantage.get("type") not in ("client", "server", "network", "unknown"):
        report.add("R-header", where, "vantage_point.type %r" % (vantage.get("type"),))
    trace.vantage = vantage.get("type")


def cross_check(report, traces):
    """Compare the two ends of each connection."""
    groups = collections.defaultdict(list)
    for trace in traces:
        groups[trace.group_id].append(trace)
    for group, pair in groups.items():
        if len(pair) != 2:
            continue
        a, b = pair
        if {a.vantage, b.vantage} != {"client", "server"}:
            continue
        for sender, receiver in ((a, b), (b, a)):
            for key, when in receiver.received.items():
                sent = sender.sent.get(key)
                if sent is None:
                    report.add("R-cross", receiver.path,
                               "received packet %s that %s never logged as sent" %
                               (key, sender.vantage))
                elif when <= sent:
                    report.add("R-cross", receiver.path,
                               "packet %s received at %s, not after it was sent at %s" %
                               (key, when, sent))


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    report = Report()
    traces = [validate_file(path, report) for path in args.files]
    cross_check(report, traces)
    if args.json:
        print(json.dumps({rule: len(v) for rule, v in report.violations.items()}, indent=1))
    else:
        for rule, items in report.violations.items():
            print("%s: %d violation(s)" % (rule, len(items)))
            for item in items[:5]:
                print("    " + item)
        print("%d file(s), %d violation(s)" % (len(args.files), report.count()))
    return 1 if report.count() else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
