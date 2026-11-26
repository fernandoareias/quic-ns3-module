#!/usr/bin/env python3
# Copyright (c) 2026 Fernando Areias
#
# SPDX-License-Identifier: GPL-2.0-only
"""Independent lint of the QUIC wire format found in pcap files.

The checker does not share code with the C++ module. It reads the bytes of the UDP datagrams that
the simulator wrote to a pcap file and checks them against RFC 8999, RFC 9000 and RFC 9001. The
module only emulates the cryptography: packets travel in clear and carry a 16 byte AEAD tag, so the
checker can read the headers and the frames and can still check what a real endpoint would see.

Every check has a rule id, listed in RULES. The report gives the number of violations of each rule
and a few examples, which makes the count a measure of how far a capture is from the standards.

Usage:
    quic_pcap_lint.py [--port N]... [--mtu N] [--json] [--expect FILE] capture.pcap...

The exit status is 0 when there is no violation, or when every count is within the limits of the
file given with --expect (a JSON object {rule: maximum}), and 1 otherwise.
"""

import argparse
import collections
import json
import struct
import sys

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
AEAD_TAG = 16
MIN_INITIAL_DATAGRAM = 1200
MAX_CID_LENGTH = 20

RULES = collections.OrderedDict(
    [
        ("R-hdr-01", "Fixed Bit is 1 (RFC 9000 17.2, 17.3)"),
        ("R-hdr-02", "connection ids are at most 20 bytes in a version 1 or 2 long header (RFC 9000 17.2)"),
        ("R-hdr-03", "reserved bits are zero (RFC 9000 17.2, 17.3)"),
        ("R-hdr-04", "long header is well formed: Token Length, Length and the packet number fit the packet (RFC 9000 17.2)"),
        ("R-hdr-05", "packet number and protected payload are at least 20 bytes (RFC 9001 5.4.2)"),
        ("R-hdr-06", "version is 1, 2, 0 (negotiation) or a reserved version (RFC 9000 15, RFC 9369)"),
        ("R-hdr-07", "Version Negotiation packet is well formed (RFC 8999 6)"),
        ("R-hdr-08", "Version Negotiation echoes the connection ids of the packet it answers (RFC 9000 17.2.1)"),
        ("R-hdr-09", "short header carries a destination id of the length the peer chose (RFC 9000 17.3)"),
        ("R-hdr-10", "Retry packet is well formed (RFC 9000 17.2.5)"),
        ("R-frame-01", "frame type uses the shortest variable-length encoding (RFC 9000 12.4)"),
        ("R-frame-02", "frame type is defined"),
        ("R-frame-03", "frame is allowed in this packet type (RFC 9000 12.4, table 3)"),
        ("R-frame-04", "frame is well formed (RFC 9000 19)"),
        ("R-frame-05", "packet carries at least one frame (RFC 9000 12.4)"),
        ("R-frame-06", "NEW_CONNECTION_ID fields are valid (RFC 9000 19.15)"),
        ("R-dgram-01", "datagram with a client Initial, or a server ack-eliciting Initial, has 1200 bytes (RFC 9000 14.1)"),
        ("R-dgram-02", "coalesced long header packets are in encryption-level order (RFC 9000 12.2)"),
        ("R-dgram-03", "coalesced packets share one destination id (RFC 9000 12.2)"),
        ("R-dgram-04", "IP datagram does not exceed the MTU"),
        ("R-dgram-05", "datagram is not IP fragmented (RFC 9000 14)"),
        ("R-hs-01", "the first long header packet of the server is an Initial (RFC 9001 4)"),
        ("R-hs-02", "a packet number is not reused in a packet number space (RFC 9000 12.3)"),
        ("R-rec-01", "ACK does not acknowledge a packet that was never sent (RFC 9000 13.1)"),
    ]
)

# Frame types of RFC 9000 and of the extensions of the module, with the packet types that may carry
# them: I Initial, H Handshake, Z 0-RTT, O 1-RTT.
KNOWN_FRAMES = {
    0x00: ("PADDING", "IHZO"),
    0x01: ("PING", "IHZO"),
    0x02: ("ACK", "IHO"),
    0x03: ("ACK_ECN", "IHO"),
    0x04: ("RESET_STREAM", "ZO"),
    0x05: ("STOP_SENDING", "ZO"),
    0x06: ("CRYPTO", "IHO"),
    0x07: ("NEW_TOKEN", "O"),
    0x10: ("MAX_DATA", "ZO"),
    0x11: ("MAX_STREAM_DATA", "ZO"),
    0x12: ("MAX_STREAMS_BIDI", "ZO"),
    0x13: ("MAX_STREAMS_UNI", "ZO"),
    0x14: ("DATA_BLOCKED", "ZO"),
    0x15: ("STREAM_DATA_BLOCKED", "ZO"),
    0x16: ("STREAMS_BLOCKED_BIDI", "ZO"),
    0x17: ("STREAMS_BLOCKED_UNI", "ZO"),
    0x18: ("NEW_CONNECTION_ID", "ZO"),
    0x19: ("RETIRE_CONNECTION_ID", "ZO"),
    0x1A: ("PATH_CHALLENGE", "ZO"),
    0x1B: ("PATH_RESPONSE", "O"),
    0x1C: ("CONNECTION_CLOSE", "IHO"),
    0x1D: ("CONNECTION_CLOSE_APP", "ZO"),
    0x1E: ("HANDSHAKE_DONE", "O"),
    0x1F: ("IMMEDIATE_ACK", "ZO"),
    0x24: ("RESET_STREAM_AT", "ZO"),
    0x30: ("DATAGRAM", "ZO"),
    0x31: ("DATAGRAM_LEN", "ZO"),
    0xAF: ("ACK_FREQUENCY", "ZO"),
}
for _type in range(0x08, 0x10):
    KNOWN_FRAMES[_type] = ("STREAM", "ZO")

# Multipath frames (RFC 10069) are only allowed in 1-RTT packets. Their fields are not checked yet.
MULTIPATH_FRAMES = {
    0x3E: "PATH_ACK",
    0x3F: "PATH_ACK_ECN",
    0x3E75: "PATH_ABANDON",
    0x3E76: "PATH_STATUS_BACKUP",
    0x3E77: "PATH_STATUS_AVAILABLE",
    0x3E78: "PATH_NEW_CONNECTION_ID",
    0x3E79: "PATH_RETIRE_CONNECTION_ID",
    0x3E7A: "MAX_PATH_ID",
    0x3E7B: "PATHS_BLOCKED",
    0x3E7C: "PATH_CIDS_BLOCKED",
}

NOT_ACK_ELICITING = {0x00, 0x02, 0x03, 0x1C, 0x1D}

PACKET_NAMES = {"I": "Initial", "H": "Handshake", "Z": "0-RTT", "O": "1-RTT"}
LEVEL_ORDER = {"I": 0, "H": 1, "Z": 2, "O": 3}
SPACE = {"I": 0, "H": 1, "Z": 2, "O": 2}


class ParseError(Exception):
    """A field does not fit in the bytes that are left."""


class Reader:
    """Sequential reader of a byte string."""

    def __init__(self, data, pos=0, end=None):
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else end

    def left(self):
        return self.end - self.pos

    def take(self, count):
        if count < 0 or self.pos + count > self.end:
            raise ParseError("need %d bytes, %d left" % (count, self.left()))
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self):
        return self.take(1)[0]

    def varint(self):
        """Returns (value, number of bytes used)."""
        first = self.take(1)[0]
        size = 1 << (first >> 6)
        value = first & 0x3F
        for byte in self.take(size - 1):
            value = (value << 8) | byte
        return value, size


def varint_len(value):
    """Shortest encoding length of a variable-length integer."""
    if value < 1 << 6:
        return 1
    if value < 1 << 14:
        return 2
    if value < 1 << 30:
        return 4
    return 8


def long_packet_type(version, first):
    """Letter of the packet type of a long header: I, Z, H or R (Retry)."""
    bits = (first >> 4) & 3
    if version == QUIC_V2:
        return {1: "I", 2: "Z", 3: "H", 0: "R"}[bits]
    return {0: "I", 1: "Z", 2: "H", 3: "R"}[bits]


def is_reserved_version(version):
    return (version & 0x0F0F0F0F) == 0x0A0A0A0A


def decode_packet_number(largest, truncated, nbits):
    """RFC 9000 appendix A.3."""
    expected = largest + 1
    win = 1 << nbits
    half = win // 2
    mask = win - 1
    candidate = (expected & ~mask) | truncated
    if candidate <= expected - half and candidate < (1 << 62) - win:
        return candidate + win
    if candidate > expected + half and candidate >= win:
        return candidate - win
    return candidate


class Linter:
    """Checks datagrams in the order in which they were captured."""

    def __init__(self, mtu=None, max_examples=3):
        self.mtu = mtu
        self.max_examples = max_examples
        self.counts = collections.Counter()
        self.examples = collections.defaultdict(list)
        self.datagrams = 0
        self.packets = 0
        self.frames = 0
        self.new_capture()

    def new_capture(self):
        """Forgets the state of the connections: the counts are kept, the flows are not."""
        self.client = {}  # pair of endpoints -> endpoint that sent the first Initial
        self.last_long = {}  # (src, dst) -> (dcid, scid) of the latest long header
        self.known_scid_lengths = collections.defaultdict(set)  # (src, dst) -> SCID lengths
        self.largest_pn = {}  # (src, dst, space) -> largest packet number seen
        self.sent_pns = collections.defaultdict(set)  # (src, dst, space) -> packet numbers
        self.server_first_long = set()  # (src, dst) pairs whose first long header was checked

    def violation(self, rule, where, message):
        self.counts[rule] += 1
        if len(self.examples[rule]) < self.max_examples:
            self.examples[rule].append("%s: %s" % (where, message))

    # ----- datagram level -----

    def check_datagram(self, where, src, dst, data, fragment=False):
        """Checks one UDP payload sent from src to dst (endpoints are (address, port))."""
        self.datagrams += 1
        if fragment:
            self.violation("R-dgram-05", where, "IP fragment")
            return
        if self.mtu is not None:
            ip_size = len(data) + (28 if ":" not in src[0] else 48)
            if ip_size > self.mtu:
                self.violation("R-dgram-04", where, "IP datagram of %d bytes, MTU %d" % (ip_size, self.mtu))

        pair = frozenset((src, dst))
        pos = 0
        previous_level = -1
        dcids = set()
        has_initial = False
        initial_ack_eliciting = False
        while pos < len(data):
            try:
                kind, end, info = self.parse_packet(where, src, dst, data, pos)
            except ParseError as error:
                self.violation("R-hdr-04", where, "packet at offset %d: %s" % (pos, error))
                return
            if kind is None:
                return
            self.packets += 1
            if kind in ("V", "R"):
                if pos != 0 or end != len(data):
                    self.violation("R-dgram-02", where, "%s packet is coalesced" % kind)
                return
            level = LEVEL_ORDER[kind]
            if level < previous_level:
                self.violation("R-dgram-02", where, "%s after a packet of a higher level" % PACKET_NAMES[kind])
            previous_level = max(previous_level, level)
            if info["dcid"] is not None:
                dcids.add(info["dcid"])
            if kind == "I":
                has_initial = True
                initial_ack_eliciting = initial_ack_eliciting or info["ack_eliciting"]
                self.client.setdefault(pair, src)
            pos = end
        if len(dcids) > 1:
            self.violation("R-dgram-03", where, "%d different destination ids" % len(dcids))
        if has_initial and len(data) < MIN_INITIAL_DATAGRAM:
            is_client = self.client.get(pair) == src
            if is_client or initial_ack_eliciting:
                self.violation("R-dgram-01", where, "%d bytes with an Initial packet" % len(data))

    # ----- packet level -----

    def parse_packet(self, where, src, dst, data, pos):
        """Parses one packet at pos. Returns (kind, end, info) or (None, 0, None) after an error.

        kind is I, H, Z or O for the packets that carry frames, V for Version Negotiation and R for
        Retry.
        """
        first = data[pos]
        if first & 0x80:
            return self.parse_long(where, src, dst, data, pos)
        return self.parse_short(where, src, dst, data, pos)

    def parse_long(self, where, src, dst, data, pos):
        reader = Reader(data, pos + 1)
        version = int.from_bytes(reader.take(4), "big")
        first = data[pos]
        dcil = reader.u8()
        if version != 0 and dcil > MAX_CID_LENGTH:
            self.violation("R-hdr-02", where, "destination id of %d bytes" % dcil)
            return None, 0, None
        dcid = bytes(reader.take(dcil))
        scil = reader.u8()
        if version != 0 and scil > MAX_CID_LENGTH:
            self.violation("R-hdr-02", where, "source id of %d bytes" % scil)
            return None, 0, None
        scid = bytes(reader.take(scil))

        if version == 0:
            return self.check_version_negotiation(where, src, dst, data, pos, reader, dcid, scid)

        if version not in (QUIC_V1, QUIC_V2) and not is_reserved_version(version):
            self.violation("R-hdr-06", where, "version 0x%08x" % version)
            return None, 0, None
        if not first & 0x40:
            self.violation("R-hdr-01", where, "Fixed Bit is 0 in a long header")
        kind = long_packet_type(version, first)
        self.last_long[(src, dst)] = (dcid, scid)
        self.known_scid_lengths[(src, dst)].add(scil)
        pair = frozenset((src, dst))
        if kind == "R":
            return self.check_retry(where, data, pos, reader)

        if first & 0x0C:
            self.violation("R-hdr-03", where, "reserved bits 0x%x in a long header" % (first & 0x0C))
        if kind != "I" and (src, dst) not in self.server_first_long and self.client.get(pair) not in (None, src):
            self.server_first_long.add((src, dst))
            self.violation("R-hs-01", where, "the first packet of the server is a %s packet" % PACKET_NAMES[kind])
        if kind == "I":
            self.server_first_long.add((src, dst))
            token_len, _ = reader.varint()
            reader.take(token_len)
        length, _ = reader.varint()
        pn_len = (first & 3) + 1
        if length < pn_len or length > reader.left():
            self.violation(
                "R-hdr-04", where, "Length %d with %d bytes left (packet number %d bytes)" % (length, reader.left(), pn_len)
            )
            return None, 0, None
        end = reader.pos + length
        return self.finish_protected(where, src, dst, data, kind, reader, pn_len, end, dcid)

    def check_version_negotiation(self, where, src, dst, data, pos, reader, dcid, scid):
        remaining = reader.left()
        if remaining < 4 or remaining % 4:
            self.violation("R-hdr-07", where, "%d bytes of versions" % remaining)
        reverse = self.last_long.get((dst, src))
        if reverse is not None:
            if dcid != reverse[1] or scid != reverse[0]:
                self.violation("R-hdr-08", where, "dcid %s scid %s, expected %s and %s" % (dcid.hex(), scid.hex(), reverse[1].hex(), reverse[0].hex()))
        else:
            self.violation("R-hdr-08", where, "no earlier long header to compare with")
        return "V", len(data), {"dcid": None, "ack_eliciting": False}

    def check_retry(self, where, data, pos, reader):
        if reader.left() < AEAD_TAG:
            self.violation("R-hdr-10", where, "Retry packet of %d bytes after the ids" % reader.left())
        return "R", len(data), {"dcid": None, "ack_eliciting": False}

    def parse_short(self, where, src, dst, data, pos):
        first = data[pos]
        if not first & 0x40:
            self.violation("R-hdr-01", where, "Fixed Bit is 0 in a short header")
        if first & 0x18:
            self.violation("R-hdr-03", where, "reserved bits 0x%x in a short header" % (first & 0x18))
        lengths = self.known_scid_lengths.get((dst, src), set())
        if len(lengths) != 1:
            # The destination id length is unknown or ambiguous: assume the module default.
            cid_len = 8
        else:
            cid_len = next(iter(lengths))
        pn_len = (first & 3) + 1
        reader = Reader(data, pos + 1)
        try:
            dcid = bytes(reader.take(cid_len))
        except ParseError:
            self.violation("R-hdr-09", where, "short header shorter than the destination id")
            return None, 0, None
        return self.finish_protected(where, src, dst, data, "O", reader, pn_len, len(data), dcid)

    def finish_protected(self, where, src, dst, data, kind, reader, pn_len, end, dcid):
        """Reads the packet number and the frames of a packet that ends at end."""
        try:
            truncated = int.from_bytes(reader.take(pn_len), "big")
        except ParseError as error:
            self.violation("R-hdr-04", where, str(error))
            return None, 0, None
        frames_start = reader.pos
        if pn_len + (end - frames_start) < 4 + AEAD_TAG or end - AEAD_TAG < frames_start:
            self.violation(
                "R-hdr-05",
                where,
                "%s packet with %d bytes of packet number and protected payload"
                % (PACKET_NAMES[kind], pn_len + end - frames_start),
            )
            return kind, end, {"dcid": dcid, "ack_eliciting": False}
        key = (src, dst, SPACE[kind])
        largest = self.largest_pn.get(key, -1)
        packet_number = decode_packet_number(largest, truncated, 8 * pn_len)
        self.largest_pn[key] = max(largest, packet_number)
        if packet_number in self.sent_pns[key]:
            self.violation("R-hs-02", where, "%s packet number %d sent twice" % (PACKET_NAMES[kind], packet_number))
        self.sent_pns[key].add(packet_number)
        ack_eliciting = self.check_frames(where, src, dst, kind, Reader(data, frames_start, end - AEAD_TAG))
        return kind, end, {"dcid": dcid, "ack_eliciting": ack_eliciting}

    # ----- frame level -----

    def check_frames(self, where, src, dst, kind, reader):
        """Checks the frames of a packet. Returns True when one of them is ack-eliciting."""
        ack_eliciting = False
        count = 0
        while reader.left() > 0:
            start = reader.pos
            try:
                frame_type, size = reader.varint()
                if size > varint_len(frame_type):
                    self.violation("R-frame-01", where, "type 0x%x in %d bytes" % (frame_type, size))
                if frame_type in KNOWN_FRAMES:
                    name, allowed = KNOWN_FRAMES[frame_type]
                elif frame_type in MULTIPATH_FRAMES:
                    name, allowed = MULTIPATH_FRAMES[frame_type], "O"
                else:
                    self.violation("R-frame-02", where, "type 0x%x" % frame_type)
                    return ack_eliciting
                if kind not in allowed:
                    self.violation("R-frame-03", where, "%s in a %s packet" % (name, PACKET_NAMES[kind]))
                if frame_type not in NOT_ACK_ELICITING:
                    ack_eliciting = True
                count += 1
                self.frames += 1
                if frame_type in MULTIPATH_FRAMES:
                    return ack_eliciting
                self.check_frame_body(where, src, dst, kind, frame_type, reader)
            except ParseError as error:
                self.violation("R-frame-04", where, "frame at offset %d: %s" % (start, error))
                return ack_eliciting
        if count == 0:
            self.violation("R-frame-05", where, "no frame in a %s packet" % PACKET_NAMES[kind])
        return ack_eliciting

    def check_frame_body(self, where, src, dst, kind, frame_type, reader):
        if frame_type == 0x00:
            while reader.left() > 0 and reader.data[reader.pos] == 0:
                reader.pos += 1
        elif frame_type in (0x02, 0x03):
            self.check_ack(where, src, dst, kind, frame_type, reader)
        elif frame_type == 0x04:
            for _ in range(3):
                reader.varint()
        elif frame_type == 0x05:
            for _ in range(2):
                reader.varint()
        elif frame_type == 0x06:
            reader.varint()
            length, _ = reader.varint()
            reader.take(length)
        elif frame_type == 0x07:
            length, _ = reader.varint()
            if length == 0:
                raise ParseError("empty token in NEW_TOKEN")
            reader.take(length)
        elif 0x08 <= frame_type <= 0x0F:
            reader.varint()
            if frame_type & 0x04:
                reader.varint()
            if frame_type & 0x02:
                length, _ = reader.varint()
                reader.take(length)
            else:
                reader.take(reader.left())
        elif frame_type in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):
            reader.varint()
        elif frame_type in (0x11, 0x15):
            reader.varint()
            reader.varint()
        elif frame_type == 0x18:
            self.check_new_connection_id(where, reader)
        elif frame_type in (0x1A, 0x1B):
            reader.take(8)
        elif frame_type == 0x1C:
            reader.varint()
            reader.varint()
            length, _ = reader.varint()
            reader.take(length)
        elif frame_type == 0x1D:
            reader.varint()
            length, _ = reader.varint()
            reader.take(length)
        elif frame_type == 0x24:
            for _ in range(4):
                reader.varint()
        elif frame_type == 0x30:
            reader.take(reader.left())
        elif frame_type == 0x31:
            length, _ = reader.varint()
            reader.take(length)
        elif frame_type == 0xAF:
            for _ in range(4):
                reader.varint()

    def check_ack(self, where, src, dst, kind, frame_type, reader):
        largest, _ = reader.varint()
        reader.varint()  # ACK Delay
        range_count, _ = reader.varint()
        first_range, _ = reader.varint()
        if first_range > largest:
            raise ParseError("first ACK range %d is larger than the largest acknowledged %d" % (first_range, largest))
        if range_count > reader.left():
            raise ParseError("%d ACK ranges do not fit" % range_count)
        smallest = largest - first_range
        for _ in range(range_count):
            gap, _ = reader.varint()
            length, _ = reader.varint()
            top = smallest - gap - 2
            if top < 0 or length > top:
                raise ParseError("ACK range below packet number 0")
            smallest = top - length
        if frame_type == 0x03:
            for _ in range(3):
                reader.varint()
        peer_key = (dst, src, SPACE[kind])
        sent = self.largest_pn.get(peer_key, -1)
        if largest > sent:
            self.violation("R-rec-01", where, "acknowledges %d, the peer sent up to %d" % (largest, sent))

    def check_new_connection_id(self, where, reader):
        sequence, _ = reader.varint()
        retire, _ = reader.varint()
        length = reader.u8()
        reader.take(length)
        reader.take(16)
        if not 1 <= length <= MAX_CID_LENGTH:
            self.violation("R-frame-06", where, "connection id of %d bytes" % length)
        if retire > sequence:
            self.violation("R-frame-06", where, "Retire Prior To %d above the sequence number %d" % (retire, sequence))

    # ----- report -----

    def report(self):
        return {
            "datagrams": self.datagrams,
            "packets": self.packets,
            "frames": self.frames,
            "violations": {rule: self.counts.get(rule, 0) for rule in RULES},
            "examples": {rule: self.examples[rule] for rule in RULES if self.examples.get(rule)},
        }


# ----- pcap reading -----


def read_pcap(path):
    """Yields (timestamp, link type, bytes) of every record of a classic pcap file."""
    with open(path, "rb") as stream:
        header = stream.read(24)
        if len(header) < 24:
            raise ValueError("%s is not a pcap file" % path)
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            order = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            order = ">"
        else:
            raise ValueError("%s is not a classic pcap file" % path)
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        link_type = struct.unpack(order + "I", header[20:24])[0]
        while True:
            record = stream.read(16)
            if len(record) < 16:
                return
            seconds, fraction, captured, _ = struct.unpack(order + "IIII", record)
            data = stream.read(captured)
            yield seconds + fraction / (1e9 if nano else 1e6), link_type, data


def link_payload(link_type, data):
    """Returns (ethertype, bytes) of the network layer, or None."""
    if link_type == 1 and len(data) >= 14:
        ethertype = struct.unpack(">H", data[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(data) >= 18:
            ethertype = struct.unpack(">H", data[16:18])[0]
            offset = 18
        return ethertype, data[offset:]
    if link_type == 9 and len(data) >= 2:
        protocol = struct.unpack(">H", data[:2])[0]
        return {0x0021: 0x0800, 0x0057: 0x86DD}.get(protocol), data[2:]
    if link_type in (12, 101) and data:
        version = data[0] >> 4
        return {4: 0x0800, 6: 0x86DD}.get(version), data
    if link_type == 113 and len(data) >= 16:
        return struct.unpack(">H", data[14:16])[0], data[16:]
    return None


def udp_datagram(ethertype, packet):
    """Returns (source, destination, payload, fragment) of a UDP datagram, or None."""
    if ethertype == 0x0800 and len(packet) >= 20:
        header_len = (packet[0] & 0x0F) * 4
        if packet[9] != 17:
            return None
        flags_fragment = struct.unpack(">H", packet[6:8])[0]
        fragment = bool(flags_fragment & 0x2000 or flags_fragment & 0x1FFF)
        source = ".".join(str(b) for b in packet[12:16])
        destination = ".".join(str(b) for b in packet[16:20])
        body = packet[header_len:]
    elif ethertype == 0x86DD and len(packet) >= 40:
        next_header = packet[6]
        offset = 40
        while next_header in (0, 43, 60) and len(packet) >= offset + 8:
            next_header = packet[offset]
            offset += (packet[offset + 1] + 1) * 8
        fragment = next_header == 44
        if next_header != 17:
            return None
        source = packet[8:24].hex()
        destination = packet[24:40].hex()
        body = packet[offset:]
    else:
        return None
    if len(body) < 8:
        return None
    sport, dport, length = struct.unpack(">HHH", body[:6])
    payload = body[8 : max(8, length)]
    return (source, sport), (destination, dport), payload, fragment


def lint_file(linter, path, ports):
    linter.new_capture()
    for index, (timestamp, link_type, data) in enumerate(read_pcap(path), 1):
        decoded = link_payload(link_type, data)
        if decoded is None or decoded[0] is None:
            continue
        datagram = udp_datagram(*decoded)
        if datagram is None:
            continue
        src, dst, payload, fragment = datagram
        if ports and src[1] not in ports and dst[1] not in ports:
            continue
        where = "%s#%d t=%.6f %s:%d>%s:%d" % (path.rsplit("/", 1)[-1], index, timestamp, src[0], src[1], dst[0], dst[1])
        linter.check_datagram(where, src, dst, payload, fragment)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Lint the QUIC wire format of pcap files")
    parser.add_argument("captures", nargs="+", help="classic pcap files written by ns-3")
    parser.add_argument("--port", type=int, action="append", default=[], help="UDP port of QUIC (default: every UDP datagram)")
    parser.add_argument("--mtu", type=int, default=None, help="IP MTU of the links")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--expect", help="JSON file with the largest allowed count of each rule")
    parser.add_argument("--examples", type=int, default=3, help="examples to print for each rule")
    args = parser.parse_args(argv)

    linter = Linter(mtu=args.mtu, max_examples=args.examples)
    for path in args.captures:
        lint_file(linter, path, set(args.port))
    report = linter.report()

    allowed = {}
    if args.expect:
        with open(args.expect) as stream:
            allowed = json.load(stream)
    failed = any(count > allowed.get(rule, 0) for rule, count in report["violations"].items())

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("%d datagrams, %d packets, %d frames" % (report["datagrams"], report["packets"], report["frames"]))
        for rule, description in RULES.items():
            count = report["violations"][rule]
            print("%-11s %6d  %s" % (rule, count, description))
            for example in report["examples"].get(rule, []):
                print("              %s" % example)
        total = sum(report["violations"].values())
        print("%d violations%s" % (total, "" if failed else " (within the expected counts)" if total else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
