#!/usr/bin/env python3
# Copyright (c) 2026 Fernando Areias
#
# SPDX-License-Identifier: GPL-2.0-only
"""Tests of quic_pcap_lint.py: well formed packets give no violation and each rule fires.

Run with: python3 -m unittest contrib/quic/test/tools/test_quic_pcap_lint.py
"""

import os
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import quic_pcap_lint as lint  # noqa: E402

CLIENT = ("10.1.1.1", 49153)
SERVER = ("10.1.1.2", 443)


def varint(value):
    if value < 1 << 6:
        return bytes([value])
    if value < 1 << 14:
        return struct.pack(">H", 0x4000 | value)
    if value < 1 << 30:
        return struct.pack(">I", 0x80000000 | value)
    return struct.pack(">Q", 0xC000000000000000 | value)


def crypto(size, offset=0):
    return b"\x06" + varint(offset) + varint(size) + b"\x01" * size


def long_packet(kind, dcid, scid, pn, frames, version=1, token=b"", pn_len=4):
    """Builds an Initial ('I'), 0-RTT ('Z') or Handshake ('H') packet with a 16 byte tag."""
    bits = {"I": 0, "Z": 1, "H": 2}[kind]
    if version == lint.QUIC_V2:
        bits = {"I": 1, "Z": 2, "H": 3}[kind]
    first = 0xC0 | (bits << 4) | (pn_len - 1)
    body = pn.to_bytes(pn_len, "big") + frames + b"\x00" * lint.AEAD_TAG
    out = bytes([first]) + struct.pack(">I", version) + bytes([len(dcid)]) + dcid
    out += bytes([len(scid)]) + scid
    if kind == "I":
        out += varint(len(token)) + token
    return out + varint(len(body)) + body


def short_packet(dcid, pn, frames, pn_len=2, first=0x40):
    return bytes([first | (pn_len - 1)]) + dcid + pn.to_bytes(pn_len, "big") + frames + b"\x00" * lint.AEAD_TAG


def padded(frames, total):
    return frames + b"\x00" * (total - len(frames))


DCID = bytes.fromhex("8394c8f03e515708")
SCID_C = bytes.fromhex("c0c1c2c3c4c5c6c7")
SCID_S = bytes.fromhex("f067a5502a4262b5")


def client_initial():
    """A client Initial datagram of 1200 bytes, shaped like the one of RFC 9001 A.2."""
    packet = long_packet("I", DCID, b"", 2, padded(crypto(241), 1162))
    return packet


class LintTest(unittest.TestCase):
    def check(self, *datagrams):
        linter = lint.Linter()
        for index, (src, dst, data) in enumerate(datagrams):
            linter.check_datagram("dg%d" % index, src, dst, data)
        return linter

    def assertClean(self, linter):
        self.assertEqual({rule: n for rule, n in linter.counts.items() if n}, {}, linter.examples)

    def assertOnly(self, linter, rule):
        self.assertEqual(set(linter.counts), {rule}, (dict(linter.counts), dict(linter.examples)))

    def test_rfc9001_a2_header(self):
        packet = client_initial()
        self.assertEqual(len(packet), 1200)
        self.assertEqual(packet[:22].hex(), "c300000001088394c8f03e5157080000449e00000002")
        self.assertClean(self.check((CLIENT, SERVER, packet)))

    def test_short_initial_datagram(self):
        packet = long_packet("I", DCID, b"", 0, padded(crypto(241), 600))
        self.assertOnly(self.check((CLIENT, SERVER, packet)), "R-dgram-01")

    def test_fixed_bit(self):
        packet = bytearray(client_initial())
        packet[0] &= 0xBF
        self.assertOnly(self.check((CLIENT, SERVER, bytes(packet))), "R-hdr-01")

    def test_reserved_bits(self):
        packet = bytearray(client_initial())
        packet[0] |= 0x08
        self.assertOnly(self.check((CLIENT, SERVER, bytes(packet))), "R-hdr-03")

    def test_connection_id_length(self):
        packet = long_packet("I", bytes(21), b"", 0, padded(crypto(10), 1162))
        self.assertIn("R-hdr-02", self.check((CLIENT, SERVER, packet)).counts)

    def test_length_beyond_datagram(self):
        packet = client_initial()[:-10]
        self.assertIn("R-hdr-04", self.check((CLIENT, SERVER, packet)).counts)

    def test_server_flight_is_clean(self):
        ack = b"\x02\x02\x00\x00\x00"
        initial = long_packet("I", SCID_C, SCID_S, 0, ack + crypto(90), pn_len=2)
        handshake = long_packet("H", SCID_C, SCID_S, 0, padded(crypto(2000), 1100), pn_len=2)
        datagram = initial + handshake
        self.assertGreaterEqual(len(datagram), 1200)
        self.assertClean(self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, datagram)))

    def test_server_must_start_with_initial(self):
        handshake = long_packet("H", SCID_C, SCID_S, 0, padded(crypto(300), 1100), pn_len=2)
        self.assertIn("R-hs-01", self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, handshake)).counts)

    def test_stream_in_initial(self):
        stream = b"\x0a" + varint(0) + varint(50) + b"\x02" * 50
        packet = long_packet("I", DCID, b"", 0, padded(stream, 1162))
        self.assertOnly(self.check((CLIENT, SERVER, packet)), "R-frame-03")

    def test_coalescing_order(self):
        handshake = long_packet("H", SCID_C, SCID_S, 0, crypto(30), pn_len=2)
        initial = long_packet("I", SCID_C, SCID_S, 0, padded(crypto(30), 1150), pn_len=2)
        linter = self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, handshake + initial))
        self.assertIn("R-dgram-02", linter.counts)

    def test_coalesced_packets_share_a_destination_id(self):
        first = long_packet("I", SCID_C, SCID_S, 0, padded(crypto(90), 600), pn_len=2)
        second = long_packet("H", bytes(8), SCID_S, 0, padded(crypto(300), 600), pn_len=2)
        linter = self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, first + second))
        self.assertIn("R-dgram-03", linter.counts)

    def test_frame_type_not_shortest(self):
        frames = b"\x40\x01" + b"\x00" * 30
        packet = long_packet("I", DCID, b"", 0, padded(frames, 1162))
        self.assertOnly(self.check((CLIENT, SERVER, packet)), "R-frame-01")

    def test_unknown_frame_type(self):
        packet = long_packet("I", DCID, b"", 0, padded(b"\x20", 1162))
        self.assertIn("R-frame-02", self.check((CLIENT, SERVER, packet)).counts)

    def test_ack_ranges(self):
        frames = b"\x02\x05\x00\x00\x07"  # first range 7 above the largest acknowledged 5
        packet = long_packet("I", DCID, b"", 0, padded(frames, 1162))
        self.assertIn("R-frame-04", self.check((CLIENT, SERVER, packet)).counts)

    def test_packet_without_frames(self):
        initial = long_packet("I", SCID_C, SCID_S, 0, padded(crypto(30), 1150), pn_len=2)
        empty = long_packet("H", SCID_C, SCID_S, 0, b"")
        linter = self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, initial + empty))
        self.assertOnly(linter, "R-frame-05")

    def test_packet_too_small_to_sample(self):
        initial = long_packet("I", SCID_C, SCID_S, 0, padded(crypto(30), 1150), pn_len=2)
        tiny = long_packet("H", SCID_C, SCID_S, 0, b"\x01", pn_len=1)
        linter = self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, initial + tiny))
        self.assertOnly(linter, "R-hdr-05")

    def test_new_connection_id(self):
        good = b"\x18\x01\x00\x08" + bytes(8) + bytes(16)
        bad = b"\x18\x01\x02\x08" + bytes(8) + bytes(16)
        linter = lint.Linter()
        linter.check_datagram("a", CLIENT, SERVER, long_packet("I", DCID, b"", 0, padded(crypto(5), 1162)))
        linter.check_datagram("b", CLIENT, SERVER, short_packet(DCID, 1, good + b"\x01"))
        self.assertClean(linter)
        linter.check_datagram("c", CLIENT, SERVER, short_packet(DCID, 2, bad))
        self.assertOnly(linter, "R-frame-06")

    def test_version_negotiation(self):
        versions = struct.pack(">II", 1, 0x1A2A3A4A)
        good = bytes([0xC0]) + bytes(4) + bytes([8]) + SCID_C + bytes([8]) + DCID + versions
        wrong = bytes([0xC0]) + bytes(4) + bytes([8]) + DCID + bytes([0]) + versions
        initial = long_packet("I", DCID, SCID_C, 0, padded(crypto(30), 1162), version=0x2A3A4A5A)
        self.assertClean(self.check((CLIENT, SERVER, initial), (SERVER, CLIENT, good)))
        self.assertIn("R-hdr-08", self.check((CLIENT, SERVER, initial), (SERVER, CLIENT, wrong)).counts)

    def test_packet_number_reuse(self):
        packet = long_packet("I", DCID, b"", 7, padded(crypto(5), 1162))
        self.assertIn("R-hs-02", self.check((CLIENT, SERVER, packet), (CLIENT, SERVER, packet)).counts)

    def test_ack_of_a_packet_never_sent(self):
        ack = b"\x02\x09\x00\x00\x00"
        initial = long_packet("I", SCID_C, SCID_S, 0, ack + crypto(90), pn_len=2)
        linter = self.check((CLIENT, SERVER, client_initial()), (SERVER, CLIENT, padded(initial, 1200)))
        self.assertIn("R-rec-01", linter.counts)

    def test_mtu(self):
        linter = lint.Linter(mtu=1200)
        linter.check_datagram("a", CLIENT, SERVER, client_initial())
        self.assertEqual(linter.counts["R-dgram-04"], 1)

    def test_packet_number_decoding(self):
        self.assertEqual(lint.decode_packet_number(0xA82F30EA, 0x9B32, 16), 0xA82F9B32)

    def test_random_input_never_raises(self):
        rng = random.Random(7)
        seeds = [client_initial(), short_packet(DCID, 3, b"\x01"), bytes([0xC0]) + bytes(4) + b"\x08" + DCID + b"\x00"]
        linter = lint.Linter()
        for _ in range(3000):
            seed = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 6)):
                seed[rng.randrange(len(seed))] = rng.randrange(256)
            cut = rng.randint(1, len(seed))
            linter.check_datagram("fuzz", CLIENT, SERVER, bytes(seed[:cut]))
            linter.check_datagram("rand", SERVER, CLIENT, bytes(rng.randrange(256) for _ in range(rng.randint(1, 80))))

    def test_pcap_file(self):
        def pcap(datagrams):
            out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 9)
            for number, data in enumerate(datagrams):
                udp = struct.pack(">HHHH", 49153, 443, 8 + len(data), 0) + data
                ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes([10, 1, 1, 1]), bytes([10, 1, 1, 2]))
                frame = struct.pack(">H", 0x0021) + ip + udp
                out += struct.pack("<IIII", 1, number, len(frame), len(frame)) + frame
            return out

        with tempfile.TemporaryDirectory() as directory:
            good = os.path.join(directory, "good.pcap")
            bad = os.path.join(directory, "bad.pcap")
            with open(good, "wb") as stream:
                stream.write(pcap([client_initial()]))
            with open(bad, "wb") as stream:
                stream.write(pcap([client_initial()[:900]]))
            self.assertEqual(lint.main([good]), 0)
            self.assertEqual(lint.main([bad]), 1)


if __name__ == "__main__":
    unittest.main()
