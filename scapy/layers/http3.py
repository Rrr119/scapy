# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
HTTP/3 and QPACK

HTTP/3 frames from RFC 9114 and QPACK field sections from RFC 9204. QPACK
decoding is stateful: the dynamic table is updated by instructions carried on
the QPACK encoder stream. :class:`QPACKDecoder` implements that state.
"""

from scapy.fields import (
    PacketListField,
    StrLenField,
)
from scapy.error import log_runtime
from scapy.packet import Packet

from scapy.layers.quic import (
    QuicVarEnumField,
    QuicVarIntField,
    QuicVarLenField,
    quic_decode_varint,
)

# Typing imports
from typing import (
    Any,
    Dict,
    List,
    Tuple,
)


HTTP3_DATA = 0x00
HTTP3_HEADERS = 0x01
HTTP3_CANCEL_PUSH = 0x03
HTTP3_SETTINGS = 0x04
HTTP3_PUSH_PROMISE = 0x05
HTTP3_GOAWAY = 0x07
HTTP3_MAX_PUSH_ID = 0x0D
HTTP3_DUPLICATE_PUSH = 0x0E

HTTP3_CONTROL = 0x00
HTTP3_PUSH = 0x01
HTTP3_QPACK_ENCODER = 0x02
HTTP3_QPACK_DECODER = 0x03

_http3_frames = {
    HTTP3_DATA: "DATA",
    HTTP3_HEADERS: "HEADERS",
    HTTP3_CANCEL_PUSH: "CANCEL_PUSH",
    HTTP3_SETTINGS: "SETTINGS",
    HTTP3_PUSH_PROMISE: "PUSH_PROMISE",
    HTTP3_GOAWAY: "GOAWAY",
    HTTP3_MAX_PUSH_ID: "MAX_PUSH_ID",
    HTTP3_DUPLICATE_PUSH: "DUPLICATE_PUSH",
}

_http3_streams = {
    HTTP3_CONTROL: "Control",
    HTTP3_PUSH: "Push",
    HTTP3_QPACK_ENCODER: "QPACK Encoder",
    HTTP3_QPACK_DECODER: "QPACK Decoder",
}

_http3_settings = {
    0x01: "QPACK_MAX_TABLE_CAPACITY",
    0x02: "MAX_FIELD_SECTION_SIZE",
    0x07: "QPACK_BLOCKED_STREAMS",
    0x08: "ENABLE_CONNECT_PROTOCOL",
    0x33: "H3_DATAGRAM",
}


QPACK_STATIC_TABLE = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html;charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000;includesubdomains"),
    ("strict-transport-security", "max-age=31536000;includesubdomains;preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none';object-src 'none';base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
]

_QPACK_STATIC = [
    (name.encode(), value.encode()) for name, value in QPACK_STATIC_TABLE
]

# RFC 7541 Appendix B, used unchanged by QPACK.
_HUFFMAN_CODES = [
    0x00001FF8, 0x007FFFD8, 0x0FFFFFE2, 0x0FFFFFE3, 0x0FFFFFE4, 0x0FFFFFE5,
    0x0FFFFFE6, 0x0FFFFFE7, 0x0FFFFFE8, 0x00FFFFEA, 0x3FFFFFFC, 0x0FFFFFE9,
    0x0FFFFFEA, 0x3FFFFFFD, 0x0FFFFFEB, 0x0FFFFFEC, 0x0FFFFFED, 0x0FFFFFEE,
    0x0FFFFFEF, 0x0FFFFFF0, 0x0FFFFFF1, 0x0FFFFFF2, 0x3FFFFFFE, 0x0FFFFFF3,
    0x0FFFFFF4, 0x0FFFFFF5, 0x0FFFFFF6, 0x0FFFFFF7, 0x0FFFFFF8, 0x0FFFFFF9,
    0x0FFFFFFA, 0x0FFFFFFB, 0x00000014, 0x000003F8, 0x000003F9, 0x00000FFA,
    0x00001FF9, 0x00000015, 0x000000F8, 0x000007FA, 0x000003FA, 0x000003FB,
    0x000000F9, 0x000007FB, 0x000000FA, 0x00000016, 0x00000017, 0x00000018,
    0x00000000, 0x00000001, 0x00000002, 0x00000019, 0x0000001A, 0x0000001B,
    0x0000001C, 0x0000001D, 0x0000001E, 0x0000001F, 0x0000005C, 0x000000FB,
    0x00007FFC, 0x00000020, 0x00000FFB, 0x000003FC, 0x00001FFA, 0x00000021,
    0x0000005D, 0x0000005E, 0x0000005F, 0x00000060, 0x00000061, 0x00000062,
    0x00000063, 0x00000064, 0x00000065, 0x00000066, 0x00000067, 0x00000068,
    0x00000069, 0x0000006A, 0x0000006B, 0x0000006C, 0x0000006D, 0x0000006E,
    0x0000006F, 0x00000070, 0x00000071, 0x00000072, 0x000000FC, 0x00000073,
    0x000000FD, 0x00001FFB, 0x0007FFF0, 0x00001FFC, 0x00003FFC, 0x00000022,
    0x00007FFD, 0x00000003, 0x00000023, 0x00000004, 0x00000024, 0x00000005,
    0x00000025, 0x00000026, 0x00000027, 0x00000006, 0x00000074, 0x00000075,
    0x00000028, 0x00000029, 0x0000002A, 0x00000007, 0x0000002B, 0x00000076,
    0x0000002C, 0x00000008, 0x00000009, 0x0000002D, 0x00000077, 0x00000078,
    0x00000079, 0x0000007A, 0x0000007B, 0x00007FFE, 0x000007FC, 0x00003FFD,
    0x00001FFD, 0x0FFFFFFC, 0x000FFFE6, 0x003FFFD2, 0x000FFFE7, 0x000FFFE8,
    0x003FFFD3, 0x003FFFD4, 0x003FFFD5, 0x007FFFD9, 0x003FFFD6, 0x007FFFDB,
    0x007FFFDA, 0x007FFFDD, 0x007FFFDE, 0x007FFFDF, 0x00FFFFEB, 0x007FFFE0,
    0x00FFFFEC, 0x00FFFFED, 0x003FFFD7, 0x007FFFE1, 0x00FFFFEE, 0x007FFFE2,
    0x007FFFE3, 0x007FFFE4, 0x007FFFE5, 0x001FFFDC, 0x003FFFD8, 0x007FFFE6,
    0x003FFFD9, 0x007FFFE7, 0x007FFFE8, 0x00FFFFEF, 0x003FFFDA, 0x001FFFDD,
    0x000FFFE9, 0x003FFFDB, 0x003FFFDC, 0x007FFFE9, 0x007FFFEA, 0x001FFFDE,
    0x007FFFEB, 0x003FFFDD, 0x003FFFDE, 0x00FFFFF0, 0x001FFFDF, 0x003FFFDF,
    0x007FFFEC, 0x007FFFED, 0x001FFFE0, 0x001FFFE1, 0x003FFFE0, 0x001FFFE2,
    0x007FFFEE, 0x003FFFE1, 0x007FFFEF, 0x007FFFF0, 0x000FFFEA, 0x003FFFE2,
    0x003FFFE3, 0x003FFFE4, 0x007FFFF1, 0x003FFFE5, 0x003FFFE6, 0x007FFFF2,
    0x03FFFFE0, 0x03FFFFE1, 0x000FFFEB, 0x0007FFF1, 0x003FFFE7, 0x007FFFF3,
    0x003FFFE8, 0x01FFFFEC, 0x03FFFFE2, 0x03FFFFE3, 0x03FFFFE4, 0x07FFFFDE,
    0x07FFFFDF, 0x03FFFFE5, 0x00FFFFF1, 0x01FFFFED, 0x0007FFF2, 0x001FFFE3,
    0x03FFFFE6, 0x07FFFFE0, 0x07FFFFE1, 0x03FFFFE7, 0x07FFFFE2, 0x00FFFFF2,
    0x001FFFE4, 0x001FFFE5, 0x03FFFFE8, 0x03FFFFE9, 0x0FFFFFFD, 0x07FFFFE3,
    0x07FFFFE4, 0x07FFFFE5, 0x000FFFEC, 0x00FFFFF3, 0x000FFFED, 0x001FFFE6,
    0x003FFFE9, 0x001FFFE7, 0x001FFFE8, 0x007FFFF4, 0x003FFFEA, 0x003FFFEB,
    0x01FFFFEE, 0x01FFFFEF, 0x00FFFFF4, 0x00FFFFF5, 0x03FFFFEA, 0x007FFFF5,
    0x03FFFFEB, 0x07FFFFE6, 0x03FFFFEC, 0x03FFFFED, 0x07FFFFE7, 0x07FFFFE8,
    0x07FFFFE9, 0x07FFFFEA, 0x07FFFFEB, 0x0FFFFFFE, 0x07FFFFEC, 0x07FFFFED,
    0x07FFFFEE, 0x07FFFFEF, 0x07FFFFF0, 0x03FFFFEE, 0x3FFFFFFF,
]

_HUFFMAN_LENGTHS = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
]

_HUFFMAN_DECODE = {
    (code, length): symbol
    for symbol, (code, length) in enumerate(zip(_HUFFMAN_CODES, _HUFFMAN_LENGTHS))
}


class QPACKError(ValueError):
    pass


class QPACKIncomplete(QPACKError):
    pass


def qpack_huffman_decode(data):
    # type: (bytes) -> bytes
    output = bytearray()
    code = 0
    length = 0
    for byte in data:
        for bit in range(7, -1, -1):
            code = (code << 1) | ((byte >> bit) & 1)
            length += 1
            symbol = _HUFFMAN_DECODE.get((code, length))
            if symbol is None:
                if length > 30:
                    raise QPACKError("invalid QPACK Huffman code")
                continue
            if symbol == 256:
                raise QPACKError("QPACK Huffman EOS in string")
            output.append(symbol)
            code = 0
            length = 0
    if length > 7 or code != (1 << length) - 1:
        raise QPACKError("invalid QPACK Huffman padding")
    return bytes(output)


def qpack_huffman_encode(data):
    # type: (bytes) -> bytes
    bits = 0
    bit_count = 0
    output = bytearray()
    for byte in data:
        code = _HUFFMAN_CODES[byte]
        length = _HUFFMAN_LENGTHS[byte]
        bits = (bits << length) | code
        bit_count += length
        while bit_count >= 8:
            bit_count -= 8
            output.append((bits >> bit_count) & 0xFF)
    if bit_count:
        output.append(((bits << (8 - bit_count)) | ((1 << (8 - bit_count)) - 1)) & 0xFF)
    return bytes(output)


def qpack_decode_integer(data, offset, prefix_bits):
    # type: (bytes, int, int) -> Tuple[int, int]
    if offset >= len(data):
        raise QPACKIncomplete("missing QPACK integer")
    mask = (1 << prefix_bits) - 1
    value = data[offset] & mask
    offset += 1
    if value < mask:
        return value, offset
    shift = 0
    while True:
        if offset >= len(data):
            raise QPACKIncomplete("truncated QPACK integer")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 56:
            raise QPACKError("QPACK integer is too large")


def qpack_encode_integer(value, prefix_bits, first_byte=0):
    # type: (int, int, int) -> bytes
    mask = (1 << prefix_bits) - 1
    if value < mask:
        return bytes([first_byte | value])
    output = bytearray([first_byte | mask])
    value -= mask
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def qpack_decode_string(data, offset, prefix_bits=7):
    # type: (bytes, int, int) -> Tuple[bytes, int]
    if offset >= len(data):
        raise QPACKIncomplete("missing QPACK string")
    huffman = bool(data[offset] & (1 << prefix_bits))
    length, offset = qpack_decode_integer(data, offset, prefix_bits)
    if offset + length > len(data):
        raise QPACKIncomplete("truncated QPACK string")
    value = data[offset:offset + length]
    if huffman:
        value = qpack_huffman_decode(value)
    return value, offset + length


def qpack_encode_string(value, prefix_bits=7, huffman=False):
    # type: (bytes, int, bool) -> bytes
    encoded = qpack_huffman_encode(value) if huffman else value
    first = (1 << prefix_bits) if huffman else 0
    return qpack_encode_integer(len(encoded), prefix_bits, first) + encoded


class QPACKDecoder:
    """QPACK dynamic table and field section decoder."""

    def __init__(self, max_table_capacity=0):
        # type: (int) -> None
        self.capacity = 0
        self.max_table_capacity = max_table_capacity
        self.insert_count = 0
        self.size = 0
        self.entries = {}  # type: Dict[int, Tuple[bytes, bytes]]
        self.order = []  # type: List[int]

    @property
    def max_entries(self):
        # type: () -> int
        return self.capacity // 32

    def set_capacity(self, capacity):
        # type: (int) -> None
        self.capacity = max(0, capacity)
        while self.order and self.size > self.capacity:
            index = self.order.pop(0)
            name, value = self.entries.pop(index)
            self.size -= len(name) + len(value) + 32

    def insert(self, name, value):
        # type: (bytes, bytes) -> None
        entry_size = len(name) + len(value) + 32
        if entry_size > self.capacity:
            raise QPACKError("QPACK entry exceeds table capacity")
        while self.order and self.size + entry_size > self.capacity:
            index = self.order.pop(0)
            old_name, old_value = self.entries.pop(index)
            self.size -= len(old_name) + len(old_value) + 32
        self.entries[self.insert_count] = (name, value)
        self.order.append(self.insert_count)
        self.insert_count += 1
        self.size += entry_size

    def get(self, absolute_index):
        # type: (int) -> Tuple[bytes, bytes]
        try:
            return self.entries[absolute_index]
        except KeyError:
            raise QPACKError("unknown QPACK dynamic table index")

    def decode_encoder_instruction(self, data, offset):
        # type: (bytes, int) -> Tuple[Tuple[Any, ...], int]
        if offset >= len(data):
            raise QPACKIncomplete("missing QPACK encoder instruction")
        first = data[offset]
        if first & 0x80:
            index, pos = qpack_decode_integer(data, offset, 6)
            is_static = bool(first & 0x40)
            if is_static:
                if index >= len(_QPACK_STATIC):
                    raise QPACKError("invalid QPACK static index")
                name = _QPACK_STATIC[index][0]
            else:
                name = self.get(self.insert_count - index - 1)[0]
            value, pos = qpack_decode_string(data, pos, 7)
            self.insert(name, value)
            return ("insert", name, value), pos
        if first & 0x40:
            huffman = bool(first & 0x20)
            name_len, pos = qpack_decode_integer(data, offset, 5)
            if pos + name_len > len(data):
                raise QPACKIncomplete("truncated QPACK encoder instruction")
            name = data[pos:pos + name_len]
            pos += name_len
            if huffman:
                name = qpack_huffman_decode(name)
            value, pos = qpack_decode_string(data, pos, 7)
            self.insert(name, value)
            return ("insert", name, value), pos
        if first & 0x20:
            capacity, pos = qpack_decode_integer(data, offset, 5)
            if capacity > self.max_table_capacity and self.max_table_capacity:
                raise QPACKError("QPACK capacity exceeds peer setting")
            self.set_capacity(capacity)
            return ("capacity", capacity), pos
        index, pos = qpack_decode_integer(data, offset, 5)
        name, value = self.get(self.insert_count - index - 1)
        self.insert(name, value)
        return ("duplicate", name, value), pos

    def decode_header_block(self, data):
        # type: (bytes) -> List[Tuple[bytes, bytes]]
        encoded_insert_count, offset = qpack_decode_integer(data, 0, 8)
        if encoded_insert_count == 0:
            required_insert_count = 0
        else:
            full_range = 2 * self.max_entries
            if not full_range or encoded_insert_count > full_range:
                raise QPACKError("invalid QPACK Required Insert Count")
            max_value = self.insert_count + self.max_entries
            max_wrapped = (max_value // full_range) * full_range
            required_insert_count = max_wrapped + encoded_insert_count - 1
            if required_insert_count > max_value:
                if required_insert_count <= full_range:
                    raise QPACKError("invalid QPACK Required Insert Count")
                required_insert_count -= full_range
            if required_insert_count == 0:
                raise QPACKError("invalid QPACK Required Insert Count")
        sign = bool(data[offset] & 0x80)
        delta_base, offset = qpack_decode_integer(data, offset, 7)
        if sign:
            base = required_insert_count - delta_base - 1
        else:
            base = required_insert_count + delta_base
        if base < 0:
            raise QPACKError("negative QPACK Base")

        headers = []  # type: List[Tuple[bytes, bytes]]
        while offset < len(data):
            first = data[offset]
            if first & 0x80:
                index, offset = qpack_decode_integer(data, offset, 6)
                if first & 0x40:
                    if index >= len(_QPACK_STATIC):
                        raise QPACKError("invalid QPACK static index")
                    headers.append(_QPACK_STATIC[index])
                else:
                    headers.append(self.get(base - index - 1))
            elif first & 0x40:
                index, offset = qpack_decode_integer(data, offset, 4)
                if first & 0x10:
                    if index >= len(_QPACK_STATIC):
                        raise QPACKError("invalid QPACK static index")
                    name = _QPACK_STATIC[index][0]
                else:
                    name = self.get(base - index - 1)[0]
                value, offset = qpack_decode_string(data, offset, 7)
                headers.append((name, value))
            elif first & 0x20:
                name, offset = qpack_decode_string(data, offset, 3)
                value, offset = qpack_decode_string(data, offset, 7)
                headers.append((name, value))
            elif first & 0x10:
                index, offset = qpack_decode_integer(data, offset, 4)
                headers.append(self.get(base + index))
            elif first & 0x08:
                index, offset = qpack_decode_integer(data, offset, 3)
                name = self.get(base + index)[0]
                value, offset = qpack_decode_string(data, offset, 7)
                headers.append((name, value))
            else:
                raise QPACKError("invalid QPACK field line")
        return headers


def qpack_decode_encoder_instructions(data, decoder):
    # type: (bytes, QPACKDecoder) -> Tuple[List[Tuple[Any, ...]], int]
    instructions = []
    offset = 0
    while offset < len(data):
        try:
            instruction, new_offset = decoder.decode_encoder_instruction(data, offset)
        except QPACKIncomplete:
            break
        except QPACKError as ex:
            log_runtime.debug("QPACK: invalid encoder instruction: %s", ex)
            break
        instructions.append(instruction)
        offset = new_offset
    return instructions, offset


class HTTP3Stream(Packet):
    """Control, push, or QPACK stream marker."""

    __slots__ = ["instructions"]
    name = "HTTP/3 Stream"
    fields_desc = [QuicVarIntField("stream_type", 0)]

    def __init__(self, *args, **kwargs):
        self.instructions = kwargs.pop("instructions", [])
        super(HTTP3Stream, self).__init__(*args, **kwargs)

    def mysummary(self):
        return "HTTP/3 %s stream" % _http3_streams.get(
            self.stream_type, "Unknown"
        ), [HTTP3Stream]


class H3Frame(Packet):
    name = "HTTP/3 Frame"
    fields_desc = [
        QuicVarEnumField("Type", None, _http3_frames),
        QuicVarLenField("Length", None, length_of="Data"),
        StrLenField("Data", b"", length_from=lambda pkt: pkt.Length),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            try:
                frame_type, _ = quic_decode_varint(_pkt)
            except ValueError:
                return H3UnknownFrame
            return _http3_frame_cls.get(frame_type, H3UnknownFrame)
        return H3UnknownFrame

    def extract_padding(self, s):
        return b"", s


class H3DataFrame(H3Frame):
    name = "HTTP/3 - DATA"

    def __init__(self, *args, **kwargs):
        if not args and "Type" not in kwargs:
            kwargs["Type"] = HTTP3_DATA
        super(H3DataFrame, self).__init__(*args, **kwargs)


class H3HeadersFrame(H3Frame):
    __slots__ = ["headers", "header_dict", "http3_decoder"]
    name = "HTTP/3 - HEADERS"

    def __init__(self, *args, **kwargs):
        self.headers = []
        self.header_dict = {}
        self.http3_decoder = kwargs.pop("http3_decoder", None)
        if not args and "Type" not in kwargs:
            kwargs["Type"] = HTTP3_HEADERS
        super(H3HeadersFrame, self).__init__(*args, **kwargs)
        self.decode_headers()

    def decode_headers(self):
        decoder = self.http3_decoder
        if decoder is None and self.underlayer is not None:
            decoder = getattr(self.underlayer, "http3_decoder", None)
        if decoder is None:
            return
        try:
            self.headers = decoder.decode_header_block(self.Data)
        except QPACKError as ex:
            log_runtime.debug("HTTP/3: QPACK header decoding failed: %s", ex)
            self.headers = []
        self.header_dict = {}
        for name, value in self.headers:
            self.header_dict.setdefault(name, []).append(value)

    def mysummary(self):
        return "HTTP/3 HEADERS (%d fields)" % len(self.headers), [H3Frame]


class H3SettingsFrame(H3Frame):
    __slots__ = ["settings", "settings_list"]
    name = "HTTP/3 - SETTINGS"

    def __init__(self, *args, **kwargs):
        self.settings = {}
        self.settings_list = []
        if not args and "Type" not in kwargs:
            kwargs["Type"] = HTTP3_SETTINGS
        super(H3SettingsFrame, self).__init__(*args, **kwargs)
        self.decode_settings()

    def decode_settings(self):
        self.settings = {}
        self.settings_list = []
        data = self.Data
        offset = 0
        try:
            while offset < len(data):
                setting_id, offset = quic_decode_varint(data, offset)
                value, offset = quic_decode_varint(data, offset)
                self.settings[setting_id] = value
                self.settings_list.append((setting_id, value))
        except ValueError:
            return

    def mysummary(self):
        return "HTTP/3 SETTINGS (%d entries)" % len(self.settings_list), [H3Frame]


class H3CancelPushFrame(H3Frame):
    name = "HTTP/3 - CANCEL_PUSH"
    fields_desc = [
        QuicVarEnumField("Type", HTTP3_CANCEL_PUSH, _http3_frames),
        QuicVarLenField("Length", None, length_of="PushID"),
        QuicVarIntField("PushID", 0),
    ]


class H3PushPromiseFrame(H3Frame):
    __slots__ = ["push_id", "headers", "http3_decoder"]
    name = "HTTP/3 - PUSH_PROMISE"

    def __init__(self, *args, **kwargs):
        self.push_id = None
        self.headers = []
        if not args and "Type" not in kwargs:
            kwargs["Type"] = HTTP3_PUSH_PROMISE
        super(H3PushPromiseFrame, self).__init__(*args, **kwargs)
        if self.Data:
            try:
                self.push_id, offset = quic_decode_varint(self.Data, 0)
                decoder = getattr(self, "http3_decoder", None)
                if decoder is None and self.underlayer is not None:
                    decoder = getattr(self.underlayer, "http3_decoder", None)
                if decoder is not None:
                    self.headers = decoder.decode_header_block(self.Data[offset:])
            except (ValueError, QPACKError) as ex:
                log_runtime.debug(
                    "HTTP/3: invalid PUSH_PROMISE frame: %s", ex
                )


class H3GoAwayFrame(H3Frame):
    name = "HTTP/3 - GOAWAY"
    fields_desc = [
        QuicVarEnumField("Type", HTTP3_GOAWAY, _http3_frames),
        QuicVarLenField("Length", None, length_of="StreamID"),
        QuicVarIntField("StreamID", 0),
    ]


class H3MaxPushIdFrame(H3Frame):
    name = "HTTP/3 - MAX_PUSH_ID"
    fields_desc = [
        QuicVarEnumField("Type", HTTP3_MAX_PUSH_ID, _http3_frames),
        QuicVarLenField("Length", None, length_of="PushID"),
        QuicVarIntField("PushID", 0),
    ]


class H3DuplicatePushFrame(H3Frame):
    name = "HTTP/3 - DUPLICATE_PUSH"
    fields_desc = [
        QuicVarEnumField("Type", HTTP3_DUPLICATE_PUSH, _http3_frames),
        QuicVarLenField("Length", None, length_of="PushID"),
        QuicVarIntField("PushID", 0),
    ]


class H3UnknownFrame(H3Frame):
    name = "HTTP/3 - Unknown"


_http3_frame_cls = {
    HTTP3_DATA: H3DataFrame,
    HTTP3_HEADERS: H3HeadersFrame,
    HTTP3_CANCEL_PUSH: H3CancelPushFrame,
    HTTP3_SETTINGS: H3SettingsFrame,
    HTTP3_PUSH_PROMISE: H3PushPromiseFrame,
    HTTP3_GOAWAY: H3GoAwayFrame,
    HTTP3_MAX_PUSH_ID: H3MaxPushIdFrame,
    HTTP3_DUPLICATE_PUSH: H3DuplicatePushFrame,
}


class HTTP3(Packet):
    name = "HTTP/3"
    fields_desc = [
        PacketListField(
            "frames",
            [],
            H3Frame,
            length_from=lambda pkt: len(pkt.original),
        ),
    ]

    def post_dissect(self, s):
        decoder = QPACKDecoder()
        for frame in self.frames:
            if isinstance(frame, H3HeadersFrame):
                frame.http3_decoder = decoder
                frame.decode_headers()
            elif isinstance(frame, H3SettingsFrame):
                frame.decode_settings()
        return s


def qpack_parse_http3_frames(data, decoder):
    # type: (bytes, QPACKDecoder) -> Tuple[List[H3Frame], int]
    frames = []  # type: List[H3Frame]
    offset = 0
    while offset < len(data):
        start = offset
        try:
            frame_type, offset = quic_decode_varint(data, offset)
            length, offset = quic_decode_varint(data, offset)
        except ValueError:
            break
        if offset + length > len(data):
            offset = start
            break
        end = offset + length
        raw = data[start:end]
        frame = H3Frame(raw)
        if isinstance(frame, H3HeadersFrame):
            frame.http3_decoder = decoder
            frame.decode_headers()
        elif isinstance(frame, H3SettingsFrame):
            frame.decode_settings()
        elif isinstance(frame, H3PushPromiseFrame):
            frame.http3_decoder = decoder
            if frame.Data:
                try:
                    push_id, pos = quic_decode_varint(frame.Data, 0)
                    frame.push_id = push_id
                    frame.headers = decoder.decode_header_block(frame.Data[pos:])
                except (ValueError, QPACKError) as ex:
                    log_runtime.debug(
                        "HTTP/3: invalid PUSH_PROMISE frame: %s", ex
                    )
        frames.append(frame)
        offset = end
    return frames, offset
