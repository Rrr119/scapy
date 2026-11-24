# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
QUIC

This module implements the QUIC v1 transport layer from RFC 9000 and packet
protection from RFC 9001. HTTP/3 frames and QPACK live in
:mod:`scapy.layers.http3`.

QUIC packet protection is stateful. When QUIC is dissected below UDP, Scapy
keeps one :class:`QUICConnectionState` per UDP flow in ``QUIC_SESSIONS`` and
uses TLS key logs from ``conf.tls_nss_filename`` / ``conf.tls_nss_keys`` for
Handshake and 1-RTT packets. Initial packets are decrypted with the keys
derived from the client Destination Connection ID.
"""

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from scapy.config import conf
from scapy.error import log_runtime
from scapy.fields import (
    _EnumField,
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    EnumField,
    Field,
    FieldLenField,
    FieldListField,
    IntField,
    MultipleTypeField,
    PacketListField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
)
from scapy.packet import Packet, bind_layers
from scapy.sessions import DefaultSession
from scapy.utils import strxor

from scapy.layers.inet import UDP
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.session import load_nss_keys

# Typing imports
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)


QUIC_VERSION_1 = 0x00000001
QUIC_VERSION_2 = 0x6B3343CF

# RFC 9001 section 5.2 and RFC 9369 section 3.3
QUIC_INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

QUIC_MAX_VARINT = 0x3FFFFFFFFFFFFFFF

_quic_payloads = {
    0x00: "PADDING",
    0x01: "PING",
    0x02: "ACK",
    0x03: "ACK_ECN",
    0x04: "RESET_STREAM",
    0x05: "STOP_SENDING",
    0x06: "CRYPTO",
    0x07: "NEW_TOKEN",
    0x08: "STREAM",
    0x09: "STREAM_FIN",
    0x0A: "STREAM_LEN",
    0x0B: "STREAM_LEN_FIN",
    0x0C: "STREAM_OFF",
    0x0D: "STREAM_OFF_FIN",
    0x0E: "STREAM_OFF_LEN",
    0x0F: "STREAM_OFF_LEN_FIN",
    0x10: "MAX_DATA",
    0x11: "MAX_STREAM_DATA",
    0x12: "MAX_STREAMS_BIDI",
    0x13: "MAX_STREAMS_UNI",
    0x14: "DATA_BLOCKED",
    0x15: "STREAM_DATA_BLOCKED",
    0x16: "STREAMS_BLOCKED_BIDI",
    0x17: "STREAMS_BLOCKED_UNI",
    0x18: "NEW_CONNECTION_ID",
    0x19: "RETIRE_CONNECTION_ID",
    0x1A: "PATH_CHALLENGE",
    0x1B: "PATH_RESPONSE",
    0x1C: "CONNECTION_CLOSE",
    0x1D: "CONNECTION_CLOSE_APP",
    0x1E: "HANDSHAKE_DONE",
    0x30: "DATAGRAM",
    0x31: "DATAGRAM_LEN",
}

_quic_packet_types = {
    0x00: "Initial",
    0x01: "0-RTT",
    0x02: "Handshake",
    0x03: "Retry",
}


def quic_decode_varint(data, offset=0):
    # type: (bytes, int) -> Tuple[int, int]
    """Decode one RFC 9000 variable-length integer."""
    if offset >= len(data):
        raise ValueError("missing QUIC varint")
    prefix = data[offset] >> 6
    size = 1 << prefix
    if offset + size > len(data):
        raise ValueError("truncated QUIC varint")
    value = int.from_bytes(data[offset:offset + size], "big")
    return value & (QUIC_MAX_VARINT >> (8 * (8 - size))), offset + size


def quic_encode_varint(value):
    # type: (int) -> bytes
    """Encode one RFC 9000 variable-length integer."""
    if value < 0 or value > QUIC_MAX_VARINT:
        raise struct.error("QUIC varint out of range")
    if value < 0x40:
        return struct.pack("!B", value)
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def quic_decode_packet_number(truncated, pn_len, expected):
    # type: (int, int, int) -> int
    """RFC 9000 Appendix A.3 packet number reconstruction."""
    window = 1 << (pn_len * 8)
    half_window = window // 2
    candidate = (expected & ~(window - 1)) | truncated
    if candidate <= expected - half_window and candidate < (1 << 62) - window:
        return candidate + window
    if candidate > expected + half_window and candidate >= window:
        return candidate - window
    return candidate


class QUICCrypto:
    """One direction of a QUIC packet protection context."""

    def __init__(self, secret, cipher_name, hash_name):
        # type: (bytes, str, str) -> None
        hash_alg = TLS13_HKDF(hash_name)
        key_len = 32 if cipher_name in ("aes-256-gcm", "chacha20-poly1305") else 16
        self.cipher_name = cipher_name
        self.hash_name = hash_name
        self.key = hash_alg.expand_label(secret, b"quic key", b"", key_len)
        self.iv = hash_alg.expand_label(secret, b"quic iv", b"", 12)
        self.hp = hash_alg.expand_label(secret, b"quic hp", b"", key_len)
        self.aead = AESGCM(self.key)

    def _hp_mask(self, sample):
        # type: (bytes) -> bytes
        if self.cipher_name == "chacha20-poly1305":
            counter = int.from_bytes(sample[12:16], "little")
            nonce = counter.to_bytes(4, "little") + sample[:12]
            decryptor = Cipher(
                algorithms.ChaCha20(self.hp, nonce),
                mode=None,
            ).encryptor()
            return decryptor.update(b"\x00" * 5)
        encryptor = Cipher(algorithms.AES(self.hp), modes.ECB()).encryptor()
        return encryptor.update(sample[:16]) + encryptor.finalize()

    def remove_header_protection(self, packet, pn_offset, is_long):
        # type: (bytes, int, bool) -> Tuple[int, int, bytes]
        sample = packet[pn_offset + 4:pn_offset + 20]
        if len(sample) != 16:
            raise ValueError("QUIC packet is too short for header protection")
        mask = self._hp_mask(sample)
        if is_long:
            first = packet[0] ^ (mask[0] & 0x0F)
        else:
            first = packet[0] ^ (mask[0] & 0x1F)
        pn_len = (first & 0x03) + 1
        protected_pn = packet[pn_offset:pn_offset + pn_len]
        plain_pn = bytes(
            a ^ b for a, b in zip(protected_pn, mask[1:1 + pn_len])
        )
        return first, pn_len, plain_pn

    def decrypt(self, plain_header, ciphertext, packet_number):
        # type: (bytes, bytes, int) -> Optional[bytes]
        nonce = strxor(self.iv, packet_number.to_bytes(12, "big"))
        try:
            return self.aead.decrypt(nonce, ciphertext, plain_header)
        except InvalidTag:
            # An authentication failure only means that this candidate key is
            # not the one used for this packet.
            return None

    def encrypt(self, plain_header, payload, packet_number):
        # type: (bytes, bytes, int) -> bytes
        nonce = strxor(self.iv, packet_number.to_bytes(12, "big"))
        return self.aead.encrypt(nonce, payload, plain_header)


def quic_crypto_candidates(secret):
    # type: (bytes) -> List[QUICCrypto]
    """
    Derive candidate cipher contexts from a TLS traffic secret.

    TLS key logs carry the traffic secret but not the negotiated cipher suite.
    The secret length identifies SHA-384, while SHA-256 suites are distinguished
    by successful AEAD authentication.
    """
    suites = ()  # type: Tuple[Tuple[str, str], ...]
    if len(secret) == 48:
        suites = (("aes-256-gcm", "sha384"),)
    else:
        suites = (
            ("aes-128-gcm", "sha256"),
            ("chacha20-poly1305", "sha256"),
        )
    return [QUICCrypto(secret, cipher, hash_alg) for cipher, hash_alg in suites]


def quic_initial_crypto(version, dcid):
    # type: (int, bytes) -> Tuple[QUICCrypto, QUICCrypto]
    if version == QUIC_VERSION_2:
        salt = QUIC_INITIAL_SALT_V2
    else:
        salt = QUIC_INITIAL_SALT_V1
    hkdf = TLS13_HKDF("sha256")
    initial_secret = hkdf.extract(salt, dcid)
    client_secret = hkdf.expand_label(
        initial_secret, b"client in", b"", hkdf.hash.digest_size
    )
    server_secret = hkdf.expand_label(
        initial_secret, b"server in", b"", hkdf.hash.digest_size
    )
    return (
        quic_crypto_candidates(client_secret)[0],
        quic_crypto_candidates(server_secret)[0],
    )


class QUICConnectionState:
    """Per-flow state used to decrypt packets and reassemble QUIC streams."""

    def __init__(self, flow, client_endpoint=None):
        # type: (Tuple[Tuple[str, int], Tuple[str, int]], Optional[Tuple[str, int]]) -> None  # noqa: E501
        self.flow = flow
        self.client_endpoint = client_endpoint or flow[0]
        self.server_endpoint = flow[1] if flow[0] == self.client_endpoint else flow[0]
        self.initial_dcid = None  # type: Optional[bytes]
        self.dcid_len = 0
        self.initial_keys = None  # type: Optional[Tuple[QUICCrypto, QUICCrypto]]
        self.handshake_keys = {}  # type: Dict[bool, QUICCrypto]
        self.application_keys = {}  # type: Dict[bool, QUICCrypto]
        self.packet_numbers = {}  # type: Dict[str, int]
        self.streams = {}  # type: Dict[Tuple[bool, int], Dict[str, Any]]
        self.qpack_decoders = {}  # type: Dict[bool, Any]
        self.client_random = None  # type: Optional[bytes]
        self.crypto_streams = {}  # type: Dict[bool, bytearray]

    def is_client_packet(self, packet):
        # type: (Packet) -> bool
        underlayer = packet.underlayer
        if underlayer is None or underlayer.underlayer is None:
            return True
        ip = underlayer.underlayer
        endpoint = (getattr(ip, "src", ""), getattr(underlayer, "sport", 0))
        return endpoint == self.client_endpoint

    def describe_packet_space(self, packet):
        # type: (Packet) -> str
        if isinstance(packet, QUIC_Initial):
            return "initial"
        if isinstance(packet, QUIC_Handshake):
            return "handshake"
        return "application"

    def get_crypto(self, packet):
        # type: (Packet) -> Optional[QUICCrypto]
        is_client = self.is_client_packet(packet)
        space = self.describe_packet_space(packet)
        if space == "initial":
            if self.initial_keys is None:
                return None
            return self.initial_keys[0 if is_client else 1]
        cache = self.handshake_keys if space == "handshake" else self.application_keys
        return cache.get(is_client)

    def reset_initial(self, version, dcid, dcil):
        # type: (int, bytes, int) -> None
        self.initial_dcid = dcid
        self.dcid_len = dcil
        self.initial_keys = quic_initial_crypto(version, dcid)
        self.handshake_keys.clear()
        self.application_keys.clear()
        self.packet_numbers.clear()
        self.streams.clear()
        self.qpack_decoders.clear()
        self.crypto_streams.clear()

    def try_keylog_crypto(self, packet, packet_bytes, pn_offset, is_long):
        # type: (Packet, bytes, int, bool) -> Optional[Tuple[QUICCrypto, int, bytes, bytes]]  # noqa: E501
        """Try every compatible traffic secret from the NSS key log."""
        if conf.tls_nss_filename is not None and conf.tls_nss_keys is None:
            conf.tls_nss_keys = load_nss_keys(conf.tls_nss_filename)
        if not conf.tls_nss_keys:
            return None
        space = self.describe_packet_space(packet)
        if space == "handshake":
            labels = (
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            )
        else:
            labels = ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")
        is_client = self.is_client_packet(packet)
        ordered_labels = (labels[0], labels[1]) if is_client else (labels[1], labels[0])
        expected = self.packet_numbers.get(space, 0)
        for label in ordered_labels:
            for secret in conf.tls_nss_keys.get(label, {}).values():
                for crypto in quic_crypto_candidates(secret):
                    result = quic_remove_protection_and_decrypt(
                        crypto, packet_bytes, pn_offset, is_long, expected
                    )
                    if result is not None:
                        plain_header, payload, packet_number = result
                        cache = (
                            self.handshake_keys
                            if space == "handshake"
                            else self.application_keys
                        )
                        cache[is_client] = crypto
                        return crypto, packet_number, plain_header, payload
        return None

    def feed_crypto(self, is_client, data, offset=0):
        # type: (bool, bytes, int) -> None
        """Track ClientHello data for diagnostics."""
        buf = self.crypto_streams.setdefault(is_client, bytearray())
        if offset > len(buf):
            return
        buf.extend(data)
        raw = bytes(buf)
        if len(raw) < 44 or raw[:1] != b"\x16":
            return
        if raw[5:6] == b"\x01":
            self.client_random = raw[11:43]

    def feed_stream(self, is_client, stream_id, offset, data, fin):
        # type: (bool, int, int, bytes, bool) -> Optional[Packet]
        key = (is_client, stream_id)
        stream = self.streams.setdefault(
            key,
            {
                "buffer": bytearray(),
                "next_offset": 0,
                "pending": {},
                "kind": None,
                "fin": False,
            },
        )
        if fin:
            stream["fin"] = True
        if offset < stream["next_offset"]:
            data = data[stream["next_offset"] - offset:]
            offset = stream["next_offset"]
        if not data:
            return None
        if offset > stream["next_offset"]:
            stream["pending"][offset] = data
            return None
        stream["buffer"].extend(data)
        stream["next_offset"] += len(data)
        while stream["next_offset"] in stream["pending"]:
            chunk = stream["pending"].pop(stream["next_offset"])
            stream["buffer"].extend(chunk)
            stream["next_offset"] += len(chunk)
        return self.parse_stream(stream, is_client, stream_id)

    def parse_stream(self, stream, is_client, stream_id):
        # type: (Dict[str, Any], bool, int) -> Optional[Packet]
        from scapy.layers.http3 import (
            HTTP3,
            HTTP3_QPACK_ENCODER,
            HTTP3Stream,
            qpack_decode_encoder_instructions,
            qpack_parse_http3_frames,
        )

        data = bytes(stream["buffer"])
        if stream["kind"] is None:
            if stream_id & 0x02:
                try:
                    stream_type, consumed = quic_decode_varint(data)
                except ValueError:
                    return None
                stream["kind"] = stream_type
                stream["buffer"] = bytearray(data[consumed:])
                data = bytes(stream["buffer"])
            else:
                stream["kind"] = HTTP3
        kind = stream["kind"]
        if kind == HTTP3_QPACK_ENCODER:
            decoder = self.qpack_decoders.setdefault(is_client, None)
            if decoder is None:
                from scapy.layers.http3 import QPACKDecoder
                decoder = self.qpack_decoders[is_client] = QPACKDecoder()
            try:
                instructions, consumed = qpack_decode_encoder_instructions(
                    data, decoder
                )
            except ValueError as ex:
                log_runtime.debug("QUIC: invalid QPACK encoder stream: %s", ex)
                return None
            if not consumed:
                return None
            stream["buffer"] = bytearray(data[consumed:])
            return HTTP3Stream(
                stream_type=HTTP3_QPACK_ENCODER,
                instructions=instructions,
            )
        if kind not in (HTTP3, 0x00):
            return None
        decoder = self.qpack_decoders.setdefault(is_client, None)
        if decoder is None:
            from scapy.layers.http3 import QPACKDecoder
            decoder = self.qpack_decoders[is_client] = QPACKDecoder()
        try:
            frames, consumed = qpack_parse_http3_frames(data, decoder)
        except ValueError as ex:
            log_runtime.debug("QUIC: invalid HTTP/3 stream: %s", ex)
            return None
        if not consumed:
            return None
        stream["buffer"] = bytearray(data[consumed:])
        pkt = HTTP3(frames=frames)
        for frame in frames:
            frame.http3_decoder = decoder
        return pkt


QUIC_SESSIONS = {}  # type: Dict[Tuple[Tuple[str, int], Tuple[str, int]], QUICConnectionState]  # noqa: E501


def quic_reset_sessions():
    """Clear per-flow QUIC decryption and stream reassembly state."""
    QUIC_SESSIONS.clear()


class QUICSession(DefaultSession):
    """Sniff session that resets QUIC flow state at the start of a capture."""

    def __init__(self, *args, **kwargs):
        super(QUICSession, self).__init__(*args, **kwargs)
        quic_reset_sessions()


class QuicVarIntField(Field[int, int]):
    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[int]) -> bytes
        val = self.i2m(pkt, val)
        if val is None:
            val = 0
        return s + quic_encode_varint(val)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, int]
        value, offset = quic_decode_varint(s)
        return s[offset:], value

    def i2len(self, pkt, x):
        # type: (Packet, int) -> int
        value = self.i2m(pkt, x)
        if value is None:
            return 1
        if value < 0 or value > QUIC_MAX_VARINT:
            return 8
        return len(quic_encode_varint(value))


class QuicVarLenField(FieldLenField, QuicVarIntField):
    pass


class QuicVarEnumField(QuicVarIntField, _EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Any) -> None
        _EnumField.__init__(self, name, default, enum)  # type: ignore
        QuicVarIntField.__init__(self, name, default)  # type: ignore

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        return _EnumField.any2i(self, pkt, x)  # type: ignore

    def i2repr(self, pkt, x):
        # type: (Optional[Packet], int) -> Any
        return _EnumField.i2repr(self, pkt, x)


# -- Headers --


_quic_long_hdr = {
    0: "Short",
    1: "Long",
}

_quic_long_pkttyp = _quic_packet_types


def quic_parse_long_prefix(data):
    # type: (bytes) -> Tuple[int, int, bytes, bytes, int, int]
    """Return version, packet type, DCID, SCID, varint offset and DCID length."""
    if len(data) < 7:
        raise ValueError("truncated QUIC long header")
    version = struct.unpack("!I", data[1:5])[0]
    dcil = data[5]
    offset = 6
    if offset + dcil + 1 > len(data):
        raise ValueError("truncated QUIC connection ID")
    dcid = data[offset:offset + dcil]
    offset += dcil
    scil = data[offset]
    offset += 1
    if offset + scil > len(data):
        raise ValueError("truncated QUIC source connection ID")
    scid = data[offset:offset + scil]
    offset += scil
    packet_type = (data[0] & 0x30) >> 4 if version else 4
    return version, packet_type, dcid, scid, offset, dcil


def quic_long_payload_offset(data, version, packet_type, offset):
    # type: (bytes, int, int, int) -> Tuple[int, int, int]
    """Return (pn_offset, packet_end, length)."""
    if version == 0 or packet_type == 3:
        return offset, len(data), 0
    if packet_type == 0:
        token_len, offset = quic_decode_varint(data, offset)
        offset += token_len
    length, offset = quic_decode_varint(data, offset)
    pn_offset = offset
    packet_end = pn_offset + length
    return pn_offset, packet_end, length


def quic_long_length_offset(data):
    # type: (bytes) -> int
    version, packet_type, _, _, offset, _ = quic_parse_long_prefix(data)
    if version == 0 or packet_type == 3:
        return offset
    if packet_type == 0:
        token_len, offset = quic_decode_varint(data, offset)
        offset += token_len
    return offset


def quic_apply_header_protection(crypto, plain_header, ciphertext, pn_len):
    # type: (QUICCrypto, bytes, bytes, int) -> bytes
    pn_offset = len(plain_header) - pn_len
    sample = ciphertext[4 - pn_len:20 - pn_len]
    if len(sample) != 16:
        raise ValueError("QUIC packet is too short for header protection")
    mask = crypto._hp_mask(sample)
    first = plain_header[0]
    if first & 0x80:
        first ^= mask[0] & 0x0F
    else:
        first ^= mask[0] & 0x1F
    protected_pn = bytes(
        a ^ b
        for a, b in zip(plain_header[pn_offset:], mask[1:1 + pn_len])
    )
    return (
        bytes([first])
        + plain_header[1:pn_offset]
        + protected_pn
        + ciphertext
    )


def quic_remove_protection_and_decrypt(
    crypto, data, pn_offset, is_long, expected_pn=0
):
    # type: (QUICCrypto, bytes, int, bool, int) -> Optional[Tuple[bytes, bytes, int]]
    try:
        first, pn_len, plain_pn = crypto.remove_header_protection(
            data, pn_offset, is_long
        )
    except (IndexError, ValueError):
        return None
    if is_long:
        packet_type = (first & 0x30) >> 4
        try:
            version, _, _, _, header_offset, _ = quic_parse_long_prefix(data)
            accepted_pn_offset, packet_end, _ = quic_long_payload_offset(
                data, version, packet_type, header_offset
            )
        except (IndexError, ValueError, struct.error):
            return None
        if accepted_pn_offset != pn_offset:
            return None
    else:
        packet_end = len(data)
    if packet_end > len(data):
        return None
    header_end = pn_offset + pn_len
    if packet_end - header_end < 16:
        return None
    plain_header = bytes([first]) + data[1:pn_offset] + plain_pn
    truncated_pn = int.from_bytes(plain_pn, "big")
    packet_number = quic_decode_packet_number(truncated_pn, pn_len, expected_pn)
    ciphertext = data[header_end:packet_end]
    payload = crypto.decrypt(plain_header, ciphertext, packet_number)
    if payload is None:
        return None
    return plain_header, payload, packet_number


def quic_flow_from_underlayer(underlayer):
    # type: (Optional[Packet]) -> Optional[Tuple[Tuple[str, int], Tuple[str, int]]]
    if underlayer is None or not hasattr(underlayer, "sport"):
        return None
    ip = underlayer.underlayer
    if ip is None or not hasattr(ip, "src"):
        return None
    src = (getattr(ip, "src", ""), int(getattr(underlayer, "sport", 0)))
    dst = (getattr(ip, "dst", ""), int(getattr(underlayer, "dport", 0)))
    if not src[0] or not dst[0]:
        return None
    return tuple(sorted((src, dst)))  # type: ignore


def quic_endpoint_from_underlayer(underlayer):
    # type: (Optional[Packet]) -> Optional[Tuple[str, int]]
    if underlayer is None or not hasattr(underlayer, "sport"):
        return None
    ip = underlayer.underlayer
    if ip is None or not hasattr(ip, "src"):
        return None
    return getattr(ip, "src", ""), int(getattr(underlayer, "sport", 0))


class QUIC(Packet):
    __slots__ = [
        "quic_session",
        "_quic_plaintext",
        "_quic_plaintext_valid",
        "_quic_remainder",
        "_quic_packet_number",
    ]
    match_subclass = True

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """Return the right class for the given data."""
        if _pkt:
            hdr = _pkt[0]
            if hdr & 0x80:
                if hdr & 0x40 == 0:
                    return QUIC_Version
                typ = (hdr & 0x30) >> 4
                return {
                    0: QUIC_Initial,
                    1: QUIC_0RTT,
                    2: QUIC_Handshake,
                    3: QUIC_Retry,
                }[typ]
            return QUIC_1RTT
        return QUIC_Initial

    def __init__(self, *args, **kwargs):
        self.quic_session = kwargs.pop("quic_session", None)
        self._quic_plaintext = None
        self._quic_plaintext_valid = False
        self._quic_remainder = b""
        self._quic_packet_number = None
        underlayer = kwargs.get("_underlayer")
        if self.quic_session is None:
            flow = quic_flow_from_underlayer(underlayer)
            if flow is not None:
                self.quic_session = QUIC_SESSIONS.get(flow)
                if self.quic_session is None:
                    self.quic_session = QUICConnectionState(
                        flow, quic_endpoint_from_underlayer(underlayer)
                    )
                    QUIC_SESSIONS[flow] = self.quic_session
        super(QUIC, self).__init__(*args, **kwargs)

    def pre_dissect(self, s):
        if self.quic_session is None or len(s) < 1:
            return s
        first = s[0]
        is_long = bool(first & 0x80)
        try:
            if is_long:
                version, packet_type, dcid, _, offset, dcil = \
                    quic_parse_long_prefix(s)
                if packet_type == 0:
                    if self.quic_session.initial_dcid is None:
                        self.quic_session.reset_initial(version, dcid, dcil)
                    elif (
                        self.quic_session.initial_dcid != dcid
                        and self.quic_session.is_client_packet(self)
                    ):
                        self.quic_session.reset_initial(version, dcid, dcil)
                pn_offset, packet_end, _ = quic_long_payload_offset(
                    s, version, packet_type, offset
                )
            else:
                if self.quic_session.initial_dcid is None:
                    return s
                pn_offset = 1 + self.quic_session.dcid_len
                packet_end = len(s)
            if packet_end > len(s):
                return s
            if is_long and (version in (0, 0xFFFF0A0A, 0xFF00001D) or packet_type == 3):
                return s
            space = self.quic_session.describe_packet_space(self)
            expected_pn = self.quic_session.packet_numbers.get(space, 0)
            crypto = self.quic_session.get_crypto(self)
            result = None
            if crypto is not None:
                result = quic_remove_protection_and_decrypt(
                    crypto, s[:packet_end], pn_offset, is_long, expected_pn
                )
            if result is None:
                result = self.quic_session.try_keylog_crypto(
                    self, s[:packet_end], pn_offset, is_long
                )
            if result is None:
                return s
            if len(result) == 4:
                _, packet_number, plain_header, payload = result
            else:
                plain_header, payload, packet_number = result
            pn_len = (plain_header[0] & 0x03) + 1
            self.quic_session.packet_numbers[space] = max(
                packet_number,
                self.quic_session.packet_numbers.get(space, 0),
            )
            self._quic_plaintext = payload
            self._quic_plaintext_valid = True
            self._quic_packet_number = packet_number
            self._quic_remainder = s[packet_end:]
            header = (
                bytes([plain_header[0]])
                + s[1:pn_offset]
                + plain_header[pn_offset:pn_offset + pn_len]
            )
            return header + s[pn_offset + pn_len:packet_end] + \
                self._quic_remainder
        except (IndexError, ValueError, struct.error):
            return s

    def post_dissect(self, s):
        if self._quic_plaintext_valid:
            if self._quic_packet_number is not None and \
                    "PacketNumber" in self.fields:
                self.PacketNumber = self._quic_packet_number
            return self._quic_plaintext
        return s

    def extract_padding(self, s):
        if self._quic_remainder:
            return s, self._quic_remainder
        return super(QUIC, self).extract_padding(s)

    def guess_payload_class(self, payload):
        if self._quic_plaintext_valid:
            return QUIC_Frames
        return super(QUIC, self).guess_payload_class(payload)

    def post_build(self, pkt, pay):
        if not pay:
            return pkt
        is_long = bool(pkt[0] & 0x80)
        try:
            if is_long:
                version, packet_type, _, _, offset, _ = \
                    quic_parse_long_prefix(pkt)
                if packet_type in (3, 4):
                    return pkt + pay
                pn_offset, _, _ = quic_long_payload_offset(
                    pkt, version, packet_type, offset
                )
            else:
                if self.quic_session is None:
                    return pkt + pay
                pn_offset = 1 + self.quic_session.dcid_len
            pn_len = (pkt[0] & 0x03) + 1
            minimum_payload = max(0, 4 - pn_len)
            if len(pay) < minimum_payload:
                pay += b"\x00" * (minimum_payload - len(pay))
            packet_number = int.from_bytes(
                pkt[pn_offset:pn_offset + pn_len], "big"
            )
            crypto = None
            if isinstance(self, QUIC_Initial):
                initial = quic_initial_crypto(version, self.DstConnID)
                is_client = getattr(self, "is_client", True)
                if self.quic_session is not None:
                    is_client = self.quic_session.is_client_packet(self)
                crypto = initial[0 if is_client else 1]
            elif self.quic_session is not None:
                crypto = self.quic_session.get_crypto(self)
            if crypto is None:
                return pkt + pay
            plain_header = pkt
            if is_long:
                length_offset = quic_long_length_offset(pkt)
                old_length, length_end = quic_decode_varint(pkt, length_offset)
                new_length = pn_len + len(pay) + 16
                if (
                    "Length" not in self.fields
                    or self.fields.get("Length") is None
                ):
                    length_bytes = quic_encode_varint(new_length)
                    plain_header = (
                        pkt[:length_offset]
                        + length_bytes
                        + pkt[length_end:]
                    )
                else:
                    new_length = old_length
            ciphertext = crypto.encrypt(plain_header, pay, packet_number)
            return quic_apply_header_protection(
                crypto, plain_header, ciphertext, pn_len
            )
        except (IndexError, ValueError, struct.error):
            return pkt + pay

    def mysummary(self):
        if self._quic_plaintext_valid:
            return "%s (decrypted)" % self.name, [QUIC]
        return self.name, [QUIC]


class QUIC_Version(QUIC):
    name = "QUIC - Version Negotiation"
    fields_desc = [
        BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
        BitField("Unused", 0, 7),
        IntField("Version", 0),
        FieldLenField("DstConnIDLen", None, length_of="DstConnID", fmt="B"),
        StrLenField("DstConnID", "", length_from=lambda pkt: pkt.DstConnIDLen),
        FieldLenField("SrcConnIDLen", None, length_of="SrcConnID", fmt="B"),
        StrLenField("SrcConnID", "", length_from=lambda pkt: pkt.SrcConnIDLen),
        FieldListField("SupportedVersions", [], IntField("", 0)),
    ]


def QuicPacketNumberField(name, default):
    # type: (str, int) -> MultipleTypeField
    return MultipleTypeField(
        [
            (
                ByteField(name, default),
                (
                    lambda pkt: pkt.PacketNumberLen == 0,
                    lambda _, val: val < 0x100,
                ),
            ),
            (
                ShortField(name, default),
                (
                    lambda pkt: pkt.PacketNumberLen == 1,
                    lambda _, val: val < 0x10000,
                ),
            ),
            (
                ThreeBytesField(name, default),
                (
                    lambda pkt: pkt.PacketNumberLen == 2,
                    lambda _, val: val < 0x1000000,
                ),
            ),
            (
                IntField(name, default),
                (
                    lambda pkt: pkt.PacketNumberLen == 3,
                    lambda _, val: val < 0x100000000,
                ),
            ),
        ],
        ByteField(name, default),
    )


class QuicPacketNumberBitFieldLenField(BitField):
    def i2m(self, pkt, x):
        if x is None and pkt is not None:
            PacketNumber = pkt.PacketNumber or 0
            if PacketNumber < 0 or PacketNumber > 0xFFFFFFFF:
                raise struct.error("requires 0 <= number <= 0xFFFFFFFF")
            if PacketNumber < 0x100:
                return 0
            elif PacketNumber < 0x10000:
                return 1
            elif PacketNumber < 0x1000000:
                return 2
            return 3
        elif x is None:
            return 0
        return x


class QUIC_Initial(QUIC):
    name = "QUIC - Initial"
    Version = QUIC_VERSION_1
    fields_desc = (
        [
            BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
            BitField("FixedBit", 1, 1),
            BitEnumField("LongPacketType", 0, 2, _quic_long_pkttyp),
            BitField("Reserved", 0, 2),
            QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        ]
        + QUIC_Version.fields_desc[2:7]
        + [
            QuicVarLenField("TokenLen", None, length_of="Token"),
            StrLenField("Token", "", length_from=lambda pkt: pkt.TokenLen),
            QuicVarIntField("Length", 0),
            QuicPacketNumberField("PacketNumber", 0),
        ]
    )


class QUIC_0RTT(QUIC):
    name = "QUIC - 0-RTT"
    LongPacketType = 1
    fields_desc = QUIC_Initial.fields_desc[:10] + [
        QuicVarIntField("Length", 0),
        QuicPacketNumberField("PacketNumber", 0),
    ]


class QUIC_Handshake(QUIC):
    name = "QUIC - Handshake"
    LongPacketType = 2
    fields_desc = QUIC_0RTT.fields_desc


class QUIC_Retry(QUIC):
    name = "QUIC - Retry"
    LongPacketType = 3
    Version = QUIC_VERSION_1
    fields_desc = (
        QUIC_Initial.fields_desc[:3]
        + [
            BitField("Unused", 0, 4),
        ]
        + QUIC_Version.fields_desc[2:7]
    )


class QUIC_1RTT(QUIC):
    name = "QUIC - 1-RTT"
    fields_desc = [
        BitEnumField("HeaderForm", 0, 1, _quic_long_hdr),
        BitField("FixedBit", 1, 1),
        BitField("SpinBit", 0, 1),
        BitField("Reserved", 0, 2),
        BitField("KeyPhase", 0, 1),
        QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        StrLenField(
            "DstConnID",
            "",
            length_from=lambda pkt: pkt.quic_session.dcid_len
            if pkt.quic_session is not None else 0,
        ),
        QuicPacketNumberField("PacketNumber", 0),
    ]


# -- Transport frames --


class QuicPaddingField(StrField):
    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, bytes]
        index = 0
        while index < len(s) and s[index] == 0:
            index += 1
        return s[index:], s[:index]


class QUIC_Frame(Packet):
    name = "QUIC Frame"

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            try:
                frame_type, _ = quic_decode_varint(_pkt)
            except ValueError:
                return QUIC_Unknown
            if 0x08 <= frame_type <= 0x0F:
                return QUIC_STREAM
            return _quic_frame_cls.get(frame_type, QUIC_Unknown)
        return QUIC_Unknown

    def extract_padding(self, s):
        return b"", s


class QUIC_PADDING(QUIC_Frame):
    name = "QUIC - PADDING"
    fields_desc = [
        ByteEnumField("FrameType", 0, _quic_payloads),
        QuicPaddingField("Padding", b""),
    ]


class QUIC_PING(QUIC_Frame):
    name = "QUIC - PING"
    fields_desc = [ByteEnumField("FrameType", 1, _quic_payloads)]


class QUIC_ACKRange(Packet):
    name = "QUIC - ACK Range"
    fields_desc = [
        QuicVarIntField("Gap", 0),
        QuicVarIntField("ACKRangeLength", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class QUIC_ACK(QUIC_Frame):
    name = "QUIC - ACK"
    fields_desc = [
        QuicVarEnumField("FrameType", 2, _quic_payloads),
        QuicVarIntField("LargestAcknowledged", 0),
        QuicVarIntField("ACKDelay", 0),
        QuicVarIntField("ACKRangeCount", 0),
        QuicVarIntField("FirstACKRange", 0),
        PacketListField(
            "ACKRanges",
            [],
            QUIC_ACKRange,
            count_from=lambda pkt: pkt.ACKRangeCount,
        ),
        ConditionalField(
            QuicVarIntField("ECT0Count", 0),
            lambda pkt: pkt.FrameType == 0x03,
        ),
        ConditionalField(
            QuicVarIntField("ECT1Count", 0),
            lambda pkt: pkt.FrameType == 0x03,
        ),
        ConditionalField(
            QuicVarIntField("ECNCEThreshold", 0),
            lambda pkt: pkt.FrameType == 0x03,
        ),
    ]


class QUIC_RESET_STREAM(QUIC_Frame):
    name = "QUIC - RESET_STREAM"
    fields_desc = [
        QuicVarEnumField("FrameType", 4, _quic_payloads),
        QuicVarIntField("StreamID", 0),
        QuicVarIntField("ApplicationErrorCode", 0),
        QuicVarIntField("FinalSize", 0),
    ]


class QUIC_STOP_SENDING(QUIC_Frame):
    name = "QUIC - STOP_SENDING"
    fields_desc = [
        QuicVarEnumField("FrameType", 5, _quic_payloads),
        QuicVarIntField("StreamID", 0),
        QuicVarIntField("ApplicationErrorCode", 0),
    ]


class QUIC_CRYPTO(QUIC_Frame):
    name = "QUIC - CRYPTO"
    fields_desc = [
        QuicVarEnumField("FrameType", 6, _quic_payloads),
        QuicVarIntField("Offset", 0),
        QuicVarLenField("Length", None, length_of="Data"),
        StrLenField("Data", b"", length_from=lambda pkt: pkt.Length),
    ]


class QUIC_NEW_TOKEN(QUIC_Frame):
    name = "QUIC - NEW_TOKEN"
    fields_desc = [
        QuicVarEnumField("FrameType", 7, _quic_payloads),
        QuicVarLenField("TokenLength", None, length_of="Token"),
        StrLenField("Token", b"", length_from=lambda pkt: pkt.TokenLength),
    ]


class QUIC_STREAM(QUIC_Frame):
    name = "QUIC - STREAM"
    fields_desc = [
        QuicVarEnumField("FrameType", 8, _quic_payloads),
        QuicVarIntField("StreamID", 0),
        ConditionalField(
            QuicVarIntField("Offset", 0),
            lambda pkt: bool(pkt.FrameType & 0x04),
        ),
        ConditionalField(
            QuicVarLenField("DataLength", None, length_of="Data"),
            lambda pkt: bool(pkt.FrameType & 0x02),
        ),
        StrLenField(
            "Data",
            b"",
            length_from=lambda pkt: pkt.DataLength if
            getattr(pkt, "DataLength", None) is not None else
            len(getattr(pkt, "original", b"")),
        ),
    ]


class QUIC_MAX_DATA(QUIC_Frame):
    name = "QUIC - MAX_DATA"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x10, _quic_payloads),
        QuicVarIntField("MaximumData", 0),
    ]


class QUIC_MAX_STREAM_DATA(QUIC_Frame):
    name = "QUIC - MAX_STREAM_DATA"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x11, _quic_payloads),
        QuicVarIntField("StreamID", 0),
        QuicVarIntField("MaximumStreamData", 0),
    ]


class QUIC_MAX_STREAMS(QUIC_Frame):
    name = "QUIC - MAX_STREAMS"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x12, _quic_payloads),
        QuicVarIntField("MaximumStreams", 0),
    ]


class QUIC_DATA_BLOCKED(QUIC_MAX_DATA):
    name = "QUIC - DATA_BLOCKED"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x14, _quic_payloads),
        QuicVarIntField("MaximumData", 0),
    ]


class QUIC_STREAM_DATA_BLOCKED(QUIC_MAX_STREAM_DATA):
    name = "QUIC - STREAM_DATA_BLOCKED"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x15, _quic_payloads),
        QuicVarIntField("StreamID", 0),
        QuicVarIntField("MaximumStreamData", 0),
    ]


class QUIC_STREAMS_BLOCKED(QUIC_MAX_STREAMS):
    name = "QUIC - STREAMS_BLOCKED"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x16, _quic_payloads),
        QuicVarIntField("MaximumStreams", 0),
    ]


class QUIC_NEW_CONNECTION_ID(QUIC_Frame):
    name = "QUIC - NEW_CONNECTION_ID"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x18, _quic_payloads),
        QuicVarIntField("SequenceNumber", 0),
        QuicVarIntField("RetirePriorTo", 0),
        FieldLenField("Length", None, length_of="ConnectionID", fmt="B"),
        StrLenField("ConnectionID", b"", length_from=lambda pkt: pkt.Length),
        StrFixedLenField("StatelessResetToken", b"\x00" * 16, length=16),
    ]


class QUIC_RETIRE_CONNECTION_ID(QUIC_Frame):
    name = "QUIC - RETIRE_CONNECTION_ID"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x19, _quic_payloads),
        QuicVarIntField("SequenceNumber", 0),
    ]


class QUIC_PATH_CHALLENGE(QUIC_Frame):
    name = "QUIC - PATH_CHALLENGE"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x1A, _quic_payloads),
        StrFixedLenField("Data", b"\x00" * 8, length=8),
    ]


class QUIC_PATH_RESPONSE(QUIC_Frame):
    name = "QUIC - PATH_RESPONSE"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x1B, _quic_payloads),
        StrFixedLenField("Data", b"\x00" * 8, length=8),
    ]


class QUIC_CONNECTION_CLOSE(QUIC_Frame):
    name = "QUIC - CONNECTION_CLOSE"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x1C, _quic_payloads),
        QuicVarIntField("ErrorCode", 0),
        ConditionalField(
            QuicVarIntField("TriggerFrameType", 0),
            lambda pkt: pkt.FrameType == 0x1C,
        ),
        QuicVarLenField("ReasonPhraseLength", None, length_of="ReasonPhrase"),
        StrLenField(
            "ReasonPhrase",
            b"",
            length_from=lambda pkt: pkt.ReasonPhraseLength,
        ),
    ]


class QUIC_HANDSHAKE_DONE(QUIC_Frame):
    name = "QUIC - HANDSHAKE_DONE"
    fields_desc = [QuicVarEnumField("FrameType", 0x1E, _quic_payloads)]


class QUIC_DATAGRAM(QUIC_Frame):
    name = "QUIC - DATAGRAM"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x30, _quic_payloads),
        ConditionalField(
            QuicVarLenField("Length", None, length_of="Data"),
            lambda pkt: pkt.FrameType == 0x31,
        ),
        StrLenField(
            "Data",
            b"",
            length_from=lambda pkt: pkt.Length
            if pkt.FrameType == 0x31
            else max(0, len(pkt.original) - 1),
        ),
    ]


class QUIC_Unknown(QUIC_Frame):
    name = "QUIC - Unknown"
    fields_desc = [
        QuicVarEnumField("FrameType", None, _quic_payloads),
        StrField("Data", b""),
    ]


_quic_frame_cls = {
    0x00: QUIC_PADDING,
    0x01: QUIC_PING,
    0x02: QUIC_ACK,
    0x03: QUIC_ACK,
    0x04: QUIC_RESET_STREAM,
    0x05: QUIC_STOP_SENDING,
    0x06: QUIC_CRYPTO,
    0x07: QUIC_NEW_TOKEN,
    0x10: QUIC_MAX_DATA,
    0x11: QUIC_MAX_STREAM_DATA,
    0x12: QUIC_MAX_STREAMS,
    0x13: QUIC_MAX_STREAMS,
    0x14: QUIC_DATA_BLOCKED,
    0x15: QUIC_STREAM_DATA_BLOCKED,
    0x16: QUIC_STREAMS_BLOCKED,
    0x17: QUIC_STREAMS_BLOCKED,
    0x18: QUIC_NEW_CONNECTION_ID,
    0x19: QUIC_RETIRE_CONNECTION_ID,
    0x1A: QUIC_PATH_CHALLENGE,
    0x1B: QUIC_PATH_RESPONSE,
    0x1C: QUIC_CONNECTION_CLOSE,
    0x1D: QUIC_CONNECTION_CLOSE,
    0x1E: QUIC_HANDSHAKE_DONE,
    0x30: QUIC_DATAGRAM,
    0x31: QUIC_DATAGRAM,
}


class QUIC_Frames(Packet):
    __slots__ = ["quic_session"]
    name = "QUIC Frames"
    fields_desc = [
        PacketListField(
            "frames",
            [],
            QUIC_Frame,
            length_from=lambda pkt: len(pkt.original),
        ),
    ]

    def __init__(self, *args, **kwargs):
        underlayer = kwargs.get("_underlayer")
        self.quic_session = getattr(underlayer, "quic_session", None)
        super(QUIC_Frames, self).__init__(*args, **kwargs)

    def post_dissect(self, s):
        if self.quic_session is None:
            return s
        is_client = self.quic_session.is_client_packet(self.underlayer)
        http3_packets = []
        for frame in self.frames:
            if isinstance(frame, QUIC_CRYPTO):
                self.quic_session.feed_crypto(
                    is_client, frame.Data, getattr(frame, "Offset", 0)
                )
            elif isinstance(frame, QUIC_STREAM):
                pkt = self.quic_session.feed_stream(
                    is_client,
                    frame.StreamID,
                    getattr(frame, "Offset", 0) or 0,
                    frame.Data,
                    bool(frame.FrameType & 0x01),
                )
                if pkt is not None:
                    http3_packets.append(pkt)
        for http3 in http3_packets:
            self.add_payload(http3)
        return b""


bind_layers(UDP, QUIC, sport=443)
bind_layers(UDP, QUIC, dport=443)
