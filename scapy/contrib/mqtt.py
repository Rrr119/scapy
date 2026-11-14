# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Santiago Hernandez Ramos <shramos@protonmail.com>

# scapy.contrib.description = Message Queuing Telemetry Transport (MQTT)
# scapy.contrib.status = loads

"""
MQTT (Message Queuing Telemetry Transport) layer.

Supports MQTT 3.1, 3.1.1 and 5.0 (RFC 9005). MQTT 5.0 packets carry a
properties field on CONNECT, CONNACK and PUBLISH (and the CONNECT will
payload). Each property is an :class:`MQTTProperty` whose value is decoded
according to its identifier: integers, length prefixed strings, binary data,
variable byte integers and UTF-8 string pairs.

Example, dissecting a MQTT 5.0 CONNECT packet::

    >>> from scapy.contrib.mqtt import MQTT, MQTT_PROP_RECEIVE_MAXIMUM
    >>> packet = MQTT(b"\\x10\\x10\\x00\\x04MQTT\\x05\\x02\\x00<"
    ...               b"\\x03\\x21\\x00\\x0a\\x00\\x00")
    >>> connect = packet[MQTTConnect]
    >>> connect.protolevel
    5
    >>> connect.properties[0].prop == MQTT_PROP_RECEIVE_MAXIMUM
    True
    >>> connect.properties[0].value
    10
    >>> connect.clientId
    b''

Building a MQTT 5.0 PUBLISH packet with a user property::

    >>> stream = (
    ...     MQTT() / MQTTConnect(protolevel=5, clientId="")
    ...     / MQTT() / MQTTPublish(
    ...         topic="sensors/temp",
    ...         value=b"21.5",
    ...         properties=[
    ...             MQTTProperty(prop=MQTT_PROP_USER_PROPERTY,
    ...                          value=(b"unit", b"celsius")),
    ...         ],
    ...     )
    ... )
    >>> MQTT(raw(stream))[MQTTPublish].properties[0].value
    (b'unit', b'celsius')
"""

import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitEnumField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    IntField,
    LongField,
    MultipleTypeField,
    PacketListField,
    ShortField,
    StrLenField,
)
from scapy.layers.inet import TCP
from scapy.error import Scapy_Exception
from scapy.compat import chb, raw
from scapy.volatile import RandNum
from scapy.config import conf


# CUSTOM FIELDS
# source: http://stackoverflow.com/a/43717630
class VariableFieldLenField(FieldLenField):
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        data = []
        while val:
            if val > 127:
                data.append(val & 127)
                val //= 128
            else:
                data.append(val)
                lastoffset = len(data) - 1
                data = b"".join(chb(val | (0 if i == lastoffset else 128))
                                for i, val in enumerate(data))
                return s + data
            if len(data) > 3:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)
        # If val is None / 0
        return s + b"\x00"

    def getfield(self, pkt, s):
        value = 0
        for offset, curbyte in enumerate(s):
            curbyte = curbyte
            value += (curbyte & 127) * (128 ** offset)
            if curbyte & 128 == 0:
                return s[offset + 1:], value
            if offset > 2:
                raise Scapy_Exception("%s: malformed length field" %
                                      self.__class__.__name__)

    def randval(self):
        return RandVariableFieldLen()


class RandVariableFieldLen(RandNum):
    def __init__(self):
        RandNum.__init__(self, 0, 268435455)


class VarIntField(ByteField):
    """MQTT 5.0 variable byte integer field (RFC 9005 section 1.5.5)."""

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        data = b""
        while True:
            curbyte = val % 128
            val //= 128
            if val > 0:
                curbyte |= 128
            data += struct.pack("!B", curbyte)
            if val == 0:
                break
        return s + data

    def getfield(self, pkt, s):
        value = 0
        for offset, curbyte in enumerate(s[:4]):
            value += (curbyte & 127) * (128 ** offset)
            if curbyte & 128 == 0:
                return s[offset + 1:], value
        raise Scapy_Exception("VarIntField: malformed variable byte integer")


class MQTTStringField(StrLenField):
    """MQTT UTF-8 encoded string, prefixed with a two byte length."""

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        return s + struct.pack("!H", len(val)) + val

    def getfield(self, pkt, s):
        if len(s) < 2:
            raise Scapy_Exception("MQTTStringField: truncated string length")
        slen = struct.unpack("!H", s[:2])[0]
        if len(s) < 2 + slen:
            raise Scapy_Exception("MQTTStringField: truncated string value")
        return s[2 + slen:], self.m2i(pkt, s[2:2 + slen])


class MQTTBinaryField(MQTTStringField):
    """MQTT binary data, prefixed with a two byte length."""


class MQTTStringPairField(StrLenField):
    """MQTT user property: two length-prefixed UTF-8 strings (name, value)."""

    def addfield(self, pkt, s, val):
        name, value = val
        name = self.i2m(pkt, name)
        value = self.i2m(pkt, value)
        return (
            s
            + struct.pack("!H", len(name)) + name
            + struct.pack("!H", len(value)) + value
        )

    def getfield(self, pkt, s):
        remain, name = MQTTStringField("", b"").getfield(pkt, s)
        remain, value = MQTTStringField("", b"").getfield(pkt, remain)
        return remain, (name, value)


# LAYERS
CONTROL_PACKET_TYPE = {
    1: 'CONNECT',
    2: 'CONNACK',
    3: 'PUBLISH',
    4: 'PUBACK',
    5: 'PUBREC',
    6: 'PUBREL',
    7: 'PUBCOMP',
    8: 'SUBSCRIBE',
    9: 'SUBACK',
    10: 'UNSUBSCRIBE',
    11: 'UNSUBACK',
    12: 'PINGREQ',
    13: 'PINGRESP',
    14: 'DISCONNECT',
    15: 'AUTH'  # Added in v5.0
}


QOS_LEVEL = {
    0: 'At most once delivery',
    1: 'At least once delivery',
    2: 'Exactly once delivery'
}


# source: http://stackoverflow.com/a/43722441
class MQTT(Packet):
    name = "MQTT fixed header"
    fields_desc = [
        BitEnumField("type", 1, 4, CONTROL_PACKET_TYPE),
        BitEnumField("DUP", 0, 1, {0: 'Disabled',
                                   1: 'Enabled'}),
        BitEnumField("QOS", 0, 2, QOS_LEVEL),
        BitEnumField("RETAIN", 0, 1, {0: 'Disabled',
                                      1: 'Enabled'}),
        # Since the size of the len field depends on the next layer, we need
        # to "cheat" with the length_of parameter and use adjust parameter to
        # calculate the value.
        VariableFieldLenField("len", None, length_of="len",
                              adjust=lambda pkt, x: len(pkt.payload),),
    ]


PROTOCOL_LEVEL = {
    3: 'v3.1',
    4: 'v3.1.1',
    5: 'v5.0'
}


# MQTT 5.0 property identifiers (RFC 9005 section 2.2.2.2)
MQTT_PROP_PAYLOAD_FORMAT_INDICATOR = 0x01
MQTT_PROP_MESSAGE_EXPIRY_INTERVAL = 0x02
MQTT_PROP_CONTENT_TYPE = 0x03
MQTT_PROP_RESPONSE_TOPIC = 0x08
MQTT_PROP_CORRELATION_DATA = 0x09
MQTT_PROP_SUBSCRIPTION_IDENTIFIER = 0x0B
MQTT_PROP_SESSION_EXPIRY_INTERVAL = 0x11
MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER = 0x12
MQTT_PROP_SERVER_KEEP_ALIVE = 0x13
MQTT_PROP_AUTHENTICATION_METHOD = 0x15
MQTT_PROP_AUTHENTICATION_DATA = 0x16
MQTT_PROP_REQUEST_PROBLEM_INFORMATION = 0x17
MQTT_PROP_WILL_DELAY_INTERVAL = 0x18
MQTT_PROP_REQUEST_RESPONSE_INFORMATION = 0x19
MQTT_PROP_RESPONSE_INFORMATION = 0x1A
MQTT_PROP_SERVER_REFERENCE = 0x1C
MQTT_PROP_REASON_STRING = 0x1F
MQTT_PROP_RECEIVE_MAXIMUM = 0x21
MQTT_PROP_TOPIC_ALIAS_MAXIMUM = 0x22
MQTT_PROP_TOPIC_ALIAS = 0x23
MQTT_PROP_MAXIMUM_QOS = 0x24
MQTT_PROP_RETAIN_AVAILABLE = 0x25
MQTT_PROP_USER_PROPERTY = 0x26
MQTT_PROP_MAXIMUM_PACKET_SIZE = 0x27
MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE = 0x28
MQTT_PROP_SUBSCRIPTION_IDENTIFIERS_AVAILABLE = 0x29
MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE = 0x2A

MQTT_PROPERTY_IDENTIFIERS = {
    MQTT_PROP_PAYLOAD_FORMAT_INDICATOR: 'payload format indicator',
    MQTT_PROP_MESSAGE_EXPIRY_INTERVAL: 'message expiry interval',
    MQTT_PROP_CONTENT_TYPE: 'content type',
    MQTT_PROP_RESPONSE_TOPIC: 'response topic',
    MQTT_PROP_CORRELATION_DATA: 'correlation data',
    MQTT_PROP_SUBSCRIPTION_IDENTIFIER: 'subscription identifier',
    MQTT_PROP_SESSION_EXPIRY_INTERVAL: 'session expiry interval',
    MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER: 'assigned client identifier',
    MQTT_PROP_SERVER_KEEP_ALIVE: 'server keep alive',
    MQTT_PROP_AUTHENTICATION_METHOD: 'authentication method',
    MQTT_PROP_AUTHENTICATION_DATA: 'authentication data',
    MQTT_PROP_REQUEST_PROBLEM_INFORMATION: 'request problem information',
    MQTT_PROP_WILL_DELAY_INTERVAL: 'will delay interval',
    MQTT_PROP_REQUEST_RESPONSE_INFORMATION: 'request response information',
    MQTT_PROP_RESPONSE_INFORMATION: 'response information',
    MQTT_PROP_SERVER_REFERENCE: 'server reference',
    MQTT_PROP_REASON_STRING: 'reason string',
    MQTT_PROP_RECEIVE_MAXIMUM: 'receive maximum',
    MQTT_PROP_TOPIC_ALIAS_MAXIMUM: 'topic alias maximum',
    MQTT_PROP_TOPIC_ALIAS: 'topic alias',
    MQTT_PROP_MAXIMUM_QOS: 'maximum QoS',
    MQTT_PROP_RETAIN_AVAILABLE: 'retain available',
    MQTT_PROP_USER_PROPERTY: 'user property',
    MQTT_PROP_MAXIMUM_PACKET_SIZE: 'maximum packet size',
    MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE:
        'wildcard subscription available',
    MQTT_PROP_SUBSCRIPTION_IDENTIFIERS_AVAILABLE:
        'subscription identifiers available',
    MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE: 'shared subscription available',
}

# Value kind associated with every property identifier
MQTT_PROPERTY_TYPES = {
    MQTT_PROP_PAYLOAD_FORMAT_INDICATOR: 'byte',
    MQTT_PROP_MESSAGE_EXPIRY_INTERVAL: 'int',
    MQTT_PROP_CONTENT_TYPE: 'string',
    MQTT_PROP_RESPONSE_TOPIC: 'string',
    MQTT_PROP_CORRELATION_DATA: 'binary',
    MQTT_PROP_SUBSCRIPTION_IDENTIFIER: 'varint',
    MQTT_PROP_SESSION_EXPIRY_INTERVAL: 'int',
    MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER: 'string',
    MQTT_PROP_SERVER_KEEP_ALIVE: 'short',
    MQTT_PROP_AUTHENTICATION_METHOD: 'string',
    MQTT_PROP_AUTHENTICATION_DATA: 'binary',
    MQTT_PROP_REQUEST_PROBLEM_INFORMATION: 'byte',
    MQTT_PROP_WILL_DELAY_INTERVAL: 'int',
    MQTT_PROP_REQUEST_RESPONSE_INFORMATION: 'byte',
    MQTT_PROP_RESPONSE_INFORMATION: 'string',
    MQTT_PROP_SERVER_REFERENCE: 'string',
    MQTT_PROP_REASON_STRING: 'string',
    MQTT_PROP_RECEIVE_MAXIMUM: 'short',
    MQTT_PROP_TOPIC_ALIAS_MAXIMUM: 'short',
    MQTT_PROP_TOPIC_ALIAS: 'short',
    MQTT_PROP_MAXIMUM_QOS: 'byte',
    MQTT_PROP_RETAIN_AVAILABLE: 'byte',
    MQTT_PROP_USER_PROPERTY: 'pair',
    MQTT_PROP_MAXIMUM_PACKET_SIZE: 'long',
    MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE: 'byte',
    MQTT_PROP_SUBSCRIPTION_IDENTIFIERS_AVAILABLE: 'byte',
    MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE: 'byte',
}


def mqtt_property_value_field(prop_id):
    """Build the field holding the value of a property of the given id."""
    prop_type = MQTT_PROPERTY_TYPES.get(prop_id)
    if prop_type == 'byte':
        return ByteField("value", 0)
    if prop_type == 'short':
        return ShortField("value", 0)
    if prop_type == 'int':
        return IntField("value", 0)
    if prop_type == 'long':
        return LongField("value", 0)
    if prop_type == 'varint':
        return VarIntField("value", 0)
    if prop_type == 'binary':
        return MQTTBinaryField("value", b"")
    if prop_type == 'pair':
        return MQTTStringPairField("value", (b"", b""))
    # 'string' and unknown identifiers are dissected as length-prefixed data
    return MQTTStringField("value", b"")


class MQTTProperty(Packet):
    """A single MQTT 5.0 property (identifier plus typed value)."""

    name = "MQTT property"
    fields_desc = [
        ByteEnumField("prop", 0, MQTT_PROPERTY_IDENTIFIERS),
        MQTTStringField("value", b""),
    ]

    _property_classes = {}

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            prop_id = _pkt[0]
            if prop_id not in cls._property_classes:
                cls._property_classes[prop_id] = type(
                    "MQTTProperty_%d" % prop_id,
                    (cls,),
                    {"fields_desc": [
                        ByteEnumField(
                            "prop",
                            prop_id,
                            MQTT_PROPERTY_IDENTIFIERS
                        ),
                        mqtt_property_value_field(prop_id),
                    ]},
                )
            return cls._property_classes[prop_id]
        return cls

    def self_build(self):
        prop_id = self.fields.get("prop", self.fields_desc[0].default)
        value = self.fields.get(
            "value",
            mqtt_property_value_field(prop_id).default
        )
        value_field = mqtt_property_value_field(prop_id)
        return (
            self.fields_desc[0].addfield(self, b"", prop_id)
            + value_field.addfield(self, b"", value)
        )

    def extract_padding(self, s):
        return b"", s


class MQTTPropertiesField(PacketListField):
    """Length prefixed list of MQTT 5.0 properties."""

    __slots__ = ["proplen"]

    def __init__(self, name, default):
        self.proplen = VarIntField(name + "_len", None)
        super(MQTTPropertiesField, self).__init__(
            name,
            default,
            pkt_cls=MQTTProperty,
        )

    def i2m(self, pkt, val):
        if val is None:
            val = []
        return val

    def addfield(self, pkt, s, val):
        props = val or []
        data = b"".join(raw(item) for item in props)
        return s + self.proplen.addfield(pkt, b"", len(data)) + data

    def getfield(self, pkt, s):
        remain, proplen = self.proplen.getfield(pkt, s)
        if len(remain) < proplen:
            raise Scapy_Exception(
                "MQTTPropertiesField: truncated properties (got %d bytes, "
                "expected %d)" % (len(remain), proplen)
            )
        props_bytes = remain[:proplen]
        props = []
        while props_bytes:
            prop_id = props_bytes[0]
            prop_cls = MQTTProperty.dispatch_hook(_pkt=props_bytes)
            prop = prop_cls()
            props_bytes = props_bytes[1:]
            value_field = prop_cls.fields_desc[1]
            props_bytes, value = value_field.getfield(prop, props_bytes)
            prop.fields["prop"] = prop_id
            prop.fields["value"] = value
            props.append(prop)
        return remain[proplen:], props


class MQTTConnect(Packet):
    name = "MQTT connect"
    fields_desc = [
        FieldLenField("length", None, length_of="protoname"),
        StrLenField("protoname", "",
                    length_from=lambda pkt: pkt.length),
        ByteEnumField("protolevel", 5, PROTOCOL_LEVEL),
        BitEnumField("usernameflag", 0, 1, {0: 'Disabled',
                                            1: 'Enabled'}),
        BitEnumField("passwordflag", 0, 1, {0: 'Disabled',
                                            1: 'Enabled'}),
        BitEnumField("willretainflag", 0, 1, {0: 'Disabled',
                                              1: 'Enabled'}),
        BitEnumField("willQOSflag", 0, 2, QOS_LEVEL),
        BitEnumField("willflag", 0, 1, {0: 'Disabled',
                                        1: 'Enabled'}),
        BitEnumField("cleansess", 0, 1, {0: 'Disabled',
                                         1: 'Enabled'}),
        BitEnumField("reserved", 0, 1, {0: 'Disabled',
                                        1: 'Enabled'}),
        ShortField("klive", 0),
        # MQTT 5.0 only: connect properties
        ConditionalField(MQTTPropertiesField("properties", []),
                         lambda pkt: pkt.protolevel == 5),
        FieldLenField("clientIdlen", None, length_of="clientId"),
        StrLenField("clientId", "",
                    length_from=lambda pkt: pkt.clientIdlen),
        # Payload with optional fields depending on the flags
        # MQTT 5.0 only: will properties come before the will payload
        ConditionalField(MQTTPropertiesField("willproperties", []),
                         lambda pkt: pkt.protolevel == 5 and
                         pkt.willflag == 1),
        ConditionalField(FieldLenField("wtoplen", None, length_of="willtopic"),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(StrLenField("willtopic", "",
                                     length_from=lambda pkt: pkt.wtoplen),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(FieldLenField("wmsglen", None, length_of="willmsg"),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(StrLenField("willmsg", "",
                                     length_from=lambda pkt: pkt.wmsglen),
                         lambda pkt: pkt.willflag == 1),
        ConditionalField(FieldLenField("userlen", None, length_of="username"),
                         lambda pkt: pkt.usernameflag == 1),
        ConditionalField(StrLenField("username", "",
                                     length_from=lambda pkt: pkt.userlen),
                         lambda pkt: pkt.usernameflag == 1),
        ConditionalField(FieldLenField("passlen", None, length_of="password"),
                         lambda pkt: pkt.passwordflag == 1),
        ConditionalField(StrLenField("password", "",
                                     length_from=lambda pkt: pkt.passlen),
                         lambda pkt: pkt.passwordflag == 1),
    ]


class MQTTDisconnect(Packet):
    name = "MQTT disconnect"
    fields_desc = []


RETURN_CODE = {
    0: 'Connection Accepted',
    1: 'Unacceptable protocol version',
    2: 'Identifier rejected',
    3: 'Server unavailable',
    4: 'Bad username/password',
    5: 'Not authorized'
}


MQTT5_REASON_CODE = {
    0x00: 'Success',
    0x80: 'Unspecified error',
    0x81: 'Malformed Packet',
    0x82: 'Protocol Error',
    0x83: 'Implementation specific error',
    0x84: 'Unsupported Protocol Version',
    0x85: 'Client Identifier not valid',
    0x86: 'Bad User Name or Password',
    0x87: 'Not authorized',
    0x88: 'Server unavailable',
    0x89: 'Server busy',
    0x8A: 'Banned',
    0x8C: 'Bad authentication method',
    0x90: 'Topic Name invalid',
    0x95: 'Packet too large',
    0x97: 'Quota exceeded',
    0x99: 'Payload format invalid',
    0x9A: 'Retain not supported',
    0x9B: 'QoS not supported',
    0x9C: 'Use another server',
    0x9D: 'Server moved',
    0x9F: 'Connection rate exceeded',
}


def mqtt_connack_is_v5(pkt):
    """A CONNACK packet carries a reason code and properties on MQTT 5.0.

    During dissection the fixed header length is available; while building a
    packet with properties the length is still computed, so the presence of the
    properties field is used instead.
    """
    if pkt.fields.get("properties"):
        return True
    underlayer = pkt.underlayer
    return (
        underlayer is not None
        and underlayer.fields.get("len") is not None
        and underlayer.len >= 3
    )


class MQTTConnack(Packet):
    name = "MQTT connack"
    fields_desc = [
        ByteField("sessPresentFlag", 0),
        MultipleTypeField(
            [
                (ByteEnumField("retcode", 0, MQTT5_REASON_CODE),
                 mqtt_connack_is_v5),
            ],
            ByteEnumField("retcode", 0, RETURN_CODE),
        ),
        ConditionalField(MQTTPropertiesField("properties", []),
                         mqtt_connack_is_v5),
        # this package has not payload
    ]


def mqtt_publish_is_v5(pkt):
    """A PUBLISH packet carries properties only when the session uses MQTT 5.

    The version is not present in the PUBLISH packet itself, so it is taken
    from the CONNECT/CONNACK packet recorded on the same MQTT stack.
    """
    layer = pkt
    while layer is not None:
        connect = layer.getlayer(MQTTConnect)
        if connect is not None:
            return connect.protolevel == 5
        layer = layer.underlayer
    return False


def mqtt_publish_value_len(pkt):
    if pkt.underlayer is None:
        return 0
    fixed_overhead = pkt.length + 2
    if pkt.underlayer.QOS in (1, 2):
        fixed_overhead += 2
    if mqtt_publish_is_v5(pkt):
        prop_field = pkt.fieldtype["properties"]
        fixed_overhead += len(prop_field.addfield(pkt, b"", pkt.properties))
    remaining = pkt.underlayer.len - fixed_overhead
    return remaining if remaining > 0 else 0


class MQTTPublish(Packet):
    name = "MQTT publish"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "",
                    length_from=lambda pkt: pkt.length),
        ConditionalField(ShortField("msgid", None),
                         lambda pkt: pkt.underlayer is not None and
                         pkt.underlayer.QOS in (1, 2)),
        ConditionalField(MQTTPropertiesField("properties", []),
                         mqtt_publish_is_v5),
        StrLenField("value", "",
                    length_from=mqtt_publish_value_len)
    ]


class MQTTPuback(Packet):
    name = "MQTT puback"
    fields_desc = [
        ShortField("msgid", None),
    ]


class MQTTPubrec(Packet):
    name = "MQTT pubrec"
    fields_desc = [
        ShortField("msgid", None),
    ]


class MQTTPubrel(Packet):
    name = "MQTT pubrel"
    fields_desc = [
        ShortField("msgid", None),
    ]


class MQTTPubcomp(Packet):
    name = "MQTT pubcomp"
    fields_desc = [
        ShortField("msgid", None),
    ]


class MQTTTopic(Packet):
    name = "MQTT topic"
    fields_desc = [
        FieldLenField("length", None, length_of="topic"),
        StrLenField("topic", "", length_from=lambda pkt:pkt.length)
    ]

    def guess_payload_class(self, payload):
        return conf.padding_layer


class MQTTTopicQOS(MQTTTopic):
    fields_desc = MQTTTopic.fields_desc + [ByteEnumField("QOS", 0, QOS_LEVEL)]


class MQTTSubscribe(Packet):
    name = "MQTT subscribe"
    fields_desc = [
        ShortField("msgid", None),
        PacketListField("topics", [], pkt_cls=MQTTTopicQOS)
    ]


ALLOWED_RETURN_CODE = {
    0x00: 'Granted QoS 0',
    0x01: 'Granted QoS 1',
    0x02: 'Granted QoS 2',
    0x80: 'Unspecified error',
    0x83: 'Implementation specific error',
    0x87: 'Not authorized',
    0x8F: 'Topic Filter invalid',
    0x91: 'Packet Identifier in use',
    0x97: 'Quota exceeded',
    0x9E: 'Shared Subscriptions not supported',
    0xA1: 'Subscription Identifiers not supported',
    0xA2: 'Wildcard Subscriptions not supported',
}


class MQTTSuback(Packet):
    name = "MQTT suback"
    fields_desc = [
        ShortField("msgid", None),
        FieldListField("retcodes", None, ByteEnumField("", None, ALLOWED_RETURN_CODE))
    ]


class MQTTUnsubscribe(Packet):
    name = "MQTT unsubscribe"
    fields_desc = [
        ShortField("msgid", None),
        PacketListField("topics", [], pkt_cls=MQTTTopic)
    ]


class MQTTUnsuback(Packet):
    name = "MQTT unsuback"
    fields_desc = [
        ShortField("msgid", None)
    ]


# LAYERS BINDINGS

bind_layers(TCP, MQTT, sport=1883)
bind_layers(TCP, MQTT, dport=1883)
bind_layers(MQTT, MQTTConnect, type=1)
bind_layers(MQTT, MQTTConnack, type=2)
bind_layers(MQTT, MQTTPublish, type=3)
bind_layers(MQTT, MQTTPuback, type=4)
bind_layers(MQTT, MQTTPubrec, type=5)
bind_layers(MQTT, MQTTPubrel, type=6)
bind_layers(MQTT, MQTTPubcomp, type=7)
bind_layers(MQTT, MQTTSubscribe, type=8)
bind_layers(MQTT, MQTTSuback, type=9)
bind_layers(MQTT, MQTTUnsubscribe, type=10)
bind_layers(MQTT, MQTTUnsuback, type=11)
bind_layers(MQTT, MQTTDisconnect, type=14)
bind_layers(MQTTConnect, MQTT)
bind_layers(MQTTConnack, MQTT)
bind_layers(MQTTPublish, MQTT)
bind_layers(MQTTPuback, MQTT)
bind_layers(MQTTPubrec, MQTT)
bind_layers(MQTTPubrel, MQTT)
bind_layers(MQTTPubcomp, MQTT)
bind_layers(MQTTSubscribe, MQTT)
bind_layers(MQTTSuback, MQTT)
bind_layers(MQTTUnsubscribe, MQTT)
bind_layers(MQTTUnsuback, MQTT)
bind_layers(MQTTDisconnect, MQTT)
