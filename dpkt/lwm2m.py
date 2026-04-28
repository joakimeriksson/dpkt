# -*- coding: utf-8 -*-
"""Lightweight Machine to Machine (LWM2M) Protocol."""
from __future__ import print_function
from __future__ import absolute_import

import struct
from . import dpkt
from .compat import compat_ord

# LWM2M Standard Object IDs (OMA)
LWM2M_OBJ_SECURITY = 0
LWM2M_OBJ_SERVER = 1
LWM2M_OBJ_ACCESS_CONTROL = 2
LWM2M_OBJ_DEVICE = 3
LWM2M_OBJ_CONN_MONITOR = 4
LWM2M_OBJ_FIRMWARE_UPDATE = 5
LWM2M_OBJ_LOCATION = 6
LWM2M_OBJ_CONN_STATS = 7

# LWM2M Device Object Resources (Object ID 3)
LWM2M_DEV_MANUFACTURER = 0
LWM2M_DEV_MODEL_NUMBER = 1
LWM2M_DEV_SERIAL_NUMBER = 2
LWM2M_DEV_FIRMWARE_VERSION = 3
LWM2M_DEV_REBOOT = 4
LWM2M_DEV_FACTORY_RESET = 5
LWM2M_DEV_AVAILABLE_POWER_SOURCES = 6
LWM2M_DEV_POWER_SOURCE_VOLTAGE = 7
LWM2M_DEV_POWER_SOURCE_CURRENT = 8
LWM2M_DEV_BATTERY_LEVEL = 9
LWM2M_DEV_MEMORY_FREE = 10
LWM2M_DEV_ERROR_CODE = 11
LWM2M_DEV_RESET_ERROR_CODE = 12
LWM2M_DEV_CURRENT_TIME = 13
LWM2M_DEV_UTC_OFFSET = 14
LWM2M_DEV_TIMEZONE = 15
LWM2M_DEV_SUPPORTED_BINDING = 16

# TLV Type IDs (top two bits of the TLV type byte)
LWM2M_TLV_OBJECT_INSTANCE = 0x00     # 00
LWM2M_TLV_RESOURCE_INSTANCE = 0x40   # 01
LWM2M_TLV_MULTIPLE_RESOURCE = 0x80   # 10
LWM2M_TLV_RESOURCE = 0xC0            # 11


class LWM2M(object):
    """LWM2M Protocol namespace (OMA Lightweight M2M).

    LwM2M payloads ride inside CoAP, so this class is a logical
    namespace rather than a wire-level packet. It groups:

    * an abstract data model — :class:`LWM2M.Resource`,
      :class:`LWM2M.ObjectInstance`
    * supported wire formats — :class:`LWM2M.TLV` (more to come)
    * format dispatch — :meth:`LWM2M.encode`, :meth:`LWM2M.decode`

    The data model lets callers construct an LwM2M payload once and
    serialize it to whichever format the peer asked for, and decode any
    incoming payload back to the same uniform shape.
    """

    # ---------------------------------------------------------------- formats

    class ContentFormat(object):
        """CoAP Content-Format option values for LWM2M payloads."""
        TEXT = 0
        OPAQUE = 42
        TLV = 11542
        JSON = 11543
        SENML_JSON = 110
        SENML_CBOR = 112
        LWM2M_CBOR = 11544

    # ---------------------------------------------------------- data model

    class Resource(object):
        """LwM2M Resource — a single value or a multi-instance value-set.

        For a single-instance Resource, set ``value`` and leave
        ``instances`` as ``None``. For a multi-instance Resource, set
        ``instances`` to a dict mapping ``instance_id`` → value.
        """

        def __init__(self, id, value=None, instances=None):
            self.id = id
            self.value = value
            self.instances = instances

        @property
        def is_multi(self):
            return self.instances is not None

        def __repr__(self):
            if self.is_multi:
                return 'Resource(id=%d, instances=%r)' % (self.id, self.instances)
            return 'Resource(id=%d, value=%r)' % (self.id, self.value)

        def __eq__(self, other):
            return (isinstance(other, LWM2M.Resource)
                    and self.id == other.id
                    and self.value == other.value
                    and self.instances == other.instances)

    class ObjectInstance(object):
        """LwM2M Object Instance — an ordered set of Resources."""

        def __init__(self, id=0, resources=None):
            self.id = id
            self.resources = list(resources or [])

        def __repr__(self):
            return 'ObjectInstance(id=%d, resources=%r)' % (self.id, self.resources)

        def __eq__(self, other):
            return (isinstance(other, LWM2M.ObjectInstance)
                    and self.id == other.id
                    and self.resources == other.resources)

    # --------------------------------------------------------- wire formats

    class TLV(dpkt.Packet):
        """LWM2M Binary TLV Format. OMA LwM2M v1.0, Section 6.3.3.

        Attributes:
            type (int): TLV Type (Object Instance, Resource, etc.)
            id (int): Identifier (8 or 16 bits)
            value (bytes): Value
        """

        def __init__(self, *args, **kwargs):
            self.type = 0
            self.id = 0
            self.value = b''
            super(LWM2M.TLV, self).__init__(*args, **kwargs)

        def unpack(self, buf):
            if not buf:
                raise dpkt.NeedData('empty TLV')

            type_byte = compat_ord(buf[0])
            self.type = type_byte & 0xC0  # bits 7-6
            id_len = (type_byte & 0x20) >> 5  # bit 5: 0=8bit, 1=16bit
            length_type = (type_byte & 0x18) >> 3  # bits 4-3
            val_len = type_byte & 0x07  # bits 2-0: value length if length_type=00

            off = 1

            if id_len == 0:
                if off >= len(buf): raise dpkt.NeedData()
                self.id = compat_ord(buf[off])
                off += 1
            else:
                if off + 2 > len(buf): raise dpkt.NeedData()
                self.id = struct.unpack('>H', buf[off:off+2])[0]
                off += 2

            if length_type == 1:
                if off >= len(buf): raise dpkt.NeedData()
                val_len = compat_ord(buf[off])
                off += 1
            elif length_type == 2:
                if off + 2 > len(buf): raise dpkt.NeedData()
                val_len = struct.unpack('>H', buf[off:off+2])[0]
                off += 2
            elif length_type == 3:
                if off + 3 > len(buf): raise dpkt.NeedData()
                val_len = struct.unpack('>I', b'\x00' + buf[off:off+3])[0]
                off += 3

            if off + val_len > len(buf):
                raise dpkt.NeedData('short TLV value')

            self.value = buf[off:off+val_len]
            self.data = buf[off+val_len:]

        def __bytes__(self):
            id_bit = 0x20 if self.id > 255 else 0x00

            val_len = len(self.value)
            if val_len < 8:
                len_type = 0x00
                len_bits = val_len
                len_field = b''
            elif val_len < 256:
                len_type = 0x08
                len_bits = 0
                len_field = struct.pack('B', val_len)
            elif val_len < 65536:
                len_type = 0x10
                len_bits = 0
                len_field = struct.pack('>H', val_len)
            else:
                len_type = 0x18
                len_bits = 0
                len_field = struct.pack('>I', val_len)[1:]

            type_byte = self.type | id_bit | len_type | len_bits
            res = struct.pack('B', type_byte)

            if id_bit:
                res += struct.pack('>H', self.id)
            else:
                res += struct.pack('B', self.id)

            res += len_field
            res += self.value
            return res

        def __len__(self):
            return len(bytes(self))

    # ---------------------------------------------------------- dispatch

    @staticmethod
    def encode(obj, content_format, base_path=''):
        """Encode a Resource / ObjectInstance / list to wire bytes.

        ``base_path`` is reserved for self-describing formats and is
        ignored by the TLV codec. Only :data:`LWM2M.ContentFormat.TLV`
        is implemented today.
        """
        if content_format == LWM2M.ContentFormat.TLV:
            return _encode_tlv(obj)
        raise NotImplementedError(
            'LWM2M content format %r is not implemented' % content_format)

    @staticmethod
    def decode(buf, content_format, base_path=''):
        """Decode wire bytes to data-model objects.

        Returns a single :class:`LWM2M.ObjectInstance` or
        :class:`LWM2M.Resource` when the payload describes one;
        otherwise a list. For TLV, decoded ``Resource.value`` fields
        are raw ``bytes`` (TLV is not self-describing — apply your
        Object schema to interpret them).
        """
        if content_format == LWM2M.ContentFormat.TLV:
            return _decode_tlv(buf)
        raise NotImplementedError(
            'LWM2M content format %r is not implemented' % content_format)


# ============================================================ TLV codec

def _encode_tlv_value(v):
    """Encode a Python value into the bytes of a TLV value field."""
    if isinstance(v, bytes):
        return v
    if isinstance(v, bool):  # check before int — bool is a subclass of int
        return b'\x01' if v else b'\x00'
    if isinstance(v, int):
        if -128 <= v <= 127:
            return struct.pack('>b', v)
        if -32768 <= v <= 32767:
            return struct.pack('>h', v)
        if -2147483648 <= v <= 2147483647:
            return struct.pack('>i', v)
        return struct.pack('>q', v)
    if isinstance(v, float):
        return struct.pack('>d', v)
    if isinstance(v, str):
        return v.encode('utf-8')
    raise TypeError('cannot encode TLV value of type %s' % type(v).__name__)


def _resource_to_tlv(res):
    if res.is_multi:
        body = b''
        for inst_id in sorted(res.instances):
            inner = LWM2M.TLV(type=LWM2M_TLV_RESOURCE_INSTANCE,
                              id=inst_id,
                              value=_encode_tlv_value(res.instances[inst_id]))
            body += bytes(inner)
        return LWM2M.TLV(type=LWM2M_TLV_MULTIPLE_RESOURCE, id=res.id, value=body)
    return LWM2M.TLV(type=LWM2M_TLV_RESOURCE, id=res.id,
                     value=_encode_tlv_value(res.value))


def _encode_tlv(obj):
    if isinstance(obj, LWM2M.Resource):
        return bytes(_resource_to_tlv(obj))
    if isinstance(obj, LWM2M.ObjectInstance):
        body = b''.join(bytes(_resource_to_tlv(r)) for r in obj.resources)
        return bytes(LWM2M.TLV(type=LWM2M_TLV_OBJECT_INSTANCE, id=obj.id, value=body))
    if isinstance(obj, (list, tuple)):
        return b''.join(_encode_tlv(item) for item in obj)
    raise TypeError('cannot encode %s as TLV' % type(obj).__name__)


def _tlv_to_model(tlv):
    if tlv.type == LWM2M_TLV_RESOURCE:
        return LWM2M.Resource(id=tlv.id, value=tlv.value)
    if tlv.type == LWM2M_TLV_RESOURCE_INSTANCE:
        return LWM2M.Resource(id=tlv.id, value=tlv.value)
    if tlv.type == LWM2M_TLV_MULTIPLE_RESOURCE:
        instances = {}
        buf = tlv.value
        while buf:
            inner = LWM2M.TLV(buf)
            instances[inner.id] = inner.value
            buf = inner.data
        return LWM2M.Resource(id=tlv.id, instances=instances)
    if tlv.type == LWM2M_TLV_OBJECT_INSTANCE:
        children = []
        buf = tlv.value
        while buf:
            child = LWM2M.TLV(buf)
            children.append(_tlv_to_model(child))
            buf = child.data
        return LWM2M.ObjectInstance(id=tlv.id, resources=children)
    raise ValueError('unknown TLV type 0x%02x' % tlv.type)


def _decode_tlv(buf):
    items = []
    while buf:
        tlv = LWM2M.TLV(buf)
        items.append(_tlv_to_model(tlv))
        buf = tlv.data
    if len(items) == 1:
        return items[0]
    return items


# ================================================================ tests

def test_lwm2m():
    from binascii import unhexlify
    CF = LWM2M.ContentFormat

    # ---- TLV: low-level wire round-trip ------------------------------
    # OMA spec example: Resource 5850 (Switch) = True (0x01)
    buf = unhexlify('e116da01')
    tlv = LWM2M.TLV(buf)
    assert tlv.type == LWM2M_TLV_RESOURCE
    assert tlv.id == 5850
    assert tlv.value == b'\x01'
    assert bytes(tlv) == buf

    # Resource 0 (Manufacturer): "Open Mobile Alliance"
    buf2 = unhexlify('c800144f70656e204d6f62696c6520416c6c69616e6365')
    tlv2 = LWM2M.TLV(buf2)
    assert tlv2.id == 0
    assert tlv2.value == b'Open Mobile Alliance'
    assert bytes(tlv2) == buf2

    # ---- Data model + TLV codec --------------------------------------
    inst = LWM2M.ObjectInstance(id=0, resources=[
        LWM2M.Resource(id=LWM2M_DEV_MANUFACTURER, value='Open Mobile Alliance'),
        LWM2M.Resource(id=LWM2M_DEV_BATTERY_LEVEL, value=100),
        LWM2M.Resource(id=LWM2M_DEV_AVAILABLE_POWER_SOURCES,
                       instances={0: 1, 1: 5}),
    ])
    tlv_bytes = LWM2M.encode(inst, CF.TLV)
    decoded = LWM2M.decode(tlv_bytes, CF.TLV)
    assert isinstance(decoded, LWM2M.ObjectInstance)
    assert decoded.id == 0
    assert len(decoded.resources) == 3
    # TLV decode returns raw bytes for values (no schema).
    assert decoded.resources[0].value == b'Open Mobile Alliance'
    # The multi-instance resource came back as a multi-instance Resource.
    multi = decoded.resources[2]
    assert multi.is_multi
    assert set(multi.instances.keys()) == {0, 1}

    # ---- Direct Resource + bare-list paths ---------------------------
    single = LWM2M.Resource(id=5850, value=True)
    rt = LWM2M.decode(LWM2M.encode(single, CF.TLV), CF.TLV)
    assert isinstance(rt, LWM2M.Resource) and rt.id == 5850

    # ---- Unimplemented format ----------------------------------------
    try:
        LWM2M.decode(b'', CF.JSON)
    except NotImplementedError:
        pass
    else:
        raise AssertionError('expected NotImplementedError')


if __name__ == '__main__':
    test_lwm2m()
    print('Tests passed.')
