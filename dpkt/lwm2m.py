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

# LWM2M TLV Type IDs
LWM2M_TLV_OBJECT_INSTANCE = 0x00  # 00
LWM2M_TLV_RESOURCE_INSTANCE = 0x40  # 01
LWM2M_TLV_MULTIPLE_RESOURCE = 0x80  # 10
LWM2M_TLV_RESOURCE = 0xC0  # 11


class LWM2M_TLV(dpkt.Packet):
    """LWM2M Binary TLV Format.

    OMA LWM2M v1.0, Section 6.3.3.

    Attributes:
        type (int): TLV Type (Object Instance, Resource, etc.)
        id (int): Identifier (8 or 16 bits)
        value (bytes): Value
    """

    def __init__(self, *args, **kwargs):
        self.type = 0
        self.id = 0
        self.value = b''
        super(LWM2M_TLV, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        if not buf:
            raise dpkt.NeedData('empty TLV')
        
        # Type byte
        type_byte = compat_ord(buf[0])
        self.type = type_byte & 0xC0  # bits 7-6
        id_len = (type_byte & 0x20) >> 5  # bit 5: 0=8bit, 1=16bit
        length_type = (type_byte & 0x18) >> 3  # bits 4-3: 00=no length, 01=8bit, 10=16bit, 11=24bit
        val_len = type_byte & 0x07  # bits 2-0: value length if length_type=00
        
        off = 1
        
        # Identifier
        if id_len == 0:
            if off >= len(buf): raise dpkt.NeedData()
            self.id = compat_ord(buf[off])
            off += 1
        else:
            if off + 2 > len(buf): raise dpkt.NeedData()
            self.id = struct.unpack('>H', buf[off:off+2])[0]
            off += 2
            
        # Length
        if length_type == 1: # 8-bit length
            if off >= len(buf): raise dpkt.NeedData()
            val_len = compat_ord(buf[off])
            off += 1
        elif length_type == 2: # 16-bit length
            if off + 2 > len(buf): raise dpkt.NeedData()
            val_len = struct.unpack('>H', buf[off:off+2])[0]
            off += 2
        elif length_type == 3: # 24-bit length
            if off + 3 > len(buf): raise dpkt.NeedData()
            val_len = struct.unpack('>I', b'\x00' + buf[off:off+3])[0]
            off += 3
        # if length_type == 0, val_len is already set from bits 2-0
            
        if off + val_len > len(buf):
            raise dpkt.NeedData('short TLV value')
            
        self.value = buf[off:off+val_len]
        self.data = buf[off+val_len:]

    def __bytes__(self):
        # Determine Identifier length bit
        id_bit = 0x20 if self.id > 255 else 0x00
        
        # Determine Length type and value
        val_len = len(self.value)
        if val_len < 8:
            len_type = 0x00
            len_bits = val_len
            len_field = b''
        elif val_len < 256:
            len_type = 0x08 # 01
            len_bits = 0
            len_field = struct.pack('B', val_len)
        elif val_len < 65536:
            len_type = 0x10 # 10
            len_bits = 0
            len_field = struct.pack('>H', val_len)
        else:
            len_type = 0x18 # 11
            len_bits = 0
            len_field = struct.pack('>I', val_len)[1:] # 24-bit

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


def parse_tlvs(buf):
    """Parse a buffer containing multiple LWM2M TLVs."""
    tlvs = []
    while buf:
        tlv = LWM2M_TLV(buf)
        tlvs.append(tlv)
        buf = tlv.data
    return tlvs


def test_lwm2m():
    from binascii import unhexlify
    # Example from OMA spec: Resource 5850 (Switch) with value 1 (True)
    # Type: 11 (Resource), ID length 1 (16-bit), Length type 00, Length 1
    # 0xC0 | 0x20 | 0x00 | 0x01 = 0xE1
    # ID: 5850 = 0x16da
    # Value: 0x01
    buf = unhexlify('e116da01')
    tlv = LWM2M_TLV(buf)
    assert tlv.type == LWM2M_TLV_RESOURCE
    assert tlv.id == 5850
    assert tlv.value == b'\x01'
    assert bytes(tlv) == buf

    # Multiple resources example
    # Resource 0 (Manufacturer): "Open Mobile Alliance"
    # Type: 11, ID len 0 (8-bit), Len type 01 (8-bit), Val len 20
    # 0xC0 | 0x00 | 0x08 | 0x00 = 0xC8
    buf2 = unhexlify('c800144f70656e204d6f62696c6520416c6c69616e6365')
    tlv2 = LWM2M_TLV(buf2)
    assert tlv2.id == 0
    assert tlv2.value == b'Open Mobile Alliance'
    assert bytes(tlv2) == buf2

    # Test parse_tlvs
    combined = buf + buf2
    tlvs = parse_tlvs(combined)
    assert len(tlvs) == 2
    assert tlvs[0].id == 5850
    assert tlvs[1].id == 0


if __name__ == '__main__':
    test_lwm2m()
    print('Tests passed.')
