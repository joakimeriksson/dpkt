# -*- coding: utf-8 -*-
"""IEEE 802.15.4."""
from __future__ import absolute_import

import struct
from . import dpkt
from .compat import compat_ord

# Frame Types
TYPE_BEACON = 0
TYPE_DATA = 1
TYPE_ACK = 2
TYPE_CMD = 3

# Addressing Modes
ADDR_MODE_NONE = 0
ADDR_MODE_RSVD = 1
ADDR_MODE_SHORT = 2
ADDR_MODE_EXT = 3

class IEEE802154(dpkt.Packet):
    """IEEE 802.15.4 MAC Layer.
    
    Attributes:
        fcf (int): Frame Control Field (16 bits)
        seq (int): Sequence Number (8 bits)
        dst_pan (int): Destination PAN ID
        dst_addr (bytes): Destination Address (2 or 8 bytes)
        src_pan (int): Source PAN ID
        src_addr (bytes): Source Address (2 or 8 bytes)
    """
    __hdr__ = (
        ('fcf', 'H', 0),
        ('seq', 'B', 0)
    )
    __byte_order__ = '<'
    
    # dpkt bit fields are defined from MSB to LSB of the whole field
    # For a 16-bit little-endian word, we must be careful.
    # 0x6141 -> binary 0110 0001 0100 0001
    # Bits (LSB first):
    # 0-2: Type (1 = Data) -> 001 (at the end)
    # 3: Security (0)
    # 4: Frame Pending (0)
    # 5: AR (1)
    # 6: PAN ID Comp (1)
    # 7-9: Rsvd (000)
    # 10-11: Dst Mode (2 = Short) -> 10
    # 12-13: Version (0) -> 00
    # 14-15: Src Mode (2 = Short) -> 10
    
    # Map from MSB (bit 15) to LSB (bit 0)
    __bit_fields__ = {
        'fcf': (
            ('src_mode', 2),      # bits 15-14
            ('version', 2),       # bits 13-12
            ('dst_mode', 2),      # bits 11-10
            ('_rsvd', 3),         # bits 9-7
            ('pan_id_comp', 1),   # bit 6
            ('ar', 1),            # bit 5
            ('frame_pending', 1), # bit 4
            ('security', 1),      # bit 3
            ('type', 3),          # bits 2-0
        )
    }

    def __init__(self, *args, **kwargs):
        self.dst_pan = None
        self.dst_addr = None
        self.src_pan = None
        self.src_addr = None
        super(IEEE802154, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = self.__hdr_len__
        
        # Dest PAN ID and Addr
        if self.dst_mode != ADDR_MODE_NONE:
            if off + 2 > len(buf): raise dpkt.NeedData()
            self.dst_pan = struct.unpack('<H', buf[off:off+2])[0]
            off += 2
            
            addr_len = 2 if self.dst_mode == ADDR_MODE_SHORT else 8
            if off + addr_len > len(buf): raise dpkt.NeedData()
            raw = buf[off:off+addr_len]
            # 802.15.4 extended addresses are little-endian in the frame;
            # reverse to big-endian (EUI-64) like Contiki-NG does
            self.dst_addr = raw[::-1] if addr_len == 8 else raw
            off += addr_len

        # Source PAN ID / Addr
        if self.src_mode != ADDR_MODE_NONE:
            # If both addresses present and Compression=1, Source PAN is omitted.
            if not (self.src_mode != ADDR_MODE_NONE and self.dst_mode != ADDR_MODE_NONE and self.pan_id_comp):
                if off + 2 > len(buf): raise dpkt.NeedData()
                self.src_pan = struct.unpack('<H', buf[off:off+2])[0]
                off += 2
            else:
                self.src_pan = self.dst_pan

            addr_len = 2 if self.src_mode == ADDR_MODE_SHORT else 8
            if off + addr_len > len(buf): raise dpkt.NeedData()
            raw = buf[off:off+addr_len]
            self.src_addr = raw[::-1] if addr_len == 8 else raw
            off += addr_len
            
        self.data = buf[off:]

    def __bytes__(self):
        res = self.pack_hdr()
        
        if self.dst_mode != ADDR_MODE_NONE:
            res += struct.pack('<H', self.dst_pan)
            # Reverse extended addresses back to little-endian for the frame
            addr = self.dst_addr
            res += addr[::-1] if len(addr) == 8 else addr

        if self.src_mode != ADDR_MODE_NONE:
            if not (self.src_mode != ADDR_MODE_NONE and self.dst_mode != ADDR_MODE_NONE and self.pan_id_comp):
                res += struct.pack('<H', self.src_pan)
            addr = self.src_addr
            res += addr[::-1] if len(addr) == 8 else addr
            
        return res + bytes(self.data)

def test_ieee802154():
    from binascii import unhexlify
    # Data Frame, Ack Req, PAN ID Comp, Dest Short, Source Short
    # FCF bits: Src(10) Ver(00) Dst(10) Rsvd(000) PANComp(1) AR(1) Pend(0) Sec(0) Type(001)
    # Binary: 1000 1000 0110 0001 = 0x8861
    # Let's use 0x6141 which the user mentioned (Type=1, Sec=0, Pend=0, AR=1, PANComp=1, Dst=2, Ver=0, Src=2)
    # Wait, the user said: bits 0-2 Frame Type, ..., 10-11 Dest Mode, 12-13 Version, 14-15 Source Mode.
    # 0x6141 -> binary 0110 0001 0100 0001
    # Bits 0-2: 001 -> 1 (Data) - OK
    # Bit 3: 0 (Sec) - OK
    # Bit 4: 0 (Pend) - OK
    # Bit 5: 0 (AR) -> WAIT, 0x6141 bit 5 is 0. 
    # Ah, 0x6141:
    # 0110 0001 0100 0001
    # Bit 5 is '0'. Bit 6 is '1'.
    
    # Let's use a known correct FCF from a real trace if possible, 
    # or just trust my bit mapping.
    
    # 0x6141 mapping:
    # src_mode (bits 15-14): 01 -> 1 (Reserved/Short in some versions)
    # version (bits 13-12): 10 -> 2 (Reserved)
    # dst_mode (bits 11-10): 00 -> 0 (None)
    # pan_id_comp (bit 6): 1
    # ar (bit 5): 0
    
    # Let's use the bits from Wikipedia:
    # Type=1 (Data), Sec=0, Pend=0, AR=1, PANComp=1, Dst=2, Ver=0, Src=2
    # Bits: Src(10) Ver(00) Dst(10) Rsvd(000) PANComp(1) AR(1) Pend(0) Sec(0) Type(001)
    # Binary: 1000 1000 0110 0001 = 0x8861
    
    buf = unhexlify('6188' + '01' + 'abcd' + '1234' + '5678') + b'payload'
    mac = IEEE802154(buf)
    assert mac.type == TYPE_DATA
    assert mac.ar == 1
    assert mac.pan_id_comp == 1
    assert mac.dst_mode == ADDR_MODE_SHORT
    assert mac.src_mode == ADDR_MODE_SHORT
    assert mac.seq == 1
    assert mac.dst_pan == 0xcdab
    assert mac.src_pan == 0xcdab
    assert mac.data == b'payload'
    assert bytes(mac) == buf

if __name__ == '__main__':
    test_ieee802154()
    print('Tests passed.')
