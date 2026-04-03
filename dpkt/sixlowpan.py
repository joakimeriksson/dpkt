# -*- coding: utf-8 -*-
"""6LoWPAN (RFC 4944, RFC 6282)."""
from __future__ import absolute_import

import struct
from . import dpkt
from .compat import compat_ord

# Dispatch values (RFC 4944, RFC 6282)
DISPATCH_NALP = 0x00    # Not a LoWPAN packet
DISPATCH_IPV6 = 0x41    # Uncompressed IPv6
DISPATCH_IPHC = 0x60    # IP Header Compression (RFC 6282) - first 3 bits are 011
DISPATCH_FRAG1 = 0xC0   # First fragment - first 5 bits are 11000
DISPATCH_FRAGN = 0xE0   # Subsequent fragments - first 5 bits are 11100

class SixLoWPAN(dpkt.Packet):
    """6LoWPAN Layer."""
    def unpack(self, buf):
        if not buf: raise dpkt.NeedData()
        b0 = compat_ord(buf[0])
        
        self.dispatch = b0
        
        if b0 == DISPATCH_IPV6:
            from . import ip6
            self.data = self.ip6 = ip6.IP6(buf[1:])
        elif (b0 & 0xE0) == DISPATCH_IPHC:
            self.data = self.iphc = SixLoWPAN_IPHC(buf)
        elif (b0 & 0xF8) == DISPATCH_FRAG1 or (b0 & 0xF8) == DISPATCH_FRAGN:
            self.data = self.frag = SixLoWPAN_Frag(buf)
        else:
            self.data = buf

class SixLoWPAN_IPHC(dpkt.Packet):
    """6LoWPAN IPHC Header (RFC 6282)."""
    __hdr__ = (
        ('iphc', 'H', 0),
    )
    # Big-endian 16-bit word
    __bit_fields__ = {
        'iphc': (
            ('_dispatch', 3), # 011
            ('tf', 2),
            ('nh', 1),
            ('hlim', 2),
            ('cid', 1),
            ('sac', 1),
            ('sam', 2),
            ('m', 1),
            ('dac', 1),
            ('dam', 2),
        )
    }

class SixLoWPAN_Frag(dpkt.Packet):
    """6LoWPAN Fragment Header."""
    __hdr__ = (
        ('size_tag', 'H', 0), # 5 bits dispatch, 11 bits size
    )
    __bit_fields__ = {
        'size_tag': (
            ('_dispatch', 5),
            ('datagram_size', 11),
        )
    }
    
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = 2
        if off + 2 > len(buf): raise dpkt.NeedData()
        self.datagram_tag = struct.unpack('>H', buf[off:off+2])[0]
        off += 2
        
        b0 = compat_ord(buf[0])
        if (b0 & 0xF8) == DISPATCH_FRAGN:
            if off >= len(buf): raise dpkt.NeedData()
            self.datagram_offset = compat_ord(buf[off])
            off += 1
        else:
            self.datagram_offset = 0
            
        self.data = buf[off:]

def test_sixlowpan():
    from binascii import unhexlify
    # FRAG1: Size 100, Tag 0xabcd
    # Binary: 11000 000 01100100 = 0xc064
    buf = unhexlify('c064' + 'abcd') + b'payload'
    lowpan = SixLoWPAN(buf)
    assert isinstance(lowpan.data, SixLoWPAN_Frag)
    assert lowpan.frag.datagram_size == 100
    assert lowpan.frag.datagram_tag == 0xabcd
    assert lowpan.frag.data == b'payload'

if __name__ == '__main__':
    test_sixlowpan()
    print('Tests passed.')
