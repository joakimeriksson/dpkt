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

    def decompress(self, src_mac=None, dst_mac=None):
        """Try to decompress into an IP6 packet.
        Requires MAC addresses for IPHC decompression.
        """
        if isinstance(self.data, SixLoWPAN_IPHC):
            return self.data.decompress(src_mac, dst_mac)
        elif self.dispatch == DISPATCH_IPV6:
            return self.ip6
        return None

class SixLoWPAN_IPHC(dpkt.Packet):
    """6LoWPAN IPHC Header (RFC 6282)."""
    __hdr__ = (
        ('iphc', 'H', 0),
    )
    __byte_order__ = '>'
    # Map from MSB to LSB of the 16-bit word
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

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        off = 2
        # Traffic Class, Flow Label (TF)
        # 00: TC, FL (4 bytes)
        # 01: DSCP, ECN, Rsvd, FL (3 bytes)
        # 10: ECN, Rsvd, TC, Rsvd (1 byte)
        # 11: Omitted
        if self.tf == 0:
            off += 4
        elif self.tf == 1:
            off += 3
        elif self.tf == 2:
            off += 1
            
        # Next Header (NH)
        if self.nh == 0:
            off += 1
            
        # Hop Limit (HLIM)
        if self.hlim == 0:
            off += 1
            
        # Source Address (SAM)
        if not self.sac: # Stateless
            if self.sam == 0: off += 16
            elif self.sam == 1: off += 8
            elif self.sam == 2: off += 2
        
        # Destination Address (DAM)
        if not self.dac: # Stateless
            if not self.m: # Unicast
                if self.dam == 0: off += 16
                elif self.dam == 1: off += 8
                elif self.dam == 2: off += 2
            else: # Multicast
                if self.dam == 0: off += 16
                elif self.dam == 1: off += 6
                elif self.dam == 2: off += 4
                elif self.dam == 3: off += 1

        self.data = buf[off:]

    def decompress(self, src_mac, dst_mac):
        from . import ip6
        p = ip6.IP6()
        buf = bytes(self)[2:] # Skip IPHC 2 bytes
        off = 0
        
        # Traffic Class, Flow Label
        if self.tf == 0:
            v_tc_fl = struct.unpack('>I', buf[off:off+4])[0]
            p.v_tc_fl = (6 << 28) | (v_tc_fl & 0x0FFFFFFF)
            off += 4
        elif self.tf == 1:
            # ECN (2) DSCP (6) Rsvd (4) FL (20) -> DSCP (6) ECN (2) FL (20)
            ecn_dscp = compat_ord(buf[off])
            fl = struct.unpack('>H', buf[off+1:off+3])[0]
            p.v_tc_fl = (6 << 28) | ((ecn_dscp & 0x3F) << 22) | ((ecn_dscp >> 6) << 20) | (fl & 0xFFFFF)
            off += 3
        elif self.tf == 2:
            ecn_tc = compat_ord(buf[off])
            p.v_tc_fl = (6 << 28) | ((ecn_tc & 0x3F) << 20) | ((ecn_tc >> 6) << 20)
            off += 1
        else:
            p.v_tc_fl = (6 << 28)

        # Next Header
        if self.nh == 0:
            p.nxt = compat_ord(buf[off])
            off += 1
        else:
            # TODO: Handle NHC (UDP compression etc)
            p.nxt = 0 

        # Hop Limit
        if self.hlim == 1: p.hlim = 1
        elif self.hlim == 2: p.hlim = 64
        elif self.hlim == 3: p.hlim = 255
        else:
            p.hlim = compat_ord(buf[off])
            off += 1

        # Source Address
        if not self.sac:
            if self.sam == 0:
                p.src = buf[off:off+16]
                off += 16
            elif self.sam == 1:
                p.src = b'\xfe\x80' + b'\x00' * 6 + buf[off:off+8]
                off += 8
            elif self.sam == 2:
                p.src = b'\xfe\x80' + b'\x00' * 6 + b'\x00\x00\x00\xff\xfe\x00' + buf[off:off+2]
                off += 2
            elif self.sam == 3:
                # Derive from L2
                p.src = derive_ip6_addr(b'\xfe\x80' + b'\x00' * 6, src_mac)
        
        # Destination Address
        if not self.dac:
            if not self.m: # Unicast
                if self.dam == 0:
                    p.dst = buf[off:off+16]
                    off += 16
                elif self.dam == 1:
                    p.dst = b'\xfe\x80' + b'\x00' * 6 + buf[off:off+8]
                    off += 8
                elif self.dam == 2:
                    p.dst = b'\xfe\x80' + b'\x00' * 6 + b'\x00\x00\x00\xff\xfe\x00' + buf[off:off+2]
                    off += 2
                elif self.dam == 3:
                    p.dst = derive_ip6_addr(b'\xfe\x80' + b'\x00' * 6, dst_mac)
            else: # Multicast
                if self.dam == 0:
                    p.dst = buf[off:off+16]
                    off += 16
                elif self.dam == 1:
                    p.dst = b'\xff' + bytes([compat_ord(buf[off])]) + b'\x00' * 9 + buf[off+1:off+6]
                    off += 6
                elif self.dam == 2:
                    p.dst = b'\xff' + bytes([compat_ord(buf[off])]) + b'\x00' * 11 + buf[off+1:off+4]
                    off += 4
                elif self.dam == 3:
                    p.dst = b'\xff\x02' + b'\x00' * 13 + bytes([compat_ord(buf[off])])
                    off += 1

        p.data = buf[off:]
        p.plen = len(p.data)
        return p

def derive_ip6_addr(prefix, mac):
    """Derive an IPv6 address from a 64-bit prefix and a MAC address."""
    if not mac: return prefix + b'\x00' * 8
    if len(mac) == 8:
        # 64-bit MAC, flip bit 1 of the first byte (Universal/Local)
        # Actually in 6LoWPAN, we just use it as is but flip the L bit?
        # RFC 4944: IID is formed by complement of the 'Universal/Local' bit.
        iid = bytearray(mac)
        iid[0] ^= 0x02
        return prefix + bytes(iid)
    elif len(mac) == 2:
        # 16-bit short address
        return prefix + b'\x00\x00\x00\xff\xfe\x00' + mac
    return prefix + b'\x00' * 8

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
