# -*- coding: utf-8 -*-
"""6LoWPAN (RFC 4944, RFC 6282).

Based on Contiki-NG's sicslowpan.c implementation.
"""
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

# NHC (Next Header Compression) constants
NHC_EXT_HDR_MASK = 0xF0
NHC_EXT_HDR_ID = 0xE0
NHC_UDP_MASK = 0xF8
NHC_UDP_ID = 0xF0
NHC_UDP_CHECKSUM_C = 0x04  # Checksum compressed (elided)
NHC_UDP_CS_P_00 = 0xF0     # Both ports inline
NHC_UDP_CS_P_01 = 0xF1     # Src inline, dst compressed
NHC_UDP_CS_P_10 = 0xF2     # Src compressed, dst inline
NHC_UDP_CS_P_11 = 0xF3     # Both ports compressed

# Extension header IDs for NHC
NHC_EXT_HBHO = 0   # Hop-by-Hop Options
NHC_EXT_ROUTING = 1
NHC_EXT_FRAGMENT = 2
NHC_EXT_DESTO = 3

# Protocol numbers
PROTO_HBHO = 0
PROTO_ROUTING = 43
PROTO_FRAGMENT = 44
PROTO_ICMP6 = 58
PROTO_DESTO = 60
PROTO_UDP = 17

# NHC EID to protocol number
_nhc_eid_to_proto = {0: PROTO_HBHO, 1: PROTO_ROUTING, 2: PROTO_FRAGMENT, 3: PROTO_DESTO}
_proto_to_nhc_eid = {v: k for k, v in _nhc_eid_to_proto.items()}

# Protocols compressible via NHC (from sicslowpan.c IS_COMPRESSABLE_PROTO)
_nhc_compressible = {PROTO_UDP, PROTO_HBHO, PROTO_DESTO, PROTO_ROUTING, PROTO_FRAGMENT}


class SixLoWPAN(dpkt.Packet):
    """6LoWPAN Layer."""
    __hdr__ = ()

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
        """Decompress into an IP6 packet. Requires MAC addresses for IPHC."""
        if isinstance(self.data, SixLoWPAN_IPHC):
            return self.data.decompress(src_mac, dst_mac)
        elif self.dispatch == DISPATCH_IPV6:
            return self.ip6
        return None

    def compress(self, ip6_pkt, src_mac=None, dst_mac=None):
        """Compress an IP6 packet into IPHC."""
        self.iphc = SixLoWPAN_IPHC()
        self.data = self.iphc.compress(ip6_pkt, src_mac, dst_mac)
        return self

    def __bytes__(self):
        if hasattr(self, 'iphc'):
            return bytes(self.iphc)
        if self.dispatch == DISPATCH_IPV6:
            return struct.pack('B', DISPATCH_IPV6) + bytes(self.data)
        return bytes(self.data)


class SixLoWPAN_IPHC(dpkt.Packet):
    """6LoWPAN IPHC Header (RFC 6282)."""
    __hdr__ = (
        ('iphc', 'H', 0),
    )
    __byte_order__ = '>'
    __bit_fields__ = {
        'iphc': (
            ('_dispatch', 3),  # 011
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
        self._raw = buf  # Preserve original buffer for decompress
        # Compute payload offset (skip all inline fields)
        off = 2
        if self.cid:
            off += 1  # Context Identifier Extension byte
        if self.tf == 0: off += 4
        elif self.tf == 1: off += 3
        elif self.tf == 2: off += 1
        if self.nh == 0: off += 1
        if self.hlim == 0: off += 1
        if not self.sac:
            if self.sam == 0: off += 16
            elif self.sam == 1: off += 8
            elif self.sam == 2: off += 2
        else:
            if self.sam == 1: off += 8
            elif self.sam == 2: off += 2
        if not self.dac:
            if not self.m:
                if self.dam == 0: off += 16
                elif self.dam == 1: off += 8
                elif self.dam == 2: off += 2
            else:
                if self.dam == 0: off += 16
                elif self.dam == 1: off += 6
                elif self.dam == 2: off += 4
                elif self.dam == 3: off += 1
        else:
            if not self.m:
                if self.dam == 1: off += 8
                elif self.dam == 2: off += 2
            # Context-based multicast: not common
        self.data = buf[off:]

    def decompress(self, src_mac, dst_mac):
        """Decompress IPHC to IPv6. Based on sicslowpan.c uncompress_hdr_iphc()."""
        from . import ip6
        p = ip6.IP6()
        buf = self._raw[2:]  # Skip IPHC 2 bytes
        off = 0

        # CID byte (context identifier extension)
        if self.cid:
            # sci = (buf[off] >> 4) & 0x0F
            # dci = buf[off] & 0x0F
            off += 1

        # --- Traffic Class & Flow Label ---
        if self.tf == 0:
            # 4 bytes: ECN|DSCP + Flow Label
            tmp = compat_ord(buf[off])
            fl_bytes = buf[off + 1:off + 4]
            tc = ((tmp >> 2) & 0x3C) | (tmp & 0x03)  # DSCP(6) | ECN(2)
            fl = ((compat_ord(fl_bytes[0]) & 0x0F) << 16) | (compat_ord(fl_bytes[1]) << 8) | compat_ord(fl_bytes[2])
            p.v_tc_fl = (6 << 28) | (tc << 20) | fl
            off += 4
        elif self.tf == 1:
            # 3 bytes: ECN + Flow Label (TC partially compressed)
            tmp = compat_ord(buf[off])
            ecn = (tmp >> 6) & 0x03
            fl = ((tmp & 0x0F) << 16) | (compat_ord(buf[off + 1]) << 8) | compat_ord(buf[off + 2])
            p.v_tc_fl = (6 << 28) | (ecn << 20) | fl
            off += 3
        elif self.tf == 2:
            # 1 byte: ECN|DSCP (Flow Label compressed)
            tmp = compat_ord(buf[off])
            tc = ((tmp >> 2) & 0x3C) | (tmp & 0x03)
            p.v_tc_fl = (6 << 28) | (tc << 20)
            off += 1
        else:
            # Both compressed
            p.v_tc_fl = (6 << 28)

        # --- Next Header ---
        if self.nh == 0:
            p.nxt = compat_ord(buf[off])
            off += 1
        else:
            p.nxt = 0  # Will be filled by NHC processing below

        # --- Hop Limit ---
        _hlim_values = {1: 1, 2: 64, 3: 255}
        if self.hlim in _hlim_values:
            p.hlim = _hlim_values[self.hlim]
        else:
            p.hlim = compat_ord(buf[off])
            off += 1

        # --- Source Address ---
        ll_prefix = b'\xfe\x80' + b'\x00' * 6
        if self.sac:
            # Context-based source
            if self.sam == 0:
                p.src = b'\x00' * 16  # Unspecified
            elif self.sam == 1:
                p.src = ll_prefix + buf[off:off + 8]  # TODO: use context prefix
                off += 8
            elif self.sam == 2:
                p.src = ll_prefix + b'\x00\x00\x00\xff\xfe\x00' + buf[off:off + 2]
                off += 2
            elif self.sam == 3:
                p.src = derive_ip6_addr(ll_prefix, src_mac)  # TODO: use context prefix
        else:
            # Stateless (link-local)
            if self.sam == 0:
                p.src = buf[off:off + 16]
                off += 16
            elif self.sam == 1:
                p.src = ll_prefix + buf[off:off + 8]
                off += 8
            elif self.sam == 2:
                p.src = ll_prefix + b'\x00\x00\x00\xff\xfe\x00' + buf[off:off + 2]
                off += 2
            elif self.sam == 3:
                p.src = derive_ip6_addr(ll_prefix, src_mac)

        # --- Destination Address ---
        if self.m:
            # Multicast
            if not self.dac:
                if self.dam == 0:
                    p.dst = buf[off:off + 16]
                    off += 16
                elif self.dam == 1:
                    # FFXX::00XX:XXXX:XXXX — 6 bytes: 1 scope + 5 address
                    scope = compat_ord(buf[off])
                    p.dst = bytes([0xff, scope]) + b'\x00' * 9 + buf[off + 1:off + 6]
                    off += 6
                elif self.dam == 2:
                    # FFXX::00XX:XXXX — 4 bytes: 1 scope + 3 address
                    scope = compat_ord(buf[off])
                    p.dst = bytes([0xff, scope]) + b'\x00' * 11 + buf[off + 1:off + 4]
                    off += 4
                elif self.dam == 3:
                    # FF02::00XX — 1 byte
                    p.dst = b'\xff\x02' + b'\x00' * 13 + buf[off:off + 1]
                    off += 1
            else:
                # Context-based multicast (not commonly used)
                p.dst = buf[off:off + 16]
                off += 16
        else:
            # Unicast
            if not self.dac:
                if self.dam == 0:
                    p.dst = buf[off:off + 16]
                    off += 16
                elif self.dam == 1:
                    p.dst = ll_prefix + buf[off:off + 8]
                    off += 8
                elif self.dam == 2:
                    p.dst = ll_prefix + b'\x00\x00\x00\xff\xfe\x00' + buf[off:off + 2]
                    off += 2
                elif self.dam == 3:
                    p.dst = derive_ip6_addr(ll_prefix, dst_mac)
            else:
                # Context-based unicast
                if self.dam == 0:
                    p.dst = buf[off:off + 16]
                    off += 16
                elif self.dam == 1:
                    p.dst = ll_prefix + buf[off:off + 8]  # TODO: context prefix
                    off += 8
                elif self.dam == 2:
                    p.dst = ll_prefix + b'\x00\x00\x00\xff\xfe\x00' + buf[off:off + 2]
                    off += 2
                elif self.dam == 3:
                    p.dst = derive_ip6_addr(ll_prefix, dst_mac)

        # --- NHC (Next Header Compression) ---
        if self.nh == 1:
            off = self._decompress_nhc(p, buf, off)
            # NHC handlers (e.g. UDP) may set p.data directly
            if not isinstance(p.data, bytes) or len(p.data) > 0:
                p.plen = len(p.data) if isinstance(p.data, bytes) else 0
                return p

        p.data = buf[off:]
        p.plen = len(p.data)
        return p

    def _decompress_nhc(self, p, buf, off):
        """Decompress NHC headers. Based on sicslowpan.c."""
        # Process extension header chain
        while off < len(buf):
            nhc = compat_ord(buf[off])

            if (nhc & NHC_EXT_HDR_MASK) == NHC_EXT_HDR_ID:
                # Extension header NHC: 1110 EID[2:0] NH
                eid = (nhc >> 1) & 0x07
                nh_flag = nhc & 0x01
                off += 1

                proto = _nhc_eid_to_proto.get(eid, 0)
                p.nxt = proto

                if not nh_flag:
                    # Next header inline
                    p.nxt = compat_ord(buf[off])
                    off += 1

                # Extension header length
                ext_len = compat_ord(buf[off])
                off += 1
                # Skip extension header payload
                off += ext_len

                if not nh_flag:
                    break  # No more compressed headers

            elif (nhc & NHC_UDP_MASK) == NHC_UDP_ID:
                # UDP NHC: 11110 C PP
                p.nxt = PROTO_UDP
                off = self._decompress_nhc_udp(p, buf, off)
                break
            else:
                # Unknown NHC or ICMPv6 (not NHC-compressible)
                # Treat remaining as raw payload
                break

        return off

    def _decompress_nhc_udp(self, p, buf, off):
        """Decompress NHC UDP header. Based on sicslowpan.c."""
        from . import udp as udp_mod
        nhc = compat_ord(buf[off])
        off += 1

        port_mode = nhc & 0x03
        checksum_compressed = nhc & NHC_UDP_CHECKSUM_C

        if port_mode == 0:
            # Both ports 16-bit inline
            src_port = struct.unpack('>H', buf[off:off + 2])[0]
            off += 2
            dst_port = struct.unpack('>H', buf[off:off + 2])[0]
            off += 2
        elif port_mode == 1:
            # Src 16-bit inline, dst 8-bit (0xF000 + val)
            src_port = struct.unpack('>H', buf[off:off + 2])[0]
            off += 2
            dst_port = 0xF000 + compat_ord(buf[off])
            off += 1
        elif port_mode == 2:
            # Src 8-bit (0xF000 + val), dst 16-bit inline
            src_port = 0xF000 + compat_ord(buf[off])
            off += 1
            dst_port = struct.unpack('>H', buf[off:off + 2])[0]
            off += 2
        else:
            # Both 4-bit (0xF0B0 + nibble)
            both = compat_ord(buf[off])
            off += 1
            src_port = 0xF0B0 + ((both >> 4) & 0x0F)
            dst_port = 0xF0B0 + (both & 0x0F)

        if not checksum_compressed:
            checksum = struct.unpack('>H', buf[off:off + 2])[0]
            off += 2
        else:
            checksum = 0

        # Build UDP header (8 bytes) + remaining data
        udp_payload = buf[off:]
        udp_hdr = struct.pack('>HHHH', src_port, dst_port,
                              8 + len(udp_payload), checksum)
        p.data = udp_hdr + udp_payload
        p.plen = len(p.data)
        # Return offset past entire buffer since we consumed the rest as UDP payload
        return len(buf)

    def compress(self, p, src_mac, dst_mac=None):
        """Compress IP6 packet. Based on sicslowpan.c compress_hdr_iphc()."""
        self.iphc = 0x6000  # Dispatch 011
        res = b""

        # --- Traffic Class & Flow Label ---
        tc = (p.v_tc_fl >> 20) & 0xFF if hasattr(p, 'v_tc_fl') else 0
        fl = p.v_tc_fl & 0xFFFFF if hasattr(p, 'v_tc_fl') else 0

        if tc == 0 and fl == 0:
            self.tf = 3  # Both omitted
        elif fl == 0:
            self.tf = 2  # FL omitted, TC inline (1 byte)
            # Encode TC as ECN(2)|DSCP(6) → byte = (DSCP<<2)|ECN
            dscp = (tc >> 2) & 0x3F
            ecn = tc & 0x03
            res += bytes([(dscp << 2) | ecn])
        else:
            self.tf = 0  # Both inline (4 bytes)
            dscp = (tc >> 2) & 0x3F
            ecn = tc & 0x03
            res += bytes([(ecn << 6) | dscp])
            res += struct.pack('>I', fl)[1:]  # 3 bytes of flow label

        # --- Next Header ---
        self.nh = 0  # Inline next header (NHC not used for compression yet)
        res += bytes([p.nxt])

        # --- Hop Limit ---
        if p.hlim == 1:
            self.hlim = 1
        elif p.hlim == 64:
            self.hlim = 2
        elif p.hlim == 255:
            self.hlim = 3
        else:
            self.hlim = 0
            res += bytes([p.hlim])

        # --- Source Address ---
        ll_prefix = b'\xfe\x80' + b'\x00' * 6
        if p.src == b'\x00' * 16:
            # Unspecified address
            self.sac = 1
            self.sam = 0
        elif p.src[:8] == ll_prefix:
            self.sac = 0
            if src_mac and p.src == derive_ip6_addr(ll_prefix, src_mac):
                self.sam = 3  # Fully elided
            elif _is_16bit_compressible(p.src):
                self.sam = 2  # 16-bit inline
                res += p.src[14:16]
            else:
                self.sam = 1  # 64-bit IID inline
                res += p.src[8:16]
        else:
            self.sac = 0
            self.sam = 0  # Full 128-bit inline
            res += p.src

        # --- Destination Address ---
        if p.dst[0] == 0xff:
            # Multicast
            self.m = 1
            self.dac = 0
            if _is_mcast_8bit(p.dst):
                self.dam = 3  # FF02::00XX — 1 byte
                res += p.dst[15:16]
            elif _is_mcast_32bit(p.dst):
                self.dam = 2  # FFXX::00XX:XXXX — 4 bytes
                res += bytes([p.dst[1]]) + p.dst[13:16]
            elif _is_mcast_48bit(p.dst):
                self.dam = 1  # FFXX::00XX:XXXX:XXXX — 6 bytes
                res += bytes([p.dst[1]]) + p.dst[11:16]
            else:
                self.dam = 0  # Full 128-bit
                res += p.dst
        else:
            # Unicast
            self.m = 0
            self.dac = 0
            if p.dst[:8] == ll_prefix:
                if dst_mac and p.dst == derive_ip6_addr(ll_prefix, dst_mac):
                    self.dam = 3  # Fully elided
                elif _is_16bit_compressible(p.dst):
                    self.dam = 2  # 16-bit inline
                    res += p.dst[14:16]
                else:
                    self.dam = 1  # 64-bit IID inline
                    res += p.dst[8:16]
            else:
                self.dam = 0  # Full 128-bit
                res += p.dst

        self.data = res + bytes(p.data)
        return self.data

    def __bytes__(self):
        self.iphc = (self.iphc & 0x1FFF) | 0x6000
        return self.pack_hdr() + bytes(self.data)


def derive_ip6_addr(prefix, mac):
    """Derive an IPv6 address from a 64-bit prefix and a MAC address.
    Flips the Universal/Local bit per RFC 4944.
    """
    if not mac:
        return prefix + b'\x00' * 8
    if len(mac) == 8:
        iid = bytearray(mac)
        iid[0] ^= 0x02  # Flip U/L bit
        return prefix + bytes(iid)
    elif len(mac) == 2:
        return prefix + b'\x00\x00\x00\xff\xfe\x00' + mac
    return prefix + b'\x00' * 8


def _is_16bit_compressible(addr):
    """Check if address IID matches ::00FF:FE00:XXXX pattern."""
    return addr[8:14] == b'\x00\x00\x00\xff\xfe\x00'


def _is_mcast_8bit(addr):
    """FF02::00XX — compressible to 1 byte."""
    return (addr[1] == 0x02 and
            addr[2:14] == b'\x00' * 12 and
            addr[14] == 0x00)


def _is_mcast_32bit(addr):
    """FFXX::00XX:XXXX — compressible to 4 bytes."""
    return (addr[2:12] == b'\x00' * 10 and
            addr[12] == 0x00)


def _is_mcast_48bit(addr):
    """FFXX::00XX:XXXX:XXXX — compressible to 6 bytes."""
    return (addr[2:10] == b'\x00' * 8 and
            addr[10] == 0x00)


class SixLoWPAN_Frag(dpkt.Packet):
    """6LoWPAN Fragment Header."""
    __hdr__ = (
        ('size_tag', 'H', 0),
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
        self.datagram_tag = struct.unpack('>H', buf[off:off + 2])[0]
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

    # Test FRAG1
    buf = unhexlify('c064' + 'abcd') + b'payload'
    lowpan = SixLoWPAN(buf)
    assert isinstance(lowpan.data, SixLoWPAN_Frag)
    assert lowpan.frag.datagram_size == 100
    assert lowpan.frag.datagram_tag == 0xabcd
    assert lowpan.frag.data == b'payload'

    # Test IPHC decompress with the _raw buffer fix
    # IPHC=0x7A3B: TF=3 NH=0 HLIM=2(64) SAM=3 M=1 DAM=3
    # Inline: NH(3a) + mcast_byte(1a) + ICMPv6 payload
    buf2 = unhexlify('7a3b3a1a9b0065190000')
    lowpan2 = SixLoWPAN(buf2)
    assert isinstance(lowpan2.data, SixLoWPAN_IPHC)
    ip6 = lowpan2.decompress(src_mac=b'\x02\x00\x02\x00\x02\x00\x02\x00')
    assert ip6.nxt == 58  # ICMPv6
    assert ip6.hlim == 64
    assert ip6.dst == unhexlify('ff02') + b'\x00' * 13 + b'\x1a'  # ff02::1a
    assert ip6.data[:2] == b'\x9b\x00'  # RPL DIS

    # Test roundtrip compress -> decompress
    from . import ip6 as ip6_mod
    dodagid = unhexlify('fd000000000000000000000000000001')
    src_mac = dodagid[-8:]
    p = ip6_mod.IP6()
    p.v_tc_fl = 0x60000000
    p.nxt = 58
    p.hlim = 255
    p.src = dodagid
    p.dst = unhexlify('ff02000000000000000000000000001a')
    p.data = b'\x9b\x01\x00\x00'  # fake ICMPv6

    iphc = SixLoWPAN_IPHC()
    iphc.compress(p, src_mac=src_mac)
    raw = bytes(iphc)

    iphc2 = SixLoWPAN_IPHC(raw)
    p2 = iphc2.decompress(src_mac=src_mac, dst_mac=None)
    assert p2.nxt == 58
    assert p2.hlim == 255
    assert p2.src == dodagid
    assert p2.dst == p.dst
    assert p2.data == b'\x9b\x01\x00\x00'


if __name__ == '__main__':
    test_sixlowpan()
    print('Tests passed.')
