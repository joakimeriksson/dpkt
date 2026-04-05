# $Id: icmp6.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Internet Control Message Protocol for IPv6."""
from __future__ import absolute_import

import struct
from . import dpkt
from .compat import compat_ord

ICMP6_DST_UNREACH = 1  # dest unreachable, codes:
ICMP6_PACKET_TOO_BIG = 2  # packet too big
ICMP6_TIME_EXCEEDED = 3  # time exceeded, code:
ICMP6_PARAM_PROB = 4  # ip6 header bad

ICMP6_ECHO_REQUEST = 128  # echo service
ICMP6_ECHO_REPLY = 129  # echo reply
MLD_LISTENER_QUERY = 130  # multicast listener query
MLD_LISTENER_REPORT = 131  # multicast listener report
MLD_LISTENER_DONE = 132  # multicast listener done

# RFC2292 decls
ICMP6_MEMBERSHIP_QUERY = 130  # group membership query
ICMP6_MEMBERSHIP_REPORT = 131  # group membership report
ICMP6_MEMBERSHIP_REDUCTION = 132  # group membership termination

ND_ROUTER_SOLICIT = 133  # router solicitation
ND_ROUTER_ADVERT = 134  # router advertisement
ND_NEIGHBOR_SOLICIT = 135  # neighbor solicitation
ND_NEIGHBOR_ADVERT = 136  # neighbor advertisement
ND_REDIRECT = 137  # redirect

ICMP6_ROUTER_RENUMBERING = 138  # router renumbering

ICMP6_WRUREQUEST = 139  # who are you request
ICMP6_WRUREPLY = 140  # who are you reply
ICMP6_FQDN_QUERY = 139  # FQDN query
ICMP6_FQDN_REPLY = 140  # FQDN reply
ICMP6_NI_QUERY = 139  # node information request
ICMP6_NI_REPLY = 140  # node information reply
ICMP6_RPL_CONTROL = 155  # RFC 6550

# RPL Control Message Codes
RPL_DIS = 0x00
RPL_DIO = 0x01
RPL_DAO = 0x02
RPL_DAO_ACK = 0x03
RPL_CC = 0x80

# RPL Option Types
RPL_OPT_PAD1 = 0
RPL_OPT_PADN = 1
RPL_OPT_METRIC_CONTAINER = 2
RPL_OPT_ROUTING_INFO = 3
RPL_OPT_DODAG_CONF = 4
RPL_OPT_TARGET = 5
RPL_OPT_TRANSIT_INFO = 6
RPL_OPT_SOLICIT_INFO = 7
RPL_OPT_PREFIX_INFO = 8
RPL_OPT_TARGET_DESC = 9

ICMP6_MAXTYPE = 201


class ICMP6(dpkt.Packet):
    """Internet Control Message Protocol for IPv6.

    Internet Control Message Protocol version 6 (ICMPv6) is the implementation of the Internet Control Message Protocol
    (ICMP) for Internet Protocol version 6 (IPv6). ICMPv6 is an integral part of IPv6 and performs error reporting
    and diagnostic functions.

    Attributes:
        __hdr__: Header fields of ICMPv6.
            type: (int): Type. Control messages are identified by the value in the type field.  (1 byte)
            code: (int): Code. The code field gives additional context information for the message. (1 byte)
            sum: (int): Checksum. ICMPv6 provides a minimal level of message integrity verification. (2 bytes)
    """

    __hdr__ = (
        ('type', 'B', 0),
        ('code', 'B', 0),
        ('sum', 'H', 0)
    )

    class Error(dpkt.Packet):
        __hdr__ = (('pad', 'I', 0), )

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            from . import ip6
            self.data = self.ip6 = ip6.IP6(self.data)

    class Unreach(Error):
        pass

    class TooBig(Error):
        __hdr__ = (('mtu', 'I', 1232), )

    class TimeExceed(Error):
        pass

    class ParamProb(Error):
        __hdr__ = (('ptr', 'I', 0), )

    class Echo(dpkt.Packet):
        __hdr__ = (('id', 'H', 0), ('seq', 'H', 0))

    class RPLDIS(dpkt.Packet):
        __hdr__ = (
            ('flags', 'B', 0),
            ('rsvd', 'B', 0)
        )

        def __init__(self, *args, **kwargs):
            self.opts = []
            super(ICMP6.RPLDIS, self).__init__(*args, **kwargs)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.opts = decode_rpl_opts(self.data)
            self.data = b''

        def __bytes__(self):
            return self.pack_hdr() + encode_rpl_opts(self.opts)

    class RPLDIO(dpkt.Packet):
        __hdr__ = (
            ('instance_id', 'B', 0),
            ('version', 'B', 0),
            ('rank', 'H', 0),
            ('_g_mop_prf', 'B', 0),
            ('dtsn', 'B', 0),
            ('flags', 'B', 0),
            ('rsvd', 'B', 0),
            ('dodagid', '16s', b'\x00' * 16)
        )
        __bit_fields__ = {
            '_g_mop_prf': (
                ('g', 1),
                ('_rsvd', 1),
                ('mop', 3),
                ('prf', 3)
            )
        }

        def __init__(self, *args, **kwargs):
            self.opts = []
            super(ICMP6.RPLDIO, self).__init__(*args, **kwargs)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.opts = decode_rpl_opts(self.data)
            self.data = b''

        def __bytes__(self):
            return self.pack_hdr() + encode_rpl_opts(self.opts)

    class RPLDAO(dpkt.Packet):
        __hdr__ = (
            ('instance_id', 'B', 0),
            ('_k_d_flags', 'B', 0),
            ('rsvd', 'B', 0),
            ('dao_sequence', 'B', 0)
        )
        __bit_fields__ = {
            '_k_d_flags': (
                ('k', 1),
                ('d', 1),
                ('flags', 6)
            )
        }

        def __init__(self, *args, **kwargs):
            self.opts = []
            super(ICMP6.RPLDAO, self).__init__(*args, **kwargs)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            if self.d:
                self.dodagid = self.data[:16]
                self.data = self.data[16:]
            else:
                self.dodagid = None
            self.opts = decode_rpl_opts(self.data)
            self.data = b''

        def __bytes__(self):
            res = self.pack_hdr()
            if self.d and self.dodagid:
                res += self.dodagid
            res += encode_rpl_opts(self.opts)
            return res

    class RPLDAOACK(dpkt.Packet):
        __hdr__ = (
            ('instance_id', 'B', 0),
            ('_d_flags', 'B', 0),
            ('dao_sequence', 'B', 0),
            ('status', 'B', 0)
        )
        __bit_fields__ = {
            '_d_flags': (
                ('d', 1),
                ('flags', 7)
            )
        }

        def __init__(self, *args, **kwargs):
            self.opts = []
            super(ICMP6.RPLDAOACK, self).__init__(*args, **kwargs)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            if self.d:
                self.dodagid = self.data[:16]
                self.data = self.data[16:]
            else:
                self.dodagid = None
            self.opts = decode_rpl_opts(self.data)
            self.data = b''

        def __bytes__(self):
            res = self.pack_hdr()
            if self.d and self.dodagid:
                res += self.dodagid
            res += encode_rpl_opts(self.opts)
            return res

    class RPLOption(dpkt.Packet):
        __hdr__ = (
            ('type', 'B', 0),
            ('len', 'B', 0)
        )

        def unpack(self, buf):
            if not buf: raise dpkt.NeedData()
            self.type = compat_ord(buf[0])
            if self.type == RPL_OPT_PAD1:
                self.len = 0
                self.data = b''
                return
            
            # For subclasses with their own __hdr__, use Packet.unpack
            if self.__class__ != ICMP6.RPLOption:
                dpkt.Packet.unpack(self, buf)
                return

            if len(buf) < 2: raise dpkt.NeedData()
            self.len = compat_ord(buf[1])
            if len(buf) < 2 + self.len: raise dpkt.NeedData()
            self.data = buf[2:2+self.len]

        def __bytes__(self):
            if self.type == RPL_OPT_PAD1:
                return b'\x00'
            if self.__class__ != ICMP6.RPLOption:
                return self.pack_hdr() + bytes(self.data)
            return struct.pack('BB', self.type, len(self.data)) + bytes(self.data)

    class RPLOptDODAGConf(RPLOption):
        __hdr__ = (
            ('type', 'B', RPL_OPT_DODAG_CONF),
            ('len', 'B', 14),
            ('flags', 'B', 0),
            ('dio_int_min', 'B', 0),
            ('dio_int_doub', 'B', 0),
            ('dio_redun', 'B', 0),
            ('max_rank_inc', 'H', 0),
            ('min_hop_rank_inc', 'H', 0),
            ('ocp', 'H', 0),
            ('rsvd', 'B', 0),
            ('def_lifetime', 'B', 0),
            ('lifetime_unit', 'H', 0)
        )

    class RPLOptPrefixInfo(RPLOption):
        __hdr__ = (
            ('type', 'B', RPL_OPT_PREFIX_INFO),
            ('len', 'B', 30),
            ('prefix_len', 'B', 0),
            ('_l_a_r_flags', 'B', 0),
            ('valid_lifetime', 'I', 0),
            ('pref_lifetime', 'I', 0),
            ('rsvd', 'I', 0),
            ('prefix', '16s', b'\x00' * 16)
        )
        __bit_fields__ = {
            '_l_a_r_flags': (
                ('l', 1),
                ('a', 1),
                ('r', 1),
                ('flags', 5)
            )
        }

    class RPLOptTarget(RPLOption):
        __hdr__ = (
            ('type', 'B', RPL_OPT_TARGET),
            ('len', 'B', 0),
            ('flags', 'B', 0),
            ('prefix_len', 'B', 0)
        )
        # Prefix follows

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.prefix = self.data
            self.data = b''

        def __bytes__(self):
            return self.pack_hdr() + self.prefix

    class RPLOptTransitInfo(RPLOption):
        __hdr__ = (
            ('type', 'B', RPL_OPT_TRANSIT_INFO),
            ('len', 'B', 0),
            ('flags', 'B', 0),
            ('path_ctl', 'B', 0),
            ('path_seq', 'B', 0),
            ('path_lifetime', 'B', 0)
        )
        # Parent address follows (optional)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.parent = self.data
            self.data = b''

        def __bytes__(self):
            return self.pack_hdr() + self.parent

    class RPLOptPadN(RPLOption):
        __hdr__ = (
            ('type', 'B', RPL_OPT_PADN),
            ('len', 'B', 0)
        )

    _typesw = {1: Unreach, 2: TooBig, 3: TimeExceed, 4: ParamProb, 128: Echo, 129: Echo}
    _rplsw = {
        RPL_DIS: RPLDIS, RPL_DIO: RPLDIO,
        RPL_DAO: RPLDAO, RPL_DAO_ACK: RPLDAOACK
    }
    _rploptsw = {
        RPL_OPT_PADN: RPLOptPadN,
        RPL_OPT_DODAG_CONF: RPLOptDODAGConf,
        RPL_OPT_PREFIX_INFO: RPLOptPrefixInfo,
        RPL_OPT_TARGET: RPLOptTarget,
        RPL_OPT_TRANSIT_INFO: RPLOptTransitInfo
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            if self.type == ICMP6_RPL_CONTROL:
                self.data = self._rplsw[self.code](self.data)
            else:
                self.data = self._typesw[self.type](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            pass


def decode_rpl_opts(buf):
    """Return a list of RPL options decoded from buf."""
    opts = []
    while buf:
        t = compat_ord(buf[0])
        if t == RPL_OPT_PAD1:
            opts.append(ICMP6.RPLOption(buf[:1]))
            buf = buf[1:]
            continue
        if len(buf) < 2:
            break
        l = compat_ord(buf[1])
        if len(buf) < 2 + l:
            break
        opt_buf = buf[:2+l]
        cls = ICMP6._rploptsw.get(t, ICMP6.RPLOption)
        opts.append(cls(opt_buf))
        buf = buf[2+l:]
    return opts


def encode_rpl_opts(opts):
    """Return a bytes string of encoded RPL options."""
    return b''.join([bytes(opt) for opt in opts])


def test_icmp6_rpl():
    from binascii import unhexlify
    # RPL DIO Example
    # ICMPv6 Type 155, Code 1 (DIO), Checksum 0xdead
    # RPL Header: Instance 1, Ver 2, Rank 256 (0x0100), G=0, MOP=1, Prf=0 (0x08), DTSN 3, Flags 0, Rsvd 0
    # DODAGID: fd00::1
    buf = unhexlify(
        '9b01dead' +  # ICMPv6
        '0102010008030000fd000000000000000000000000000001'
    )
    icmp = ICMP6(buf)
    assert icmp.type == ICMP6_RPL_CONTROL
    assert icmp.code == RPL_DIO
    dio = icmp.rpldio
    assert dio.instance_id == 1
    assert dio.version == 2
    assert dio.rank == 0x0100
    assert dio.mop == 1
    assert dio.dodagid == unhexlify('fd000000000000000000000000000001')
    assert bytes(icmp) == buf

    # RPL DIS Example
    buf2 = unhexlify('9b00beef0000')
    icmp2 = ICMP6(buf2)
    assert icmp2.code == RPL_DIS
    assert icmp2.rpldis.flags == 0
    assert bytes(icmp2) == buf2

    # RPL DIO with Options
    # DIO + DODAG Conf (Type 4, Len 14, ...)
    buf3 = unhexlify(
        '9b01abcd' +  # ICMPv6
        '0102010008030000fd000000000000000000000000000001' +  # DIO
        '040e000c080a07000100010000010001'  # DODAG Conf
    )
    icmp3 = ICMP6(buf3)
    assert icmp3.code == RPL_DIO
    assert len(icmp3.rpldio.opts) == 1
    assert isinstance(icmp3.rpldio.opts[0], ICMP6.RPLOptDODAGConf)
    assert icmp3.rpldio.opts[0].dio_int_min == 12
    assert bytes(icmp3) == buf3


if __name__ == '__main__':
    test_icmp6_rpl()
    print('Tests passed.')
