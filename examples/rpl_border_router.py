#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
RPL Border Router Example using Contiki-NG Serial Radio protocol.
"""
from __future__ import print_function
import sys
import os
import time
import struct
import binascii

# Add parent directory to sys.path to find dpkt
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import dpkt
from dpkt.slip import SLIP, decode, encode
from dpkt.ieee802154 import IEEE802154, ADDR_MODE_EXT, ADDR_MODE_SHORT, TYPE_DATA
from dpkt.sixlowpan import SixLoWPAN
from dpkt.ip6 import IP6
from dpkt.icmp6 import ICMP6, ICMP6_RPL_CONTROL, RPL_DIO, RPL_DIS, RPL_DAO, RPL_DAO_ACK
from dpkt.icmp6 import RPL_OPT_DODAG_CONF, RPL_OPT_PREFIX_INFO

def create_dio(instance_id=1, version=1, rank=256, dodagid=None, prefix=None):
    if dodagid is None:
        dodagid = b'\xfd\x00' + b'\x00' * 14
    
    dio = ICMP6.RPLDIO(
        instance_id=instance_id,
        version=version,
        rank=rank,
        dodagid=dodagid,
        mop=1, # Non-storing
        prf=0,
        g=0
    )
    
    # Add DODAG Config Option
    dio.opts.append(ICMP6.RPLOptDODAGConf(
        dio_int_min=12,
        dio_int_doub=8,
        dio_redun=10,
        max_rank_inc=1792,
        min_hop_rank_inc=256,
        ocp=1 # MRHOF
    ))
    
    # Add Prefix Info Option
    if prefix:
        dio.opts.append(ICMP6.RPLOptPrefixInfo(
            prefix_len=64,
            l=1, a=1,
            valid_lifetime=86400,
            pref_lifetime=14400,
            prefix=prefix
        ))
    
    icmp = ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DIO, data=dio)
    # Checksum will be calculated by IP6 or manually
    return icmp

def main():
    print("RPL Border Router starting...")
    
    # Configuration
    SERIAL_PORT = '/dev/tty.usbserial-xxx' # Change to your serial port
    BAUDRATE = 115200
    DODAGID = binascii.unhexlify('fd000000000000000000000000000001')
    PREFIX = binascii.unhexlify('fd000000000000000000000000000000')
    
    # Create a DIO packet
    dio_icmp = create_dio(dodagid=DODAGID, prefix=PREFIX)
    
    # Wrap in IP6
    ip = IP6(nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=255)
    ip.src = DODAGID
    ip.dst = binascii.unhexlify('ff02000000000000000000000000001a') # all-rpl-nodes
    ip.data = dio_icmp
    
    # Note: dpkt doesn't automatically calculate ICMPv6 checksum across IP6 header.
    # We'd need a helper for that if we were sending real packets.
    
    print("Formed DIO packet:")
    print(binascii.hexlify(bytes(ip)))
    
    # Mock loop for demonstration
    print("\nListening for packets (MOCK)...")
    
    # Mock a SLIP-framed 802.15.4 frame containing a RPL DIS
    # Contiki-NG serial-radio uses 0x41 ('A') as prefix for 802.15.4 frames in some versions,
    # or just raw SLIP.
    
    # IEEE 802.15.4 Data Frame, Seq 1, PAN 0xabcd, Dst fd00::1 (ext), Src Short 0x0002
    # This is just a placeholder for the mock.
    mock_mac = IEEE802154(
        type=TYPE_DATA,
        seq=1,
        dst_pan=0xabcd,
        dst_mode=ADDR_MODE_EXT,
        dst_addr=DODAGID[-8:],
        src_mode=ADDR_MODE_SHORT,
        src_addr=b'\x00\x02',
        pan_id_comp=1
    )
    
    # 6LoWPAN IPHC DIS
    # For now let's just use uncompressed IPv6 DIS for simplicity in mock
    dis_icmp = ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DIS, data=ICMP6.RPLDIS())
    dis_ip = IP6(nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=1, src=b'\xfe\x80' + b'\x00'*6 + b'\x00\x00\x00\xff\xfe\x00\x00\x02', dst=ip.dst, data=dis_icmp)
    
    mock_mac.data = b'\x41' + bytes(dis_ip) # 0x41 is DISPATCH_IPV6
    
    slip_pkt = encode(bytes(mock_mac))
    
    # Process the mock packet
    print("Received mock SLIP packet (len %d)" % len(slip_pkt))
    
    pkts = decode(slip_pkt)
    for p in pkts:
        mac = IEEE802154(p)
        print("MAC: Type=%d, Src=%s, Dst=%s" % (mac.type, binascii.hexlify(mac.src_addr) if mac.src_addr else "None", binascii.hexlify(mac.dst_addr) if mac.dst_addr else "None"))
        
        lowpan = SixLoWPAN(mac.data)
        ip6_pkt = lowpan.decompress(src_mac=mac.src_addr, dst_mac=mac.dst_addr)
        
        if ip6_pkt:
            print("IPv6: Src=%s, Dst=%s, Next=%d" % (binascii.hexlify(ip6_pkt.src), binascii.hexlify(ip6_pkt.dst), ip6_pkt.nxt))
            if isinstance(ip6_pkt.data, ICMP6):
                icmp = ip6_pkt.data
                if icmp.type == ICMP6_RPL_CONTROL:
                    print("RPL Control: Code=%d" % icmp.code)
                    if icmp.code == RPL_DIS:
                        print("Received DIS! Sending DIO...")
                        # In a real app, we'd send the DIO back over SLIP

if __name__ == "__main__":
    main()
