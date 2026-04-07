#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
RPL Shell - A CLI to interact with an RPL network via a SLIP radio.
Supports sending pings (ICMPv6 Echo) and RPL control messages.
"""
from __future__ import print_function
import sys
import os
import time
import struct
import binascii
import threading
import socket

try:
    import readline
except ImportError:
    pass

# Add parent directory to sys.path to find dpkt
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import dpkt
from dpkt.slip import SLIP, decode, encode
from dpkt.ieee802154 import IEEE802154, ADDR_MODE_EXT, ADDR_MODE_SHORT, TYPE_DATA
from dpkt.sixlowpan import SixLoWPAN
from dpkt.ip6 import IP6
from dpkt.icmp6 import (ICMP6, ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY,
                         ICMP6_RPL_CONTROL, RPL_DIO, RPL_DAO, RPL_DAO_ACK)

try:
    import serial
except ImportError:
    print("pyserial not found. Install with: pixi add pyserial")
    serial = None


def icmp6_checksum(src, dst, icmp_bytes):
    """Compute ICMPv6 checksum with IPv6 pseudo-header (RFC 2460)."""
    ph = src + dst + struct.pack('>I', len(icmp_bytes)) + b'\x00\x00\x00\x3a'
    data = ph + icmp_bytes
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

class RPLShell:
    def __init__(self, port, baudrate, dodagid):
        self.port_name = port
        self.baudrate = baudrate
        self.dodagid = binascii.unhexlify(dodagid)
        self.serial = None
        self.running = True
        self.pings = {} # (id, seq) -> start_time
        self.routing_table = {} # target -> parent

    def start(self):
        if not serial: return
        try:
            # serial_for_url handles socket://localhost:1234 as well as /dev/tty...
            self.serial = serial.serial_for_url(self.port_name, baudrate=self.baudrate, timeout=0.1)
            print("Connected to %s." % self.port_name)
            
            # Start reader thread
            t = threading.Thread(target=self.reader_loop)
            t.daemon = True
            t.start()

            # Start periodic DIO thread (RPL Root behavior)
            t2 = threading.Thread(target=self.root_loop)
            t2.daemon = True
            t2.start()
            
            self.shell_loop()
        except Exception as e:
            print("Error: %s" % e)

    def root_loop(self):
        """Background loop to act as RPL Root (sending periodic DIOs)."""
        while self.running:
            self.send_dio()
            # Wait 30 seconds for next DIO (simulating basic trickle)
            time.sleep(30)

    def send_dio(self):
        """Construct and send a broadcast DIO."""
        if not self.serial: return
        dio_icmp = self.create_dio()
        target_mcast = binascii.unhexlify('ff02000000000000000000000000001a')
        ip = IP6(nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=255, src=self.dodagid,
                 dst=target_mcast, data=dio_icmp)

        # Compute ICMPv6 checksum
        dio_icmp.sum = 0
        dio_icmp.sum = icmp6_checksum(ip.src, ip.dst, bytes(dio_icmp))

        src_mac = self.dodagid[-8:]
        lowpan = SixLoWPAN().compress(ip, src_mac=src_mac)
        
        mac = IEEE802154(
            type=TYPE_DATA, seq=0, dst_pan=0xabcd, dst_mode=ADDR_MODE_SHORT,
            dst_addr=b'\xff\xff', src_mode=ADDR_MODE_EXT, src_addr=src_mac,
            pan_id_comp=1, data=bytes(lowpan)
        )
        self.serial.write(encode(bytes(mac)))

    def reader_loop(self):
        buffer = b""
        SLIP_END = b'\xC0'
        while self.running:
            chunk = self.serial.read(100)
            if not chunk: continue
            
            buffer += chunk
            if SLIP_END in chunk:
                pkts = decode(buffer)
                parts = buffer.split(SLIP_END)
                buffer = parts[-1]
                
                for p in pkts:
                    if not p:
                        continue
                    if p.startswith(b'!') or p.startswith(b'#'):
                        continue  # Skip slip-radio commands/logs
                    self.handle_packet(p)

    def handle_packet(self, buf):
        try:
            mac = IEEE802154(buf)
            if mac.type != TYPE_DATA:
                return
            
            lowpan = SixLoWPAN(mac.data)
            ip6_pkt = lowpan.decompress(src_mac=mac.src_addr, dst_mac=mac.dst_addr)

            # 6LoWPAN decompress returns raw bytes as payload - parse ICMPv6
            if ip6_pkt and ip6_pkt.nxt == 58 and isinstance(ip6_pkt.data, bytes):
                try:
                    ip6_pkt.data = ICMP6(ip6_pkt.data)
                except Exception:
                    pass

            if ip6_pkt and isinstance(ip6_pkt.data, ICMP6):
                icmp = ip6_pkt.data
                if icmp.type == ICMP6_ECHO_REPLY:
                    echo = icmp.echo
                    key = (echo.id, echo.seq)
                    if key in self.pings:
                        rtt = (time.time() - self.pings[key]) * 1000
                        print("\nReply from %s: icmp_seq=%d time=%.2f ms" % 
                              (socket.inet_ntop(socket.AF_INET6, ip6_pkt.src), echo.seq, rtt))
                        del self.pings[key]
                    else:
                        print("\nUnsolicited Echo Reply from %s" % socket.inet_ntop(socket.AF_INET6, ip6_pkt.src))
                elif icmp.type == ICMP6_RPL_CONTROL:
                    print("\nReceived RPL Control message (Code %d) from %s" % 
                          (icmp.code, socket.inet_ntop(socket.AF_INET6, ip6_pkt.src)))
                    if icmp.code == dpkt.icmp6.RPL_DIS:  # DIS
                        print("Responding to DIS with DIO...")
                        self.send_dio()
                    elif icmp.code == RPL_DAO:
                        dao = icmp.rpldao
                        target = None
                        parent = None
                        for opt in dao.opts:
                            if isinstance(opt, ICMP6.RPLOptTarget):
                                target = opt.prefix
                            elif isinstance(opt, ICMP6.RPLOptTransitInfo):
                                parent = opt.parent

                        if target and parent:
                            if len(target) < 16:
                                target = target + b'\x00' * (16 - len(target))

                            t_str = socket.inet_ntop(socket.AF_INET6, target)
                            p_str = socket.inet_ntop(socket.AF_INET6, parent)
                            print("\nDAO from %s: Target %s via %s" %
                                  (socket.inet_ntop(socket.AF_INET6, ip6_pkt.src), t_str, p_str))
                            self.routing_table[target] = parent

                        # Send DAO-ACK if K flag is set
                        if dao.k:
                            print("  Sending DAO-ACK to %s" % socket.inet_ntop(socket.AF_INET6, ip6_pkt.src))
                            dao_ack_icmp = self.create_dao_ack(dao)
                            dao_ack_icmp.sum = 0
                            dao_ack_icmp.sum = icmp6_checksum(self.dodagid, ip6_pkt.src, bytes(dao_ack_icmp))
                            ack_ip = IP6(nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=64,
                                         src=self.dodagid, dst=ip6_pkt.src,
                                         data=dao_ack_icmp)
                            src_mac = self.dodagid[-8:]
                            dst_mac = ip6_pkt.src[-8:]
                            lowpan = SixLoWPAN().compress(ack_ip, src_mac=src_mac, dst_mac=dst_mac)
                            mac = IEEE802154(
                                type=TYPE_DATA, seq=0, dst_pan=0xabcd,
                                dst_mode=ADDR_MODE_EXT, dst_addr=dst_mac,
                                src_mode=ADDR_MODE_EXT, src_addr=src_mac,
                                pan_id_comp=1, data=bytes(lowpan)
                            )
                            self.serial.write(encode(bytes(mac)))
        except Exception as e:
            pass # Ignore malformed packets in shell

    def send_ping(self, target_str, seq=1):
        try:
            target = socket.inet_pton(socket.AF_INET6, target_str)
        except socket.error:
            print("Invalid IPv6 address.")
            return

        echo = ICMP6.Echo(id=os.getpid() & 0xFFFF, seq=seq)
        icmp = ICMP6(type=ICMP6_ECHO_REQUEST, data=echo)

        # Compute checksum with final destination (before SRH changes it)
        icmp.sum = 0
        icmp.sum = icmp6_checksum(self.dodagid, target, bytes(icmp))

        # Build IP6
        ip = IP6(nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=64, src=self.dodagid, dst=target, data=icmp)

        # RPL Non-storing: if target is in routing table, we must use Source Routing Header (SRH)
        route = self.get_route(target)
        if len(route) > 1:
            # Route is e.g. [NodeB, NodeA] where NodeA is target.
            # IPv6 Dest should be the first hop (NodeB).
            # SRH contains the rest of the path (NodeA).
            first_hop = route[0]
            srh_hops = route[1:]
            
            srh = dpkt.ip6.IP6RoutingHeader(
                type=3, # RPL Source Route
                segs_left=len(srh_hops),
                len=len(srh_hops) * 2, # each hop is 16 bytes / 8 octets = 2 units
                nxt=dpkt.ip.IP_PROTO_ICMP6,
                addresses=srh_hops
            )
            ip.dst = first_hop
            ip.nxt = dpkt.ip.IP_PROTO_ROUTING
            ip.data = srh
            # Link SRH to ICMP
            srh.data = icmp
            print("Using Source Route: %s" % " -> ".join([socket.inet_ntop(socket.AF_INET6, h) for h in route]))

        # Build 6LoWPAN with IPHC compression
        src_mac = self.dodagid[-8:]
        # L2 dest is the first hop MAC
        dst_mac = ip.dst[-8:]
        lowpan = SixLoWPAN().compress(ip, src_mac=src_mac, dst_mac=dst_mac)
        
        mac = IEEE802154(
            type=TYPE_DATA, seq=seq & 0xFF,
            dst_pan=0xabcd, dst_mode=ADDR_MODE_EXT, dst_addr=dst_mac,
            src_mode=ADDR_MODE_EXT, src_addr=src_mac,
            pan_id_comp=1, data=bytes(lowpan)
        )
        
        self.pings[(echo.id, echo.seq)] = time.time()
        self.serial.write(encode(bytes(mac)))
        print("Pinging %s..." % target_str)

    def get_route(self, target):
        """Return a list of hop addresses from Root to Target (excluding Root, including Target)."""
        path = []
        curr = target
        while curr in self.routing_table:
            path.insert(0, curr)
            curr = self.routing_table[curr]
            if curr == self.dodagid:
                break
        return path

    def create_dio(self):
        dio = ICMP6.RPLDIO(
            instance_id=1, version=1, rank=256,
            dodagid=self.dodagid, mop=1, prf=0, g=1
        )
        dio.opts.append(ICMP6.RPLOptDODAGConf(
            dio_int_min=12, dio_int_doub=8, dio_redun=10,
            max_rank_inc=1792, min_hop_rank_inc=256, ocp=1,
            def_lifetime=30, lifetime_unit=60
        ))
        dio.opts.append(ICMP6.RPLOptPrefixInfo(
            prefix_len=64, l=1, a=1,
            valid_lifetime=86400, pref_lifetime=14400,
            prefix=self.dodagid[:8] + b'\x00' * 8
        ))
        icmp = ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DIO, data=dio)
        return icmp

    def create_dao_ack(self, dao):
        """Create a DAO-ACK in response to a DAO."""
        dao_ack = ICMP6.RPLDAOACK(
            instance_id=dao.instance_id,
            d=dao.d,
            dao_sequence=dao.dao_sequence,
            status=0
        )
        if dao.d and hasattr(dao, 'dodagid') and dao.dodagid:
            dao_ack.dodagid = dao.dodagid
        else:
            dao_ack.dodagid = None
        return ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DAO_ACK, data=dao_ack)

    def shell_loop(self):
        print("RPL Shell. Commands: ping <addr>, routes, dio, exit")
        seq = 1
        while self.running:
            try:
                line = input("rpl> ").strip().split()
                if not line: continue
                
                cmd = line[0].lower()
                if cmd == "exit":
                    self.running = False
                elif cmd == "routes":
                    print("RPL Routing Table (Non-storing):")
                    for t, p in self.routing_table.items():
                        print("  %s -> %s" % (socket.inet_ntop(socket.AF_INET6, t),
                                              socket.inet_ntop(socket.AF_INET6, p)))
                elif cmd == "ping" and len(line) > 1:
                    self.send_ping(line[1], seq)
                    seq += 1
                elif cmd == "dio":
                    print("Sending manual DIO to broadcast...")
                    self.send_dio()
                else:
                    print("Unknown command or missing arguments.")
            except EOFError:
                break
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    PORT = 'socket://localhost:60001'
    DODAGID = 'fd000000000000000000000000000001' 
    shell = RPLShell(PORT, 115200, DODAGID)
    print("Simulation setup:")
    print("1. Start COOJA with ./run_cooja.sh")
    print("2. Start 'Serial Socket Server' on Mote 1 (port 60001)")
    print("3. Target Mote 2 address is likely fd00::202:2:2:2")
    shell.start()
