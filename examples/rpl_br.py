#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Native RPL Border Router in Python.
Communicates with a slip-radio mote via SLIP, sending raw 802.15.4 frames.
Implements RPL root (Non-storing), 6LoWPAN IPHC, and basic ND.
"""
from __future__ import print_function
import sys
import os
import time
import struct
import binascii
import threading
import socket
import select
import argparse

try:
    import readline
except ImportError:
    pass

# Add parent directory to sys.path to find dpkt
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import dpkt
from dpkt.slip import decode, encode
from dpkt.ieee802154 import IEEE802154, ADDR_MODE_EXT, ADDR_MODE_SHORT, TYPE_DATA
from dpkt.sixlowpan import SixLoWPAN, derive_ip6_addr
from dpkt.ip6 import IP6, IP6RoutingHeader
from dpkt.icmp6 import (ICMP6, ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY,
                         ICMP6_RPL_CONTROL, RPL_DIO, RPL_DIS, RPL_DAO, RPL_DAO_ACK)

try:
    import serial
except ImportError:
    serial = None

# ICMPv6 ND constants
ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERT = 136


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


class RPLBorderRouter:
    def __init__(self, port, prefix, use_tun=False):
        self.port_name = port
        self.prefix = binascii.unhexlify(prefix)[:8]  # 8-byte prefix
        self.mac = None  # Set from ?M response
        self.dodagid = None  # Set after MAC received
        self.link_local = None  # fe80:: + IID
        self.use_tun = use_tun
        self.serial = None
        self.tun_fd = None
        self.running = True
        self.mac_ready = threading.Event()
        self.routing_table = {}
        self.neighbors = {}  # IPv6 addr -> L2 MAC (from received packets)
        self.pings = {}
        self.mac_seq = 0

    def start(self):
        if not serial:
            print("Error: pyserial not installed.")
            return
        try:
            self.serial = serial.serial_for_url(self.port_name, baudrate=115200, timeout=0.1)
            print("Connected to %s" % self.port_name)

            # Request MAC from slip-radio
            self.request_mac()

            if self.use_tun:
                self.tun_fd = self._open_tun()
                if self.tun_fd:
                    threading.Thread(target=self.tun_loop, daemon=True).start()

            threading.Thread(target=self.reader_loop, daemon=True).start()
            threading.Thread(target=self.root_loop, daemon=True).start()
            self.shell_loop()
        except Exception as e:
            print("Error: %s" % e)

    def request_mac(self):
        self.log("Requesting MAC from radio...")
        self.serial.write(encode(b'?M'))

    def set_radio_channel(self, channel=26):
        """Set radio channel via !V command."""
        # RADIO_PARAM_CHANNEL = 0
        self.serial.write(encode(b'!V' + struct.pack('>HH', 0, channel)))

    def handle_radio_command(self, data):
        self.log("Radio cmd: %s (%d bytes)" % (
            data[:2].decode(errors='replace'), len(data)))
        if data.startswith(b'!M'):
            self.mac = data[2:10]
            # Derive addresses from MAC (U/L bit flip per RFC 4862)
            iid = bytearray(self.mac)
            iid[0] ^= 0x02
            self.dodagid = self.prefix + bytes(iid)
            self.link_local = b'\xfe\x80' + b'\x00' * 6 + bytes(iid)
            self.log("Radio MAC: %s" % binascii.hexlify(self.mac).decode())
            self.log("DODAGID:   %s" % socket.inet_ntop(socket.AF_INET6, self.dodagid))
            self.log("Link-local: %s" % socket.inet_ntop(socket.AF_INET6, self.link_local))
            self.mac_ready.set()
        elif data.startswith(b'!R'):
            status = data[3] if len(data) > 3 else -1
            tx = data[4] if len(data) > 4 else 0
            self.log("Radio: TX report status=%d tx=%d" % (status, tx))

    # --- RPL Messages ---

    def create_dio(self):
        dio = ICMP6.RPLDIO(instance_id=1, version=1, rank=256,
                           dodagid=self.dodagid, mop=1, prf=0, g=1)
        dio.opts.append(ICMP6.RPLOptDODAGConf(
            dio_int_min=12, dio_int_doub=8, dio_redun=10,
            max_rank_inc=1792, min_hop_rank_inc=256, ocp=1,
            def_lifetime=30, lifetime_unit=60))
        dio.opts.append(ICMP6.RPLOptPrefixInfo(
            prefix_len=64, l=1, a=1,
            valid_lifetime=86400, pref_lifetime=14400,
            prefix=self.prefix + b'\x00' * 8))
        return ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DIO, data=dio)

    def create_dao_ack(self, dao):
        # Contiki-NG sends 4-byte DAO-ACK: instance_id, flags(0), sequence, status
        # No DODAGID (D=0), matching rpl_icmp6_dao_ack_output()
        dao_ack = ICMP6.RPLDAOACK(
            instance_id=dao.instance_id, d=0,
            dao_sequence=dao.dao_sequence, status=0)
        dao_ack.dodagid = None
        return ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DAO_ACK, data=dao_ack)

    def create_na(self, target_ip, dst_ip):
        """Create Neighbor Advertisement for target_ip."""
        # NA: flags(4) + target(16) + TLLAO option(8)
        # Flags: R=1 (router), S=1 (solicited), O=1 (override) = 0xE0000000
        flags = struct.pack('>I', 0xE0000000)
        # Target Link-Layer Address Option (type=2, len=2 (16 bytes), + 6 padding for 8-byte addr)
        tllao = struct.pack('BB', 2, 2) + self.mac + b'\x00' * 6
        na_data = flags + target_ip + tllao
        icmp = ICMP6(type=ND_NEIGHBOR_ADVERT, code=0)
        icmp.data = na_data
        return icmp

    # --- Sending ---

    def send_to_radio(self, ip6_pkt):
        """Send an IPv6 packet over radio."""
        if not self.mac:
            return

        # Compute ICMPv6 checksum before SRH modifies dst
        if isinstance(ip6_pkt.data, ICMP6):
            ip6_pkt.data.sum = 0
            icmp_bytes = bytes(ip6_pkt.data)
            ip6_pkt.data.sum = icmp6_checksum(ip6_pkt.src, ip6_pkt.dst, icmp_bytes)

        # Source routing for non-storing mode
        route = self.get_route(ip6_pkt.dst)
        if len(route) > 1:
            first_hop = route[0]
            srh_hops = route[1:]
            srh = IP6RoutingHeader(type=3, segs_left=len(srh_hops),
                                   len=len(srh_hops) * 2,
                                   nxt=ip6_pkt.nxt, addresses=srh_hops)
            ip6_pkt.nxt = dpkt.ip.IP_PROTO_ROUTING
            srh.data = ip6_pkt.data
            ip6_pkt.data = srh
            ip6_pkt.dst = first_hop

        # MAC addressing — use neighbor table learned from received packets
        is_mcast = ip6_pkt.dst[0] == 0xff
        if is_mcast:
            dst_mac = b'\xff\xff'
            dst_mode = ADDR_MODE_SHORT
        elif ip6_pkt.dst in self.neighbors:
            dst_mac = self.neighbors[ip6_pkt.dst]
            dst_mode = ADDR_MODE_EXT
        else:
            # No neighbor entry — use raw IID as MAC (best effort)
            dst_mac = ip6_pkt.dst[-8:]
            dst_mode = ADDR_MODE_EXT
            self.log("Warning: no neighbor for %s, using IID as MAC" %
                     socket.inet_ntop(socket.AF_INET6, ip6_pkt.dst))

        lowpan = SixLoWPAN().compress(ip6_pkt, src_mac=self.mac, dst_mac=dst_mac)

        self.mac_seq = (self.mac_seq + 1) & 0xff
        mac_frame = IEEE802154(type=TYPE_DATA, seq=self.mac_seq, dst_pan=0xabcd,
                               dst_addr=dst_mac, dst_mode=dst_mode,
                               src_mode=ADDR_MODE_EXT, src_addr=self.mac,
                               pan_id_comp=1, ar=1, data=bytes(lowpan))

        frame = bytes(mac_frame)
        # Send via slip-radio !S command: !S + packet_id + attr_count(0) + frame
        cmd = b'!S' + bytes([self.mac_seq]) + b'\x00' + frame
        self.serial.write(encode(cmd))

    def get_route(self, target):
        path = []
        curr = target
        while curr in self.routing_table:
            path.insert(0, curr)
            curr = self.routing_table[curr]
            if curr == self.dodagid:
                break
        return path

    # --- Receiving ---

    def handle_mac_frame(self, p):
        if len(p) < 5:
            return
        try:
            mac = IEEE802154(p)
        except dpkt.dpkt.NeedData:
            return
        if mac.type != TYPE_DATA:
            return

        src_str = binascii.hexlify(mac.src_addr).decode() if mac.src_addr else "?"
        dst_str = binascii.hexlify(mac.dst_addr).decode() if mac.dst_addr else "?"

        try:
            lowpan = SixLoWPAN(mac.data)
            ip6 = lowpan.decompress(src_mac=mac.src_addr, dst_mac=mac.dst_addr if mac.dst_addr else self.mac)
        except Exception as e:
            self.log("6LoWPAN error [%s→%s]: %s data=%s" % (
                src_str, dst_str, e, binascii.hexlify(mac.data[:20]).decode()))
            return

        if not ip6:
            return

        # Parse ICMPv6 payload
        if ip6.nxt == 58 and isinstance(ip6.data, bytes):
            try:
                ip6.data = ICMP6(ip6.data)
            except Exception:
                pass

        # Learn neighbor: map IPv6 source → L2 MAC from this frame
        if mac.src_addr and len(mac.src_addr) == 8:
            self.neighbors[ip6.src] = mac.src_addr
            # Also map link-local and global addresses derived from this MAC
            ll = derive_ip6_addr(b'\xfe\x80' + b'\x00' * 6, mac.src_addr)
            self.neighbors[ll] = mac.src_addr
            gl = derive_ip6_addr(self.prefix, mac.src_addr)
            self.neighbors[gl] = mac.src_addr

        ip_src = socket.inet_ntop(socket.AF_INET6, ip6.src)
        ip_dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)

        # Describe and handle
        if isinstance(ip6.data, ICMP6):
            icmp = ip6.data
            self._log_icmp(ip_src, ip_dst, icmp)
            self._handle_icmp(ip6, icmp)
        elif ip6.nxt == 17:
            # UDP
            udp_data = ip6.data if isinstance(ip6.data, bytes) else bytes(ip6.data)
            if len(udp_data) >= 8:
                src_port = (udp_data[0] << 8) | udp_data[1]
                dst_port = (udp_data[2] << 8) | udp_data[3]
                payload = udp_data[8:]
                self.log("Recv %s:%d -> %s:%d UDP [%d] %s" % (
                    ip_src, src_port, ip_dst, dst_port, len(payload),
                    payload.decode(errors='replace')))
            else:
                self.log("Recv %s -> %s UDP (%d bytes)" % (ip_src, ip_dst, len(udp_data)))
        else:
            self.log("Recv %s -> %s proto=%d %d bytes" % (ip_src, ip_dst, ip6.nxt, len(ip6.data)))

        # TUN bridge
        if self.use_tun and self.tun_fd:
            hdr = struct.pack(">I", socket.AF_INET6) if sys.platform == 'darwin' else b''
            os.write(self.tun_fd, hdr + bytes(ip6))

    def _log_icmp(self, ip_src, ip_dst, icmp):
        if icmp.type == ICMP6_ECHO_REQUEST:
            desc = "Echo Request"
        elif icmp.type == ICMP6_ECHO_REPLY:
            desc = "Echo Reply"
        elif icmp.type == ND_NEIGHBOR_SOLICIT:
            target = icmp.data[4:20] if len(icmp.data) >= 20 else b''
            desc = "NS for %s" % socket.inet_ntop(socket.AF_INET6, target) if len(target) == 16 else "NS"
        elif icmp.type == ND_NEIGHBOR_ADVERT:
            desc = "NA"
        elif icmp.type == ICMP6_RPL_CONTROL:
            names = {RPL_DIS: "DIS", RPL_DIO: "DIO", RPL_DAO: "DAO", RPL_DAO_ACK: "DAO-ACK"}
            desc = "RPL %s" % names.get(icmp.code, "code=%d" % icmp.code)
            if icmp.code == RPL_DIO and hasattr(icmp, 'rpldio'):
                desc += " rank=%d" % icmp.rpldio.rank
            elif icmp.code == RPL_DAO and hasattr(icmp, 'rpldao'):
                desc += " seq=%d k=%d" % (icmp.rpldao.dao_sequence, icmp.rpldao.k)
        else:
            desc = "ICMPv6 type=%d code=%d" % (icmp.type, icmp.code)
        self.log("Recv %s -> %s %s" % (ip_src, ip_dst, desc))

    def _handle_icmp(self, ip6, icmp):
        if icmp.type == ICMP6_ECHO_REQUEST:
            # Respond to ping
            echo = icmp.echo
            reply_echo = ICMP6.Echo(id=echo.id, seq=echo.seq)
            reply = ICMP6(type=ICMP6_ECHO_REPLY, data=reply_echo)
            self.send_to_radio(IP6(nxt=58, hlim=64, src=self.dodagid,
                                   dst=ip6.src, data=reply))
            self.log("  Sent Echo Reply")

        elif icmp.type == ICMP6_ECHO_REPLY:
            key = (icmp.echo.id, icmp.echo.seq)
            if key in self.pings:
                self.log("  RTT: %.2fms" % ((time.time() - self.pings[key]) * 1000))
                del self.pings[key]

        elif icmp.type == ND_NEIGHBOR_SOLICIT:
            # Respond to NS with NA
            if len(icmp.data) >= 20:
                target = icmp.data[4:20]
                if target == self.dodagid or target == self.link_local:
                    self.log("  Responding with NA")
                    na = self.create_na(target, ip6.src)
                    self.send_to_radio(IP6(nxt=58, hlim=255, src=self.dodagid,
                                           dst=ip6.src, data=na))

        elif icmp.type == ICMP6_RPL_CONTROL:
            if icmp.code == RPL_DIS:
                self.log("  Responding with DIO")
                self.send_to_radio(IP6(nxt=58, hlim=255, src=self.link_local,
                                       dst=ip6.src, data=self.create_dio()))

            elif icmp.code == RPL_DIO:
                pass  # We're root, just observe

            elif icmp.code == RPL_DAO:
                dao = icmp.rpldao
                target, parent = None, None
                for opt in dao.opts:
                    if isinstance(opt, ICMP6.RPLOptTarget):
                        target = opt.prefix
                    elif isinstance(opt, ICMP6.RPLOptTransitInfo):
                        parent = opt.parent
                if target and parent:
                    if len(target) < 16:
                        target += b'\x00' * (16 - len(target))
                    self.routing_table[target] = parent
                    self.log("  Route: %s via %s" % (
                        socket.inet_ntop(socket.AF_INET6, target),
                        socket.inet_ntop(socket.AF_INET6, parent)))
                if dao.k:
                    # Use global address for DAO-ACK so SRH works for multi-hop
                    dao_ack_dst = target if target else ip6.src
                    self.log("  Sending DAO-ACK to %s" % socket.inet_ntop(socket.AF_INET6, dao_ack_dst))
                    ack = self.create_dao_ack(dao)
                    self.send_to_radio(IP6(nxt=58, hlim=64, src=self.dodagid,
                                           dst=dao_ack_dst, data=ack))

    # --- Serial I/O ---

    def reader_loop(self):
        buffer = b""
        SLIP_END = b'\xC0'
        while self.running:
            chunk = self.serial.read(256)
            if not chunk:
                continue
            buffer += chunk
            if SLIP_END in chunk:
                pkts = decode(buffer)
                buffer = buffer.split(SLIP_END)[-1]
                for p in pkts:
                    if not p:
                        continue
                    try:
                        if p.startswith(b'!'):
                            self.handle_radio_command(p)
                        elif p.startswith(b'E'):
                            self.log("Radio ERROR: %s" % p.decode(errors='replace').strip())
                        elif p.startswith(b'#'):
                            self.log("Radio: %s" % p[1:].decode(errors='replace').strip())
                        elif len(p) >= 5:
                            self.handle_mac_frame(p)
                    except Exception as e:
                        import traceback
                        self.log("Error: %s\n%s" % (e, traceback.format_exc()))

    def tun_loop(self):
        while self.running:
            r, _, _ = select.select([self.tun_fd], [], [], 1.0)
            if not r:
                continue
            data = os.read(self.tun_fd, 2048)
            if sys.platform == 'darwin':
                data = data[4:]
            try:
                self.send_to_radio(IP6(data))
            except Exception as e:
                self.log("TUN error: %s" % e)

    # --- RPL Root Loop ---

    def root_loop(self):
        self.log("Waiting for radio MAC...")
        self.mac_ready.wait(timeout=10)
        if not self.mac:
            self.log("No MAC received, sending DIOs with default address")
        while self.running:
            self.send_dio_broadcast()
            time.sleep(30)

    def send_dio_broadcast(self):
        if not self.dodagid:
            return
        # DIO source must be link-local so nodes add us as a link-local
        # neighbor. Link-local is always on-link, enabling the RPL probe.
        self.send_to_radio(IP6(
            nxt=58, hlim=255, src=self.link_local,
            dst=binascii.unhexlify('ff02000000000000000000000000001a'),
            data=self.create_dio()))

    # --- Shell ---

    def log(self, msg):
        if sys.stdin.isatty():
            print("\r\033[K%s" % msg)
            sys.stdout.write("rpl-br> ")
            sys.stdout.flush()
        else:
            print(msg)

    def shell_loop(self):
        print("RPL Border Router. Type 'help' for commands.")
        seq = 1
        while self.running:
            try:
                line = input("rpl-br> ").strip().split()
                if not line:
                    continue
                cmd = line[0].lower()
                if cmd in ("exit", "quit"):
                    self.running = False
                    break
                elif cmd == "help":
                    print("  info, routes, dio, ping <addr>, exit")
                elif cmd == "info":
                    print("DODAGID:    %s" % (socket.inet_ntop(socket.AF_INET6, self.dodagid) if self.dodagid else "not set"))
                    print("Link-local: %s" % (socket.inet_ntop(socket.AF_INET6, self.link_local) if self.link_local else "not set"))
                    print("Radio MAC:  %s" % (binascii.hexlify(self.mac).decode() if self.mac else "not set"))
                    print("Prefix:     %s/64" % socket.inet_ntop(socket.AF_INET6, self.prefix + b'\x00' * 8))
                    print("MOP: 1 (Non-storing), Routes: %d" % len(self.routing_table))
                elif cmd == "routes":
                    if not self.routing_table:
                        print("  (empty)")
                    for t, p in self.routing_table.items():
                        print("  %s -> %s" % (socket.inet_ntop(socket.AF_INET6, t),
                                              socket.inet_ntop(socket.AF_INET6, p)))
                elif cmd == "dio":
                    self.send_dio_broadcast()
                    print("DIO sent")
                elif cmd == "ping" and len(line) > 1:
                    try:
                        target = socket.inet_pton(socket.AF_INET6, line[1])
                        echo = ICMP6.Echo(id=os.getpid() & 0xFFFF, seq=seq)
                        self.pings[(echo.id, echo.seq)] = time.time()
                        self.send_to_radio(IP6(nxt=58, hlim=64, src=self.dodagid, dst=target,
                                               data=ICMP6(type=ICMP6_ECHO_REQUEST, data=echo)))
                        print("Ping %s seq=%d" % (line[1], seq))
                        seq += 1
                    except Exception as e:
                        print("Error: %s" % e)
                else:
                    print("Unknown: %s" % cmd)
            except (EOFError, KeyboardInterrupt):
                self.running = False
                break

    @staticmethod
    def _open_tun():
        from fcntl import ioctl
        if sys.platform == 'linux':
            fd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", b"tun0", 0x0001 | 0x1000)
            ioctl(fd, 0x400454ca, ifr)
            return fd
        elif sys.platform == 'darwin':
            s = socket.socket(32, socket.SOCK_DGRAM, 2)
            info = struct.pack("I96s", 0, b"com.apple.net.utun_control")
            res = ioctl(s, 0xc0644e03, info)
            ctl_id = struct.unpack("I96s", res)[0]
            for i in range(11):
                try:
                    s.connect(struct.pack("IIII", 32, 0, ctl_id, i + 1))
                    print("Opened utun%d" % i)
                    return s.fileno()
                except socket.error:
                    continue
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RPL Border Router (Python)")
    parser.add_argument("port", nargs='?', default="socket://localhost:60001",
                        help="Serial port (default: socket://localhost:60001)")
    parser.add_argument("--prefix", default="fd00000000000000",
                        help="IPv6 /64 prefix hex (default: fd00::)")
    parser.add_argument("--tun", action="store_true", help="Enable TUN bridging")
    args = parser.parse_args()
    RPLBorderRouter(args.port, args.prefix, args.tun).start()
