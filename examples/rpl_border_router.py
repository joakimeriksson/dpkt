#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
RPL Border Router - Bridging Serial Radio (SLIP/802.15.4) and a TUN interface.
This version supports real serial ports and creates a TUN interface on macOS/Linux.
Run with sudo/root privileges for TUN creation.
"""
from __future__ import print_function
import sys
import os
import time
import struct
import binascii
import socket
import threading
import select
from fcntl import ioctl

# Add parent directory to sys.path to find dpkt
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import dpkt
from dpkt.slip import SLIP, decode, encode
from dpkt.ieee802154 import IEEE802154, ADDR_MODE_EXT, ADDR_MODE_SHORT, TYPE_DATA
from dpkt.sixlowpan import SixLoWPAN
from dpkt.ip6 import IP6
from dpkt.icmp6 import ICMP6, ICMP6_RPL_CONTROL, RPL_DIO, RPL_DIS, RPL_DAO, RPL_DAO_ACK
from dpkt.icmp6 import RPL_OPT_DODAG_CONF, RPL_OPT_PREFIX_INFO

try:
    import serial
except ImportError:
    print("pyserial not found. Install with: pixi add pyserial")
    serial = None

# --- TUN Interface Helpers ---

def open_tun_linux(name="tun0"):
    # Standard Linux TUN/TAP opening via /dev/net/tun
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    ioctl(fd, TUNSETIFF, ifr)
    return fd

def open_tun_darwin():
    # macOS utun opening via AF_SYS_CONTROL socket
    # This is complex to do purely in Python without a C extension,
    # but we can try common utun indices.
    SYSPROTO_CONTROL = 2
    AF_SYS_CONTROL = 32
    CTLIOCGINFO = 0xc0644e03
    
    s = socket.socket(AF_SYS_CONTROL, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
    info = struct.pack("I96s", 0, b"com.apple.net.utun_control")
    res = ioctl(s, CTLIOCGINFO, info)
    ctl_id = struct.unpack("I96s", res)[0]
    
    # Try utun0 to utun10
    for i in range(11):
        try:
            addr = struct.pack("IIII", 32, 0, ctl_id, i + 1)
            s.connect(addr)
            print("Opened utun%d" % i)
            return s.fileno()
        except socket.error:
            continue
    raise Exception("Could not open any utun device")

def open_tun():
    if sys.platform == 'linux':
        return open_tun_linux()
    elif sys.platform == 'darwin':
        return open_tun_darwin()
    else:
        raise NotImplementedError("TUN not supported on %s" % sys.platform)

# --- Border Router Class ---

class RPLBorderRouter:
    def __init__(self, port, baudrate, dodagid, prefix):
        self.port_name = port
        self.baudrate = baudrate
        self.dodagid = binascii.unhexlify(dodagid)
        self.prefix = binascii.unhexlify(prefix)
        self.serial = None
        self.tun_fd = None
        self.running = True

    def setup(self):
        if serial:
            try:
                self.serial = serial.serial_for_url(self.port_name, baudrate=self.baudrate, timeout=0.1)
                print("Connected to %s." % self.port_name)
            except Exception as e:
                print("Failed to connect to serial: %s" % e)
        
        try:
            self.tun_fd = open_tun()
            print("Opened TUN interface (fd=%d)" % self.tun_fd)
            # You might need to run 'ifconfig utunX inet6 fd00::1/64 up' manually 
            # or add a helper here to do it via os.system.
        except Exception as e:
            print("Failed to open TUN interface: %s" % e)

    def create_dio(self):
        dio = ICMP6.RPLDIO(
            instance_id=1, version=1, rank=256,
            dodagid=self.dodagid, mop=1, prf=0, g=1
        )
        dio.opts.append(ICMP6.RPLOptDODAGConf(
            dio_int_min=12, dio_int_doub=8, dio_redun=10,
            max_rank_inc=1792, min_hop_rank_inc=256, ocp=1
        ))
        dio.opts.append(ICMP6.RPLOptPrefixInfo(
            prefix_len=64, l=1, a=1,
            valid_lifetime=86400, pref_lifetime=14400,
            prefix=self.prefix
        ))
        icmp = ICMP6(type=ICMP6_RPL_CONTROL, code=RPL_DIO, data=dio)
        return icmp

    def serial_to_tun(self):
        """Read from serial (SLIP -> 802.15.4 -> 6LoWPAN) and write to TUN."""
        buffer = b""
        while self.running:
            if not self.serial:
                time.sleep(1)
                continue
                
            chunk = self.serial.read(100)
            if not chunk:
                continue
            
            buffer += chunk
            if SLIP_END in chunk:
                pkts = decode(buffer)
                # Keep the last partial packet in buffer
                parts = buffer.split(bytes([SLIP_END]))
                buffer = parts[-1]
                
                for p in pkts:
                    try:
                        mac = IEEE802154(p)
                        if mac.type != TYPE_DATA: continue
                        
                        lowpan = SixLoWPAN(mac.data)
                        ip6_pkt = lowpan.decompress(src_mac=mac.src_addr, dst_mac=mac.dst_addr)
                        
                        if ip6_pkt:
                            print("Serial->TUN: IPv6 %s -> %s" % (binascii.hexlify(ip6_pkt.src), binascii.hexlify(ip6_pkt.dst)))
                            # On macOS utun, packets need a 4-byte family header (usually AF_INET6)
                            if sys.platform == 'darwin':
                                os.write(self.tun_fd, struct.pack(">I", socket.AF_INET6) + bytes(ip6_pkt))
                            else:
                                os.write(self.tun_fd, bytes(ip6_pkt))
                    except Exception as e:
                        print("Error processing serial packet: %s" % e)

    def tun_to_serial(self):
        """Read from TUN (IPv6) and write to serial (6LoWPAN -> 802.15.4 -> SLIP)."""
        while self.running:
            if self.tun_fd is None or not self.serial:
                time.sleep(1)
                continue
            
            try:
                # Read from TUN
                r, _, _ = select.select([self.tun_fd], [], [], 1.0)
                if not r: continue
                
                pkt_data = os.read(self.tun_fd, 2048)
                if sys.platform == 'darwin':
                    # Skip the 4-byte family header on macOS
                    pkt_data = pkt_data[4:]
                
                ip6_pkt = IP6(pkt_data)
                print("TUN->Serial: IPv6 %s -> %s" % (binascii.hexlify(ip6_pkt.src), binascii.hexlify(ip6_pkt.dst)))
                
                # IPHC compression
                src_mac = self.dodagid[-8:]
                dst_mac = b'\xff\xff' if ip6_pkt.dst[0] == 0xff else ip6_pkt.dst[-8:]
                lowpan = SixLoWPAN().compress(ip6_pkt, src_mac=src_mac, dst_mac=dst_mac)
                
                # Wrap in 802.15.4
                mac = IEEE802154(
                    type=TYPE_DATA, seq=0,
                    dst_pan=0xabcd, dst_mode=ADDR_MODE_EXT if len(dst_mac)==8 else ADDR_MODE_SHORT,
                    dst_addr=dst_mac, src_mode=ADDR_MODE_EXT,
                    src_addr=src_mac,
                    pan_id_comp=1, data=bytes(lowpan)
                )
                
                self.serial.write(encode(bytes(mac)))
            except Exception as e:
                print("Error processing TUN packet: %s" % e)

    def run(self):
        self.setup()
        
        # Start threads
        t1 = threading.Thread(target=self.serial_to_tun)
        t2 = threading.Thread(target=self.tun_to_serial)
        t1.start()
        t2.start()
        
        print("Border Router is active. Press Ctrl+C to stop.")
        try:
            while True:
                # Periodic DIO
                if self.serial:
                    dio = self.create_dio()
                    # Wrap DIO in IP6
                    ip = IP6(nxt=dpkt.ip.IP_PROTO_ICMP6, hlim=255, src=self.dodagid,
                             dst=binascii.unhexlify('ff02000000000000000000000000001a'), data=dio)
                    
                    # IPHC compression
                    src_mac = self.dodagid[-8:]
                    lowpan = SixLoWPAN().compress(ip, src_mac=src_mac)
                    
                    mac = IEEE802154(
                        type=TYPE_DATA, seq=0, dst_pan=0xabcd, dst_mode=ADDR_MODE_SHORT,
                        dst_addr=b'\xff\xff', src_mode=ADDR_MODE_EXT, src_addr=src_mac,
                        pan_id_comp=1, data=bytes(lowpan)
                    )
                    self.serial.write(encode(bytes(mac)))
                time.sleep(10)
        except KeyboardInterrupt:
            self.running = False
            t1.join()
            t2.join()

if __name__ == "__main__":
    SLIP_END = 0xC0
    # Example Config
    PORT = '/dev/tty.usbserial-xxx'
    BAUD = 115200
    DODAGID = 'fd000000000000000000000000000001'
    PREFIX  = 'fd000000000000000000000000000000'
    
    br = RPLBorderRouter(PORT, BAUD, DODAGID, PREFIX)
    br.run()
