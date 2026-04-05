# -*- coding: utf-8 -*-
"""Serial Line IP (SLIP)."""
from __future__ import absolute_import

from . import dpkt
from .compat import compat_ord

SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD

class SLIP(dpkt.Packet):
    """Serial Line IP (SLIP)."""
    def unpack(self, buf):
        # SLIP is a framing protocol, often used to wrap other packets.
        # This implementation handles unescaping.
        res = []
        i = 0
        while i < len(buf):
            b = compat_ord(buf[i])
            if b == SLIP_ESC:
                if i + 1 < len(buf):
                    next_b = compat_ord(buf[i+1])
                    if next_b == SLIP_ESC_END:
                        res.append(SLIP_END)
                        i += 2
                        continue
                    elif next_b == SLIP_ESC_ESC:
                        res.append(SLIP_ESC)
                        i += 2
                        continue
            res.append(b)
            i += 1
        self.data = bytes(bytearray(res))

    def __bytes__(self):
        # This implementation handles escaping.
        res = []
        for b in bytearray(self.data):
            if b == SLIP_END:
                res.extend([SLIP_ESC, SLIP_ESC_END])
            elif b == SLIP_ESC:
                res.extend([SLIP_ESC, SLIP_ESC_ESC])
            else:
                res.append(b)
        return bytes(bytearray(res))

def decode(buf):
    """Decode a stream of bytes containing SLIP-framed packets."""
    packets = []
    for chunk in buf.split(bytes(bytearray([SLIP_END]))):
        if chunk:
            packets.append(SLIP(chunk).data)
    return packets

def encode(buf):
    """Encode a packet into a SLIP-framed byte string."""
    return bytes(bytearray([SLIP_END])) + bytes(SLIP(data=buf)) + bytes(bytearray([SLIP_END]))

def test_slip():
    data = b'hello' + bytes(bytearray([SLIP_END])) + b'world' + bytes(bytearray([SLIP_ESC]))
    encoded = SLIP(data=data)
    assert bytes(encoded) == b'hello' + bytes(bytearray([SLIP_ESC, SLIP_ESC_END])) + b'world' + bytes(bytearray([SLIP_ESC, SLIP_ESC_ESC]))
    
    decoded = SLIP(bytes(encoded))
    assert decoded.data == data
    
    # Test stream decoding
    stream = encode(b'pkt1') + encode(b'pkt2')
    pkts = decode(stream)
    assert pkts == [b'pkt1', b'pkt2']

if __name__ == '__main__':
    test_slip()
    print('Tests passed.')
