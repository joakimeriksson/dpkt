#!/usr/bin/env python
import os
import socket
import dpkt
import struct
import time
import select

def encode_int(val):
    """Encode integer to LWM2M binary format (1, 2, 4, or 8 bytes)."""
    if -128 <= val <= 127:
        return struct.pack('b', val)
    elif -32768 <= val <= 32767:
        return struct.pack('>h', val)
    elif -2147483648 <= val <= 2147483647:
        return struct.pack('>i', val)
    else:
        return struct.pack('>q', val)

def decode_int(val):
    """Decode LWM2M binary integer."""
    if len(val) == 1: return struct.unpack('b', val)[0]
    if len(val) == 2: return struct.unpack('>h', val)[0]
    if len(val) == 4: return struct.unpack('>i', val)[0]
    if len(val) == 8: return struct.unpack('>q', val)[0]
    return 0

def encode_float(val):
    """Encode float to LWM2M binary format (4 or 8 bytes IEEE 754)."""
    return struct.pack('>f', val) # 4-byte float

def default_bind_host(server_host, server_port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((server_host, server_port))
        return probe.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        probe.close()

def run_leshan_agent():
    SERVER_HOST = os.environ.get('LESHAN_HOST', 'leshan.eclipseprojects.io')
    SERVER_PORT = 5683
    BIND_HOST = os.environ.get('LWM2M_BIND_HOST', default_bind_host(SERVER_HOST, SERVER_PORT))
    ENDPOINT = 'dpkt-agent-2026'
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_HOST, 5685))
    sock.setblocking(0)

    def send_reg(is_update=False):
        # Register Object 3 (Device), 6 (Location), and 3303 (Temperature)
        reg = dpkt.coap.CoAP(
            t=dpkt.coap.COAP_CON,
            code=dpkt.coap.COAP_POST,
            id=int(time.time()) & 0xFFFF,
            token=b'\xaa\xbb',
            data=b'</3/0>,</6/0>,</3303/0>' if not is_update else b''
        )
        reg.opts.append((dpkt.coap.COAP_OPT_URI_PATH, b'rd'))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, f"ep={ENDPOINT}".encode()))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, b"lwm2m=1.0"))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, b"lt=86400"))
        reg.opts.append((dpkt.coap.COAP_OPT_URI_QUERY, b"b=U"))
        reg.opts.append((dpkt.coap.COAP_OPT_CONTENT_FORMAT, struct.pack('B', dpkt.coap.COAP_FORMAT_LINK)))
        sock.sendto(bytes(reg), (SERVER_HOST, SERVER_PORT))
        print(f"[*] Sent {'Update' if is_update else 'Registration'} for {ENDPOINT}")

    send_reg()
    last_update = time.time()
    
    try:
        while True:
            ready = select.select([sock], [], [], 1.0)
            if ready[0]:
                data, addr = sock.recvfrom(2048)
                try:
                    req = dpkt.coap.CoAP(data)
                    paths = []
                    accept = None
                    for opt_num, opt_val in req.opts:
                        if opt_num == dpkt.coap.COAP_OPT_URI_PATH:
                            paths.append(opt_val.decode())
                        if opt_num == dpkt.coap.COAP_OPT_ACCEPT:
                            if not opt_val: accept = 0
                            elif len(opt_val) == 1: accept = struct.unpack('B', opt_val)[0]
                            elif len(opt_val) == 2: accept = struct.unpack('>H', opt_val)[0]

                    path_str = "/" + "/".join(paths)
                    
                    if req.code == dpkt.coap.COAP_GET:
                        print(f"[*] Received CoAP GET {path_str} (Accept={accept})")
                        
                        resp_data = b''
                        content_format = dpkt.coap.COAP_FORMAT_LWM2M_TLV
                        
                        # Route by Object ID
                        obj_id = int(paths[0])
                        
                        if obj_id == 3: # Device
                            resources = {
                                0: (b'dpkt-project', 'string'), 1: (b'cli-agent-v1.2', 'string'),
                                2: (b'SN-2026-DPKT', 'string'), 3: (b'1.9.8', 'string'),
                                6: (encode_int(1), 'multiple_int'), 7: (encode_int(3800), 'multiple_int'),
                                9: (encode_int(95), 'int'), 10: (encode_int(1024), 'int'),
                                13: (encode_int(int(time.time())), 'int'), 14: (b'+01:00', 'string'),
                                15: (b'Europe/Stockholm', 'string'), 17: (b'DPKT-Map-Agent', 'string'),
                                18: (b'v1.0-virtual', 'string'), 20: (encode_int(1), 'int'), 21: (encode_int(2048), 'int'),
                            }
                        elif obj_id == 6: # Location
                            resources = {
                                0: (encode_float(59.3293), 'float'), # Latitude (Stockholm)
                                1: (encode_float(18.0686), 'float'), # Longitude
                                2: (encode_float(15.0), 'float'),    # Altitude
                                5: (encode_int(int(time.time())), 'int') # Timestamp
                            }
                        elif obj_id == 3303: # Temperature
                            resources = {
                                5700: (encode_float(21.5), 'float'), # Sensor Value
                                5701: (b'Cel', 'string')             # Units
                            }
                        else:
                            resources = {}

                        if not resources:
                            resp = dpkt.coap.CoAP(t=dpkt.coap.COAP_ACK, code=dpkt.coap.COAP_NOT_FOUND, id=req.id, token=req.token)
                            sock.sendto(bytes(resp), addr)
                            continue

                        # Resource or Object response
                        if len(paths) >= 3:
                            res_id = int(paths[-1])
                            if res_id in resources:
                                val, rtype = resources[res_id]
                                if (accept == 0 or accept is None) and rtype in ['string', 'int']:
                                    resp_data = val if rtype == 'string' else str(decode_int(val)).encode()
                                    content_format = dpkt.coap.COAP_FORMAT_TEXT
                                else:
                                    tlv_type = dpkt.lwm2m.LWM2M_TLV_MULTIPLE_RESOURCE if rtype == 'multiple_int' else dpkt.lwm2m.LWM2M_TLV_RESOURCE
                                    if rtype == 'multiple_int':
                                        val = bytes(dpkt.lwm2m.LWM2M_TLV(type=dpkt.lwm2m.LWM2M_TLV_RESOURCE_INSTANCE, id=0, value=val))
                                    tlv = dpkt.lwm2m.LWM2M_TLV(type=tlv_type, id=res_id, value=val)
                                    resp_data = bytes(tlv)
                            else:
                                resp = dpkt.coap.CoAP(t=dpkt.coap.COAP_ACK, code=dpkt.coap.COAP_NOT_FOUND, id=req.id, token=req.token)
                                sock.sendto(bytes(resp), addr)
                                continue
                        else: # Instance or Object read
                            tlvs = []
                            for rid in sorted(resources.keys()):
                                val, rtype = resources[rid]
                                if rtype == 'multiple_int':
                                    inst = dpkt.lwm2m.LWM2M_TLV(type=dpkt.lwm2m.LWM2M_TLV_RESOURCE_INSTANCE, id=0, value=val)
                                    tlvs.append(dpkt.lwm2m.LWM2M_TLV(type=dpkt.lwm2m.LWM2M_TLV_MULTIPLE_RESOURCE, id=rid, value=bytes(inst)))
                                else:
                                    tlvs.append(dpkt.lwm2m.LWM2M_TLV(type=dpkt.lwm2m.LWM2M_TLV_RESOURCE, id=rid, value=val))
                            obj_inst = dpkt.lwm2m.LWM2M_TLV(type=dpkt.lwm2m.LWM2M_TLV_OBJECT_INSTANCE, id=0, value=b''.join(bytes(t) for t in tlvs))
                            resp_data = bytes(obj_inst)

                        resp = dpkt.coap.CoAP(t=dpkt.coap.COAP_ACK, code=dpkt.coap.COAP_CONTENT, id=req.id, token=req.token, data=resp_data)
                        fmt_val = struct.pack('>H', content_format) if content_format > 255 else struct.pack('B', content_format)
                        resp.opts.append((dpkt.coap.COAP_OPT_CONTENT_FORMAT, fmt_val))
                        sock.sendto(bytes(resp), addr)
                        print(f"    [+] Responded {path_str} (format {content_format})")
                except Exception as e:
                    print(f"[!] Error: {e}")

            if time.time() - last_update > 60:
                send_reg(is_update=True)
                last_update = time.time()

    except KeyboardInterrupt: pass
    finally: sock.close()

if __name__ == "__main__":
    run_leshan_agent()
