"""Feed shelly_discover a real mDNS reply and check it is understood.

Multicast cannot be exercised in every environment, so this drives the part
that can be: a reply arriving by unicast, which is exactly what a proxy or
repeater between VLANs sends back.
"""
import importlib.util
import os
import socket
import struct
import sys
import tempfile
import threading
import time

os.environ.setdefault('UPSMON_STATE', tempfile.mkdtemp())
os.environ.setdefault('UPSMON_RUN', tempfile.mkdtemp())
source = sys.argv[1] if len(sys.argv) > 1 else '/tmp/test_upsmon.py'
path = os.environ['UPSMON_STATE'] + '/m.py'
open(path, 'w').write(open(source).read())
spec = importlib.util.spec_from_file_location('m', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def encode(name):
    out = b''
    for label in name.split('.'):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b'\x00'


def reply(instance, host, ip, service='_shelly._tcp.local'):
    body = encode(service) + struct.pack('!HHIH', 12, 1, 120,
                                         len(encode(instance))) + encode(instance)
    srv = struct.pack('!HHH', 0, 0, 80) + encode(host)
    body += encode(instance) + struct.pack('!HHIH', 33, 1, 120, len(srv)) + srv
    body += encode(host) + struct.pack('!HHIH', 1, 1, 120, 4) + socket.inet_aton(ip)
    return struct.pack('!HHHHHH', 0, 0x8400, 0, 3, 0, 0) + body


DEVICES = (('shellyplugmg3-089272534650._shelly._tcp.local',
            'shellyplugmg3-089272534650.local', '172.16.16.12'),
           ('shellyplusht-a8032abc1234._shelly._tcp.local',
            'shellyplusht-a8032abc1234.local', '172.16.16.13'))


def service_type_reply():
    """What enumerating _services._dns-sd._udp.local answers: the service type
    itself. It is not a device and must not be listed as one."""
    service = '_services._dns-sd._udp.local'
    target = '_shelly._tcp.local'
    body = (encode(service) + struct.pack('!HHIH', 12, 1, 120, len(encode(target)))
            + encode(target))
    return struct.pack('!HHHHHH', 0, 0x8400, 0, 1, 0, 0) + body


def mixed_case_reply():
    """The same device answering with two spellings of its own name, which is
    what a real plug does across its PTR and SRV records."""
    body = b''
    for instance in ('ShellyPlugMG3-089272534650._shelly._tcp.local',
                     'shellyplugmg3-089272534650._shelly._tcp.local'):
        body += (encode('_shelly._tcp.local')
                 + struct.pack('!HHIH', 12, 1, 120, len(encode(instance)))
                 + encode(instance))
    host = 'shellyplugmg3-089272534650.local'
    body += (encode(host) + struct.pack('!HHIH', 1, 1, 120, 4)
             + socket.inet_aton('172.16.16.12'))
    return struct.pack('!HHHHHH', 0, 0x8400, 0, 3, 0, 0) + body


def run_discovery(answer_port):
    """Answer on the port the caller chooses, then report what was understood."""
    result = {}
    thread = threading.Thread(target=lambda: result.update(
        found=m.shelly_discover(m.Palette(False), 3.0)))
    thread.start()
    time.sleep(0.8)

    port = 5353 if answer_port == 'group' else m.shelly_discover.query_port
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for instance, host, ip in DEVICES:
        sender.sendto(reply(instance, host, ip), ('127.0.0.1', port))
    sender.close()
    thread.join()
    return result.get('found') or {}


def run_with(packets, answer_port='group'):
    result = {}
    thread = threading.Thread(target=lambda: result.update(
        found=m.shelly_discover(m.Palette(False), 3.0)))
    thread.start()
    time.sleep(0.8)
    port = 5353 if answer_port == 'group' else m.shelly_discover.query_port
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for packet in packets:
        sender.sendto(packet, ('127.0.0.1', port))
    sender.close()
    thread.join()
    return result.get('found') or {}


failures = 0
for label, where in (('a reply to the multicast group on 5353', 'group'),
                     ('a unicast reply to the query port, as a proxy sends',
                      'query')):
    found = run_discovery(where)
    print('  %s' % label)
    print('    devices understood: %d' % len(found))
    for ip, entry in sorted(found.items()):
        print('      %-15s %s%s' % (ip, ', '.join(entry['names']),
                                    '  (relayed by %s)' % entry['via']
                                    if entry['via'] else ''))
    if len(found) != 2:
        failures += 1

# A service-type answer is not a device.
found = run_with([service_type_reply()])
print('  an answer naming the service type, not a device')
print('    devices understood: %d (expected 0)' % len(found))
if found:
    failures += 1

# One device answering with two spellings of its name is still one device.
found = run_with([mixed_case_reply()])
print('  one device answering in two letter cases')
print('    devices understood: %d (expected 1)' % len(found))
for ip, entry in sorted(found.items()):
    print('      %-15s %s' % (ip, ', '.join(entry['names'])))
if len(found) != 1 or len(list(found.values())[0]['names']) != 1:
    failures += 1

sys.exit(1 if failures else 0)
