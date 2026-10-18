# Copyright [2024-2026] MapsMessaging B.V.
# Licensed under Apache-2.0 with Commons Clause; see ../../LICENSE.
"""Real tshark tests using independent CSD01 wire fixtures (no client codec)."""
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / 'wireshark' / 'mqttsn2.lua'
TSHARK = os.environ.get('TSHARK', 'tshark')


def packet(kind, body=b'', extended=False):
    size = len(body) + (4 if extended or len(body) > 253 else 2)
    header = b'\x01' + struct.pack('!HB', size, kind) if size > 255 or extended else bytes((size, kind))
    return header + body


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def capture(path, payloads, port=1884):
    """Write deterministic Ethernet/IPv4/UDP PCAP, with no capture privileges."""
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(payloads):
            udp = struct.pack('!HHHH', 40000, port, len(payload) + 8, 0) + payload
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, index % 65536,
                             0, 64, 17, 0, b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02')
            ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
            frame = bytes.fromhex('0200000000020200000000010800') + ip + udp
            out.write(struct.pack('<IIII', 1700000000 + index, 0, len(frame), len(frame)))
            out.write(frame)


def dissect(payloads, port=1884, options=(), plugin=True):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'packets.pcap'
        capture(path, payloads, port)
        cmd = [TSHARK, '-n']
        if plugin:
            cmd += ['-X', f'lua_script:{PLUGIN}']
        cmd += [*options, '-r', str(path), '-T', 'json']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise AssertionError(f'tshark failed: {result.stderr}')
        if any(error in result.stdout or error in result.stderr for error in ('Lua Error', 'Lua: Error')):
            raise AssertionError(f'Lua error: {result.stdout[:2000]} {result.stderr}')
        return [entry['_source']['layers'] for entry in json.loads(result.stdout)]


def flatten(value):
    result = {}
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                for nested, values in flatten(child).items():
                    result.setdefault(nested, []).extend(values)
            else:
                result.setdefault(key, []).append(str(child))
    elif isinstance(value, list):
        for child in value:
            for key, values in flatten(child).items():
                result.setdefault(key, []).extend(values)
    return result


# Sections refer to the pinned 14 August 2026 CSD01; see SPECIFICATION.md.
# These are hand-authored packet bodies, deliberately independent of client codecs.
FIXTURES = [
    ('connect', '3.1', 1, '01012302003c0100' + b'node'.hex(),
     {'packet_id': '291', 'version': '2', 'keep_alive': '60', 'maximum_packet_size': '256', 'client_id': 'node', 'connect.clean_start': '1'}),
    ('connack', '3.2', 2, '0f0123000000012c003c044d45544800020102' + b'assigned'.hex(),
     {'packet_id': '291', 'session_expiry': '300', 'server_keep_alive': '60', 'auth_method': 'METH', 'auth_data': '01:02', 'assigned_client_id': 'assigned'}),
    ('publish-qos0-name', '3.6', 3, '030003' + b'a/b'.hex() + '00ff',
     {'qos': '0', 'topic_name': 'a/b', 'payload': '00:ff'}),
    ('publish-qos2-dup', '3.6', 3, 'd001230007ff',
     {'packet_id': '291', 'qos': '2', 'dup': '1', 'retain': '1', 'topic_alias': '7', 'payload': 'ff'}),
    ('puback', '3.6.3', 4, '012310', {'packet_id': '291', 'reason_code': '0x10'}),
    ('pubrec', '3.6.4', 5, '0123', {'packet_id': '291'}),
    ('pubrel', '3.6.5', 6, '0123', {'packet_id': '291'}),
    ('pubcomp', '3.6.6', 7, '0123', {'packet_id': '291'}),
    ('subscribe', '3.7', 8, 'b70123' + b'a/+'.hex(),
     {'packet_id': '291', 'topic_filter': 'a/+', 'no_local': '1', 'retain_as_published': '1', 'retain_handling': '1', 'qos': '1'}),
    ('suback', '3.8', 9, '040123000702', {'topic_alias': '7', 'reason_code': '0x02'}),
    ('unsubscribe', '3.9', 10, '0101230007', {'topic_alias': '7', 'topic_type': '1'}),
    ('unsuback', '3.10', 11, '012311', {'reason_code': '0x11'}),
    ('pingreq', '3.11', 12, '0123', {'packet_id': '291'}),
    ('pingresp', '3.12', 13, '012305', {'messages_remaining': '5'}),
    ('disconnect', '3.13.3-6 (prose field order)', 14, '070123820000012c' + b'reason'.hex(),
     {'packet_id': '291', 'reason_code': '0x82', 'session_expiry': '300', 'reason_string': 'reason'}),
    ('auth', '3.3', 15, '012318044d4554480102', {'auth_method': 'METH', 'auth_data': '01:02', 'reason_code': '0x18'}),
    ('register', '3.4', 16, '0101230007' + b'a/b'.hex(), {'topic_alias': '7', 'topic_name': 'a/b'}),
    ('regack', '3.5', 17, '05012300071a', {'topic_type': '1', 'topic_alias': '7', 'reason_code': '0x1a'}),
    ('pubwos', '3.6.1', 18, '1100070102', {'retain': '1', 'topic_alias': '7', 'payload': '01:02'}),
    ('sleepreq', '3.15', 19, '0101230000012c', {'retain_topic_aliases': '1', 'sleep_duration': '300'}),
    ('sleepresp', '3.16', 20, '0101230000012c00', {'sleep_duration': '300', 'reason_code': '0x00'}),
    ('wakeup', '3.14', 21, '', {}),
    ('advertise', '3.20.1', 22, '07003c', {'gateway_id': '7', 'duration': '60'}),
    ('searchgw', '3.20.2', 23, '0102', {'network_info': '01:02'}),
    ('gwinfo', '3.20.3', 24, '07c0000201', {'gateway_id': '7', 'gateway_address': 'c0:00:02:01'}),
    ('forwarder', '3.19', 252, '02aabb040c0123', {'addressing': 'aa:bb', 'packet_id': '291'}),
    ('connection', '3.18', 254, '00046e6f6465040c0123', {'client_id': 'node', 'packet_id': '291'}),
    ('protection-aead', '3.17', 255, '1546010203040506070801020304aabb0123' + 'ee'*4 + 'aa'*16,
     {'protection.scheme': '0x46', 'protection.sender_id': '01:02:03:04:05:06:07:08', 'protection.counter': '291', 'protection.crypto': 'aa:bb', 'protection.payload': ':'.join(['ee']*4), 'protection.tag': ':'.join(['aa']*16)}),
]


class DissectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which(TSHARK):
            raise RuntimeError('tshark is required; install it rather than skipping these tests')

    def assert_fields(self, layers, expected):
        fields = flatten(layers)
        self.assertIn('mqttsn2', layers, 'MQTT-SN v2 dissector did not run')
        self.assertNotIn('mqttsn2.malformed', fields)
        for name, value in expected.items():
            self.assertIn(value, fields.get('mqttsn2.' + name, []), name)

    def test_independent_packet_catalog(self):
        rows = dissect([packet(kind, bytes.fromhex(body)) for _, _, kind, body, _ in FIXTURES])
        for row, (name, section, kind, _, expected) in zip(rows, FIXTURES):
            with self.subTest(packet=name, specification=section):
                self.assert_fields(row, {'msg_type': f'0x{kind:02x}', **expected})

    def test_extended_length_and_utf8(self):
        body = b'\x03\x00\x05' + 'a/\u00e9x'.encode() + bytes(range(256))
        encoded = packet(3, body)
        self.assert_fields(dissect([encoded])[0], {'length': str(len(encoded)), 'topic_name': 'a/\u00e9x', 'qos': '0'})

    def test_connect_all_optional_fields(self):
        # 3.1: Will Flags BEFORE Packet Id; MAM, expiry, Will, Auth, Client Id.
        body = bytes.fromhex('7f17012302003c0100050000012c0003') + b'a/b' + bytes.fromhex('00020102044d4554480002aabb') + b'node'
        self.assert_fields(dissect([packet(1, body)])[0], {
            'packet_id': '291', 'maximum_awake_messages': '5', 'session_expiry': '300',
            'will.topic_name': 'a/b', 'will.payload': '01:02', 'will.qos': '1',
            'auth_method': 'METH', 'auth_data': 'aa:bb', 'client_id': 'node'})

    def test_optional_fields_absent_and_empty_payloads(self):
        cases = [(2, '00012300'), (9, '000123'), (17, '010123'), (13, '0123'),
                 (20, '000123'), (14, '00'), (23, ''), (24, '07'), (18, '030003612f62')]
        rows = dissect([packet(k, bytes.fromhex(b)) for k, b in cases])
        for row in rows:
            self.assert_fields(row, {})
        self.assertNotIn('mqttsn2.reason_code', flatten(rows[1]))
        self.assertNotIn('mqttsn2.packet_id', flatten(rows[5]))

    def test_protection_auth_only_plaintext_is_unverified(self):
        # 3.17: HMAC-SHA256 truncated to 8 bytes; inner PINGREQ visible.
        body = bytes.fromhex('4000010203040506070801020304040c0123') + bytes(8)
        self.assert_fields(dissect([packet(255, body)])[0], {
            'packet_id': '291', 'protection.verified': '0', 'protection.tag': ':'.join(['00']*8)})

    def test_malformed_packets_have_expert_warning(self):
        # 2.1.2 lengths; 2.2 identifiers; 2.4 topic types; packet flag clauses.
        cases = [b'\0', b'\x01', b'\x01\x00', b'\x01\x00\x03\x0c', b'\x08\x0c\x01',
                 b'\x04\x0c\x01\x23\xff', packet(0), packet(253),
                 packet(12, b'\0\0'), packet(21, b'\0'), packet(8, bytes.fromhex('e3012361')),
                 packet(3, bytes.fromhex('020007')), packet(3, bytes.fromhex('83000161')),
                 packet(1, bytes.fromhex('80012302003c0100')), packet(1, bytes.fromhex('00012301003c0100')),
                 packet(1, bytes.fromhex('0001230200000100')), packet(1, bytes.fromhex('00012302003c0009')),
                 packet(9, bytes.fromhex('030123')), packet(18, bytes.fromhex('000007')),
                 packet(14, bytes.fromhex('0800')), packet(16, bytes.fromhex('02012361')),
                 packet(16, bytes.fromhex('000123c080')), packet(16, bytes.fromhex('000123610062')),
                 packet(254, bytes.fromhex('0001610215')),  # disallowed inner WAKEUP
                 packet(252, b'\0'), packet(255, bytes.fromhex('1346') + bytes(30))]
        rows = dissect(cases)
        for data, row in zip(cases, rows):
            with self.subTest(hex=data.hex()):
                self.assertIn('mqttsn2.malformed', flatten(row))

    def test_every_incomplete_prefix_is_safe(self):
        cases = []
        for _, _, kind, body, _ in FIXTURES:
            encoded = packet(kind, bytes.fromhex(body))
            cases.extend(encoded[:end] for end in range(1, len(encoded)))
        for row in dissect(cases):
            self.assertIn('mqttsn2.malformed', flatten(row))

    def test_random_datagrams_do_not_raise_lua_errors(self):
        rng = random.Random(407)
        cases = []
        for _ in range(600):
            body = rng.randbytes(rng.randrange(0, 180))
            cases.append(packet(rng.choice([item[2] for item in FIXTURES]), body))
        self.assertEqual(600, len(dissect(cases)))

    def test_decode_as_and_port_preference(self):
        data = packet(12, bytes.fromhex('0123'))
        self.assert_fields(dissect([data], 2884, ['-d', 'udp.port==2884,mqttsn2'])[0], {'packet_id': '291'})
        self.assert_fields(dissect([data], 2885, ['-o', 'mqttsn2.udp_ports:2885'])[0], {'packet_id': '291'})
        self.assertNotIn('mqttsn2', dissect([data], 2885)[0])

    def test_builtin_v1_port_is_not_overridden(self):
        # Valid 1.2 CONNECT uses type 0x04; port 1884 is deliberately separate.
        data = bytes.fromhex('0a040401003c') + b'node'
        row = dissect([data], 1883, ['-d', 'udp.port==1883,mqttsn'])[0]
        self.assertNotIn('mqttsn2', row)
        self.assertIn('mqttsn', row)

    def test_connect_presence_flag_combinations(self):
        # CSD01 3.1.2-18: each presence flag changes offsets independently.
        cases, expected = [], []
        for flags in range(128):
            body = bytes((flags,))
            if flags & 2:
                body += b'\x11'  # predefined Will alias, QoS 0, retain
            body += bytes.fromhex('012302003c0100')
            if flags & 16:
                body += b'\x05'
            if flags & 8:
                body += bytes.fromhex('0000012c')
            if flags & 2:
                body += bytes.fromhex('000700020102')
            if flags & 4:
                body += bytes.fromhex('014d0002aabb')
            body += b'node'
            cases.append(packet(1, body))
            values = {'packet_id': '291', 'client_id': 'node', 'keep_alive': '60'}
            if flags & 2:
                values.update({'will.topic_alias': '7', 'will.payload': '01:02'})
            if flags & 4:
                values.update({'auth_method': 'M', 'auth_data': 'aa:bb'})
            if flags & 8:
                values['session_expiry'] = '300'
            if flags & 16:
                values['maximum_awake_messages'] = '5'
            expected.append(values)
        for flags, (row, values) in enumerate(zip(dissect(cases), expected)):
            with self.subTest(flags=flags):
                self.assert_fields(row, values)

    def test_protection_scheme_boundaries(self):
        # 3.17 table: nominal tags; truncated auth-only tags; provider unknowns.
        cases, expected = [], []
        for scheme in [0, 1, 2, 3, 4, *range(0x40, 0x4a)]:
            size = 32 if scheme < 2 else 8 if 0x40 <= scheme <= 0x42 else 16
            payload = packet(12, bytes.fromhex('0123')) if scheme <= 4 else b'\xee' * 4
            body = bytes((0x10, scheme)) + bytes.fromhex('010203040506070801020304') + payload + bytes(size)
            cases.append(packet(255, body))
            expected.append({'protection.scheme': f'0x{scheme:02x}', 'protection.tag': ':'.join(['00'] * size)})
        for row, values in zip(dissect(cases), expected):
            self.assert_fields(row, values)
        body = bytes.fromhex('103c010203040506070801020304') + b'opaque'
        row = dissect([packet(255, body)])[0]
        self.assert_fields(row, {'protection.payload': '6f:70:61:71:75:65'})
        self.assertIn('mqttsn2.opaque', flatten(row))
        self.assertNotIn('mqttsn2.protection.tag', flatten(row))

    def test_protection_invalid_tag_rules(self):
        # MQTT-SN-3.17.2.3-1/-3/-8, 3.17.3-1, 3.17.8-1.
        prefix = bytes.fromhex('010203040506070801020304')
        cases = [packet(255, bytes((flags, scheme)) + prefix + packet(12, bytes.fromhex('0123')) + bytes(32))
                 for flags, scheme in [(0x90, 2), (0x40, 0x46), (0x20, 0), (0x10, 5), (0x10, 0x4a)]]
        cases.append(packet(255, bytes((0x40, 0)) + prefix + packet(252, b'\x00' + packet(12, bytes.fromhex('0123'))) + bytes(8)))
        for row in dissect(cases):
            self.assertIn('mqttsn2.malformed', flatten(row))

    def test_encapsulation_depth_is_bounded(self):
        # Defensive dissector limit, not a normative protocol restriction.
        data = packet(12, bytes.fromhex('0123'))
        for _ in range(10):
            data = packet(252, b'\x00' + data)
        self.assertIn('mqttsn2.malformed', flatten(dissect([data])[0]))

    def test_redissection_has_identical_fields(self):
        # Wireshark revisits frames; stateless decoding must remain stable.
        data = packet(1, bytes.fromhex('01012302003c0100') + b'node')
        once = flatten(dissect([data])[0])
        twice = flatten(dissect([data], options=['-2'])[0])
        self.assertEqual({k: v for k, v in once.items() if k.startswith('mqttsn2.')},
                         {k: v for k, v in twice.items() if k.startswith('mqttsn2.')})

    def test_client_generated_connect(self):
        # Additional integration check; independent fixtures remain authoritative.
        import sys
        sys.path.insert(0, str(ROOT / 'python' / 'src'))
        from mqttsn2.codec import ConnectOptions, encode_connect
        data = encode_connect(ConnectOptions(True, True, True, 291, 60, 256, 'node', 'METH', b'\x01\x02'))
        self.assert_fields(dissect([data])[0], {'packet_id': '291', 'client_id': 'node', 'auth_method': 'METH', 'auth_data': '01:02'})


if __name__ == '__main__':
    unittest.main()
