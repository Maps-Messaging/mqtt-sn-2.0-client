# Copyright [2024-2026] MapsMessaging B.V.
# Licensed under Apache-2.0 with Commons Clause; see ../../LICENSE.
"""Generate the synthetic example PCAP from independent CSD01 test vectors."""
from test_dissector import ROOT, FIXTURES, capture, packet

if __name__ == '__main__':
    target = ROOT / 'wireshark' / 'captures' / 'mqttsn2-csd01.pcap'
    target.parent.mkdir(parents=True, exist_ok=True)
    capture(target, [packet(kind, bytes.fromhex(body)) for _, _, kind, body, _ in FIXTURES])
    print(f'Wrote {len(FIXTURES)} synthetic packets to {target.relative_to(ROOT)}')
