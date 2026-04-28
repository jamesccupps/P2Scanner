"""analyze_pcap.py — comprehensive opcode / error-code / direction-byte
inventory for a captured pcap. Walks every TCP segment, reassembles P2
frames, and tallies what we see.

Surfaces:
  - All opcodes by message direction (5033 vs 5034) and dir byte (req/resp/err)
  - All error codes seen
  - All msg_types seen
  - Frame-size distribution per opcode (catches "weird big frame" outliers)
  - Sample raw payloads for each unknown opcode
"""

from __future__ import annotations

import struct
import subprocess
import sys
from collections import Counter, defaultdict


# Known opcodes from PROTOCOL.md / p2_scanner.py
KNOWN_OPCODES = {
    0x0100: "GetRevString",
    0x010C: "SysInfoCompact",
    0x0220: "ReadProperty(modern)",
    0x0240: "WriteWithQuality",
    0x0271: "ReadProperty(legacy)",
    0x0273: "WriteNoValue",
    0x0274: "ValuePush/COV",
    0x0981: "EnumerateAllPoints",
    0x0985: "EnumeratePrograms",
    0x0986: "EnumerateFLN",
    0x4221: "BulkPropertyRead",
    0x4634: "RoutingTable",
    0x4640: "Identify",
}

KNOWN_ERRORS = {0x0003: "not_found", 0x00AC: "not_supported"}

MSG_TYPES = {
    0x2E: "CONNECT", 0x2F: "ANNOUNCE",
    0x33: "DATA(legacy)", 0x34: "HEARTBEAT(modern)",
}

DIR_BYTES = {0x00: "Request", 0x01: "Success", 0x05: "Error"}


def parse_routing(payload):
    """Skip 4 null-terminated strings, return body offset."""
    if not payload:
        return None
    off = 1
    for _ in range(4):
        end = payload.find(b"\x00", off)
        if end < 0:
            return None
        off = end + 1
    return off


# ─── State ──────────────────────────────────────────────────────────────────

# (peer_a_ip, peer_a_port, peer_b_ip, peer_b_port) ordered → reassembly buffer
streams = defaultdict(bytearray)

opcode_counts = Counter()      # opcode → count
opcode_by_dir = defaultdict(Counter)  # dir_byte → opcode → count
error_codes = Counter()
msg_types = Counter()
unknown_opcode_samples = defaultdict(list)
opcode_sizes = defaultdict(list)
opcode_by_port = defaultdict(Counter)  # tcp_port → opcode → count

# Track conversation directionality: since TCP is bidirectional, we use
# (src_ip, src_port, dst_ip, dst_port) as the stream key — that gives one
# entry per direction.
# Stash up to 3 sample bodies for each unknown opcode.


def process_p2_frame(frame, src_ip, src_port, dst_ip, dst_port):
    if len(frame) < 12:
        return
    total_len, msg_type, seq = struct.unpack(">III", frame[:12])
    msg_types[msg_type] += 1

    payload = frame[12:total_len]
    if len(payload) < 2:
        return

    dir_byte = payload[0]
    body_off = parse_routing(payload)
    if body_off is None:
        return

    body = payload[body_off:]
    if len(body) < 2:
        return

    # Distinguish requests (have opcode) from responses (don't echo opcode)
    if dir_byte == 0x00:
        # Request — first 2 bytes after routing are the opcode
        opcode = struct.unpack(">H", body[:2])[0]
        opcode_counts[opcode] += 1
        opcode_by_dir[dir_byte][opcode] += 1
        opcode_sizes[opcode].append(total_len)
        # Note which port — useful to know if a given opcode is 5033 or 5034
        opcode_by_port[dst_port][opcode] += 1
        if opcode not in KNOWN_OPCODES and len(unknown_opcode_samples[opcode]) < 3:
            unknown_opcode_samples[opcode].append({
                "frame_len": total_len,
                "src": f"{src_ip}:{src_port}",
                "dst": f"{dst_ip}:{dst_port}",
                "body": body.hex(),
            })
    elif dir_byte == 0x05:
        # Error — u16 BE error code immediately after routing
        if len(body) >= 2:
            err = struct.unpack(">H", body[:2])[0]
            error_codes[err] += 1
    else:
        # Success response (0x01) — no opcode echo. Could still detect via
        # heuristic. For unsolicited frames on 5034 (push from PXC), the
        # opcode IS in the body since they're "requests" semantically (from
        # PXC's perspective). The scanner already handles this.
        # Also on 5034, COV pushes use dir 0x00 (PXC sends to DCC as request),
        # which we already counted above.
        pass


def consume_segment(segment_data, src_ip, src_port, dst_ip, dst_port):
    """Append segment data to the directional stream and pull complete frames."""
    key = (src_ip, src_port, dst_ip, dst_port)
    buf = streams[key]
    buf.extend(segment_data)
    while len(buf) >= 12:
        total_len = struct.unpack(">I", bytes(buf[:4]))[0]
        if total_len < 12 or total_len > 65536:
            buf.clear()
            return
        if len(buf) < total_len:
            return
        frame = bytes(buf[:total_len])
        del buf[:total_len]
        process_p2_frame(frame, src_ip, src_port, dst_ip, dst_port)


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else "/mnt/user-data/uploads/50335034.pcapng"

    # Pull every P2-relevant TCP segment
    print(f"[*] reading {pcap} via tshark...")
    cmd = ["tshark", "-r", pcap,
           "-Y", "(tcp.dstport==5033 or tcp.dstport==5034 or "
                 "tcp.srcport==5033 or tcp.srcport==5034) and tcp.len > 0",
           "-T", "fields",
           "-e", "ip.src", "-e", "tcp.srcport",
           "-e", "ip.dst", "-e", "tcp.dstport",
           "-e", "tcp.payload"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    lines = proc.stdout.strip().split("\n")
    print(f"[*] {len(lines)} TCP segments to process")

    n = 0
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 5 or not parts[4]:
            continue
        try:
            src_ip = parts[0]
            src_port = int(parts[1])
            dst_ip = parts[2]
            dst_port = int(parts[3])
            payload = bytes.fromhex(parts[4].replace(":", ""))
        except (ValueError, IndexError):
            continue
        consume_segment(payload, src_ip, src_port, dst_ip, dst_port)
        n += 1

    print(f"[*] processed {n} segments")
    print(f"[*] frames extracted (msg_types): "
          f"{sum(msg_types.values())}\n")

    # ─── Output ─────────────────────────────────────────────────────────────
    print("=" * 70)
    print(" MESSAGE TYPES")
    print("=" * 70)
    for mt, cnt in msg_types.most_common():
        print(f"  0x{mt:02X} ({MSG_TYPES.get(mt, '?'):<20s}) {cnt:>8d}")

    print("\n" + "=" * 70)
    print(" REQUEST OPCODES (dir=0x00)")
    print("=" * 70)
    for op, cnt in opcode_counts.most_common():
        name = KNOWN_OPCODES.get(op, "*** UNKNOWN ***")
        marker = "" if op in KNOWN_OPCODES else "  <-- NEW"
        sizes = opcode_sizes[op]
        if sizes:
            sz = f"sizes {min(sizes)}–{max(sizes)} avg {sum(sizes)//len(sizes)}"
        else:
            sz = ""
        print(f"  0x{op:04X}  {name:<25s}  {cnt:>6d}  {sz}{marker}")

    print("\n" + "=" * 70)
    print(" REQUEST OPCODES — BY DESTINATION PORT")
    print("=" * 70)
    for port, opcodes in sorted(opcode_by_port.items()):
        print(f"\n  → port {port}:")
        for op, cnt in opcodes.most_common():
            name = KNOWN_OPCODES.get(op, "UNKNOWN")
            print(f"    0x{op:04X}  {name:<25s}  {cnt:>6d}")

    print("\n" + "=" * 70)
    print(" ERROR CODES (dir=0x05)")
    print("=" * 70)
    for ec, cnt in error_codes.most_common():
        name = KNOWN_ERRORS.get(ec, "*** UNKNOWN ***")
        marker = "" if ec in KNOWN_ERRORS else "  <-- NEW"
        print(f"  0x{ec:04X}  {name:<25s}  {cnt:>6d}{marker}")

    print("\n" + "=" * 70)
    print(" UNKNOWN OPCODES — SAMPLE PAYLOADS")
    print("=" * 70)
    if not unknown_opcode_samples:
        print("  (none — all opcodes accounted for)")
    for op in sorted(unknown_opcode_samples):
        print(f"\n  ── opcode 0x{op:04X} ──")
        for s in unknown_opcode_samples[op]:
            print(f"    src={s['src']} → dst={s['dst']}  frame={s['frame_len']}B")
            body = s['body']
            # Wrap hex at 60 chars per line for readability
            for i in range(0, len(body), 60):
                print(f"      {body[i:i+60]}")


if __name__ == "__main__":
    main()
