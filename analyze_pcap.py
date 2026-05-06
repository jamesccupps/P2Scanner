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

import os
import struct
import subprocess
import sys
from collections import Counter, defaultdict


# Known opcodes — kept in sync with p2.lua (the canonical authoritative
# source) and PROTOCOL.md. If a new opcode is added there, mirror it here
# or this analyzer will flag it as "*** UNKNOWN ***" and drown the real
# unknowns. The lua dissector's `OPCODES` table is the source of truth.
KNOWN_OPCODES = {
    # Sysinfo / firmware
    0x0100: "GetRevString",
    0x010C: "SysInfoCompact",

    # Status / discovery / panel-name leak
    0x0050: "StatusQuery",
    0x0606: "Ping",
    0x5354: "StatusVariant",

    # Property read / write
    0x0220: "ReadShort(modern)",
    0x0271: "ReadExtended(legacy)",
    0x0272: "ReadExtended-MetaOnly",
    0x0273: "WriteNoValue/AlarmAck",
    0x0274: "ValuePush/COV",
    0x0240: "WriteWithQuality",
    0x0241: "Probe",
    0x0244: "ScopedQuery",
    0x0245: "TestProbe",
    0x0291: "Read/write 02xx (rare)",
    0x0294: "Read variant 02xx (rare)",
    0x0295: "Read variant 02xx (rare)",
    0x02A8: "Write variant 02xx (rare)",

    # Object lifecycle
    0x0203: "ObjectLifecycle 0203",
    0x0204: "CreateObject",
    0x0260: "ObjectLifecycle 0260",
    0x0263: "ObjectLifecycle 0263",

    # Routing / topology
    0x0368: "NodeRoutingQuery",

    # State-set / metadata
    0x040A: "MultiStateLabelCatalog",

    # Alarms
    0x0508: "AlarmReport",
    0x0509: "AlarmAck",

    # Enumeration / panel walk
    0x0981: "EnumeratePoints",
    0x0982: "EnumerateTrended",
    0x0983: "EnumerateVariant",
    0x0984: "EnumerateVariant",
    0x0985: "EnumeratePrograms",
    0x0986: "EnumerateFLN",
    0x0987: "EnumerateVariant",
    0x0988: "EnumerateMulti",
    0x0989: "EnumerateVariant",
    0x099F: "GetPortConfig",

    # Legacy point/title queries
    0x0961: "AnalogPointQuery(legacy)",
    0x0964: "TitleAnalogQuery",
    0x0965: "NodeDiscoveryEnumerate",
    0x0966: "ShortQuery",
    0x0969: "ScheduleObjectList",
    0x0971: "EnhancedPointRead",
    0x0974: "MultistatePointEnumerate",
    0x0975: "NodeDiscoveryWithLines",
    0x0976: "DeviceAllSubpointsRead",
    0x0979: "ShortVariant",
    0x098B: "Enumerate(newer)",
    0x098C: "ScheduleSetpointTable",
    0x098D: "ScheduleEntries",
    0x098E: "ScheduleGainConfig",
    0x098F: "ScheduleDeadband",

    # Newer-firmware capability probes (mostly errors on legacy)
    0x09A3: "EnumerateNewer",
    0x09A7: "EnumerateNewer",
    0x09AB: "EnumerateNewer",
    0x09BB: "EnumerateNewer",
    0x09C3: "EnumerateNewer",
    0x400F: "CapabilityProbe",
    0x4010: "CapabilityProbe",
    0x4011: "CapabilityProbe",
    0x4133: "CapabilityProbe",
    0x4500: "TestProbe",

    # PPCL editor
    0x4100: "PPCL LineWrite/Create",
    0x4103: "PPCL ProgramEnableHint",
    0x4104: "PPCL LineRead/Delete",
    0x4106: "PPCL ClearTracebits",

    # Bulk property
    0x4200: "PropertyQuery",
    0x4220: "BulkProperty variant",
    0x4221: "BulkPropertyRead",
    0x4222: "BulkPropertyWrite",

    # Schedule writes
    0x5003: "ScheduleObjectInfoQuery",
    0x5020: "ScheduleEntryWrite",
    0x5022: "ScheduleSlotInit",
    0x5038: "ObjectDisplayLabels",

    # Routing / identity
    0x4634: "RoutingTable",
    0x4640: "Identify",
}

# Same: kept in sync with p2.lua's STATUS_ERRORS table.
KNOWN_ERRORS = {
    0x0002: "object_unknown (scope-restricted op)",
    0x0003: "not_found",
    0x00AC: "not_supported (wrong firmware)",
    0x0E11: "already_exists (Desigo treats as success)",
    0x0E15: "wrong-write-opcode (use 0x4222 for SYST)",
}

MSG_TYPES = {
    # PROTOCOL.md "Message types": 0x33 vs 0x34 distinguishes
    # firmware dialect, NOT data-vs-keepalive. Legacy panels carry
    # operational traffic in 0x33 DATA; modern panels carry it in
    # 0x34 HEARTBEAT. Both opcodes and routing format are identical;
    # only the msg-type byte differs.
    0x2E: "CONNECT",
    0x2F: "ANNOUNCE",
    0x33: "DATA (legacy dialect)",
    0x34: "HEARTBEAT (modern dialect)",
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
    if len(sys.argv) < 2:
        print("Usage: analyze_pcap.py <pcap_file>", file=sys.stderr)
        print("", file=sys.stderr)
        print("Inventories opcodes, error codes, frame-size distribution,", file=sys.stderr)
        print("and message-type counts in a P2 capture. Requires tshark on PATH.", file=sys.stderr)
        sys.exit(2)
    pcap = sys.argv[1]
    if not os.path.isfile(pcap):
        print(f"[ERROR] pcap not found: {pcap}", file=sys.stderr)
        sys.exit(2)

    # Pull every P2-relevant TCP segment
    print(f"[*] reading {pcap} via tshark...")
    cmd = ["tshark", "-r", pcap,
           "-Y", "(tcp.dstport==5033 or tcp.dstport==5034 or "
                 "tcp.srcport==5033 or tcp.srcport==5034) and tcp.len > 0",
           "-T", "fields",
           "-e", "ip.src", "-e", "tcp.srcport",
           "-e", "ip.dst", "-e", "tcp.dstport",
           "-e", "tcp.payload"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("[ERROR] tshark not found on PATH. Install Wireshark (which", file=sys.stderr)
        print("        includes tshark) and ensure the install directory is", file=sys.stderr)
        print("        on your PATH.", file=sys.stderr)
        sys.exit(2)
    if proc.returncode != 0:
        print(f"[ERROR] tshark exited with code {proc.returncode}", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        sys.exit(2)
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
