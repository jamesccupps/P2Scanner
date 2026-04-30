# P2 Scanner

Scanner and point-read library for field controllers over the P2 protocol. Runs as a CLI, a Tk GUI, or an importable Python library.

Pure Python, zero external dependencies, read-only by design.

---

## Features

**Discovery**
- Cold-site onboarding via BACnet recon + tiered dictionary probe
- Passive multicast listener (no probes sent)
- Passive TCP 5034 listener for live COV / virtual-point / routing events
- Port-scan discovery on TCP 5033
- Automatic firmware-dialect detection (legacy vs modern panels)

**Point operations**
- Read by point name or slot number
- Full-panel walk — every point on a controller, including panel-internal variables
- FLN device enumeration
- PPCL program source dump
- 797 TEC application definitions bundled — state labels, units, and types
- Comm-status detection — distinguishes live readings from stale cached data on FLN-faulted devices, matching Desigo's `#COM` indicator
- Structured error decoding (not silent `None`s)

**I/O**
- Table, CSV, and JSON output
- Sniff or decode packet captures for automatic BLN-name learning
- Per-host dialect cache avoids re-probing on reconnect

---

## Files

| File | Description |
|------|-------------|
| `p2_scanner.py` | CLI / library. Python 3.6+. |
| `p2_gui.py`, `p2_gui_widgets.py`, `p2_gui_workers.py` | Tk GUI front-end |
| `launch_gui_windows.bat` | Windows launcher — runs the GUI under `pythonw` so no console window flashes |
| `analyze_pcap.py` | Standalone pcap inventory tool — opcode counts, error codes, frame-size distribution, sample bodies for unknowns. Useful for protocol exploration. Requires `tshark`. |
| `tecpoints.json` | Point definitions for 797 TEC applications |
| `site.json` | Site-configuration template |
| `PROTOCOL.md` | Wire-level protocol reference |
| `p2.lua` | Wireshark dissector — decodes P2 frames in Wireshark's UI |

---

## Requirements

- Python 3.6 or later
- Network access to PXC controllers on TCP/5033
- `tshark` on PATH (optional — only needed for live-sniff discovery)
- L2 access to the BAS subnet (only needed for cold discovery)

No pip packages required for the scanner itself.

---

## Quick start

### Cold onboarding (no prior knowledge)

```bash
python p2_scanner.py --cold-discover --range 192.168.1.0/24 --save site.json
```

### Known BLN name

```bash
python p2_scanner.py --discover --range 192.168.1.0/24 --network MYBLN --save site.json
```

### Read a point

```bash
python p2_scanner.py --config site.json -n NODE1 -d DEVICE1 -p "ROOM TEMP"
```

### Launch the GUI

```bash
# POSIX (Linux / macOS)
python p2_gui.py

# Windows — double-click launch_gui_windows.bat, or:
launch_gui_windows.bat
```

The Windows .bat runs the GUI under `pythonw` so there's no console flash. If
it reports "p2_gui.py not found" with the file actually present, the .bat
has been corrupted to LF-only line endings — open it in Notepad and re-save
to restore CRLF.

---

## Command reference

Common commands shown below. Full flag list: `python p2_scanner.py --help`.

### Discovery

```bash
# Default cold discovery (BACnet recon + dictionary probe)
python p2_scanner.py --cold-discover --range 192.168.1.0/24 --save site.json

# Conservative (2-second delay between probes — safe during production hours)
python p2_scanner.py --cold-discover --range 192.168.1.0/24 --cold-delay 2

# Passive multicast listen (no probes sent)
python p2_scanner.py --listen 60 --save site.json

# Learn BLN name from a packet capture
python p2_scanner.py --pcap capture.pcapng --save site.json
```

### Reading

```bash
# All points on a device
python p2_scanner.py --config site.json -n NODE1 -d DEVICE1

# Specific point by name
python p2_scanner.py --config site.json -n NODE1 -d DEVICE1 -p "ROOM TEMP"

# Specific point by slot number (Desigo-style)
python p2_scanner.py --config site.json -n NODE1 -d DEVICE1 -p 4

# Full-panel walk — includes panel-internal / PPCL variables
python p2_scanner.py --config site.json -n NODE1 --walk-points

# Dump PPCL program source
python p2_scanner.py --config site.json -n NODE1 --dump-programs

# Panel firmware info
python p2_scanner.py --config site.json -n NODE1 --info
```

### Output formats

```bash
python p2_scanner.py --config site.json -n NODE1 -d DEVICE1 -f csv > out.csv
python p2_scanner.py --config site.json -n NODE1 -d DEVICE1 -f json > out.json
```

### IP range formats

`10.0.0.50` · `10.0.0.0/24` · `10.0.0.80-200` · `10.0.0` (shorthand for `.1-254`) · comma-separated ranges.

---

## Output

Each point read produces a result dictionary:

| Field | Description |
|-------|-------------|
| `point_name` | Point name |
| `point_slot` | Subpoint slot number (1–99) |
| `value` | Numeric value (live, or stale-cached if `comm_status='comm_fault'`) |
| `value_text` | Label for digital points (`"NIGHT"`, `"COOL"`, etc.) |
| `units` | Engineering units |
| `point_type` | `analog_ro` / `analog_rw` / `digital_ro` / `digital_rw` |
| `comm_status` | `online` (live FLN read) or `comm_fault` (panel returned cached data because the device is FLN-faulted — Desigo's `#COM` indicator) |
| `comm_error_code` | Panel-reported error byte; `0x06` is the typical comm-fault code |
| `point_info` | Full metadata (state labels, units, scaling) |

Verify-online operations on a list of devices additionally produce per-device fields:

| Field | Description |
|-------|-------------|
| `status` | `online` / `offline` — authoritative classification |
| `comm_status` | `online` / `comm_fault` — only when the panel reported one |
| `room_temp` | Live ROOM TEMP value, present for online devices |
| `stale_temp` | Cached ROOM TEMP value, present for `comm_fault` devices |
| `application` | App number; populated for online AND `#COM` devices (panel-cached for the latter) |
| `application_cached` | `True` only when APPLICATION was read from a comm-faulted device's cache |

Table output shows Desigo-style `(slot) NAME` for each point. Digital points render as `LABEL (raw)`. Comm-faulted points get a `#COM` suffix.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Scan ran but returned nothing (device offline, no readable points) |
| `2` | Input rejected before any network I/O |

---

## Config file

```json
{
  "p2_network": "MYBLN",
  "p2_site": "SITE",
  "scanner_name": "P2SCAN|5034",
  "known_nodes": {
    "NODE1": "192.168.1.10",
    "NODE2": "192.168.1.11"
  }
}
```

- `p2_network` — BLN network name. Required. PXCs reject messages with the wrong name.
- `scanner_name` — Scanner identity. Some sites require a specific format; if handshakes fail, try `<SITE>DCC-SVR|5034`.
- `known_nodes` — Node name → IP map.

Auto-updated by `--save`. Extra keys are preserved.

---

## Programmatic use

```python
import p2_scanner as p2

p2.P2_NETWORK = "MYBLN"
p2.SCANNER_NAME = "P2SCAN|5034"

conn = p2.P2Connection("192.168.1.50")
if conn.connect("NODE1"):
    result = conn.read_point("DEVICE1", "ROOM TEMP", "NODE1")
    print(result['value'], result.get('units'))
    conn.close()
```

Core API:

| Function | Purpose |
|----------|---------|
| `P2Connection(host)` | Open TCP session |
| `conn.connect(node_name)` | Handshake |
| `conn.read_point(device, point, node)` | Read a single point |
| `conn.enumerate_fln(node)` | List FLN devices |
| `conn.read_firmware(node)` | Panel model / firmware |
| `scan_device(host, device, ...)` | High-level device scan with rendering |
| `get_point_info(app, point_name)` | Metadata lookup |
| `render_point_value(value, info)` | Value → display string |

The library is synchronous. For a GUI, run reads on a worker thread (see `p2_gui_workers.py` for reference).

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "P2 network name required" | Provide `--network` or `--config` |
| "Handshake failed" | Verify BLN / scanner / node names |
| Handshake takes 2+ seconds | First connect to a modern-firmware panel; the dialect auto-probe is doing its thing. Cached on subsequent connects. |
| Listener hears nothing | Site has multicast disabled — use `--sniff` or `--cold-discover` |
| "Max peer sessions reached" | Try when other supervisor connections are idle |
| All device points show `#COM` | FLN bus disconnected, or the device-side controller is faulted. Cross-check against Desigo CC's System Manager — it'll show the same `#COM` flag if the fault is real. |
| Digital point shows raw float instead of label | Read APPLICATION first — use `-n NODE -d DEVICE` so the scanner can auto-detect the app |
| Windows `launch_gui_windows.bat` says "p2_gui.py not found" but the file IS there | The .bat got LF-only line endings somehow (web upload, Git autocrlf, copy through a Linux box). Open it in Notepad and re-save — Notepad always writes CRLF, which fixes it. |
| GUI Verify Online shows 0 devices but doesn't tell me if the PXC is up | Click Verify Online anyway — on a no-device node the GUI auto-falls back to a firmware probe, which flips the node row green/red without needing any FLN devices. Or click Firmware directly. |

---

## Safety

- **Read-only.** The scanner never writes points, changes setpoints, or modifies controller state. Write-capable opcodes are documented in `PROTOCOL.md` but intentionally not exposed.
- **PXCs have a limited number of peer sessions** (typically 8–16). Don't run parallel scanners against the same panel.
- **Cold discovery sends dictionary probes.** Observed as non-disruptive, but use `--cold-delay 2` during production hours as a precaution.

## Wireshark dissector

A Lua dissector (`p2.lua`) is included for decoding P2 frames live in Wireshark — useful for protocol debugging, learning the wire format, or analyzing traffic from production sites.

**Install:**

```
# Linux / macOS
cp p2.lua ~/.local/lib/wireshark/plugins/

# Windows
copy p2.lua %APPDATA%\Wireshark\plugins\

# Or find your plugin path via Wireshark: Help → About Wireshark → Folders → Personal Lua Plugins
```

Restart Wireshark. The dissector auto-attaches to TCP ports 5033 and 5034. Decoded fields appear under the **P2** tree in the packet details pane: opcode names, error codes, sequence numbers, message types, and direction byte. The decoder also handles 0x0240 / 0x0274 push frames, the routing table 0x4634, alarm pair 0x0508/0x0509, schedule writes 0x5020/0x5022, PPCL editor 0x4100-family, and the property-write fault `0x0E15`. Multicast presence beacons on UDP/10001 are decoded under `p2_beacon`.

The dissector is conservative — it doesn't try to decode every TLV inside operational payloads, just the framing, opcodes, and the most common request/response shapes. For protocol exploration of an unfamiliar capture, run `analyze_pcap.py` against the saved file — it inventories every opcode, error code, frame-size distribution, and message-type seen, and flags anything not in `KNOWN_OPCODES` so you can spot new opcodes or unfamiliar variants quickly.

---

## See also

- **[PROTOCOL.md](PROTOCOL.md)** — wire-level protocol reference. Every opcode, every format variant, every edge case. Read this if you're debugging unusual responses, implementing your own client, or just curious how a BAS protocol works on the wire.
