#!/usr/bin/env python3
"""
Siemens P2 Protocol Scanner
============================
Universal scanner for Siemens PXC controllers using the P2 (Apogee Ethernet)
protocol. Discovers controllers, enumerates FLN devices, reads point values,
and queries firmware information — all over TCP/5033.

Quick Start:
    python p2_scanner.py --pcap capture.pcapng                              # Learn network name
    python p2_scanner.py --discover --range 10.1.1.0/24 --network MYBLN     # Find everything
    python p2_scanner.py -n 10.1.1.50 -d DEVICE1 -p "ROOM TEMP" --network MYBLN  # Read a point

Protocol: TCP/5033, Siemens Apogee P2 Ethernet

"""

import socket
import struct
import time
import sys
import argparse
import json
import csv
import re
from datetime import datetime
from collections import OrderedDict
from typing import Optional, Dict, List, Tuple, Any

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION — Defaults are auto-learned when possible
# ═══════════════════════════════════════════════════════════════════════════════

P2_PORT = 5033
P2_NETWORK = ""                  # Auto-learned from first connection
P2_SITE = ""                     # Auto-learned from first connection
SCANNER_NAME = "P2SCAN|5034"     # Generic default; sites may require <SITE>DCC-SVR|5034
DEBUG_READS = False              # When True, print raw hex on parse failures
CONNECT_TIMEOUT = 5              # TCP connect timeout (seconds)
READ_TIMEOUT = 10                # Read response timeout (seconds)

# Known nodes (optional — populated by discovery or site config file)
# Format: {"NODE_NAME": "IP_ADDRESS", ...}
KNOWN_NODES = {}


def _set_network(name: str):
    global P2_NETWORK
    P2_NETWORK = name

def _set_scanner_name(name: str):
    global SCANNER_NAME
    SCANNER_NAME = name


class ScannerInputError(ValueError):
    """Raised when the scanner is asked to do something the DBF or protocol
    rules say is invalid — e.g. reading an out-of-range slot, or reading a
    slot that isn't defined in the device's application (without --force-slot).

    The CLI catches this and exits with code 2 so shell scripts and parent
    processes can distinguish 'bad input' from 'ran fine but found nothing'.
    Library callers who want to handle input errors themselves can catch it
    directly; those who don't care will get a normal Python traceback.
    """
    pass


def save_config(filepath: str):
    """Save learned P2 network config to a JSON file."""
    config = {
        'p2_network': P2_NETWORK,
        'p2_site': P2_SITE,
        'scanner_name': SCANNER_NAME,
        'known_nodes': KNOWN_NODES,
    }
    with open(filepath, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"  Config saved to {filepath}")


def load_config(filepath: str) -> bool:
    """Load P2 network config from a JSON file."""
    global P2_NETWORK, P2_SITE, SCANNER_NAME, KNOWN_NODES
    try:
        with open(filepath, 'r') as f:
            config = json.load(f)
        if config.get('p2_network'):
            P2_NETWORK = config['p2_network']
        if config.get('p2_site'):
            P2_SITE = config['p2_site']
        if config.get('scanner_name'):
            SCANNER_NAME = config['scanner_name']
        if config.get('known_nodes'):
            KNOWN_NODES.update(config['known_nodes'])
        print(f"  Config loaded from {filepath}")
        print(f"  Network: {P2_NETWORK}  |  Site: {P2_SITE}  |  Nodes: {len(KNOWN_NODES)}")
        return True
    except FileNotFoundError:
        print(f"  [ERROR] Config file not found: {filepath}")
        return False
    except json.JSONDecodeError:
        print(f"  [ERROR] Invalid config file: {filepath}")
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# TEC APPLICATION POINT DATABASES
# ═══════════════════════════════════════════════════════════════════════════════
# Each TEC has up to 99 subpoints. The point names are fixed per application.
# Address 0 is reserved, 1-99 are subpoints.
# Format: address -> (name, description, units, read_only)

# Common points present in ALL applications (2020-2027)
COMMON_POINTS = {
    1:  ("CTLR ADDRESS",   "Controller FLN address",              "",      False),
    2:  ("APPLICATION",    "Application number",                   "",      True),
    3:  ("CTL TEMP",       "Control temperature",                  "DEG F", True),
    4:  ("ROOM TEMP",      "Room temperature sensor reading",      "DEG F", True),
    6:  ("DAY CLG STPT",   "Day cooling setpoint",                 "DEG F", False),
    8:  ("NGT CLG STPT",   "Night cooling setpoint",               "DEG F", False),
    11: ("RM STPT MIN",    "Room setpoint dial minimum",           "DEG F", False),
    12: ("RM STPT MAX",    "Room setpoint dial maximum",           "DEG F", False),
    13: ("RM STPT DIAL",   "Room setpoint dial reading",           "DEG F", True),
    14: ("STPT DIAL",      "Setpoint dial enabled",                "",      False),
    18: ("WALL SWITCH",    "Wall switch monitoring enabled",       "",      False),
    19: ("DI OVRD SW",     "Override switch status",               "",      True),
    20: ("OVRD TIME",      "Override duration (hours)",            "",      False),
    21: ("NGT OVRD",       "Night override active",                "",      True),
    24: ("DI 2",           "Digital input 2 status",               "",      True),
    29: ("DAY.NGT",        "Day/Night mode",                       "",      True),
    31: ("CLG FLOW MIN",   "Cooling minimum airflow",              "",      False),
    32: ("CLG FLOW MAX",   "Cooling maximum airflow",              "",      False),
    35: ("CTL STPT",       "Active control setpoint",              "DEG F", True),
    36: ("CTL FLOW MIN",   "Active control flow minimum",          "",      True),
    37: ("CTL FLOW MAX",   "Active control flow maximum",          "",      True),
    38: ("FLOW STPT",      "Flow setpoint",                        "PCT",   True),
    39: ("FLOW",           "Actual airflow percentage",            "PCT",   True),
    40: ("AIR VOLUME",     "Air volume (CFM)",                     "",      True),
    41: ("DMPR POS",       "Damper position",                      "PCT",   True),
    42: ("DMPR COMD",      "Damper command",                       "PCT",   True),
    43: ("DMPR STATUS",    "Damper status",                        "",      True),
    44: ("DMPR ROT ANG",   "Damper rotation angle",                "",      False),
    45: ("DUCT AREA",      "Duct cross-sectional area (sq ft)",    "",      False),
    46: ("FLOW COEFF",     "Flow coefficient",                     "",      True),
    47: ("CLG LOOPOUT",    "Cooling loop output",                  "PCT",   True),
    48: ("CLG BIAS",       "Cooling bias",                         "PCT",   False),
    49: ("CLG P GAIN",     "Cooling proportional gain",            "",      False),
    50: ("CLG I GAIN",     "Cooling integral gain",                "",      False),
    51: ("CLG D GAIN",     "Cooling derivative gain",              "",      False),
    52: ("FLOW P GAIN",    "Flow proportional gain",               "",      False),
    53: ("FLOW I GAIN",    "Flow integral gain",                   "",      False),
    54: ("FLOW D GAIN",    "Flow derivative gain",                 "",      False),
    55: ("FLOW BIAS",      "Flow bias",                            "PCT",   False),
    58: ("SWITCH LIMIT",   "Switch limit",                         "PCT",   False),
    59: ("SWITCH DBAND",   "Switch deadband",                      "DEG F", False),
    60: ("SWITCH TIME",    "Switch time (minutes)",                "",      False),
    70: ("DO 1",           "Digital output 1",                     "",      True),
    71: ("DO 2",           "Digital output 2",                     "",      True),
    75: ("DO 6",           "Digital output 6",                     "",      True),
    80: ("CAL SETUP",      "Calibration setup",                    "",      False),
    81: ("CAL MODULE",     "Calibration module",                   "",      True),
    82: ("CAL TIMER",      "Calibration timer",                    "",      True),
    83: ("CAL AIR",        "Calibration air",                      "",      True),
    84: ("MTR SETUP",      "Motor setup",                          "",      False),
    85: ("MTR1 TIMING",    "Motor 1 timing",                       "SEC",   False),
    86: ("MTR2 TIMING",    "Motor 2 timing",                       "SEC",   False),
    87: ("MTR3 TIMING",    "Motor 3 timing",                       "SEC",   False),
    90: ("LOOP TIME",      "Control loop time",                    "SEC",   False),
    91: ("ERROR STATUS",   "Error status",                         "",      True),
    92: ("DO DIR. REV",    "DO direction reverse",                 "",      False),
    93: ("VALVE COUNT",    "Number of valve actuators",            "",      False),
    95: ("DO 3",           "Digital output 3",                     "",      True),
    96: ("DO 4",           "Digital output 4",                     "",      True),
    97: ("DO 5",           "Digital output 5",                     "",      True),
    98: ("TOTAL VOLUME",   "Totalized air volume",                 "",      True),
}

# Points specific to heating applications (2021-2027)
HEATING_POINTS = {
    5:  ("HEAT.COOL",      "Current heating/cooling mode",         "",      True),
    7:  ("DAY HTG STPT",   "Day heating setpoint",                 "DEG F", False),
    9:  ("NGT HTG STPT",   "Night heating setpoint",               "DEG F", False),
    25: ("DI 3",           "Digital input 3 status",               "",      True),
    33: ("HTG FLOW MIN",   "Heating minimum airflow",              "",      False),
    34: ("HTG FLOW MAX",   "Heating maximum airflow",              "",      False),
    56: ("HTG LOOPOUT",    "Heating loop output",                  "PCT",   True),
    57: ("HTG BIAS",       "Heating bias",                         "PCT",   False),
    61: ("HTG P GAIN",     "Heating proportional gain",            "",      False),
    62: ("HTG I GAIN",     "Heating integral gain",                "",      False),
    63: ("HTG D GAIN",     "Heating derivative gain",              "",      False),
}

# Points for reheat applications (2022-2027)
REHEAT_POINTS = {
    15: ("AUX TEMP",       "Auxiliary temperature sensor",         "DEG F", True),
    16: ("FLOW START",     "Heating flow start threshold",         "PCT",   False),
    17: ("FLOW END",       "Heating flow end threshold",           "PCT",   False),
    22: ("REHEAT START",   "Reheat start threshold",               "PCT",   False),
    23: ("REHEAT END",     "Reheat end threshold",                 "PCT",   False),
}

# Hot water valve points (2023, 2025, 2027)
HW_VALVE_POINTS = {
    64: ("VLV1 POS",       "Valve 1 position",                    "PCT",   True),
    65: ("VLV1 COMD",      "Valve 1 command",                     "PCT",   True),
    66: ("VLV2 POS",       "Valve 2 position",                    "PCT",   True),
    67: ("VLV2 COMD",      "Valve 2 command",                     "PCT",   True),
}

# Fan points (2024-2027)
FAN_POINTS = {
    26: ("SERIES ON",      "Series fan ON threshold",              "",      False),
    27: ("SERIES OFF",     "Series fan OFF threshold",             "",      False),
    28: ("PARALLEL ON",    "Parallel fan ON threshold",            "",      False),
    30: ("PARALLEL OFF",   "Parallel fan OFF threshold",           "",      False),
}

# Supply temp for 2021
SUPPLY_TEMP_POINT = {
    15: ("SUPPLY TEMP",    "Supply air temperature",               "DEG F", True),
}


def get_point_table(application: int) -> Dict[int, tuple]:
    """Build the complete point table for a given TEC application number.

    First tries to load from tecpoints.json (rich format,
    797 apps with PTYPE / slope / intercept / state labels).
    Falls back to legacy tecpnts.json (name/units/dtype tuples).
    Falls back to hardcoded tables for apps 2020-2027 if neither available.

    Return format: {addr: (name, desc, units, read_only)} — same tuple shape
    as before for backwards compatibility with all call sites.
    Rich metadata is also available via get_point_info() for the output path.
    """
    global _TECPNTS_DB

    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()

    if _TECPNTS_DB and str(application) in _TECPNTS_DB:
        app_data = _TECPNTS_DB[str(application)]
        points = {}
        for addr_str, info in app_data.items():
            try:
                addr = int(addr_str)
            except (ValueError, TypeError):
                continue
            # Support both rich dict format and legacy list format
            if isinstance(info, dict):
                name = info.get('name', '')
                units = info.get('units', '')
                ptype = info.get('ptype', 4)
                # ptype 1,10 = digital RW; ptype 2 = digital RO (mostly);
                # ptype 3 = analog RO (input); ptype 4 = analog RW.
                # Use 'rw' field when present, else fall back to ptype mapping.
                rw_flag = info.get('rw')
                if rw_flag is None:
                    rw_flag = ptype not in (2, 3)
                ro = not rw_flag
            else:  # legacy list format: [name, units, dtype_str]
                name = info[0]
                units = info[1] if len(info) > 1 else ""
                dtype = info[2] if len(info) > 2 else "AO"
                ro = dtype in ('AI', 'BI')
            points[addr] = (name, name, units, ro)
        return OrderedDict(sorted(points.items()))

    # Fallback to hardcoded tables
    points = dict(COMMON_POINTS)

    if application == 2020:
        points[25] = ("DI 3", "Digital input 3 status", "", True)
    elif application == 2021:
        points.update(HEATING_POINTS)
        points.update(SUPPLY_TEMP_POINT)
    elif application == 2022:
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
    elif application == 2023:
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
        points.update(HW_VALVE_POINTS)
    elif application in (2024, 2025):
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
        points.update(FAN_POINTS)
        if application == 2025:
            points.update(HW_VALVE_POINTS)
    elif application in (2026, 2027):
        points.update(HEATING_POINTS)
        points.update(REHEAT_POINTS)
        points.update(FAN_POINTS)
        if application == 2027:
            points.update(HW_VALVE_POINTS)

    return OrderedDict(sorted(points.items()))


def get_point_info(application: int, point_name: str) -> Optional[Dict]:
    """Get the rich metadata entry for a specific (app, point name).
    Returns a dict with keys like 'name', 'ptype', 'type', 'units', 'slope',
    'intercept', 'on_label', 'off_label', 'rw'. Returns None if not found.

    Only works when tecpoints.json (rich format) is loaded.
    """
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not app_data:
        return None
    # Scan entries for a name match (point_name is the lookup key from live data)
    for addr_str, info in app_data.items():
        if isinstance(info, dict) and info.get('name') == point_name:
            return info
    return None


def resolve_slot_to_name(application: int, slot: int) -> Optional[str]:
    """Look up the point name registered at a specific slot number for an app.
    Returns None if the slot isn't defined in the app's point table.

    This is what lets '-p 29' mean 'read whatever's at slot 29 for this device.'
    """
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not app_data:
        return None
    entry = app_data.get(str(slot))
    if isinstance(entry, dict):
        return entry.get('name')
    elif isinstance(entry, (list, tuple)) and entry:
        # Legacy format support
        return entry[0]
    return None


def get_point_slot(application: int, point_name: str) -> Optional[int]:
    """Reverse lookup: find the slot number for a point name within an app.
    Used for display — shows the Desigo-style '(29) DAY.NGT' prefix."""
    global _TECPNTS_DB
    if _TECPNTS_DB is None:
        _TECPNTS_DB = _load_tecpnts_db()
    if not _TECPNTS_DB:
        return None
    app_data = _TECPNTS_DB.get(str(application))
    if not app_data:
        return None
    for addr_str, info in app_data.items():
        name_in_db = None
        if isinstance(info, dict):
            name_in_db = info.get('name')
        elif isinstance(info, (list, tuple)) and info:
            name_in_db = info[0]
        if name_in_db == point_name:
            try:
                return int(addr_str)
            except (ValueError, TypeError):
                return None
    return None


def render_point_value(value: float, info: Optional[Dict]) -> Tuple[str, str]:
    """Convert a raw float value into (display_str, value_text) using point info.

    display_str: what to show in a table cell (e.g. '74.0', 'NIGHT', '1 (ON)')
    value_text: just the label portion for digital points ('NIGHT'), empty string
                for analog points.

    If info is None or lacks labels, falls back to formatting the float.
    """
    if value is None:
        return ("—", "")

    # Digital points with on/off labels
    if info and 'on_label' in info and 'off_label' in info:
        # Siemens convention: 1 = ON/first-label, 0 = OFF/second-label
        label = info['on_label'] if value >= 0.5 else info['off_label']
        return (label, label)

    # Analog — format cleanly
    if value == int(value) and abs(value) < 100000:
        return (str(int(value)), "")
    return (f"{value:.2f}", "")


# Global cache for the full TEC point database
_TECPNTS_DB = None

def _load_tecpnts_db() -> Optional[Dict]:
    """Load the TEC point database.

    Prefers tecpoints.json (rich format, with state
    labels, slope/intercept, etc.). Falls back to legacy tecpnts.json.
    """
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    # Search order: rich format first, then legacy. Both file names are
    # supported so users can drop in either.
    search_paths = []
    for base in (here, cwd, ''):
        search_paths.append(os.path.join(base, 'tecpoints.json'))
    for base in (here, cwd, ''):
        search_paths.append(os.path.join(base, 'tecpnts.json'))
    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    db = json.load(f)
                return db
            except Exception:
                pass
    return None


# List of key points to read first (quick scan)
QUICK_SCAN_POINTS = [
    "APPLICATION", "ROOM TEMP", "CTL STPT", "CTL TEMP",
    "DAY CLG STPT", "NGT CLG STPT", "DAY HTG STPT", "NGT HTG STPT",
    "HEAT.COOL", "DAY.NGT", "FLOW", "AIR VOLUME",
    "DMPR POS", "VLV1 POS", "VLV2 POS",
    "HTG LOOPOUT", "CLG LOOPOUT", "ERROR STATUS",
]


# ═══════════════════════════════════════════════════════════════════════════════
# P2 PROTOCOL IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

class P2Message:
    """Represents a single P2 protocol message."""
    # Message types
    TYPE_CONNECT   = 0x2E
    TYPE_ANNOUNCE  = 0x2F
    TYPE_DATA      = 0x33
    TYPE_HEARTBEAT = 0x34

    # Data markers
    MARKER_KEEPALIVE = b'\x46\x40'
    MARKER_COV       = b'\x02\x74'
    MARKER_READ      = b'\x02\x71'
    MARKER_BROWSE    = b'\x42'

    def __init__(self, msg_type: int, sequence: int, payload: bytes):
        self.msg_type = msg_type
        self.sequence = sequence
        self.payload = payload
        self.is_response = payload[0] == 0x01 if payload else False

    def to_bytes(self) -> bytes:
        total_len = 12 + len(self.payload)
        header = struct.pack('>III', total_len, self.msg_type, self.sequence)
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['P2Message']:
        if len(data) < 12:
            return None
        total_len, msg_type, sequence = struct.unpack('>III', data[:12])
        payload = data[12:total_len]
        return cls(msg_type, sequence, payload)


class P2Connection:
    """Manages a TCP connection to a PXC controller using the P2 protocol."""

    def __init__(self, host: str, port: Optional[int] = None,
                 network: Optional[str] = None,
                 scanner_name: Optional[str] = None):
        # Defaults resolve at CALL time, not definition time. This avoids the
        # module-load-capture gotcha where a caller like P2Connection(ip) would
        # otherwise bake in whatever the globals happened to be when Python
        # first parsed this class — even if load_config() later updated them.
        self.host = host
        self.port = port if port is not None else P2_PORT
        self.network = network if network is not None else P2_NETWORK
        self.scanner_name = scanner_name if scanner_name is not None else SCANNER_NAME
        self.sock: Optional[socket.socket] = None
        self.sequence = 1
        self.node_name = None      # Learned from responses
        self._recv_buffer = b""

    def connect(self, node_name: str = "node") -> bool:
        """Establish TCP connection and P2 session with the PXC controller."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(CONNECT_TIMEOUT)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(READ_TIMEOUT)
        except (socket.error, socket.timeout) as e:
            print(f"  [ERROR] Connection to {self.host}:{self.port} failed: {e}")
            return False

        # P2 session handshake: send a keepalive/heartbeat to establish the session
        # The PXC won't respond to read requests until it sees this.
        if not self._handshake(node_name):
            print(f"  [ERROR] P2 handshake failed — controller did not respond")
            self.close()
            return False

        return True

    def _handshake(self, node_name: str) -> bool:
        """Send keepalive heartbeat to establish P2 session with the controller."""
        seq = self._next_seq()
        net = self.network.encode('ascii')
        src = node_name.encode('ascii')
        scanner = self.scanner_name.encode('ascii')
        site = P2_SITE.encode('ascii')

        # Build heartbeat: routing + 0x4640 identity block
        routing = (
            b'\x00' +
            net + b'\x00' +
            src + b'\x00' +
            net + b'\x00' +
            scanner + b'\x00'
        )
        identity = (
            b'\x46\x40' +
            b'\x01\x00' + bytes([len(scanner)]) + scanner +
            b'\x01\x00' + bytes([len(site)]) + site +
            b'\x01\x00' + bytes([len(net)]) + net +
            b'\x00\x01\x01' +
            b'\x00\x00\x00\x00\x00' +
            struct.pack('>I', int(time.time())) + b'\x00' +
            b'\xfe\x98\x00'
        )
        payload = routing + identity
        msg = P2Message(P2Message.TYPE_DATA, seq, payload)

        if not self._send_message(msg):
            return False

        # Wait for heartbeat response
        resp = self._recv_response(seq, max_attempts=5)
        return resp is not None

    def close(self):
        """Close the TCP connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def _next_seq(self) -> int:
        seq = self.sequence
        self.sequence += 1
        return seq

    def _build_routing(self, dest_node: str, is_request: bool = True) -> bytes:
        """Build the P2 routing header. P2 puts destination first, then source."""
        flag = b'\x00' if is_request else b'\x01'
        src = self.scanner_name.encode('ascii')
        dst = dest_node.encode('ascii')
        net = self.network.encode('ascii')
        return flag + net + b'\x00' + dst + b'\x00' + net + b'\x00' + src + b'\x00'

    def _send_message(self, msg: P2Message) -> bool:
        """Send a P2 message over the TCP connection."""
        if not self.sock:
            return False
        try:
            self.sock.sendall(msg.to_bytes())
            return True
        except socket.error as e:
            print(f"  [ERROR] Send failed: {e}")
            return False

    def _recv_message(self) -> Optional[P2Message]:
        """Receive a single P2 message from the connection."""
        if not self.sock:
            return None

        try:
            # Read until we have at least 12 bytes for the header
            while len(self._recv_buffer) < 12:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buffer += chunk

            # Parse the total length from the header
            total_len = struct.unpack('>I', self._recv_buffer[:4])[0]

            # Read until we have the full message
            while len(self._recv_buffer) < total_len:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self._recv_buffer += chunk

            # Extract the message and advance the buffer
            msg_data = self._recv_buffer[:total_len]
            self._recv_buffer = self._recv_buffer[total_len:]
            return P2Message.from_bytes(msg_data)

        except socket.timeout:
            return None
        except socket.error as e:
            print(f"  [ERROR] Receive failed: {e}")
            return None

    def _recv_response(self, expected_seq: int, max_attempts: int = 10) -> Optional[P2Message]:
        """Receive a response matching the expected sequence number."""
        for _ in range(max_attempts):
            msg = self._recv_message()
            if msg is None:
                return None
            if msg.sequence == expected_seq and msg.is_response:
                return msg
            # Got a different message (keepalive, COV, etc.) — keep reading
        return None

    def read_point(self, device: str, point_name: str,
                   node_name: str = "node") -> Optional[Dict[str, Any]]:
        """
        Read a single point value from a TEC device.

        Args:
            device: TEC device name (e.g., "DEVICE1")
            point_name: Subpoint name (e.g., "ROOM TEMP")
            node_name: P2 node name in lowercase (e.g., "node1")

        Returns:
            Dict with 'value', 'units', 'description', or None on failure.
        """
        seq = self._next_seq()

        # Build routing header
        routing = self._build_routing(node_name)

        # Build read request payload
        # Format: [routing] 02 71 00 00 01 00 [dev_len] [device] 01 00 [pt_len] [point] 00 FF
        dev_bytes = device.encode('ascii')
        pt_bytes = point_name.encode('ascii')

        read_payload = (
            routing +
            b'\x02\x71\x00\x00' +
            b'\x01\x00' + bytes([len(dev_bytes)]) + dev_bytes +
            b'\x01\x00' + bytes([len(pt_bytes)]) + pt_bytes +
            b'\x00\xff'
        )

        msg = P2Message(P2Message.TYPE_DATA, seq, read_payload)
        if not self._send_message(msg):
            return None

        # Wait for response
        resp = self._recv_response(seq)
        if resp is None:
            # No response at all — surface last_error if we have structured info
            if getattr(self, 'last_error', None):
                name, desc = self.last_error
                if DEBUG_READS:
                    print(f"    [DEBUG] {device}/{point_name}: AP2 error {name} ({desc})")
            elif DEBUG_READS:
                print(f"    [DEBUG] {device}/{point_name}: no response from PXC")
            return None

        parsed = self._parse_read_response(resp)
        if parsed is None and DEBUG_READS:
            print(f"    [DEBUG] {device}/{point_name}: parse failed")
            print(f"    [DEBUG]   response payload ({len(resp.payload)}B): {resp.payload.hex()}")
        return parsed

    def _parse_read_response(self, msg: P2Message) -> Optional[Dict[str, Any]]:
        """Parse a point read response message."""
        payload = msg.payload
        result = {
            'value': None,
            'units': '',
            'description': '',
            'point_name': '',
            'device_name': '',
            'data_type': 'unknown',
        }

        # Find the value block. Confirmed from pcap analysis against Desigo:
        #
        # ALL valid responses have this layout in the value block region:
        #   [last point_name LP-string] [01 00 00] [7 metadata bytes] [4-byte float]
        #                                                              ^^ float at +10
        #
        # Four observed shapes of the 7 metadata bytes:
        #   Shape A  (0x0271 resp, 3FFFFFFF case): 3f ff ff ff 00 00 00
        #   Shape B1 (0x0271 resp, zero-sentinel): 00 00 00 00 00 00 00
        #   Shape B2 (0x0220 resp, explicit type): 00 00 00 00 00 00 XX
        #            where XX = data-type code (0x03 = analog, etc.)
        #   Shape C  (app-2500-ish negative values): same as B1/B2 but float
        #            starts 0xbf (negative floats)
        #
        # Critical: the payload also has a TRAILING metadata block (min/max limits,
        # resolution) that looks almost identical to [01 00 00][zeros][float]. A
        # pure structural scan false-positives on it. The trailing block is always
        # preceded by bytes from the VALUE block itself (the float); the real
        # value block is always preceded by an ASCII character (last byte of a
        # length-prefixed point name string).
        #
        # So: scan FORWARD for [01 00 00] whose position-1 byte is an ASCII
        # character from A-Z, 0-9, space, or common punctuation. That's the
        # point-name tail, and the next 10 bytes are our value block.

        flags_idx = -1
        for i in range(1, len(payload) - 14):
            if (payload[i]   == 0x01 and payload[i+1] == 0x00
                and payload[i+2] == 0x00
                and payload[i+7] == 0x00 and payload[i+8] == 0x00):
                prev = payload[i-1]
                # Previous byte must be printable ASCII (end of point name string)
                # Accepted chars: A-Z, a-z, 0-9, space, period, underscore, hyphen
                is_asciiend = (
                    (0x41 <= prev <= 0x5A) or   # A-Z
                    (0x61 <= prev <= 0x7A) or   # a-z
                    (0x30 <= prev <= 0x39) or   # 0-9
                    prev in (0x20, 0x2E, 0x5F, 0x2D)  # space . _ -
                )
                if not is_asciiend:
                    continue
                # Sanity: float byte should look plausible
                first_byte = payload[i + 10]
                # Accept positive floats 0..~2e5, negative floats, zero, and
                # digital-point raw bytes (0x00-0x01 range).
                if first_byte <= 0x48 or first_byte in (0xBF, 0xC0, 0xC1, 0xC2,
                                                        0xC3, 0xC4, 0xC5):
                    flags_idx = i + 3
                    break

        if flags_idx < 0:
            # No value block found — probably an error response, a device-summary
            # bulk read, or a characterization read (different opcode). Safe to
            # return None; --debug-reads will surface the raw hex for inspection.
            return None

        # Extract device name and point name from length-prefixed strings before flags
        pre_flags = payload[:flags_idx]
        lp_strings = self._extract_lp_strings(pre_flags)

        routing_names = {self.network, self.scanner_name, P2_SITE,
                        P2_NETWORK} | {s.split('|')[0] for s in [self.scanner_name] if '|' in s}
        data_strs = [s for s in lp_strings
                     if s.upper() not in {n.upper() for n in routing_names}
                     and not s.upper().startswith('NODE')]
        if len(data_strs) >= 2:
            result['device_name'] = data_strs[0]
            result['point_name'] = data_strs[1]
            if len(data_strs) >= 3:
                result['description'] = data_strs[2]

        # Extract value after flags
        # [3F FF FF F7] [00 XX YY] [4-byte float]
        # XX = comm status: 00=online, 01=comm fault (offline)
        # YY = error code (06 = typical comm error)
        after_flags = payload[flags_idx + 3:]
        if len(after_flags) >= 8:
            # Check comm status flag (byte +2 after 3FFFFF)
            comm_status = after_flags[2] if len(after_flags) > 2 else 0
            result['comm_status'] = 'online' if comm_status == 0 else 'comm_fault'
            result['comm_error_code'] = after_flags[3] if len(after_flags) > 3 else 0

            # Surface the 4-byte property-state slot — adjacent to (not part of)
            # the float value. In decomp this appears to be a sentinel: 3FFFFFFF
            # means "no specific quality flags set"; 00000000 means "explicit
            # quality flags, all cleared." Unverified whether 00000000 implies
            # a cached/stale value vs a fresh poll. Surfacing so users can spot
            # patterns across devices.
            result['property_state_hex'] = payload[flags_idx:flags_idx + 4].hex()

            val_offset = 4  # skip flag tail byte + status bytes
            raw_val = after_flags[val_offset:val_offset + 4]
            if len(raw_val) == 4:
                result['value'] = struct.unpack('>f', raw_val)[0]
                result['value_raw_hex'] = raw_val.hex()

                # Determine data type from byte before value
                dtype_byte = after_flags[3] if len(after_flags) > 3 else 0
                if dtype_byte == 0x03:
                    result['data_type'] = 'analog'
                elif dtype_byte == 0x00:
                    result['data_type'] = 'binary' if result['value'] in (0.0, 1.0) else 'analog'

        # Extract units from after the value. Units arrive as length-prefixed
        # strings; some devices pad with a leading space (e.g. " CFM"), so we
        # strip before matching.
        after_val = payload[flags_idx + 3 + 8:]
        unit_whitelist = {
            'DEG F', 'DEG C', 'DEGF', 'DEGC',
            'PCT', '%', 'PERCENT',
            'SEC', 'MIN', 'HRS', 'HR', 'MS',
            'CFM', 'FPM', 'CF', 'FT3/MIN',
            'GPM', 'LPM', 'LPS',
            'PSI', 'KPA', 'INHG', 'IN WC', 'IN.WC', 'PA',
            'AMPS', 'VOLTS', 'V', 'A', 'MA', 'MV',
            'KW', 'KWH', 'BTU', 'BTUH', 'W', 'WH',
            'PPM', 'PPB',
            'RPM', 'HZ', 'KHZ',
            'FT', 'IN', 'M', 'MM', 'CM',
        }
        for s in self._extract_lp_strings(after_val):
            s_clean = s.strip().upper()
            if s_clean in unit_whitelist:
                result['units'] = s.strip()  # preserve original casing minus padding
                break

        return result

    @staticmethod
    def _extract_lp_strings(data: bytes) -> List[str]:
        """Extract length-prefixed strings (01 00 [len] [str] or 00 01 00 [len] [str])."""
        strings = []
        i = 0
        while i < len(data) - 3:
            # Pattern: 01 00 [len] [string]
            if data[i] == 0x01 and data[i+1] == 0x00 and 0 < data[i+2] < 100:
                slen = data[i+2]
                if i + 3 + slen <= len(data):
                    try:
                        s = data[i+3:i+3+slen].decode('ascii')
                        if s.isprintable():
                            strings.append(s)
                            i += 3 + slen
                            continue
                    except:
                        pass
            # Pattern: 00 01 00 [len] [string]
            if (i < len(data) - 4 and data[i] == 0x00 and data[i+1] == 0x01
                    and data[i+2] == 0x00 and 0 < data[i+3] < 100):
                slen = data[i+3]
                if i + 4 + slen <= len(data):
                    try:
                        s = data[i+4:i+4+slen].decode('ascii')
                        if s.isprintable():
                            strings.append(s)
                            i += 4 + slen
                            continue
                    except:
                        pass
            i += 1
        return strings

    def browse_device(self, device: str, node_name: str = "node") -> Optional[Dict[str, Any]]:
        """
        Send a device browse request to enumerate device info.

        Args:
            device: TEC device name (e.g., "DEVICE1")
            node_name: P2 node name in lowercase

        Returns:
            Dict with device info, or None on failure.
        """
        seq = self._next_seq()
        routing = self._build_routing(node_name)

        dev_bytes = device.encode('ascii')

        browse_payload = (
            routing +
            b'\x42\x00' +
            b'\x01\x00\x04SYST' +
            b'\x23\x3f\xff\xff\xff' +
            b'\x00\x00' +
            b'\x01\x00' + bytes([len(dev_bytes)]) + dev_bytes +
            b'\x00\x00\x01\x00\x00\xff\xff'
        )

        msg = P2Message(P2Message.TYPE_DATA, seq, browse_payload)
        if not self._send_message(msg):
            return None

        resp = self._recv_response(seq)
        if resp is None:
            return None

        # Parse browse response for device description and metadata
        strings = self._extract_lp_strings(resp.payload)
        routing_names = {SCANNER_NAME, P2_NETWORK, P2_SITE} | {s.split('|')[0] for s in [SCANNER_NAME] if '|' in s}
        data_strs = [s for s in strings
                     if s.upper() not in {n.upper() for n in routing_names}
                     and not s.upper().startswith('NODE')]

        result = {'device': device, 'strings': data_strs}
        if len(data_strs) >= 2:
            result['description'] = data_strs[1]
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_node_name(host: str) -> str:
    """Look up or auto-learn the P2 node name for a given IP address."""
    # Check known nodes first
    for name, ip in KNOWN_NODES.items():
        if ip == host:
            return name.lower()
    # Auto-probe the host to learn its name
    result = probe_p2_host(host)
    if result and 'node_name' in result:
        # Cache it for future use
        KNOWN_NODES[result['node_name']] = host
        return result['node_name'].lower()
    return "node"  # generic fallback


def scan_device(host: str, device: str, points: Optional[List[str]] = None,
                quick: bool = False, output_format: str = "table",
                force_slot: bool = False) -> List[Dict]:
    """
    Scan all (or selected) points on a TEC device.

    Args:
        host: PXC controller IP address
        device: TEC device name
        points: Optional list of specific point names OR slot numbers (as
                strings like "29" or "DAY.NGT"). Numeric strings trigger
                slot → name resolution via the app's point table.
        quick: If True, only read key operational points
        output_format: "table", "json", or "csv"
        force_slot: When a numeric slot isn't defined in the app's point
                    table, normally the scanner refuses with a clear error.
                    Setting force_slot=True attempts the read anyway using
                    a synthesized name (useful for protocol troubleshooting).

    Returns:
        List of point result dicts
    """
    # Pre-flight validation: check slot-range inputs BEFORE we touch the network.
    # Doesn't catch "slot not defined in app" since we don't know the app yet,
    # but range violations are purely syntactic and can be rejected up front.
    if points:
        for p in points:
            p_str = str(p).strip()
            if p_str.isdigit():
                slot = int(p_str)
                if not (1 <= slot <= 99):
                    raise ScannerInputError(
                        f"Slot {slot} out of range — TEC subpoints are 1-99")

    node_name = resolve_node_name(host)
    # P2Connection needs the current (possibly auto-learned) network name
    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET",
                        scanner_name=SCANNER_NAME)

    # When output_format="none", we're running as a step inside a larger
    # sweep (e.g. building-wide room-temp read). Suppress per-device banners
    # and progress chatter so the sweep can render a single combined table.
    suppress_output = (output_format == "none")

    if not suppress_output:
        print(f"\n{'═' * 70}")
        print(f"  P2 SCANNER — {device} on {node_name.upper()} ({host})")
        if P2_NETWORK:
            print(f"  Network: {P2_NETWORK}  |  Site: {P2_SITE or '?'}")
        print(f"{'═' * 70}")

    if not conn.connect(node_name):
        return []

    # Determine which points to scan. When using the point table, we also
    # remember the app_num so we can attach rich metadata (type, labels,
    # scaling, etc.) to each read result — this drives pretty-printing and
    # gives downstream callers the context they need.
    scan_app_num = None
    if points or quick:
        # Explicit point list or quick mode — still read APPLICATION so we
        # can (a) render labels on the output, and (b) resolve numeric slots
        # against the app's point table.
        try:
            app_result = conn.read_point(device, "APPLICATION", node_name)
            if app_result and app_result.get('value') is not None:
                scan_app_num = int(app_result['value'])
        except Exception:
            pass  # app lookup is a nice-to-have, don't fail the scan over it

        if quick:
            scan_list = list(QUICK_SCAN_POINTS)
        else:
            # User gave explicit points. Each entry can be either a name
            # ('ROOM TEMP') or a slot number ('29'). Resolve numbers here
            # BEFORE hitting the wire so we can error cleanly on undefined
            # slots rather than sending garbage to the PXC.
            scan_list = []
            for p in points:
                p_stripped = str(p).strip()
                if p_stripped.isdigit():
                    slot = int(p_stripped)
                    if not (1 <= slot <= 99):
                        conn.close()
                        raise ScannerInputError(
                            f"Slot {slot} out of range — TEC subpoints are 1-99")
                    if scan_app_num is None:
                        conn.close()
                        raise ScannerInputError(
                            f"Can't resolve slot {slot} — failed to read "
                            f"APPLICATION from {device}. Try a named point first, "
                            f"or pass force_slot=True to attempt the read anyway.")
                    resolved = resolve_slot_to_name(scan_app_num, slot)
                    if resolved:
                        print(f"  Slot {slot} on app {scan_app_num} = {resolved!r}")
                        scan_list.append(resolved)
                    elif force_slot:
                        # Forced read of undefined slot. The PXC probably
                        # won't return anything useful, but this is a
                        # protocol-troubleshooting escape hatch.
                        synth = f"POINT_{slot}"
                        print(f"  [WARN] Slot {slot} not defined in app {scan_app_num} — "
                              f"forcing read as {synth!r} (likely to fail)")
                        scan_list.append(synth)
                    else:
                        conn.close()
                        raise ScannerInputError(
                            f"Slot {slot} is not defined in app {scan_app_num}. "
                            f"Use --force-slot (CLI) or force_slot=True (library) "
                            f"to try anyway.")
                else:
                    scan_list.append(p_stripped)
    else:
        # First, read APPLICATION to get the right point table
        print(f"  Reading APPLICATION number...")
        app_result = conn.read_point(device, "APPLICATION", node_name)
        app_num = None
        if app_result and app_result.get('value') is not None:
            app_num = int(app_result['value'])
            comm = app_result.get('comm_status', 'online')
            if comm == 'comm_fault':
                print(f"  ⚠ Device has #COM — values will be stale cached data")
            print(f"  Application: {app_num}")
        scan_app_num = app_num

        pt_table = get_point_table(app_num) if app_num else {}

        if pt_table:
            # Use the point table for this application
            scan_list = [info[0] for addr, info in sorted(pt_table.items())]
            print(f"  Scanning {len(scan_list)} points for app {app_num}")
        else:
            # No point table at all — try ALL known point names as last resort
            all_names = set()
            for app in range(2020, 2028):
                for addr, info in get_point_table(app).items():
                    all_names.add(info[0])
            scan_list = sorted(all_names)
            print(f"  No point table for app {app_num} — trying {len(scan_list)} common names")

    results = []
    total = len(scan_list)
    success = 0
    failed = 0

    for i, pt_name in enumerate(scan_list):
        if not suppress_output:
            sys.stdout.write(f"\r  Scanning: {i+1}/{total} — {pt_name:<25s}")
            sys.stdout.flush()

        result = conn.read_point(device, pt_name, node_name)
        if result and result['value'] is not None:
            result['point_name'] = pt_name
            # Attach rich metadata if we have the app number. This lets the
            # output formatters show "NIGHT" instead of "1.0" for digital
            # points, correct units even when the wire response lacks them,
            # etc.
            if scan_app_num is not None:
                info = get_point_info(scan_app_num, pt_name)
                if info:
                    result['point_info'] = info
                    # Fill in units if parser didn't get them from the wire
                    if not result.get('units') and info.get('units'):
                        result['units'] = info['units']
                    # Compute a rendered value_text for digital points
                    if 'on_label' in info and 'off_label' in info:
                        val = result['value']
                        result['value_text'] = info['on_label'] if val >= 0.5 else info['off_label']
                    result['point_type'] = info.get('type', 'unknown')
                # Attach the subpoint slot number for Desigo-style '(29)'
                # display. Handled even when point_info is missing, in case
                # someone's scanning with only the legacy JSON.
                slot = get_point_slot(scan_app_num, pt_name)
                if slot is not None:
                    result['point_slot'] = slot
            results.append(result)
            success += 1
        else:
            failed += 1

        # Small delay to avoid overwhelming the controller
        time.sleep(0.05)

    conn.close()
    if not suppress_output:
        print(f"\r  Scan complete: {success} points read, {failed} failed{'':30s}")

        # Output results
        if output_format == "table":
            print_results_table(device, results)
        elif output_format == "json":
            print(json.dumps(results, indent=2))
        elif output_format == "csv":
            print_results_csv(results)

    return results


def scan_network(quick: bool = False) -> Dict[str, List[Dict]]:
    """Scan all known PXC nodes on the P2 network."""
    print(f"\n{'═' * 70}")
    print(f"  P2 NETWORK SCAN — {P2_NETWORK}")
    print(f"  {len(KNOWN_NODES)} known nodes")
    print(f"{'═' * 70}")

    all_results = {}
    for name, ip in sorted(KNOWN_NODES.items()):
        node_name = name.lower()
        conn = P2Connection(ip)

        print(f"\n  Probing {name} ({ip})...", end=" ")
        if conn.connect(node_name):
            print("CONNECTED")
            # Try reading a common point to verify the node is responsive
            result = conn.read_point("OATEMP", "OATEMP", node_name)
            if result:
                print(f"    OATEMP = {result['value']}")
            conn.close()
            all_results[name] = [result] if result else []
        else:
            print("FAILED")
            all_results[name] = []

    return all_results


# ═══════════════════════════════════════════════════════════════════════════════
# PASSIVE SNIFFER (PCAP ANALYSIS)
# ═══════════════════════════════════════════════════════════════════════════════

def sniff_pcap(pcap_file: str, output_format: str = "table") -> List[Dict]:
    """
    Parse a pcap/pcapng file and decode all P2 point data.
    Requires tshark to be installed.
    """
    import subprocess

    print(f"\n{'═' * 70}")
    print(f"  P2 PCAP DECODER — {pcap_file}")
    print(f"{'═' * 70}")

    result = subprocess.run([
        'tshark', '-r', pcap_file,
        '-Y', 'tcp.port==5033 && data.data',
        '-T', 'fields',
        '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'data.data'
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  [ERROR] tshark failed: {result.stderr}")
        return []

    ip_node = {}
    all_points = []

    for line in result.stdout.strip().split('\n'):
        parts = line.split('\t')
        if len(parts) < 4:
            continue

        fnum, src, dst = int(parts[0]), parts[1], parts[2]
        try:
            raw = bytes.fromhex(parts[3])
        except:
            continue

        # Parse potentially multiple P2 messages in one TCP segment
        pos = 0
        while pos < len(raw) - 12:
            remaining = len(raw) - pos
            if remaining < 12:
                break
            total_len = struct.unpack('>I', raw[pos:pos+4])[0]
            if total_len < 12 or total_len > remaining:
                total_len = remaining
            msg = raw[pos:pos+total_len]
            pos += total_len

            if len(msg) <= 12:
                continue

            resp_flag = msg[12]

            # Map node names from routing
            lp = P2Connection._extract_lp_strings(msg[12:])
            routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE} | {s.split('|')[0] for s in [SCANNER_NAME] if '|' in s}
            for s in lp:
                if s.upper().startswith('NODE') and s.upper() not in routing_set:
                    remote_ip = dst if src != dst else src  # DCC server sends from its IP
                    ip_node[remote_ip] = s.upper()

            # Parse 0x0274 COV data
            marker_idx = msg.find(b'\x02\x74')
            if marker_idx >= 0:
                after = msg[marker_idx + 2:]
                if len(after) >= 7 and after[0:6] == b'\x00\x01\x00\x00\x01\x00':
                    name_len = after[6]
                    if name_len > 0 and len(after) >= 7 + name_len + 7:
                        try:
                            pt_name = after[7:7+name_len].decode('ascii')
                        except:
                            continue
                        if pt_name.isprintable():
                            val_area = after[7+name_len:]
                            value = None
                            if len(val_area) >= 7 and val_area[0:3] == b'\x01\x00\x00':
                                value = struct.unpack('>f', val_area[3:7])[0]

                            remote_ip = dst if src != dst else src  # DCC server sends from its IP
                            node = ip_node.get(remote_ip, remote_ip)
                            all_points.append({
                                'frame': fnum,
                                'node': node,
                                'point_name': pt_name,
                                'value': value,
                                'type': 'COV',
                            })

            # Parse read responses (flag=1, has 3FFFFFxx)
            if resp_flag == 1:
                flags_idx = -1
                for i in range(12, len(msg) - 3):
                    if msg[i] == 0x3F and msg[i+1] == 0xFF and msg[i+2] == 0xFF:
                        flags_idx = i
                        break
                if flags_idx >= 0:
                    pre = msg[12:flags_idx]
                    data_strs = [s for s in P2Connection._extract_lp_strings(pre)
                                 if s not in routing_set and not s.upper().startswith('NODE')]
                    after_flags = msg[flags_idx + 3:]
                    if len(after_flags) >= 8 and len(data_strs) >= 2:
                        raw_val = after_flags[4:8]
                        value = struct.unpack('>f', raw_val)[0]
                        # Extract units
                        units = ''
                        for s in P2Connection._extract_lp_strings(after_flags[8:]):
                            if s in ('DEG F', 'PCT', 'SEC', 'CFM', 'PSI'):
                                units = s
                                break

                        remote_ip = dst if src != dst else src  # DCC server sends from its IP
                        node = ip_node.get(remote_ip, remote_ip)
                        all_points.append({
                            'frame': fnum,
                            'node': node,
                            'device_name': data_strs[0],
                            'point_name': data_strs[1],
                            'value': value,
                            'units': units,
                            'description': data_strs[2] if len(data_strs) >= 3 else '',
                            'type': 'READ',
                        })

    print(f"  Decoded {len(all_points)} point values")

    if output_format == "table" and all_points:
        # Group by node and device
        from itertools import groupby
        keyfunc = lambda p: (p.get('node', '?'), p.get('device_name', p.get('point_name', '?')))
        sorted_pts = sorted(all_points, key=keyfunc)
        for key, group in groupby(sorted_pts, key=keyfunc):
            pts = list(group)
            print(f"\n  {key[0]} / {key[1]}:")
            seen = set()
            for p in pts:
                pt_key = p['point_name']
                if pt_key in seen:
                    continue
                seen.add(pt_key)
                val = p['value']
                units = p.get('units', '')
                if val is not None:
                    print(f"    {pt_key:<30s} = {val:>10.2f} {units}")

    return all_points


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

def print_results_table(device: str, results: List[Dict]):
    """Print point results in a formatted table."""
    if not results:
        print("  No results.")
        return

    # Check if device is genuinely offline vs just a few unconnected inputs
    comm_fault_count = sum(1 for r in results if r.get('comm_status') == 'comm_fault')
    total_with_status = sum(1 for r in results if r.get('comm_status'))

    if total_with_status > 0 and comm_fault_count == total_with_status:
        print(f"\n  ⚠ WARNING: Device {device} has #COM (communication fault)")
        print(f"  Values shown are STALE cached data — device is offline!")
    elif comm_fault_count > total_with_status * 0.5:
        print(f"\n  ⚠ WARNING: {comm_fault_count}/{total_with_status} points show #COM")
        print(f"  Device may be offline — some values could be stale")
    elif comm_fault_count > 0:
        print(f"\n  Note: {comm_fault_count} point(s) show #COM (unconnected inputs)")

    # Column widths: Point column holds "(##) POINT_NAME_WITH_SPACES". With
    # slot numbers up to 99 that's "(##) " = 5 chars of prefix + up to 25
    # chars of name = 30. Digital labels ("NIGHT"/"COOL"/"OFF") fit in the
    # Value column without truncation while numeric values stay clean.
    print(f"\n  {'Point':<31s} {'Value':>14s} {'Units':<8s} {'Type':<12s}")
    print(f"  {'─' * 31} {'─' * 14} {'─' * 8} {'─' * 12}")

    for r in results:
        val = r.get('value')
        units = r.get('units', '')
        name = r.get('point_name', '?')
        slot = r.get('point_slot')
        comm = r.get('comm_status', '')
        info = r.get('point_info')

        # Desigo-style '(29) DAY.NGT' prefix when slot is known
        if slot is not None:
            name_display = f"({slot}) {name}"
        else:
            name_display = name

        # Type column: prefer rich 'point_type' over raw 'data_type'
        type_display = r.get('point_type') or r.get('data_type', '') or ''
        type_short = {
            'analog_ro':  'AI',
            'analog_rw':  'AO',
            'digital_ro': 'BI',
            'digital_rw': 'BO',
        }.get(type_display, type_display)

        if val is not None:
            if r.get('value_text'):
                label = r['value_text']
                raw_int = int(round(val))
                val_str = f"{label} ({raw_int})"
            else:
                if val == int(val) and abs(val) < 100000:
                    val_str = f"{int(val)}"
                else:
                    val_str = f"{val:.2f}"
            if comm == 'comm_fault':
                val_str += " #COM"
        else:
            val_str = "—"

        print(f"  {name_display:<31s} {val_str:>14s} {units:<8s} {type_short:<12s}")


def print_results_csv(results: List[Dict]):
    """Print results in CSV format."""
    writer = csv.writer(sys.stdout)
    writer.writerow(['point_slot', 'point_name', 'value', 'value_text', 'units',
                     'point_type', 'data_type', 'comm_status', 'description'])
    for r in results:
        writer.writerow([
            r.get('point_slot', ''),
            r.get('point_name', ''),
            r.get('value', ''),
            r.get('value_text', ''),
            r.get('units', ''),
            r.get('point_type', ''),
            r.get('data_type', ''),
            r.get('comm_status', ''),
            r.get('description', ''),
        ])


def _print_sweep_results(sweep_results: List[Dict], read_points: List,
                         output_format: str = "table"):
    """Render building-wide sweep output — results are flat, one row per
    (node, device, point). Prints a single combined table/CSV/JSON.
    Each result dict has '_node' and '_device' set from discover_network."""
    if not sweep_results:
        print("  No devices responded.")
        return

    if output_format == "json":
        # JSON: pass through as-is for programmatic use
        print(json.dumps(sweep_results, indent=2, default=str))
        return

    if output_format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(['node', 'device', 'description', 'point_slot',
                         'point_name', 'value', 'value_text', 'units',
                         'point_type', 'comm_status', 'error'])
        for r in sweep_results:
            writer.writerow([
                r.get('_node', r.get('node', '')),
                r.get('_device', r.get('device', '')),
                r.get('_description', r.get('description', '')),
                r.get('point_slot', ''),
                r.get('point_name', ''),
                r.get('value', ''),
                r.get('value_text', ''),
                r.get('units', ''),
                r.get('point_type', ''),
                r.get('comm_status', ''),
                r.get('error', ''),
            ])
        return

    # Table: grouped by node, then device
    print(f"\n  {'Node':<8s} {'Device':<12s} {'Point':<22s} {'Value':>14s} {'Units':<8s}")
    print(f"  {'─' * 8} {'─' * 12} {'─' * 22} {'─' * 14} {'─' * 8}")

    prev_node = None
    for r in sweep_results:
        node = r.get('_node', r.get('node', '?'))
        dev = r.get('_device', r.get('device', '?'))

        # Insert blank line between nodes for readability
        if prev_node and node != prev_node:
            print()
        prev_node = node

        if 'error' in r:
            print(f"  {node:<8s} {dev:<12s} {'(' + r['error'] + ')':<22s} "
                  f"{'—':>14s} {'':<8s}")
            continue

        name = r.get('point_name', '?')
        slot = r.get('point_slot')
        if slot is not None:
            name_display = f"({slot}) {name}"
        else:
            name_display = name

        # Clip for width
        if len(name_display) > 22:
            name_display = name_display[:21] + "…"

        val = r.get('value')
        units = r.get('units', '') or ''

        if val is None:
            val_str = "—"
        elif r.get('value_text'):
            val_str = f"{r['value_text']} ({int(round(val))})"
        elif val == int(val) and abs(val) < 100000:
            val_str = f"{int(val)}"
        else:
            val_str = f"{val:.2f}"

        if r.get('comm_status') == 'comm_fault':
            val_str += " #COM"

        print(f"  {node:<8s} {dev:<12s} {name_display:<22s} {val_str:>14s} {units:<8s}")


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

# Common TEC device name patterns to try during brute-force discovery.
# These are common conventions across commercial BAS installations. Edit
# this list to add your site's naming conventions for faster discovery.
DISCOVERY_DEVICE_PATTERNS = [
    # PW series (perimeter VAVs)
    *[f"PW{n}" for n in range(401, 451)],
    *[f"PW{n}A" for n in range(401, 420)],
    # Interior VAV series (common names across sites)
    *[f"IVV{n}" for n in range(1, 21)],
    *[f"IV{n}" for n in range(1, 21)],
    # K series (suites)
    *[f"K{n}" for n in range(400, 451)],
    # AC/AH series (AHUs)
    *[f"AC{n:02d}" for n in range(1, 20)],
    *[f"AH{n:02d}" for n in range(1, 20)],
    *[f"AH{n:02d}T1" for n in range(1, 20)],
    *[f"AC{n:02d}T1" for n in range(1, 20)],
    # BLR series
    *[f"BLR{n}" for n in range(1, 6)],
    "BLRST", "BLRSTPT", "BLRVSO", "BLROAENA",
    # Exhaust / supply fans
    *[f"EF{n}" for n in range(1, 25)],
    *[f"SF{n}" for n in range(1, 10)],
    *[f"EF{n:02d}" for n in range(1, 25)],
    # Common generic points
    "OATEMP", "OAT",
    # Floor-based naming patterns
    *[f"FLR{n}VAV{v}" for n in range(1, 21) for v in range(1, 6)],
    # Common VAV naming: V followed by numbers
    *[f"V{n}" for n in range(1, 51)],
    *[f"VAV{n}" for n in range(1, 51)],
    *[f"VAV-{n}" for n in range(1, 21)],
    # Zone controllers
    *[f"ZN{n}" for n in range(1, 31)],
    *[f"ZONE{n}" for n in range(1, 21)],
    # Room-based naming
    *[f"RM{n}" for n in range(100, 500, 100)],
    *[f"RM{n}" for n in range(401, 451)],
    # Suite-based
    *[f"STE{n}" for n in range(100, 500, 100)],
    *[f"SUITE{n}" for n in range(1, 21)],
    # Heat pump / FCU
    *[f"HP{n}" for n in range(1, 21)],
    *[f"FCU{n}" for n in range(1, 21)],
    *[f"FCU-{n}" for n in range(1, 21)],
    # CW/HW/CHW
    *[f"CWP{n}" for n in range(1, 6)],
    *[f"HWP{n}" for n in range(1, 6)],
    *[f"CHWP{n}" for n in range(1, 6)],
    # Misc
    *[f"UH{n}" for n in range(1, 11)],  # Unit heaters
    *[f"RTU{n}" for n in range(1, 11)],  # Rooftop units
    *[f"MAU{n}" for n in range(1, 6)],   # Makeup air
    *[f"CT{n}" for n in range(1, 6)],    # Cooling towers
    *[f"CH{n}" for n in range(1, 6)],    # Chillers
    *[f"P{n}" for n in range(1, 11)],    # Pumps
]

# Panel-level point names (not TECs, but readable from nodes).
# Generic starting set of common patterns. Missing point names are harmless
# (the scanner just gets no data for them). Edit this list to add the custom
# panel points used at your site for richer panel-level discovery results.
PANEL_POINT_NAMES = [
    # Outside air / weather (common naming conventions across BAS)
    "OATEMP", "OAT", "OUTSIDE_AIR_TEMP", "NEWOATEMP",
    "OAENTH", "OAENTH.BN", "OASTMP1.BN",
    # System-wide setpoints and statuses
    "HEAT.LOCKOUT", "COOL.RELEASE", "CWDFP",
    "HEAT.LOCKOUT.BN", "COOL.RELEASE.BN", "CWDFP.BN",
    # Common prefixes for zone/bay/boiler/chiller points
    "BAY.DP", "BAY.OCC", "BAY.SAT", "BAY.MAT", "BAY.RAT", "BAY.RAH",
    "BOA.DP",
    # Boiler common patterns
    "BLRST", "BLRSTPT", "BLRST.BAC", "BLRSTPT.BAC",
    *[f"BLR{n}ALM" for n in range(1, 5)],
    *[f"BLR{n}ENB" for n in range(1, 5)],
    *[f"BLR{n}ST"  for n in range(1, 5)],
    *[f"BLR{n}ALM.BAC" for n in range(1, 5)],
    *[f"BLR{n}ENB.BAC" for n in range(1, 5)],
    *[f"BLR{n}ST.BAC"  for n in range(1, 5)],
    # Chiller common patterns
    *[f"CH{n}ALM"  for n in range(1, 5)],
    *[f"CH{n}ENB"  for n in range(1, 5)],
    *[f"CH{n}ST"   for n in range(1, 5)],
    # Floor-level points (generic patterns across multi-story buildings)
    *[f"FLOOR {n:02d} AREA BOP"       for n in range(1, 21)],
    *[f"FLOOR {n:02d} AREA BOP_1_BAC" for n in range(1, 21)],
    *[f"FLOOR {n:02d} AREA BOP_2_BAC" for n in range(1, 21)],
    *[f"FLOOR_{n:02d}_AREA_BOP"       for n in range(1, 21)],
    *[f"FL{n:02d}.SAT"                for n in range(1, 21)],
    *[f"FL{n:02d}.RAT"                for n in range(1, 21)],
    # Exhaust fan enables / statuses
    *[f"EF{n}_ENABLE" for n in range(1, 21)],
    *[f"EF{n}_STATUS" for n in range(1, 21)],
    *[f"EF{n}.ENABLE" for n in range(1, 21)],
    # Lighting schedules (.OCC suffix = "Occupied mode" — standard BAS term)
    *[f"LIGHTING.FL{n:02d}.OCC" for n in range(1, 21)],
    *[f"LIGHT.FL{n:02d}.SS"     for n in range(1, 21)],
]


def parse_ip_range(range_str: str) -> List[str]:
    """
    Parse flexible IP range formats into a list of IPs.

    Supported formats:
        10.0.0.50              Single IP
        10.0.0.1-254            Last octet range
        10.0.0.0/24             CIDR notation
        10.0.0                  Shorthand for .1-.254
        10.0.0.0/24,10.20.0.0/24   Comma-separated multiple ranges
    """
    ips = []
    for part in range_str.split(','):
        part = part.strip()

        if '/' in part:
            # CIDR notation
            base, prefix_len = part.split('/')
            prefix_len = int(prefix_len)
            octets = [int(o) for o in base.split('.')]
            if prefix_len == 24:
                for i in range(1, 255):
                    ips.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{i}")
            elif prefix_len == 16:
                for s3 in range(0, 256):
                    for s4 in range(1, 255):
                        ips.append(f"{octets[0]}.{octets[1]}.{s3}.{s4}")
            else:
                # Just do /24 from the base
                for i in range(1, 255):
                    ips.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{i}")

        elif '-' in part.split('.')[-1]:
            # Range in last octet: 10.0.0.1-254
            base = '.'.join(part.split('.')[:-1])
            range_part = part.split('.')[-1]
            start, end = range_part.split('-')
            for i in range(int(start), int(end) + 1):
                ips.append(f"{base}.{i}")

        elif part.count('.') == 2:
            # Shorthand subnet: 10.0.0 → 10.0.0.1-254
            for i in range(1, 255):
                ips.append(f"{part}.{i}")

        elif part.count('.') == 3:
            # Single IP
            ips.append(part)

    return ips


def port_scan_p2(ip_list: List[str], timeout: float = 0.5) -> List[str]:
    """Scan a list of IPs for TCP/5033 open."""
    found = []
    total = len(ip_list)

    for i, ip in enumerate(ip_list):
        sys.stdout.write(f"\r  Scanning {ip} ({i+1}/{total})...   ")
        sys.stdout.flush()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, P2_PORT))
            s.close()
            if result == 0:
                found.append(ip)
                sys.stdout.write(f"\r  {ip} — P2 OPEN                    \n")
                sys.stdout.flush()
        except:
            pass

    sys.stdout.write(f"\r  Scan complete: {len(found)} P2 hosts found{'':30s}\n")
    return found


def learn_network_name(hosts: List[str]) -> Optional[str]:
    """
    Try to auto-learn the P2 network name.
    Strategy 1: If P2_NETWORK is already set, return it.
    Strategy 2: Try a live tshark capture to sniff P2 traffic.
    Strategy 3: PXCs won't respond without the name, so prompt user.
    """
    if P2_NETWORK:
        return P2_NETWORK

    # Try live capture with tshark
    name = sniff_network_name(duration=10)
    if name:
        return name

    return None


def sniff_network_name(duration: int = 10, interface: str = None) -> Optional[str]:
    """
    Use tshark to do a live capture and extract the P2 network name
    from any P2 traffic on the wire. Requires Wireshark/tshark installed.

    Args:
        duration: Seconds to capture (default 10)
        interface: Network interface to capture on (auto-detected if None)

    Returns:
        P2 network name string, or None if not found
    """
    global P2_NETWORK, P2_SITE
    import subprocess
    import shutil
    import tempfile
    import os

    # Find tshark
    tshark = shutil.which('tshark')
    if not tshark:
        # Check common Windows install paths
        for path in [
            r'C:\Program Files\Wireshark\tshark.exe',
            r'C:\Program Files (x86)\Wireshark\tshark.exe',
        ]:
            if os.path.exists(path):
                tshark = path
                break

    if not tshark:
        return None

    print(f"    Found tshark: {tshark}")
    print(f"    Capturing P2 traffic for {duration} seconds...")

    # Create temp file for capture
    tmpfile = tempfile.mktemp(suffix='.pcapng')

    try:
        # Build tshark command
        cmd = [tshark, '-a', f'duration:{duration}',
               '-f', 'tcp port 5033', '-w', tmpfile, '-q']
        if interface:
            cmd.extend(['-i', interface])

        result = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=duration + 10)

        if not os.path.exists(tmpfile) or os.path.getsize(tmpfile) < 100:
            print(f"    No P2 traffic captured")
            return None

        # Parse the capture for network name
        print(f"    Captured {os.path.getsize(tmpfile)} bytes, parsing...")
        try:
            sniff_pcap(tmpfile, "table")
        except:
            pass

        if P2_NETWORK:
            print(f"    Learned network name: {P2_NETWORK}")
            return P2_NETWORK

        # Manual parse if sniff_pcap didn't set it
        try:
            with open(tmpfile, 'rb') as f:
                raw = f.read()
            # Look for P2 routing strings (null-terminated after msg type 0x33)
            for i in range(len(raw) - 20):
                if raw[i:i+4] == b'\x00\x00\x003':  # msg type 0x33
                    # Skip header, look for null-terminated strings
                    buf = b""
                    for j in range(i + 12, min(i + 100, len(raw))):
                        if raw[j] == 0 and buf:
                            try:
                                s = buf.decode('ascii')
                                if s.isprintable() and len(s) >= 3 and '|' not in s:
                                    P2_NETWORK = s
                                    print(f"    Learned network name: {P2_NETWORK}")
                                    return P2_NETWORK
                            except:
                                pass
                            buf = b""
                        elif 32 <= raw[j] < 127:
                            buf += bytes([raw[j]])
                        else:
                            buf = b""
        except:
            pass

        return None

    except subprocess.TimeoutExpired:
        print(f"    Capture timed out")
        return None
    except FileNotFoundError:
        print(f"    tshark not found or cannot execute")
        return None
    except PermissionError:
        print(f"    Permission denied — try running as Administrator")
        return None
    finally:
        try:
            os.unlink(tmpfile)
        except:
            pass


def probe_p2_host(host: str) -> Optional[Dict[str, str]]:
    """
    Connect to a P2 host, blast heartbeats with many node names on a single
    connection, and learn its identity from whichever one it responds to.
    Returns dict with 'node_name', 'network', 'site' — or None on failure.
    Auto-learns and sets P2_NETWORK and P2_SITE globals on first success.
    """
    global P2_NETWORK, P2_SITE

    # Common PXC node naming patterns to try
    probe_names = (
        [f"node{i}" for i in range(1, 21)] +
        [f"NODE{i}" for i in range(1, 21)] +
        [f"PXC{i}" for i in range(1, 11)] +
        [f"MEC{i}" for i in range(1, 11)] +
        [f"MBC{i}" for i in range(1, 6)] +
        [f"AHU{i}" for i in range(1, 11)] +
        [f"BLR{i}" for i in range(1, 6)] +
        [f"FLR{i}" for i in range(1, 16)] +
        ["PANEL1", "PANEL2", "PANEL3", "MAIN", "LOBBY", "PENT",
         "PENTHOUSE", "BOILER", "CHILLER", "COOLING"]
    )

    net = P2_NETWORK.encode('ascii') if P2_NETWORK else b'P2NET'
    scanner = SCANNER_NAME.encode('ascii')
    site = P2_SITE.encode('ascii') if P2_SITE else b'SITE'

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))

        # Blast all heartbeats on this one connection
        for seq, target_name in enumerate(probe_names, start=100):
            target = target_name.encode('ascii')
            routing = b'\x00' + net + b'\x00' + target + b'\x00' + net + b'\x00' + scanner + b'\x00'
            identity = (
                b'\x46\x40' +
                b'\x01\x00' + bytes([len(scanner)]) + scanner +
                b'\x01\x00' + bytes([len(site)]) + site +
                b'\x01\x00' + bytes([len(net)]) + net +
                b'\x00\x01\x01' +
                b'\x00\x00\x00\x00\x00' +
                struct.pack('>I', int(time.time())) + b'\x00' +
                b'\xfe\x98\x00'
            )
            payload = routing + identity
            msg = struct.pack('>III', 12 + len(payload), 0x33, seq) + payload
            try:
                s.sendall(msg)
            except (BrokenPipeError, ConnectionResetError, OSError):
                break
            time.sleep(0.01)  # 10ms between sends

        # Now read any response — the PXC responds only to the matching name
        s.settimeout(3)
        data = b""
        try:
            while len(data) < 4096:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                s.settimeout(0.5)  # short timeout for additional data
        except socket.timeout:
            pass

        s.close()

        if not data or len(data) < 20:
            return None

        # Parse the response
        resp_payload = data[12:]
        if not resp_payload or resp_payload[0] != 0x01:
            return None

        # Extract routing strings
        null_strings = []
        buf = b""
        for b in resp_payload[1:]:
            if b == 0:
                if buf:
                    try:
                        null_strings.append(buf.decode('ascii'))
                    except:
                        null_strings.append("")
                    buf = b""
                    if len(null_strings) >= 4:
                        break
            else:
                buf += bytes([b])

        result = {}

        # Learn network name
        if len(null_strings) >= 1:
            learned_net = null_strings[0]
            if learned_net and learned_net != SCANNER_NAME:
                result['network'] = learned_net
                if not P2_NETWORK:
                    P2_NETWORK = learned_net

        # Learn node name (4th routing string)
        if len(null_strings) >= 4:
            node_name = null_strings[3]
            our_names = {SCANNER_NAME} | {s.split('|')[0] for s in [SCANNER_NAME] if '|' in s}
            if node_name and node_name not in our_names:
                result['node_name'] = node_name.upper()

        # Fallback: figure out which name matched from the sequence number
        if 'node_name' not in result and len(data) >= 12:
            resp_seq = struct.unpack('>I', data[8:12])[0]
            idx = resp_seq - 100
            if 0 <= idx < len(probe_names):
                result['node_name'] = probe_names[idx].upper()

        # Learn site from length-prefixed identity block
        lp_strings = []
        i = 0
        while i < len(resp_payload) - 3:
            if resp_payload[i] == 0x01 and resp_payload[i+1] == 0x00 and 0 < resp_payload[i+2] < 30:
                slen = resp_payload[i+2]
                if i + 3 + slen <= len(resp_payload):
                    try:
                        st = resp_payload[i+3:i+3+slen].decode('ascii')
                        if st.isprintable():
                            lp_strings.append(st)
                    except:
                        pass
                    i += 3 + slen
                    continue
            i += 1

        known = {result.get('network', ''), result.get('node_name', ''),
                 SCANNER_NAME, P2_NETWORK}
        for st in lp_strings:
            if st not in known and 2 <= len(st) <= 10:
                result['site'] = st
                if not P2_SITE:
                    P2_SITE = st
                break

        return result if 'node_name' in result else None

    except (socket.error, socket.timeout, OSError):
        return None


def discover_node_name(host: str) -> Optional[str]:
    """Connect to a PXC and learn its P2 node name. Wrapper for probe_p2_host."""
    result = probe_p2_host(host)
    return result['node_name'] if result else None


def get_node_info(host: str, node_name: str) -> Optional[Dict]:
    """
    Query firmware version and panel info from a PXC node using opcode 0x0100.
    Returns dict with revision strings, or None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))
    except:
        return None

    net = (P2_NETWORK if P2_NETWORK else "P2NET").encode('ascii')
    scanner = SCANNER_NAME.encode('ascii')
    site = (P2_SITE if P2_SITE else "SITE").encode('ascii')
    node_lower = node_name.lower().encode('ascii')

    # Handshake
    routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
    identity = (
        b'\x46\x40\x01\x00' + bytes([len(scanner)]) + scanner +
        b'\x01\x00' + bytes([len(site)]) + site +
        b'\x01\x00' + bytes([len(net)]) + net +
        b'\x00\x01\x01\x00\x00\x00\x00\x00' +
        struct.pack('>I', int(time.time())) + b'\x00\xfe\x98\x00'
    )
    hb_msg = struct.pack('>III', 12 + len(routing) + len(identity), 0x33, 1) + routing + identity
    try:
        s.sendall(hb_msg)
        s.settimeout(3)
        s.recv(4096)
    except:
        s.close()
        return None

    # Send opcode 0x0100 (GetRevString) — try with empty data
    info_routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
    info_data = struct.pack('>H', 0x0100)
    msg = struct.pack('>III', 12 + len(info_routing) + len(info_data), 0x33, 10) + info_routing + info_data

    try:
        s.sendall(msg)
        s.settimeout(3)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
                s.settimeout(0.5)
        except socket.timeout: pass

        s.close()

        if not data or len(data) <= 55 or data[12] == 0x05:
            return None

        # Extract strings from response
        payload = data[12:]
        pos = 1
        nulls = 0
        while pos < len(payload) and nulls < 4:
            if payload[pos] == 0: nulls += 1
            pos += 1

        data_area = payload[pos:]
        strings = []
        i = 0
        while i < len(data_area) - 2:
            slen = struct.unpack('>H', data_area[i:i+2])[0]
            if 0 < slen < 60 and i + 2 + slen <= len(data_area):
                try:
                    st = data_area[i+2:i+2+slen].decode('ascii')
                    if st.isprintable():
                        strings.append(st)
                        i += 2 + slen
                        continue
                except: pass
            i += 1

        routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE, node_name.upper(), node_name.lower()}
        info_strings = [st for st in strings if st not in routing_set]

        return {
            'firmware': info_strings[0] if len(info_strings) > 0 else '?',
            'model': info_strings[1] if len(info_strings) > 1 else '?',
            'extra': info_strings[2] if len(info_strings) > 2 else '',
            'raw_strings': info_strings,
        }
    except:
        s.close()
        return None


def get_device_application(host: str, node_name: str, device_name: str) -> Optional[int]:
    """Read the APPLICATION number from a specific device."""
    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET",
                        scanner_name=SCANNER_NAME)
    if not conn.connect(node_name.lower()):
        return None
    result = conn.read_point(device_name, "APPLICATION", node_name.lower())
    conn.close()
    if result and result.get('value') is not None:
        return int(result['value'])
    return None


def enumerate_fln_devices(host: str, node_name: str) -> List[Dict]:
    """
    Enumerate all FLN devices on a PXC node using opcode 0x0986.
    No brute force — asks the PXC to list every device on its FLN bus.
    
    Returns list of dicts with 'device', 'description', 'application'.
    """
    found = []
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))
    except (socket.error, socket.timeout) as e:
        print(f"    [ERROR] Connection failed: {e}")
        return []

    net = (P2_NETWORK if P2_NETWORK else "P2NET").encode('ascii')
    scanner = SCANNER_NAME.encode('ascii')
    site = (P2_SITE if P2_SITE else "SITE").encode('ascii')
    node_lower = node_name.lower().encode('ascii')

    # Handshake
    routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
    identity = (
        b'\x46\x40\x01\x00' + bytes([len(scanner)]) + scanner +
        b'\x01\x00' + bytes([len(site)]) + site +
        b'\x01\x00' + bytes([len(net)]) + net +
        b'\x00\x01\x01\x00\x00\x00\x00\x00' +
        struct.pack('>I', int(time.time())) + b'\x00\xfe\x98\x00'
    )
    hb_msg = struct.pack('>III', 12 + len(routing) + len(identity), 0x33, 1) + routing + identity
    try:
        s.sendall(hb_msg)
        s.settimeout(3)
        s.recv(4096)
    except:
        s.close()
        print(f"    [ERROR] Handshake failed")
        return []

    cursor = "*"
    seq = 2000
    
    for iteration in range(200):
        seq += 1
        cb = cursor.encode('ascii')
        enum_data = (struct.pack('>H', 0x0986) +
                     b'\x00\x00\x00' + struct.pack('>H', 1) + b'*' +
                     b'\x00\x00\x00' + struct.pack('>H', len(cb)) + cb)
        enum_routing = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
        msg = struct.pack('>III', 12 + len(enum_routing) + len(enum_data), 0x33, seq) + enum_routing + enum_data
        
        try:
            s.sendall(msg)
        except (BrokenPipeError, ConnectionResetError, OSError):
            break
        
        s.settimeout(3)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
                s.settimeout(0.5)
        except socket.timeout: pass
        
        if not data or len(data) <= 55:
            break
        if data[12] == 0x05:
            break
        
        # Parse: skip P2 header + routing, extract length-prefixed strings
        payload = data[12:]
        pos = 1
        nulls = 0
        while pos < len(payload) and nulls < 4:
            if payload[pos] == 0: nulls += 1
            pos += 1
        
        if pos >= len(payload): break
        data_area = payload[pos:]
        
        # Extract all length-prefixed strings from data area
        strings = []
        i = 0
        while i < len(data_area) - 2:
            slen = struct.unpack('>H', data_area[i:i+2])[0]
            if 0 < slen < 60 and i + 2 + slen <= len(data_area):
                try:
                    st = data_area[i+2:i+2+slen].decode('ascii')
                    if st.isprintable():
                        strings.append(st)
                        i += 2 + slen
                        continue
                except: pass
            i += 1
        
        routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE, node_name.upper(), node_name.lower()}
        device_strings = [st for st in strings if st not in routing_set]
        
        if not device_strings:
            break
        
        dev_name = device_strings[0]
        # Description is the last unique string that differs from device name
        # Response contains: [device_name, device_name, internal_name, display_name]
        # We want the display name (last one)
        desc = ''
        for st in device_strings[1:]:
            if st != dev_name:
                desc = st  # keep overwriting — last one wins
        
        if dev_name == cursor:
            break  # End of list
        
        found.append({
            'device': dev_name,
            'description': desc,
            'application': 0,
        })
        sys.stdout.write(f"\r    \u2713 {dev_name:<20s}  {desc}\n")
        sys.stdout.flush()
        
        cursor = dev_name
    
    s.close()
    sys.stdout.write(f"\r    Enumerate complete: {len(found)} devices found{'':20s}\n")
    return found


def verify_devices(host: str, node_name: str, devices: List[Dict],
                   show_filter: str = "all") -> List[Dict]:
    """
    Verify which enumerated devices are actually online by reading ROOM TEMP.
    
    Args:
        host: PXC controller IP
        node_name: P2 node name
        devices: List of device dicts from enumerate
        show_filter: "all", "online", or "offline"
    
    Returns:
        Updated device list with 'status' field added ('online'/'offline')
    """
    if not devices:
        return devices

    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET",
                        scanner_name=SCANNER_NAME)
    if not conn.connect(node_name.lower()):
        print(f"    [ERROR] Could not connect for verification")
        return devices

    total = len(devices)
    online = 0
    offline = 0

    for i, dev in enumerate(devices):
        dev_name = dev['device']
        sys.stdout.write(f"\r    Verifying: {i+1}/{total} — {dev_name:<20s}")
        sys.stdout.flush()

        # Read ROOM TEMP and check the comm status flag in the response
        # The PXC returns cached values even for dead devices, but the
        # comm_status flag (byte +5 after 3FFFFF) tells us the real status:
        #   00 = device online (live FLN communication)
        #   01 = comm fault (device offline, PXC returned stale cached data)
        #   No 3FFFFF marker = device completely gone from cache
        result = conn.read_point(dev_name, "ROOM TEMP", node_name.lower())

        if result and result.get('comm_status') == 'online':
            dev['status'] = 'online'
            dev['room_temp'] = result.get('value')
            dev['units'] = result.get('units', '')
            if dev.get('application', 0) == 0:
                app_result = conn.read_point(dev_name, "APPLICATION", node_name.lower())
                if app_result and app_result.get('value') is not None:
                    dev['application'] = int(app_result['value'])
            online += 1
        elif result and result.get('comm_status') == 'comm_fault':
            # PXC returned stale cached data — device is offline
            dev['status'] = 'offline'
            dev['stale_temp'] = result.get('value')
            offline += 1
        else:
            # No response or no 3FFFFF marker — try APPLICATION as fallback
            result2 = conn.read_point(dev_name, "APPLICATION", node_name.lower())
            if result2 and result2.get('comm_status') == 'online':
                dev['status'] = 'online'
                dev['application'] = int(result2['value'])
                online += 1
            else:
                dev['status'] = 'offline'
                offline += 1

    conn.close()

    # Print results based on filter
    sys.stdout.write(f"\r{'':60s}\r")
    print(f"    Verified: {online} online, {offline} offline, {total} total")
    print()

    for dev in devices:
        status = dev.get('status', '?')
        dev_name = dev['device']
        desc = dev.get('description', '')
        app = dev.get('application', 0)

        if show_filter == "online" and status != "online":
            continue
        if show_filter == "offline" and status != "offline":
            continue

        if status == 'online':
            temp = dev.get('room_temp')
            units = dev.get('units', '')
            app_str = f"APP {app}" if app else ""
            if temp is not None:
                print(f"    ✓ {dev_name:<20s} {app_str:>8s}  {temp:>6.1f}{units:<5s} {desc}")
            else:
                print(f"    ✓ {dev_name:<20s} {app_str:>8s}  {'':>11s} {desc}")
        else:
            stale = dev.get('stale_temp')
            stale_str = f"(stale {stale:.0f}°)" if stale is not None else "—"
            print(f"    ✗ {dev_name:<20s} {'#COM':>8s}  {stale_str:>11s} {desc}")

    return devices


def discover_devices_on_node(host: str, node_name: str,
                             device_list: Optional[List[str]] = None,
                             use_enumerate: bool = True) -> List[Dict]:
    """
    Discover TEC devices on a PXC node.
    First tries FLN enumerate (opcode 0x0986) for a complete device list.
    Falls back to batched APPLICATION reads if enumerate fails.
    """
    # Try FLN enumerate first (fast, complete, no brute force)
    if use_enumerate and device_list is None:
        print(f"    Trying FLN enumerate...")
        devs = enumerate_fln_devices(host, node_name)
        if devs:
            return devs
        print(f"    Enumerate returned no devices, falling back to brute force...")

    candidates = device_list or DISCOVERY_DEVICE_PATTERNS
    found = []
    BATCH_SIZE = 25

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, P2_PORT))
    except (socket.error, socket.timeout) as e:
        print(f"    [ERROR] Connection failed: {e}")
        return []

    net = (P2_NETWORK if P2_NETWORK else "P2NET").encode('ascii')
    scanner = SCANNER_NAME.encode('ascii')
    site = (P2_SITE if P2_SITE else "SITE").encode('ascii')
    node_lower = node_name.lower().encode('ascii')

    # Handshake
    routing_hb = b'\x00' + net + b'\x00' + node_lower + b'\x00' + net + b'\x00' + scanner + b'\x00'
    identity = (
        b'\x46\x40' +
        b'\x01\x00' + bytes([len(scanner)]) + scanner +
        b'\x01\x00' + bytes([len(site)]) + site +
        b'\x01\x00' + bytes([len(net)]) + net +
        b'\x00\x01\x01\x00\x00\x00\x00\x00' +
        struct.pack('>I', int(time.time())) + b'\x00\xfe\x98\x00'
    )
    hb_payload = routing_hb + identity
    hb_msg = struct.pack('>III', 12 + len(hb_payload), 0x33, 1) + hb_payload
    try:
        s.sendall(hb_msg)
        s.settimeout(3)
        s.recv(4096)
    except:
        s.close()
        print(f"    [ERROR] Handshake failed")
        return []

    total = len(candidates)
    base_seq = 5000
    num_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE

    for batch_num in range(num_batches):
        batch_start = batch_num * BATCH_SIZE
        batch_end = min(batch_start + BATCH_SIZE, total)
        batch = candidates[batch_start:batch_end]

        sys.stdout.write(f"\r    Probing: {batch_end}/{total}{'':20s}")
        sys.stdout.flush()

        # Build and send this batch
        seq_map = {}
        batch_msgs = b""
        for i, dev in enumerate(batch):
            seq = base_seq + batch_start + i
            seq_map[seq] = dev
            dev_bytes = dev.encode('ascii')
            routing = (b'\x00' + net + b'\x00' + node_lower + b'\x00' +
                       net + b'\x00' + scanner + b'\x00')
            read_data = (
                b'\x02\x71\x00\x00' +
                b'\x01\x00' + bytes([len(dev_bytes)]) + dev_bytes +
                b'\x01\x00\x0bAPPLICATION' +
                b'\x00\xff'
            )
            payload = routing + read_data
            msg = struct.pack('>III', 12 + len(payload), 0x33, seq) + payload
            batch_msgs += msg

        try:
            s.sendall(batch_msgs)
        except (BrokenPipeError, ConnectionResetError, OSError):
            break

        # Collect responses for this batch
        all_data = b""
        s.settimeout(2)
        try:
            while True:
                chunk = s.recv(16384)
                if not chunk:
                    break
                all_data += chunk
                s.settimeout(0.3)
        except socket.timeout:
            pass
        except (ConnectionResetError, OSError):
            break

        # Parse responses
        pos = 0
        while pos < len(all_data) - 12:
            if len(all_data) - pos < 12:
                break
            msg_len = struct.unpack('>I', all_data[pos:pos+4])[0]
            if msg_len < 12 or msg_len > len(all_data) - pos:
                pos += 1
                continue
            msg_data = all_data[pos:pos+msg_len]
            pos += msg_len
            if len(msg_data) < 13:
                continue
            resp_seq = struct.unpack('>I', msg_data[8:12])[0]
            resp_flag = msg_data[12]
            if resp_flag != 1 or resp_seq not in seq_map:
                continue
            dev_name = seq_map[resp_seq]
            if len(msg_data) <= 55:
                continue

            # Try standard parser (3FFFFF flags)
            flags_idx = -1
            for fi in range(12, len(msg_data) - 3):
                if msg_data[fi] == 0x3F and msg_data[fi+1] == 0xFF and msg_data[fi+2] == 0xFF:
                    flags_idx = fi
                    break
            if flags_idx >= 0:
                after_flags = msg_data[flags_idx + 3:]
                if len(after_flags) >= 8:
                    raw_val = after_flags[4:8]
                    app_num = int(struct.unpack('>f', raw_val)[0])
                    desc = ''
                    lp_strings = P2Connection._extract_lp_strings(msg_data[12:flags_idx])
                    routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE,
                                  node_name.upper(), node_name.lower()}
                    data_strs = [st for st in lp_strings if st not in routing_set
                               and st.upper() != 'APPLICATION']
                    if len(data_strs) >= 2:
                        desc = data_strs[1]
                    found.append({
                        'device': dev_name,
                        'application': app_num,
                        'description': desc,
                    })
                    sys.stdout.write(f"\r    \u2713 {dev_name:<20s}  APP={app_num}  {desc}\n")
                    sys.stdout.flush()
            else:
                # Fallback: device responded but different format (UC, PTEC, etc)
                # Extract description from any length-prefixed strings
                lp_strings = P2Connection._extract_lp_strings(msg_data[12:])
                routing_set = {P2_NETWORK, SCANNER_NAME, P2_SITE,
                              node_name.upper(), node_name.lower(), 'APPLICATION'}
                data_strs = [st for st in lp_strings if st not in routing_set
                           and st != dev_name]
                desc = data_strs[0] if data_strs else ''
                found.append({
                    'device': dev_name,
                    'application': 0,
                    'description': desc,
                })
                sys.stdout.write(f"\r    \u2713 {dev_name:<20s}  (non-TEC)  {desc}\n")
                sys.stdout.flush()

    s.close()
    sys.stdout.write(f"\r    Device scan complete: {len(found)} TECs found{'':30s}\n")
    return found

def discover_panel_points(host: str, node_name: str) -> List[Dict]:
    """Try reading known panel-level points from a node."""
    conn = P2Connection(host, network=P2_NETWORK if P2_NETWORK else "P2NET", scanner_name=SCANNER_NAME)
    if not conn.connect(node_name.lower()):
        return []

    found = []
    total = len(PANEL_POINT_NAMES)

    for i, pt_name in enumerate(PANEL_POINT_NAMES):
        sys.stdout.write(f"\r    Panel points: {i+1}/{total} — {pt_name:<30s}")
        sys.stdout.flush()

        # Panel points use the point name as both device and point
        result = conn.read_point(pt_name, pt_name, node_name.lower())
        if result and result.get('value') is not None:
            found.append({
                'point': pt_name,
                'value': result['value'],
                'units': result.get('units', ''),
            })

        time.sleep(0.03)

    conn.close()
    sys.stdout.write(f"\r    Panel point scan complete: {len(found)} points found{'':30s}\n")
    return found


def discover_network(ip_ranges: str = "10.0.0", scan_ports: bool = True,
                     scan_devices: bool = True, scan_panel: bool = False,
                     scan_info: bool = False, verify: str = None,
                     read_all: bool = False, output_format: str = "table",
                     read_points: Optional[List[str]] = None):
    """
    Full network discovery:
    1. Port scan for P2 hosts (or use known nodes)
    2. Handshake each to learn node names
    3. Brute-force TEC device discovery on each node
    4. Optionally read all points on every discovered device (read_all=True)
       OR read specific points across all devices (read_points=["ROOM TEMP"])
    """
    print(f"\n{'═' * 70}")
    print(f"  P2 NETWORK DISCOVERY")
    print(f"{'═' * 70}")

    # Step 1: Find P2 hosts
    if scan_ports:
        ip_list = parse_ip_range(ip_ranges)
        print(f"\n  [1/3] Port scanning {len(ip_list)} IPs for TCP/{P2_PORT}...")
        print(f"        Range: {ip_ranges}")
        hosts = port_scan_p2(ip_list)
    else:
        print(f"\n  [1/3] Using known node list ({len(KNOWN_NODES)} nodes)")
        hosts = list(KNOWN_NODES.values())

    if not hosts:
        print("  No P2 hosts found.")
        return

    # Auto-learn the P2 network name if not already known
    if not P2_NETWORK:
        print(f"\n  Auto-learning P2 network name...")
        learned = learn_network_name(hosts)
        if learned:
            print(f"  Learned network: {learned}")
        else:
            print(f"\n  ⚠ Could not auto-learn the P2 network name.")
            print(f"    PXC controllers require the correct network name to respond.")
            print(f"    Use --network <NAME> to specify it.")
            print(f"    Find it in Desigo CC under Field Networks, or in Insight.")
            print(f"    Common formats: SITEBLN, SITEEBLN, SITE_BLN")
            print(f"\n    Example: p2_scanner.py --discover --range {ip_ranges} --network MYBLN")
            return

    # Step 2: Identify each node
    print(f"\n  [2/3] Identifying {len(hosts)} P2 nodes...")
    print(f"        (trying common node names — this may take a moment)")
    node_map = {}  # ip -> node_name
    for ip in hosts:
        # Check known_nodes first (from config file)
        known_name = None
        for kname, kip in KNOWN_NODES.items():
            if kip == ip:
                known_name = kname
                break
        if known_name:
            node_map[ip] = known_name
            print(f"    {ip}... {known_name}  (from config)")
            continue

        sys.stdout.write(f"    {ip}... probing ")
        sys.stdout.flush()
        info = probe_p2_host(ip)
        if info and 'node_name' in info:
            node_map[ip] = info['node_name']
            KNOWN_NODES[info['node_name']] = ip
            extras = []
            if info.get('network'):
                extras.append(f"net={info['network']}")
            if info.get('site'):
                extras.append(f"site={info['site']}")
            extra_str = f"  ({', '.join(extras)})" if extras else ""
            sys.stdout.write(f"\r    {ip}... {info['node_name']}{extra_str}{'':20s}\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"\r    {ip}... not a PXC (DCC server or unresponsive){'':20s}\n")
            sys.stdout.flush()
            node_map[ip] = f"UNKNOWN_{ip.split('.')[-1]}"

    if P2_NETWORK:
        print(f"\n  P2 Network: {P2_NETWORK}  |  Site: {P2_SITE or '?'}")

    # Step 3: Discover devices on each node
    all_devices = {}
    if scan_devices:
        # Filter to only identified nodes (skip UNKNOWN — those are servers, not PXCs)
        pxc_nodes = {ip: name for ip, name in node_map.items()
                     if not name.startswith('UNKNOWN')}
        skipped = len(node_map) - len(pxc_nodes)
        if skipped:
            print(f"\n  Skipping {skipped} unidentified hosts (likely DCC servers)")
        print(f"\n  [3/3] Discovering TEC devices on {len(pxc_nodes)} PXC nodes...")

        for ip, name in sorted(pxc_nodes.items(), key=lambda x: x[1]):
            print(f"\n  {'─' * 60}")
            print(f"  {name} ({ip})", end="")

            # Get node firmware info if requested
            if scan_info:
                info = get_node_info(ip, name)
                if info:
                    print(f"  — {info['firmware']} / {info['model']}", end="")
                    all_devices.setdefault(name, {})['node_info'] = info

            print(f"\n  {'─' * 60}")

            devs = discover_devices_on_node(ip, name)
            all_devices[name] = {'ip': ip, 'devices': devs}

            # Verify online status if requested
            if verify and devs:
                verify_devices(ip, name, devs, show_filter=verify)

            if scan_panel:
                print(f"    Scanning panel-level points...")
                panel_pts = discover_panel_points(ip, name)
                all_devices[name]['panel_points'] = panel_pts
                if panel_pts:
                    for pt in panel_pts[:10]:
                        val = pt['value']
                        units = pt.get('units', '')
                        print(f"      {pt['point']:<35s} = {val:>10.2f} {units}")
                    if len(panel_pts) > 10:
                        print(f"      ... and {len(panel_pts) - 10} more")

    # Step 4: Optionally read all points on discovered devices
    if read_all and all_devices:
        print(f"\n{'═' * 70}")
        print(f"  READING ALL POINTS ON DISCOVERED DEVICES")
        print(f"{'═' * 70}")

        for name in sorted(all_devices.keys()):
            node_info = all_devices[name]
            ip = node_info['ip']
            devs = node_info['devices']

            for dev_info in devs:
                dev = dev_info['device']
                app = dev_info.get('application', 2023)
                desc = dev_info.get('description', '')

                print(f"\n  {'━' * 60}")
                print(f"  {name} / {dev}", end="")
                if desc:
                    print(f"  ({desc})", end="")
                print(f"  [APP {app}]")
                print(f"  {'━' * 60}")

                results = scan_device(ip, dev, quick=False, output_format=output_format)
                all_devices[name].setdefault('point_data', {})[dev] = results

    # Step 4b: Selective point read across every discovered device.
    # This is the "quick building health check" mode — read specific points
    # (by name or slot number) from every device without doing a full scan.
    # Output is a single combined table sorted by node/device.
    elif read_points and all_devices:
        print(f"\n{'═' * 70}")
        print(f"  BUILDING-WIDE READ — points: {', '.join(str(p) for p in read_points)}")
        print(f"{'═' * 70}")

        sweep_results = []  # flat list: one entry per (node, device, point)
        total_devs = sum(len(ni['devices']) for ni in all_devices.values())
        done = 0

        for name in sorted(all_devices.keys()):
            node_info = all_devices[name]
            ip = node_info['ip']
            devs = node_info['devices']

            for dev_info in devs:
                dev = dev_info['device']
                desc = dev_info.get('description', '')
                done += 1
                sys.stdout.write(f"\r  Reading {done}/{total_devs} — {name}/{dev}           ")
                sys.stdout.flush()

                try:
                    # output_format="none" suppresses per-device tables; we'll
                    # render a single combined table at the end.
                    dev_results = scan_device(ip, dev, points=list(read_points),
                                              output_format="none")
                except ScannerInputError as e:
                    # Bad input stops the whole sweep — the user gave us a
                    # slot/name that's invalid. Fail fast, same contract as
                    # single-device scans.
                    print(f"\n  [ERROR] {e}")
                    return
                except Exception as e:
                    # Per-device exceptions (timeouts, auth) are logged and
                    # skipped so one bad device doesn't kill the sweep.
                    sweep_results.append({'node': name, 'device': dev,
                                          'description': desc, 'error': str(e)})
                    continue

                if dev_results:
                    for r in dev_results:
                        r['_node'] = name
                        r['_device'] = dev
                        r['_description'] = desc
                        sweep_results.append(r)
                else:
                    # Device unreachable or point not readable — record the miss
                    sweep_results.append({'node': name, 'device': dev,
                                          'description': desc,
                                          'error': 'no data'})

        # Clear progress line
        sys.stdout.write("\r" + " " * 70 + "\r")

        # Render combined output
        _print_sweep_results(sweep_results, read_points, output_format)

    # Summary
    print(f"\n{'═' * 70}")
    print(f"  DISCOVERY RESULTS")
    print(f"{'═' * 70}")

    print(f"\n  P2 NODES:")
    for name in sorted(all_devices.keys()):
        info = all_devices[name]
        devs = info.get('devices', [])
        dev_count = len(devs)
        panel_count = len(info.get('panel_points', []))
        # Count online/offline if verified
        online = sum(1 for d in devs if d.get('status') == 'online')
        offline = sum(1 for d in devs if d.get('status') == 'offline')
        extra_parts = []
        if panel_count:
            extra_parts.append(f"{panel_count} panel points")
        if online or offline:
            extra_parts.append(f"{online} online, {offline} offline")
        extra = f"  ({', '.join(extra_parts)})" if extra_parts else ""
        print(f"    {name:<12s}  {info['ip']:<16s}  {dev_count} devices{extra}")

    total_devs = 0
    total_online = 0
    total_offline = 0
    for name in sorted(all_devices.keys()):
        devs = all_devices[name].get('devices', [])
        if devs:
            # Don't re-print device list if verify already printed it
            if not verify:
                print(f"\n  {name} DEVICES:")
                for d in devs:
                    desc = d.get('description', '')
                    desc_str = f"  ({desc})" if desc else ""
                    print(f"    {d['device']:<20s}  APP {d['application']}{desc_str}")
            total_devs += len(devs)
            total_online += sum(1 for d in devs if d.get('status') == 'online')
            total_offline += sum(1 for d in devs if d.get('status') == 'offline')

    summary = f"\n  TOTAL: {len(node_map)} nodes, {total_devs} devices discovered"
    if total_online or total_offline:
        summary += f" ({total_online} online, {total_offline} offline)"
    print(summary)
    print(f"{'═' * 70}")

    # JSON output
    if output_format == "json":
        print(json.dumps(all_devices, indent=2, default=str))


# ═══════════════════════════════════════════════════════════════════════════════
# Cold-site onboarding — discover BLN/scanner/node names on an unknown site.
#
# Pure addition to the original scanner — does NOT modify any existing code
# paths. Builds its own heartbeats independently via _cold_probe(), uses the
# existing port_scan_p2() helper, and populates KNOWN_NODES at the end via
# direct dict mutation (which save_config respects).
#
# Empirically validated: PXCs validate (BLN name, scanner name, node name)
# on handshake; wrong BLN → TCP RST; wrong scanner/node → silent drop;
# site and trailer fields are decorative.
# ═══════════════════════════════════════════════════════════════════════════════

_COLD_VENDOR_OUIS = {
    '00:c0:e4': 'Siemens Building Technologies',
    '00:a0:03': 'Siemens AG Automation',
    '00:12:ea': 'Trane',
    '00:50:db': 'Contemporary Controls',
    '00:50:7f': 'Distech Controls',
}
_COLD_SIEMENS_OUIS = {o for o, v in _COLD_VENDOR_OUIS.items() if 'Siemens' in v}
_COLD_BACNET_PORT = 47808
_COLD_FALSE_POSITIVE_PREFIXES = {
    'RM', 'VAV', 'AHU', 'FAN', 'FLR', 'CAB', 'BACNET',
    'DEVICE', 'ROOT', 'SYS', 'OBJECT', 'NET', 'SITE',
    'NODE', 'PANEL', 'ETHER', 'BVLC',
}


def _cold_extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    results, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                results.append(''.join(cur))
            cur = []
    if len(cur) >= min_len:
        results.append(''.join(cur))
    return results


def _cold_get_arp_mac(ip: str) -> Optional[str]:
    import subprocess
    try:
        if sys.platform.startswith('win'):
            result = subprocess.run(['arp', '-a', ip], capture_output=True,
                                    text=True, timeout=3)
        else:
            result = subprocess.run(['arp', '-n', ip], capture_output=True,
                                    text=True, timeout=3)
        for line in result.stdout.splitlines():
            if ip in line:
                m = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                if m:
                    return m.group(0).replace('-', ':').lower()
    except Exception:
        pass
    return None


def _cold_classify_vendor(mac: Optional[str]) -> str:
    if not mac:
        return 'Unknown (no MAC)'
    return _COLD_VENDOR_OUIS.get(mac[:8].lower(), f'Unknown OUI {mac[:8]}')


def _cold_passive_bacnet(duration: int = 30, interface: str = '0.0.0.0',
                         verbose: bool = False) -> Dict[str, dict]:
    from collections import defaultdict
    print(f"\n{'─' * 70}")
    print(f"  COLD-DISCOVER PHASE 1: Passive BACnet recon ({duration}s)")
    print(f"{'─' * 70}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind((interface, _COLD_BACNET_PORT))
    except OSError as e:
        print(f"  [FAIL] Could not bind UDP/{_COLD_BACNET_PORT}: {e}")
        sock.close()
        return {}

    discoveries: Dict[str, dict] = defaultdict(
        lambda: {'strings': set(), 'packet_count': 0, 'first_seen': None}
    )
    start = time.time()
    try:
        while time.time() - start < duration:
            sock.settimeout(1.0)
            try:
                data, (src, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if len(data) < 4 or data[0] != 0x81:
                continue
            d = discoveries[src]
            if d['first_seen'] is None:
                d['first_seen'] = time.time()
                if verbose:
                    print(f"  new BACnet source: {src}")
            d['packet_count'] += 1
            for s in _cold_extract_strings(data, min_len=4):
                d['strings'].add(s)
    except KeyboardInterrupt:
        print(f"  Interrupted.")
    finally:
        sock.close()
    print(f"  Captured from {len(discoveries)} unique BACnet source(s)")
    return dict(discoveries)


def _cold_infer_prefix(discoveries: Dict[str, dict]) -> List[str]:
    from collections import Counter
    scores: Counter = Counter()
    for info in discoveries.values():
        for s in info['strings']:
            if len(s) < 3 or s.lower() in ('bacnet', 'utf-8'):
                continue
            m = re.match(r'^([A-Za-z]{2,10})[_\-]', s)
            if m: scores[m.group(1).upper()] += 2
            m = re.match(r'^([A-Za-z]{3,8})\d', s)
            if m: scores[m.group(1).upper()] += 1
            m = re.match(r'^([A-Z][a-z]*[A-Z]+)', s)
            if m: scores[m.group(1).upper()] += 1
    ranked = [(p, c) for p, c in scores.most_common()
              if p not in _COLD_FALSE_POSITIVE_PREFIXES]
    if not ranked:
        return []
    top_score = ranked[0][1]
    return [p for p, c in ranked if c == top_score]


def _cold_generate_bln_candidates(prefixes: List[str]) -> List[str]:
    patterns = ["{p}EBLN", "{p}BLN", "{p}_BLN", "{p}-BLN",
                "{p}_EBLN", "{p}-EBLN", "{p}", "{p}NET"]
    candidates = []
    for pat in patterns:
        for p in [x.upper() for x in prefixes]:
            candidates.append(pat.format(p=p))
    candidates.extend(["APOGEE", "APOGEEBLN", "SIEMENS", "MAIN",
                       "DEFAULT", "NETWORK", "BLN1", "P2NET"])
    seen, result = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c); result.append(c)
    return result


def _cold_generate_scanner_candidates(prefixes: List[str]) -> List[str]:
    patterns = [
        "{p}DCC-SVR|5034", "{p}DCC-SVR",
        "{p}-DCC-SVR|5034", "{p}-DCC-SVR",
        "{p}DCC|5034", "{p}DCC",
    ]
    candidates = []
    for pat in patterns:
        for p in [x.upper() for x in prefixes]:
            candidates.append(pat.format(p=p))
    candidates.extend([
        "DCC-SVR|5034", "DCC-SVR",
        "INSIGHT-SVR", "INSIGHT",
        "DESIGO-CC", "DESIGO", "DESIGOCC", "APOGEE-SVR",
    ])
    seen, result = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c); result.append(c)
    return result


def _cold_generate_node_candidates(limit: int = 10) -> List[str]:
    candidates = []
    for i in range(1, limit + 1):
        candidates.append(f"node{i}")
        candidates.append(f"NODE{i}")
    candidates.extend(["MAIN", "LOBBY", "PENT", "BOILER", "CHILLER"])
    seen, result = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c); result.append(c)
    return result


def _cold_probe(host: str, bln: str, scanner: str, node: str,
                site: str = 'DIAGSITE', timeout: float = 3.0) -> Dict:
    """Independent heartbeat probe — builds its own frame, doesn't touch
    any module globals or the P2Connection class."""
    bln_b = bln.encode('ascii')
    scanner_b = scanner.encode('ascii')
    site_b = site.encode('ascii')
    node_b = node.encode('ascii')

    routing = (b'\x00' + bln_b + b'\x00' + node_b + b'\x00' +
               bln_b + b'\x00' + scanner_b + b'\x00')
    identity = (
        b'\x46\x40' +
        b'\x01\x00' + bytes([len(scanner_b)]) + scanner_b +
        b'\x01\x00' + bytes([len(site_b)]) + site_b +
        b'\x01\x00' + bytes([len(bln_b)]) + bln_b +
        b'\x00\x01\x01\x00\x00\x00\x00\x00' +
        struct.pack('>I', int(time.time())) + b'\x00\xfe\x98\x00'
    )
    payload = routing + identity
    frame = struct.pack('>III', 12 + len(payload), 0x33, 1) + payload

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, P2_PORT))
    except (ConnectionRefusedError, socket.timeout):
        return {'verdict': 'port_closed'}
    except Exception as e:
        return {'verdict': 'error', 'reason': str(e)}

    try:
        sock.sendall(frame)
    except Exception as e:
        sock.close()
        return {'verdict': 'error', 'reason': str(e)}

    sock.settimeout(2.0)
    data, reset = b"", False
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            sock.settimeout(0.5)
    except ConnectionResetError:
        reset = True
    except Exception:
        pass
    finally:
        try: sock.close()
        except Exception: pass

    if data:
        return {'verdict': 'got_response', 'data': data}
    return {'verdict': 'rejected_rst' if reset else 'rejected_silent'}


def _cold_cartesian_attack(host: str, bln_list: List[str],
                           scanner_list: List[str], node_list: List[str],
                           delay: float = 0.3, inter_tier_pause: float = 5.0,
                           force_full: bool = False
                           ) -> Optional[Tuple[str, str, str, bytes]]:
    tiers = [
        ("Tier 1 (high-probability)", 2, 3, 3),
        ("Tier 2 (plausible)",        4, 4, 5),
    ]
    if force_full:
        tiers.append(("Tier 3 (exhaustive)",
                      len(scanner_list), len(bln_list), len(node_list)))

    attempted: set = set()
    attempt_num = 0

    for idx, (label, s_n, b_n, n_n) in enumerate(tiers):
        scanners = scanner_list[:s_n]
        blns = bln_list[:b_n]
        nodes = node_list[:n_n]
        new_combos = [(sc, bl, nd)
                      for sc in scanners for bl in blns for nd in nodes
                      if (sc, bl, nd) not in attempted]
        for combo in new_combos:
            attempted.add(combo)
        if not new_combos:
            continue

        print(f"\n  {label}: {len(new_combos)} combo(s)")
        if idx > 0:
            print(f"  Pausing {inter_tier_pause}s (lockout safety)...")
            time.sleep(inter_tier_pause)

        for sc, bl, nd in new_combos:
            attempt_num += 1
            print(f"  [{attempt_num:3d}] scanner={sc!r:<25} BLN={bl!r:<12} "
                  f"node={nd!r:<8}", end=" ", flush=True)
            result = _cold_probe(host, bl, sc, nd)
            v = result['verdict']
            if v == 'got_response':
                print(f"ACCEPTED ({len(result['data'])} bytes)")
                return (sc, bl, nd, result['data'])
            elif v == 'rejected_rst':
                print(f"RST (wrong BLN)")
            elif v == 'rejected_silent':
                print(f"silent (wrong scanner/node)")
            elif v == 'port_closed':
                print(f"port closed — aborting")
                return None
            else:
                print(f"{v}")
            time.sleep(delay)
    return None


def _cold_parse_node_name(data: bytes, our_scanner: str,
                          our_bln: str) -> Optional[str]:
    if len(data) < 14 or data[12] != 0x01:
        return None
    payload = data[13:]
    strings, cur = [], bytearray()
    for b in payload:
        if b == 0:
            if cur:
                try:
                    sv = cur.decode('ascii')
                    if sv.isprintable():
                        strings.append(sv)
                except UnicodeDecodeError:
                    pass
                cur = bytearray()
            if len(strings) >= 4:
                break
        else:
            cur.append(b)
    excluded = {our_scanner, our_bln}
    for sv in strings:
        if sv not in excluded and (sv.upper().startswith('NODE')
                                   or sv.upper().startswith('PXC')):
            return sv
    return strings[3] if len(strings) >= 4 else None


def cold_discover_site(ranges: Optional[List[str]] = None,
                       pxc_ips: Optional[List[str]] = None,
                       site_hint: Optional[str] = None,
                       bacnet_duration: int = 30,
                       bacnet_interface: str = '0.0.0.0',
                       skip_bacnet: bool = False,
                       force_full: bool = False,
                       delay: float = 0.3,
                       verbose: bool = False) -> Optional[Dict]:
    """Discover BLN name, scanner name, and at least one node name on a site
    where nothing is preconfigured. Returns a dict suitable for site.json,
    or None on failure."""
    print(f"\n{'═' * 70}")
    print(f"  COLD-SITE DISCOVERY")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 70}")

    discoveries: Dict[str, dict] = {}
    inferred_prefixes: List[str] = []
    siemens_ips_from_bacnet: List[str] = []

    # Phase 1: BACnet recon
    if not skip_bacnet and not pxc_ips:
        discoveries = _cold_passive_bacnet(
            duration=bacnet_duration, interface=bacnet_interface,
            verbose=verbose)
        if discoveries:
            print(f"\n  BACnet devices:")
            for ip in sorted(discoveries, key=lambda s: tuple(int(o) for o in s.split('.'))):
                mac = _cold_get_arp_mac(ip)
                vendor = _cold_classify_vendor(mac)
                is_siemens = mac and mac[:8].lower() in _COLD_SIEMENS_OUIS
                marker = " ← SIEMENS" if is_siemens else ""
                print(f"    {ip:<16} {mac or '(unknown)':<20} "
                      f"{vendor:<32} pkts={discoveries[ip]['packet_count']}{marker}")
                if is_siemens:
                    siemens_ips_from_bacnet.append(ip)
        inferred_prefixes = _cold_infer_prefix(discoveries)
        if inferred_prefixes:
            print(f"\n  Inferred site prefix(es): {', '.join(inferred_prefixes)}")

    if site_hint:
        prefixes = [site_hint]
        print(f"\n  Using user-provided site hint: {site_hint}")
    elif inferred_prefixes:
        prefixes = inferred_prefixes
    else:
        prefixes = []
        print(f"\n  No site prefix — falling back to universal candidates")

    # Phase 2: PXC discovery and fingerprint
    if pxc_ips:
        candidate_ips = list(pxc_ips)
        print(f"\n  Using {len(candidate_ips)} provided PXC IP(s)")
    else:
        from ipaddress import ip_network
        scan_ips: set = set()
        for r in (ranges or []):
            try:
                net = ip_network(r, strict=False)
                hosts = net.hosts() if net.prefixlen <= 30 else net
                scan_ips.update(str(ip) for ip in hosts)
            except ValueError:
                scan_ips.add(r)
        scan_ips.update(siemens_ips_from_bacnet)
        if not scan_ips:
            print(f"\n  No scan targets. Provide --range or --pxc.")
            return None
        print(f"\n  PHASE 2: Port scan {len(scan_ips)} IPs for TCP/{P2_PORT}")
        candidate_ips = port_scan_p2(sorted(scan_ips,
                                     key=lambda s: tuple(int(o) for o in s.split('.'))))

    if not candidate_ips:
        print(f"  No hosts with TCP/{P2_PORT} open.")
        return None

    print(f"\n  PHASE 2b: Fingerprint {len(candidate_ips)} host(s)")
    siemens_pxcs = []
    for host in candidate_ips:
        r = _cold_probe(host, "DIAGTEST", "DIAGPROBE|5034", "node1")
        if r['verdict'] == 'rejected_rst':
            print(f"    {host:<16} SIEMENS PXC (rejected wrong BLN)")
            siemens_pxcs.append(host)
        elif r['verdict'] == 'rejected_silent':
            print(f"    {host:<16} Siemens-maybe (silent drop)")
            siemens_pxcs.append(host)
        elif r['verdict'] == 'got_response':
            print(f"    {host:<16} RESPONDED to junk — not-Siemens")
        else:
            print(f"    {host:<16} {r['verdict']}")

    if not siemens_pxcs:
        print(f"\n  No Siemens PXCs identified.")
        return None

    # Phase 3: Cartesian attack
    bln_candidates = _cold_generate_bln_candidates(prefixes)
    scanner_candidates = _cold_generate_scanner_candidates(prefixes)
    node_candidates = _cold_generate_node_candidates()
    target = siemens_pxcs[0]
    print(f"\n  PHASE 3: Cartesian attack against {target}")
    hit = _cold_cartesian_attack(target, bln_candidates, scanner_candidates,
                                  node_candidates, delay=delay,
                                  force_full=force_full)

    if not hit:
        print(f"\n{'═' * 70}")
        print(f"  INCOMPLETE — no working combo found")
        print(f"{'═' * 70}")
        print(f"  Siemens PXCs: {', '.join(siemens_pxcs)}")
        if not force_full:
            print(f"  Retry with --force-full for exhaustive sweep.")
        return None

    scanner, bln, node_guess, data = hit
    extracted = _cold_parse_node_name(data, scanner, bln)
    node = extracted or node_guess

    print(f"\n{'═' * 70}")
    print(f"  COLD DISCOVERY COMPLETE")
    print(f"{'═' * 70}")
    print(f"  BLN name:     {bln}")
    print(f"  Scanner name: {scanner}")
    print(f"  Node (for {target}): {node}")
    print(f"  All Siemens PXCs: {', '.join(siemens_pxcs)}")

    site_name = prefixes[0].upper() if prefixes else "SITE"
    site_config = {
        "p2_network": bln,
        "p2_site": site_name,
        "scanner_name": scanner,
        "known_nodes": {},
    }
    for ip in siemens_pxcs:
        label = node if ip == target else f"UNKNOWN_{ip.split('.')[-1]}"
        site_config["known_nodes"][label] = ip

    print(f"\n  site.json content:")
    for line in json.dumps(site_config, indent=2).splitlines():
        print(f"  {line}")
    return site_config


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Siemens P2 Protocol Scanner — Read TEC/FLN points from PXC controllers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # FIRST TIME — Learn network name from a pcap
  %(prog)s --pcap capture.pcapng --save site.json

  # FIRST TIME — Discover with known network name, save config
  %(prog)s --discover --range 10.0.0.0/24 --network MYBLN --save site.json

  # AFTER SETUP — Use saved config (no --network needed)
  %(prog)s --config site.json --discover --skip-portscan
  %(prog)s --config site.json -n NODE1 -d DEVICE1 --quick

  # OR — Just use --network directly every time
  %(prog)s --discover --range 10.0.0.0/24 --network MYBLN
  %(prog)s -n 10.0.0.50 -d DEVICE1 -p "ROOM TEMP" --network MYBLN

  # Discover + read every point on every device
  %(prog)s --network MYBLN --discover --range 10.0.0.0/24 --read-all

  # Get node firmware info
  %(prog)s --config site.json -n NODE1 --info

  # Discovery with firmware info for each node
  %(prog)s --config site.json --discover --skip-portscan --info

  # Multiple subnets (multiple buildings)
  %(prog)s --discover --range 10.0.0.0/24 --range 172.16.0.0/24 --network MYBLN

  # Decode a pcap file
  %(prog)s --pcap capture.pcapng

  # Show point table for an application
  %(prog)s --show-app 2023

Known nodes: """ + ', '.join(f"{n}={ip}" for n, ip in sorted(KNOWN_NODES.items()))
    )

    parser.add_argument('--node', '-n', help='PXC controller IP or node name')
    parser.add_argument('--device', '-d', help='TEC device name (e.g., DEVICE1)')
    parser.add_argument('--point', '-p', action='append',
                       help='Specific point(s) to read. Accepts point names '
                            '("ROOM TEMP") or slot numbers ("29"). Can be '
                            'passed multiple times.')
    parser.add_argument('--force-slot', action='store_true',
                       help='When reading by slot number, attempt the read '
                            'even if the slot is undefined in the app\'s '
                            'point table (for protocol troubleshooting).')
    parser.add_argument('--quick', '-q', action='store_true', help='Quick scan (key points only)')
    parser.add_argument('--discover', action='store_true', help='Discover nodes and devices')
    parser.add_argument('--range', '-r', action='append',
                       help='IP range to scan. Formats: 10.0.0.0/24, 10.0.0.1-254, '
                            '10.0.0, or single IP. Can specify multiple times.')
    parser.add_argument('--skip-portscan', action='store_true',
                       help='Skip port scan during discovery (use known nodes)')
    parser.add_argument('--with-panel', action='store_true',
                       help='Also scan panel-level points during discovery')
    parser.add_argument('--read-all', action='store_true',
                       help='Read all points on every discovered device')
    parser.add_argument('--subnet', default='10.0.0',
                       help='(deprecated, use --range) Subnet to scan (default: 10.0.0)')
    parser.add_argument('--network', help='P2 network name (auto-learned if not set)')
    parser.add_argument('--scanner-name', default=None,
                       help=f'Scanner identity on P2 network (overrides config; default from config or {SCANNER_NAME!r})')
    parser.add_argument('--config', help='Load site config from JSON file')
    parser.add_argument('--save', help='Save learned config to JSON file')
    parser.add_argument('--browse', '-b', action='store_true', help='Browse devices on a node')
    parser.add_argument('--info', action='store_true',
                       help='Show node firmware/revision info during discovery')
    parser.add_argument('--verify', action='store_true',
                       help='Verify which devices are actually online after discovery')
    parser.add_argument('--online', action='store_true',
                       help='Only show devices confirmed online (implies --verify)')
    parser.add_argument('--offline', action='store_true',
                       help='Only show devices confirmed offline (implies --verify)')
    parser.add_argument('--pcap', help='Decode a pcap/pcapng file')
    parser.add_argument('--sniff', nargs='?', const=10, type=int, metavar='SECONDS',
                       help='Live capture P2 traffic to learn network name (requires tshark/Wireshark, default 10s)')
    parser.add_argument('--scan-network', action='store_true', help='Probe all known nodes')
    parser.add_argument('--cold-discover', action='store_true',
                       help='Discover BLN/scanner/node names on an unknown site. '
                            'Uses BACnet recon + Cartesian dictionary attack.')
    parser.add_argument('--pxc', action='append', default=[],
                       help='For --cold-discover: known PXC IP (skips port scan)')
    parser.add_argument('--site-hint',
                       help='For --cold-discover: override BACnet-inferred prefix')
    parser.add_argument('--bacnet-duration', type=int, default=30,
                       help='For --cold-discover: BACnet listen seconds (default 30)')
    parser.add_argument('--bacnet-interface', default='0.0.0.0',
                       help='For --cold-discover: bind interface (default 0.0.0.0)')
    parser.add_argument('--skip-bacnet', action='store_true',
                       help='For --cold-discover: skip BACnet phase')
    parser.add_argument('--force-full', action='store_true',
                       help='For --cold-discover: enable exhaustive tier 3 sweep')
    parser.add_argument('--cold-delay', type=float, default=0.3,
                       help='For --cold-discover: delay between probes (default 0.3)')
    parser.add_argument('--debug-reads', action='store_true',
                       help='Print raw hex when a point-read fails to parse '
                            '(helpful for diagnosing unusual response shapes)')
    parser.add_argument('--format', '-f', choices=['table', 'json', 'csv'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--list-nodes', action='store_true', help='List known PXC nodes')
    parser.add_argument('--show-app', type=int, help='Show point table for TEC application')
    parser.add_argument('--port', type=int, default=P2_PORT, help=f'P2 port (default: {P2_PORT})')

    args = parser.parse_args()

    # Load site config if specified (optional — file doesn't need to exist yet)
    if args.config:
        import os
        if os.path.exists(args.config):
            load_config(args.config)
        else:
            print(f"  Config file {args.config} not found — will create after discovery")

    # Apply CLI overrides (take precedence over config file)
    if args.network:
        _set_network(args.network)
    if args.scanner_name:
        _set_scanner_name(args.scanner_name)
    if args.debug_reads:
        global DEBUG_READS
        DEBUG_READS = True

    # ─── Cold-site discovery — runs before the network-name check since
    #     the whole point is to discover the network name.
    if args.cold_discover:
        result = cold_discover_site(
            ranges=args.range,
            pxc_ips=args.pxc if args.pxc else None,
            site_hint=args.site_hint,
            bacnet_duration=args.bacnet_duration,
            bacnet_interface=args.bacnet_interface,
            skip_bacnet=args.skip_bacnet,
            force_full=args.force_full,
            delay=args.cold_delay,
            verbose=False,
        )
        if result and args.save:
            # Apply discovered values to globals, then save
            global P2_SITE
            _set_network(result['p2_network'])
            _set_scanner_name(result['scanner_name'])
            P2_SITE = result['p2_site']
            KNOWN_NODES.update(result['known_nodes'])
            save_config(args.save)
            print(f"\n  Saved to {args.save}")
        elif result:
            print(f"\n  To save: rerun with --save site.json")
        return

    # Check if we have what we need for P2 communication
    if not P2_NETWORK and not args.pcap and not args.show_app and not args.list_nodes:
        # Try sniffing if requested or if we need the network name
        if hasattr(args, 'sniff') and args.sniff:
            print(f"\n  Sniffing for P2 traffic...")
            name = sniff_network_name(duration=args.sniff)
            if name:
                print(f"  Learned network: {P2_NETWORK}  |  Site: {P2_SITE}")
                if args.save:
                    save_config(args.save)
                elif args.config:
                    save_config(args.config)
            else:
                print(f"  Could not learn network name from live traffic.")
                print(f"  Make sure this machine can see P2 traffic (same VLAN as BAS).")
                if not (args.range or args.node):
                    return

        # Still no network name?
        if not P2_NETWORK and (args.range or args.node):
            # Try auto-sniff before giving up
            if not (hasattr(args, 'sniff') and args.sniff):
                print(f"\n  Attempting to sniff P2 traffic for network name...")
                name = sniff_network_name(duration=5)
                if name:
                    print(f"  Learned network: {P2_NETWORK}")
                    
            if not P2_NETWORK:
                print(f"\n  ⚠ P2 network name required.")
                print(f"    PXC controllers won't respond without the correct network name.")
                print(f"")
                print(f"    Options:")
                print(f"      --network NAME         Specify it directly (e.g. --network MYBLN)")
                print(f"      --pcap FILE            Learn it from a Wireshark capture")
                print(f"      --sniff [SECONDS]      Live capture to auto-learn (needs tshark)")
                print(f"      --config FILE          Load from a saved config")
                print(f"")
                print(f"    To get the network name:")
                print(f"      1. Check Desigo CC → Field Networks → BLN name")
                print(f"      2. Or: grab a 5-second Wireshark capture on the BAS server,")
                print(f"         then: p2_scanner.py --pcap capture.pcapng")
                print(f"      3. Or: run on the BAS server: p2_scanner.py --sniff 10")
                return

    # List nodes
    if args.list_nodes:
        print(f"\nKnown P2 nodes on {P2_NETWORK}:")
        for name, ip in sorted(KNOWN_NODES.items()):
            print(f"  {name:<10s} {ip}")
        return

    # Show application point table
    if args.show_app:
        pt_table = get_point_table(args.show_app)
        print(f"\nTEC Application {args.show_app} — {len(pt_table)} subpoints:")
        print(f"  {'Addr':>4s}  {'Name':<25s} {'Units':<8s} {'RO':<4s} Description")
        print(f"  {'─' * 4}  {'─' * 25} {'─' * 8} {'─' * 4} {'─' * 30}")
        for addr, (name, desc, units, ro) in pt_table.items():
            ro_str = "RO" if ro else "RW"
            print(f"  {addr:>4d}  {name:<25s} {units:<8s} {ro_str:<4s} {desc}")
        return

    # Decode pcap
    if args.pcap:
        sniff_pcap(args.pcap, args.format)
        if args.save and P2_NETWORK:
            save_config(args.save)
        elif P2_NETWORK and not args.save:
            print(f"\n  Learned network: {P2_NETWORK}  |  Site: {P2_SITE}")
            print(f"  Tip: use --save site.json to save this for future scans")
        return

    # Standalone sniff mode
    if hasattr(args, 'sniff') and args.sniff and not args.discover and not args.node:
        print(f"\n  Sniffing for P2 traffic ({args.sniff} seconds)...")
        name = sniff_network_name(duration=args.sniff)
        if name:
            print(f"\n  Network: {P2_NETWORK}  |  Site: {P2_SITE}")
            if args.save:
                save_config(args.save)
            else:
                print(f"  Use --save site.json to save for future scans")
        else:
            print(f"\n  No P2 traffic detected.")
            print(f"  Make sure this machine is on the BAS VLAN and tshark is installed.")
        return

    # Discovery mode
    if args.discover:
        if args.node and not args.range:
            # Discover devices on a single node
            host = KNOWN_NODES.get(args.node.upper(), args.node)
            node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else None
            if not node_name:
                print(f"  Identifying node at {host}...")
                node_name = discover_node_name(host)
                if not node_name:
                    node_name = "UNKNOWN"
            print(f"\n{'═' * 70}")
            print(f"  DISCOVERING DEVICES ON {node_name} ({host})")

            if args.info:
                info = get_node_info(host, node_name)
                if info:
                    print(f"  Firmware: {info['firmware']}  Model: {info['model']}")
                    if info['extra']:
                        print(f"  Extra: {info['extra']}")

            print(f"{'═' * 70}")
            devs = discover_devices_on_node(host, node_name)
            if args.with_panel:
                print(f"\n  Scanning panel-level points...")
                panel_pts = discover_panel_points(host, node_name)
                for pt in panel_pts:
                    print(f"    {pt['point']:<35s} = {pt['value']:>10.2f} {pt.get('units', '')}")
            print(f"\n  Found {len(devs)} configured devices on {node_name}")

            # Verify online status if requested
            should_verify = args.verify or args.online or args.offline
            if should_verify and devs:
                show_filter = "online" if args.online else ("offline" if args.offline else "all")
                verify_devices(host, node_name, devs, show_filter=show_filter)
            else:
                for d in devs:
                    desc = d.get('description', '')
                    desc_str = f"  ({desc})" if desc else ""
                    print(f"    {d['device']:<20s}  APP {d['application']}{desc_str}")

            # If --read-all, scan every discovered device
            if args.read_all and devs:
                print(f"\n{'═' * 70}")
                print(f"  READING ALL POINTS")
                print(f"{'═' * 70}")
                # If verified, only read online devices
                for d in devs:
                    if should_verify and d.get('status') == 'offline':
                        continue
                    scan_device(host, d['device'], output_format=args.format)
        else:
            # Full network discovery
            ip_ranges = ','.join(args.range) if args.range else args.subnet
            # Determine verify filter
            verify_filter = None
            if args.online:
                verify_filter = "online"
            elif args.offline:
                verify_filter = "offline"
            elif args.verify:
                verify_filter = "all"

            discover_network(
                ip_ranges=ip_ranges,
                scan_ports=not args.skip_portscan,
                scan_devices=True,
                scan_panel=args.with_panel,
                scan_info=args.info,
                verify=verify_filter,
                read_all=args.read_all,
                output_format=args.format,
                read_points=args.point,
            )
        if args.save and P2_NETWORK:
            save_config(args.save)
        elif args.config and P2_NETWORK:
            save_config(args.config)  # Auto-save back to config file
        return

    # Network scan (legacy, simpler than discover)
    if args.scan_network:
        scan_network(args.quick)
        return

    # Resolve node name to IP
    if args.node:
        host = KNOWN_NODES.get(args.node.upper(), args.node)
    else:
        parser.print_help()
        return

    # Device scan
    if args.device:
        try:
            results = scan_device(host, args.device, args.point, args.quick,
                                  args.format, force_slot=args.force_slot)
        except ScannerInputError as e:
            print(f"\n  [ERROR] {e}")
            sys.exit(2)
        # Exit 1 if the scan completed but yielded no successful reads —
        # lets cron jobs and parent processes detect "I ran but found nothing"
        # without having to parse stdout.
        if not results:
            sys.exit(1)
    elif args.info:
        # Standalone node info query
        node_name = args.node.upper() if args.node.upper() in KNOWN_NODES else None
        if not node_name:
            node_name = discover_node_name(host)
            if not node_name:
                node_name = "UNKNOWN"
        print(f"\n  Querying {node_name} ({host})...")
        info = get_node_info(host, node_name)
        if info:
            print(f"  Firmware: {info['firmware']}")
            print(f"  Model:    {info['model']}")
            if info['extra']:
                print(f"  Extra:    {info['extra']}")
            if info.get('raw_strings'):
                print(f"  Raw:      {info['raw_strings']}")
        else:
            print(f"  Could not get info (node may not support opcode 0x0100)")
    elif args.browse:
        print(f"  Use --discover instead: p2_scanner.py --node {args.node} --discover")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
