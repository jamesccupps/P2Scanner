# APOGEE P2 Opcode Reference

Concise reference of every opcode and frame-level code documented in `PROTOCOL.md` and exercised or observed by `p2_scanner.py`. Companion to the full protocol writeup — see `PROTOCOL.md` for wire formats, capture provenance, and behavioral notes.

All opcodes are big-endian 16-bit values appearing immediately after the routing header in `0x33` / `0x34` (and Mode-C `0x2E` / `0x2F`) payloads.

---

## Frame-level codes

These are **not** operation opcodes — they are the `msg_type` byte at offset 0 of the 12-byte frame header and the direction byte inside the payload.

### `msg_type` byte

| Code | Name | Notes |
|---|---|---|
| `0x2E` | CONNECT | Legacy-dialect handshake initiator |
| `0x2F` | ANNOUNCE | Modern-dialect handshake initiator |
| `0x33` | DATA | Operational traffic — legacy dialect (PME1252 and earlier) |
| `0x34` | HEARTBEAT | Operational traffic — modern dialect (PME1300 platform) |
| `0x40` | (heartbeat) | Referenced in connection-modes table |

### Direction byte (offset 8 of payload)

| Code | Meaning |
|---|---|
| `0x00` | Request (C2S) |
| `0x01` | Successful response (S2C) |
| `0x05` | Error response (S2C) — followed by 2-byte error code |

---

## Operation opcodes

### Read / write — `02xx` family

| Opcode | Name | Notes |
|---|---|---|
| `0x0203` | ObjectLifecycle (probe) | Sibling of `0x0204`; corpus only shows client-debug names |
| `0x0204` | CreateObject | Returns `0x0E11` if name is taken |
| `0x0220` | ReadShort | Desigo CC's preferred compact read |
| `0x0240` | WriteWithQuality | 5034 BLN virtual push; errors `0x0E15` against SYST properties |
| `0x0241` | (unknown) | SYST-prefixed property-op, semantics unconfirmed (4 samples) |
| `0x0244` | Scope-restricted read | Returns `0x0002` out-of-scope; variant of `0x0240` |
| `0x0245` | (test probe) | Always errors — cold-probe captures only, not a real op |
| `0x0260` | ObjectLifecycle (probe) | Pairs with `0x0263` |
| `0x0263` | ObjectLifecycle | Object delete-related |
| `0x0271` | ReadExtended | Legacy full-value read; trailer `00 FF` |
| `0x0272` | ReadExtended-MetaOnly | Same shape as `0x0271`, no trailing sentinel; descriptor lookup |
| `0x0273` | WriteNoValue / AlarmAckTrigger | Trailer `00 00`; precedes `0x0509` in alarm-ack flows |
| `0x0274` | ValuePush / COVNotification | Bidirectional — direction determines semantics |
| `0x0291` | (write variant) | SYST + value bytes after `0x23` separator |
| `0x0294` | (read variant) | Two body shapes: 53-byte (`0x00` sep) and 222-byte preallocated (`0x01` sep) |
| `0x0295` | SYST-scoped read | Sibling of `0x0294`; plant-equipment status registers |
| `0x02A8` | (write variant) | Inline `0xC8` + type code + 4-byte float |

### Session keepalive pings — bare 09xx (PXC→DCC, no body)

Carried inside `0x2E` CONNECT frames mid-session, **2 bytes total** after the routing header (no body, no response expected). Distinct from the schedule-operation 09xx family — tell them apart by body length: <3 B = bare ping, ≥10 B = full operation.

| Opcode | Notes |
|---|---|
| `0x0951` | Bare-opcode session-keepalive ping |
| `0x0954` | Bare-opcode session-keepalive ping |
| `0x0955` | Bare-opcode session-keepalive ping |
| `0x0956` | Bare-opcode session-keepalive ping |
| `0x0959` | Bare-opcode session-keepalive ping |

### Alarms — `05xx` family

| Opcode | Name | Notes |
|---|---|---|
| `0x0508` | AlarmReport | PXC→DCC; rich payload (class, point, datetimes, value, priority); often duplicated on 5033 + 5034 |
| `0x0509` | AlarmAck | DCC→PXC; compact (class header + point name only) |

### Discovery / system info

| Opcode | Name | Notes |
|---|---|---|
| `0x0050` | StatusFlagQuery | Tiny 12-byte body; returns supervisor-name list **without authentication** — useful for cold discovery |
| `0x0100` | GetRevString | Older-firmware sysinfo (legacy equivalent of `0x010C`) |
| `0x010C` | GetSystemInfo | 2-byte request; ~269-byte response with model TLV, firmware string, build date, node# at offset ~0x68 |
| `0x0368` | NodeRoutingQuery | Carries node name + 16-bit flag/mask field |
| `0x040A` | StateSetCatalog | Multi-state label catalog (e.g. `ZONE_MODE` → 12 states, `UNOCC_OCC` → 2 states) |
| `0x0606` | (heartbeat ping) | Same shape as `0x0050`; empty-body response |

### Enumerate / schedule — `09xx` family

| Opcode | Name | Notes |
|---|---|---|
| `0x0961` | AnalogPointQuery (legacy) | Same shape as `0x0981`; mostly `0x0003`. Deprecated form of `0x0971` |
| `0x0964` | TitleAnalogQuery | Returns f32 value + units + min/max limits |
| `0x0965` | NodeDiscoveryEnumerate | Slim `0x0986` equivalent — early session reachability check |
| `0x0966` | ShortQuery | 4-byte body, no SYST tag; mostly errors |
| `0x0969` | ScheduleObjectList | Returns schedule object names under a parent |
| `0x0971` | EnhancedPointRead | Adds description + resolution + min + max + type-code over `0x0981` |
| `0x0974` | MultistatePointEnumerate | State-set-aware variant of `0x0964` |
| `0x0975` | NodeDiscoveryWithLines | Cursor + line-number trailer; maps PPCL programs to nodes |
| `0x0976` | DeviceAllSubpointsRead | Device dump: app# (u16) + description + per-slot `(slot, f32)` tuples |
| `0x0979` | ShortVariant | `0x0976`-like body with trailing `02 71` cross-opcode reference |
| `0x0981` | EnumeratePoints | Walks every point on panel — more complete than `0x0986` |
| `0x0982` | EnumerateTrended | Like `0x0981` but entries carry embedded timestamps |
| `0x0983`, `0x0984`, `0x0987`, `0x0989` | EnumerateVariants | Mostly `0x00AC` not_supported on V2.8.10 firmware |
| `0x0985` | EnumeratePrograms | Walks PPCL programs; returns source text in chunks |
| `0x0986` | EnumerateFLN | Lists TEC devices on FLN bus; simplest enumerate, works on every firmware |
| `0x0988` | EnumerateMulti | Multi-string filter (device AND subpoint AND variant) |
| `0x098B` | NewerFeature enumerate | 100% `0x0003` / `0x00AC` on PME1252 |
| `0x098C` | ScheduleSetpointTable | 5–7 floats — heating/cooling setpoint band |
| `0x098D` | ScheduleEntries | Weekly schedule payload (4-byte BACnet date encoding) |
| `0x098E` | ScheduleGainConfig | 7 floats per row — PID gains, deadtime, sampling period |
| `0x098F` | ScheduleDeadband | Single f32 — deadband / threshold |
| `0x099F` | GetPortConfig | 5-byte request `09 9F 00 04 XX`. Returns `;bd=`/`;pa=`/`;mk=`, `;mid=`/`;ety=`/`;pdl=`, port label. `0xFF`=USB Modem, `0x00`=HMI, `0x04`=undefined |
| `0x09A3`, `0x09A7`, `0x09AB`, `0x09BB`, `0x09C3` | (extended enumerates) | All `0x00AC` not_supported on legacy firmware |

### PPCL editor — `41xx` family

| Opcode | Name | Notes |
|---|---|---|
| `0x4100` | LineWrite/Create | Body: `[01 00 LL <program>] 00 00 00 [01 00 LL <line-content>] 00 0A`. Inserts/overwrites at line number in trailer |
| `0x4103` | ProgramEnableHint | Trailer `00 01 7F FF` (same as `0x4106`); hypothesized Enable/Disable mode + scope |
| `0x4104` | LineRead/Delete | Two u16s: line number + length/mode |
| `0x4106` | ClearTracebits | Trailer `00 01 7F FF`. **Modifies runtime state** — clears tracebits and triggers re-execution |

### Bulk property / browse — `42xx` family

| Opcode | Name | Notes |
|---|---|---|
| `0x4200` | PropertyQuery | Two forms: small (~30–40 B) tree-browse, large (222 B preallocated) deep-read. Trailing `FF FF` is wildcard property-id |
| `0x4220` | BulkProperty (variant) | Single sample; carries config header rather than value |
| `0x4221` | BulkPropertyRead | Constant 273-byte body; populates Desigo property dialogs |
| `0x4222` | BulkPropertyWrite | **The correct opcode for SYST setpoint writes** — `0x0240` rejects with `0x0E15` |
| `0x400F`, `0x4010`, `0x4011`, `0x4133` | (newer-firmware probes) | Constant 12–17 byte bodies; all `0x00AC` on legacy firmware |
| `0x4500` | (test probe) | Always errors — `enumeratetest{1,2,3}.pcapng` only |

### Identity / routing — `46xx` family

| Opcode | Name | Notes |
|---|---|---|
| `0x4634` | PushRoutingTable | Body is list of `{TLV name, u32 BE cost}` tuples; ACK-only response |
| `0x4640` | IdentifyBlock | Handshake payload + mid-session identity refresh. Desigo cadence: every **10.0 s exactly** per TCP connection |

### Schedule property writes / misc — `50xx` and others

| Opcode | Name | Notes |
|---|---|---|
| `0x5003` | ScheduleObjectInfo | `[01 00 04 "SYST"][01 00 LL <object>]`; returns object name (twice) + state-set ref |
| `0x5020`, `0x5022` | Schedule write pair | Documented in PROTOCOL.md *Schedule property writes* section |
| `0x5038` | DisplayLabelEnumerate | Cursor-based enumerate of `(object-name, display-label, state-set-ref)` triples |
| `0x5354` | (unknown) | Always returns `0x0003`; purpose unknown |

---

## Error codes

Returned in the response body after the `0x05` direction byte (so the wire bytes are `05 00 03` for "not found", etc.).

| Code | Approx. count | Meaning |
|---|---|---|
| `0x0002` | ~2 | Object unknown — scope-restricted ops (e.g. `0x0244`) when target is out of requesting scope |
| `0x0003` | ~1369 | Object / point not found — by far the most common error |
| `0x00AC` | ~42 | Operation not supported / unknown opcode on this firmware |
| `0x0E11` | ~2 | Object already exists — response to `0x0204` CreateObject; Desigo treats as success |
| `0x0E15` | ~7 | Wrong write opcode for this property type. Always `0x0240` WriteWithQuality issued against a SYST-tagged property — Desigo retries with `0x4222` |

---

## Quick lookups

**The 13 opcodes the scanner actively uses or watches** (from `P2Message` in `p2_scanner.py`):

| Constant | Opcode | Role |
|---|---|---|
| `OP_IDENTIFY` | `0x4640` | Mid-session identity refresh |
| `OP_READ_EXTENDED` | `0x0271` | Point read (legacy dialect) |
| `OP_READ_SHORT` | `0x0220` | Point read (modern dialect) |
| `OP_WRITE_NOVALUE` | `0x0273` | ACK-only probe/reset |
| `OP_VALUE_PUSH` | `0x0274` | DCC→PXC virtual-write or PXC→DCC COV |
| `OP_WRITE_QUALITY` | `0x0240` | PXC→DCC quality-envelope push (5034 only) |
| `OP_ENUM_FLN` | `0x0986` | Enumerate FLN devices |
| `OP_ENUM_POINTS` | `0x0981` | Enumerate all points |
| `OP_ENUM_PROGRAMS` | `0x0985` | Enumerate PPCL programs (returns source) |
| `OP_SYSINFO` | `0x0100` | Firmware/model — legacy |
| `OP_SYSINFO_COMPACT` | `0x010C` | Firmware/model — newer (2-byte request) |
| `OP_ROUTING_TABLE` | `0x4634` | BLN routing-table push |
| `OP_BULK_READ` | `0x4221` | Bulk property read (222-byte preallocated) |

**Read variants by trailer:**
- `0x0271` → trailer `00 FF` (request the value)
- `0x0272` → no trailer (descriptor only)
- `0x0273` → trailer `00 00` (no value, write-no-value)

**Property writes — pick the right opcode:**
- `0x0240` for BLN-sourced virtuals where device is `"NONE"` (panel-global)
- `0x4222` for SYST-tagged properties (setpoints, schedules, modes)
- Wrong choice → `0x0E15`

**Connection mode marker:** first 2 bytes after routing header
- `0x46 0x40` → IdentifyBlock (handshake or mid-session refresh)
- anything else → operational opcode (including inside Mode-C `0x2E`/`0x2F` framing)

**Bare-ping vs full-op disambiguation** (relevant for `09xx` opcodes inside `0x2E` frames):
- Body length <3 B → bare-opcode session-keepalive ping (`0x0951`/`0x0954`/`0x0955`/`0x0956`/`0x0959`), PXC→DCC, no response
- Body length ≥10 B → full schedule operation (DCC→PXC, Mode C)

---

*Last updated against `PROTOCOL.md` covering captures through the two-node validation capture, schedule-edit capture, PPCL-edit capture, and property-write workflow capture.*
