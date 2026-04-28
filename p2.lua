-- p2.lua — Wireshark dissector for Siemens P2 (Apogee Ethernet) protocol
--
-- Drop into Wireshark's plugin folder and restart Wireshark. Decodes
-- TCP/5033 (DCC->PXC) and TCP/5034 (PXC->DCC) traffic into a navigable
-- protocol tree. Click a packet, see the routing header, opcode, and
-- (for reads/COVs) device/point/value broken out.
--
-- Plugin folder location:
--   Help → About Wireshark → Folders → "Personal Lua Plugins"
--   Typical paths:
--     Windows: %APPDATA%\Wireshark\plugins\
--     Linux:   ~/.local/lib/wireshark/plugins/
--     macOS:   ~/.local/lib/wireshark/plugins/
--
-- Reload without restarting: Analyze → Reload Lua Plugins (Ctrl+Shift+L)
--
-- Coverage: derived from p2_scanner.py and PROTOCOL.md. Anything tagged
-- "unknown_opcode" in the dissector output is a candidate for further
-- protocol analysis. Add new opcodes to OPCODES below as they're identified.

local p2 = Proto("p2", "Siemens P2 (Apogee Ethernet)")

------------------------------------------------------------------------
-- Constants
------------------------------------------------------------------------

local MSG_TYPES = {
    [0x2E] = "CONNECT",
    [0x2F] = "ANNOUNCE",
    [0x33] = "DATA (legacy dialect)",
    [0x34] = "HEARTBEAT (modern dialect)",
}

local DIR_BYTES = {
    [0x00] = "Request",
    [0x01] = "Success Response",
    [0x05] = "Error Response",
}

-- Big-endian u16 opcode that follows the routing header in DATA/HEARTBEAT
-- frames. Names mirror p2_scanner.P2Message.OP_* constants.
local OPCODES = {
    [0x0100] = "GetRevString (legacy sysinfo)",
    [0x010C] = "SysInfoCompact (modern sysinfo)",
    [0x0220] = "ReadProperty (modern dialect)",
    [0x0240] = "WriteWithQuality (NONE-device virtual writes)",
    [0x0241] = "Unknown (0x0241)",
    [0x0271] = "ReadProperty (legacy dialect)",
    [0x0273] = "WriteNoValue / AlarmAck-trigger",
    [0x0274] = "ValuePush (DCC->PXC virtual write or PXC->DCC COV)",
    [0x0291] = "Read variant (rare)",
    [0x0294] = "Read variant (rare)",
    [0x02A8] = "Write variant (rare)",
    [0x0508] = "AlarmReport (PXC->DCC, full alarm record)",
    [0x0509] = "AlarmAck (DCC->PXC, acknowledge alarm)",
    [0x0981] = "EnumerateAllPoints (cursor-based)",
    [0x0982] = "EnumerateTrended (variant)",
    [0x0985] = "EnumeratePrograms (PPCL source dump)",
    [0x0986] = "EnumerateFLN (FLN device list)",
    [0x0988] = "EnumerateMulti (multi-string filter)",
    [0x099F] = "GetPortConfig",
    [0x4106] = "ClearTracebits",
    [0x4200] = "PropertyQuery (SYST-tagged property descriptor)",
    [0x4220] = "BulkProperty variant",
    [0x4221] = "BulkPropertyRead (273-byte responses)",
    [0x4222] = "BulkPropertyWrite (SYST-tagged setpoint writes)",
    [0x4634] = "RoutingTable (BLN topology announce)",
    [0x4640] = "Identify (mid-session identity refresh, 10s cadence)",
    [0x5003] = "Unknown (0x5003)",
}

local STATUS_ERRORS = {
    [0x0003] = "not_found (object does not exist)",
    [0x00AC] = "not_supported (opcode not on this firmware)",
    [0x0E15] = "wrong-write-opcode (use 0x4222 instead of 0x0240 for SYST props)",
    -- Populate as more error codes are observed on the wire.
}

-- Data-type codes seen in 7-byte response metadata (offset +6 within metadata)
local DATA_TYPE_CODES = {
    [0x00] = "digital/binary/enum",
    [0x01] = "rare (semantics not pinned)",
    [0x02] = "small int (likely int16)",
    [0x03] = "analog (dominant)",
    [0x06] = "analog32 / extended numeric",
}

------------------------------------------------------------------------
-- ProtoFields
------------------------------------------------------------------------

local f = {}

-- Frame header (12 bytes, big-endian)
f.total_len = ProtoField.uint32("p2.total_len", "Total Length", base.DEC)
f.msg_type  = ProtoField.uint32("p2.msg_type",  "Message Type", base.HEX, MSG_TYPES)
f.sequence  = ProtoField.uint32("p2.seq",       "Sequence",     base.DEC)

-- Routing header
f.dir_byte = ProtoField.uint8("p2.dir", "Direction", base.HEX, DIR_BYTES)
f.bln1     = ProtoField.string("p2.bln1",  "BLN Network (1)")
f.dst_node = ProtoField.string("p2.dst",   "Destination Node")
f.bln2     = ProtoField.string("p2.bln2",  "BLN Network (2)")
f.src_node = ProtoField.string("p2.src",   "Source Node")

-- Body
f.opcode      = ProtoField.uint16("p2.opcode",   "Opcode",  base.HEX, OPCODES)
f.error_code  = ProtoField.uint16("p2.err_code", "Error Code", base.HEX, STATUS_ERRORS)

-- Read / COV decoded fields
f.device_name = ProtoField.string("p2.device", "Device Name")
f.point_name  = ProtoField.string("p2.point",  "Point Name")
f.float_value = ProtoField.float ("p2.value",  "Value (float, BE)")
f.units       = ProtoField.string("p2.units",  "Units")

-- Identity-block strings (handshake)
f.scanner_name = ProtoField.string("p2.scanner", "Scanner Name")
f.site_name    = ProtoField.string("p2.site",    "Site Name")
f.network_name = ProtoField.string("p2.network", "Network Name")

-- Alarm-record fields (0x0508 / 0x0509)
f.alarm_class       = ProtoField.string("p2.alarm.class",       "Alarm Class")
f.alarm_point       = ProtoField.string("p2.alarm.point",       "Alarmed Point")
f.alarm_description = ProtoField.string("p2.alarm.description", "Alarm Description")
f.alarm_marker      = ProtoField.string("p2.alarm.marker",      "Internal Marker (4-char)")
f.alarm_time_raised = ProtoField.string("p2.alarm.t_raised",    "Time Alarm First Raised")
f.alarm_time_now    = ProtoField.string("p2.alarm.t_now",       "Time of Report (now)")
f.alarm_time_last   = ProtoField.string("p2.alarm.t_last",      "Time of Last Transition")
f.alarm_value       = ProtoField.float ("p2.alarm.value",       "Alarm-time Value")

-- Generic LP-strings collected from elsewhere in the body
f.lp_strings = ProtoField.string("p2.strings", "Decoded Strings")

p2.fields = {
    f.total_len, f.msg_type, f.sequence,
    f.dir_byte, f.bln1, f.dst_node, f.bln2, f.src_node,
    f.opcode, f.error_code,
    f.device_name, f.point_name, f.float_value, f.units,
    f.scanner_name, f.site_name, f.network_name, f.lp_strings,
    f.alarm_class, f.alarm_point, f.alarm_description, f.alarm_marker,
    f.alarm_time_raised, f.alarm_time_now, f.alarm_time_last, f.alarm_value,
}

------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------

-- Read a null-terminated ASCII string starting at `offset` in tvb. Returns
-- (string_value, length_including_null). Returns nil on missing terminator.
local function read_cstring(tvb, offset)
    local len = tvb:len()
    if offset >= len then return nil end
    for i = offset, len - 1 do
        if tvb(i, 1):uint() == 0 then
            local s = (i > offset) and tvb(offset, i - offset):string() or ""
            return s, (i - offset + 1)
        end
    end
    return nil
end

-- Pull all `01 00 LL [ASCII]` style LP-strings from a TvbRange. Mirrors
-- _extract_lp_strings in the scanner. Returns a list of {offset, length, value}.
local function extract_lp_strings(tvb)
    local out = {}
    local len = tvb:len()
    local i = 0
    while i < len - 3 do
        if tvb(i, 1):uint() == 0x01 and tvb(i+1, 1):uint() == 0x00 then
            local slen = tvb(i+2, 1):uint()
            if slen > 0 and slen < 100 and (i + 3 + slen) <= len then
                local s = tvb(i+3, slen):string()
                -- Reject obvious non-ASCII (most common false positive)
                if s:match("^[%w%p%s]*$") then
                    table.insert(out, {offset = i, length = 3 + slen, value = s})
                    i = i + 3 + slen
                else
                    i = i + 1
                end
            else
                i = i + 1
            end
        else
            i = i + 1
        end
    end
    return out
end

-- Extract u16-BE-prefixed strings (the format used in FLN-enum and sysinfo
-- responses). Returns list of {offset, length, value}.
local function extract_u16lp_strings(tvb)
    local out = {}
    local len = tvb:len()
    local i = 0
    while i < len - 2 do
        local slen = tvb(i, 2):uint()
        if slen > 0 and slen < 1024 and (i + 2 + slen) <= len then
            local ok = true
            for j = i + 2, i + 1 + slen do
                local b = tvb(j, 1):uint()
                if b < 0x20 or b > 0x7E then ok = false; break end
            end
            if ok then
                table.insert(out, {
                    offset = i, length = 2 + slen, value = tvb(i+2, slen):string()
                })
                i = i + 2 + slen
            else
                i = i + 1
            end
        else
            i = i + 1
        end
    end
    return out
end

-- Decode an 8-byte BACnet date+time block at offset `off` of `tvb`.
-- Format: year-1900, month, day, day-of-week, hour, minute, second, hundredths.
-- Returns a human-readable string, or nil if bytes don't look plausible.
local function decode_bacnet_datetime(tvb, off)
    if off + 8 > tvb:len() then return nil end
    local y   = tvb(off,     1):uint()
    local mo  = tvb(off + 1, 1):uint()
    local d   = tvb(off + 2, 1):uint()
    local dow = tvb(off + 3, 1):uint()
    local h   = tvb(off + 4, 1):uint()
    local mi  = tvb(off + 5, 1):uint()
    local s   = tvb(off + 6, 1):uint()
    local hu  = tvb(off + 7, 1):uint()
    if y < 0x70 then return nil end                   -- year 1900+ < 2012: implausible
    if mo < 1 or mo > 12 then return nil end
    if d  < 1 or d  > 31 then return nil end
    if dow > 7 then return nil end
    if h > 23 or mi > 59 or s > 59 or hu > 99 then return nil end
    local dows = {"Mon","Tue","Wed","Thu","Fri","Sat","Sun"}
    local dows_label = (dow >= 1 and dow <= 7) and dows[dow] or "?"
    return string.format("%04d-%02d-%02d %s %02d:%02d:%02d.%02d",
        y + 1900, mo, d, dows_label, h, mi, s, hu)
end

------------------------------------------------------------------------
-- Alarm-record dissector for 0x0508 (PXC->DCC) and 0x0509 (DCC->PXC).
-- Layout determined empirically from real Desigo CC traffic:
--   [opcode 2B] [LP "CC" 5B] [byte 0x23] [property-state sentinel 4B] ...
--   ...[zero pad] [LP point-name] [LP point-name (repeated)] [LP description]
--   ...zeros, ImUK marker, zeros, BACnet datetimes (raise / current / last) ...
-- 0x0509 uses the same prefix but is much smaller — no description, no
-- timestamps, no values: it's the operator-initiated ack.
------------------------------------------------------------------------

local function dissect_alarm_record(body, tree, pinfo)
    -- The first ~10 bytes are header: LP-string "CC" + 0x23 + sentinel
    if body:len() < 10 then return end

    -- LP-string at offset 0: 01 00 LL "CC"
    local class_strings = extract_lp_strings(body)
    if #class_strings >= 1 then
        tree:add(f.alarm_class,
            body(class_strings[1].offset + 3, class_strings[1].length - 3),
            class_strings[1].value)
    end

    -- Subsequent LP-strings: typically [point_name][point_name][description]
    -- The 1st and 2nd are duplicates; the 3rd (if present) is the description.
    local data_strings = {}
    for i = 2, #class_strings do
        table.insert(data_strings, class_strings[i])
    end
    if #data_strings >= 1 then
        tree:add(f.alarm_point,
            body(data_strings[1].offset + 3, data_strings[1].length - 3),
            data_strings[1].value)
        pinfo.cols.info:append(string.format(" point=%s", data_strings[1].value))
    end
    if #data_strings >= 3 then
        tree:add(f.alarm_description,
            body(data_strings[3].offset + 3, data_strings[3].length - 3),
            data_strings[3].value)
    end

    -- Hunt for the "ImUK"-style 4-char marker (4 ASCII bytes between two
    -- 4-byte all-zero runs). Only present in 0x0508.
    for i = 0, body:len() - 4 do
        local b1, b2, b3, b4 = body(i,1):uint(), body(i+1,1):uint(),
                               body(i+2,1):uint(), body(i+3,1):uint()
        if b1 >= 0x41 and b1 <= 0x7A
           and b2 >= 0x41 and b2 <= 0x7A
           and b3 >= 0x41 and b3 <= 0x7A
           and b4 >= 0x41 and b4 <= 0x7A
           and i >= 4
           and body(i-4, 4):uint() == 0
        then
            tree:add(f.alarm_marker, body(i, 4), body(i, 4):string())
            break
        end
    end

    -- Hunt for BACnet datetime blocks (8 bytes each)
    local dt_count = 0
    local dt_labels = { f.alarm_time_raised, f.alarm_time_now, f.alarm_time_last }
    local i = 0
    while i + 8 <= body:len() and dt_count < #dt_labels do
        local ts = decode_bacnet_datetime(body, i)
        if ts then
            tree:add(dt_labels[dt_count + 1], body(i, 8), ts)
            dt_count = dt_count + 1
            i = i + 8
        else
            i = i + 1
        end
    end
end


-- Mirrors p2_scanner._parse_read_response value-block scan. Looks for
-- the [01 00 00][4-byte sentinel][00 00 dtype][float] pattern preceded
-- by an ASCII byte (point-name tail).
------------------------------------------------------------------------

local function find_value_block(tvb)
    local len = tvb:len()
    -- 14 bytes needed from position i: marker(3) + sentinel(4) + status(3) + float(4)
    for i = 1, len - 14 do
        if  tvb(i, 1):uint()   == 0x01
        and tvb(i+1, 1):uint() == 0x00
        and tvb(i+2, 1):uint() == 0x00
        and tvb(i+7, 1):uint() == 0x00
        and tvb(i+8, 1):uint() == 0x00
        then
            local prev = tvb(i-1, 1):uint()
            local is_ascii_end = (prev >= 0x41 and prev <= 0x5A)
                              or (prev >= 0x61 and prev <= 0x7A)
                              or (prev >= 0x30 and prev <= 0x39)
                              or prev == 0x20 or prev == 0x2E
                              or prev == 0x5F or prev == 0x2D
            if is_ascii_end then
                local first = tvb(i+10, 1):uint()
                if first <= 0x48
                   or first == 0xBF or first == 0xC0 or first == 0xC1
                   or first == 0xC2 or first == 0xC3 or first == 0xC4
                   or first == 0xC5
                then
                    return i
                end
            end
        end
    end
    return nil
end

------------------------------------------------------------------------
-- Routing-header dissection
------------------------------------------------------------------------

-- Parses [dir][BLN\0][dst\0][BLN\0][src\0]. Adds subtree, returns body offset.
local function dissect_routing(tvb, tree)
    local rtree = tree:add(p2, tvb, "Routing Header")
    rtree:add(f.dir_byte, tvb(0, 1))
    local off = 1
    local fields = { f.bln1, f.dst_node, f.bln2, f.src_node }
    for _, field in ipairs(fields) do
        local s, n = read_cstring(tvb, off)
        if not s then return nil end
        rtree:add(field, tvb(off, n - 1), s)
        off = off + n
    end
    rtree:set_len(off)
    return off
end

------------------------------------------------------------------------
-- Body dissection by opcode
------------------------------------------------------------------------

local function dissect_read_response(tvb, tree, pinfo, dir_byte)
    -- Error response — direction is 0x05 and body has u16 BE error code
    if dir_byte == 0x05 then
        if tvb:len() >= 2 then
            tree:add(f.error_code, tvb(0, 2))
            local code = tvb(0, 2):uint()
            local name = STATUS_ERRORS[code] or string.format("unknown_0x%04X", code)
            pinfo.cols.info:append(string.format(" [ERROR %s]", name))
        end
        return
    end

    -- Success response — extract LP strings (device, point) up to value block,
    -- then decode value block and units.
    local vb = find_value_block(tvb)
    local pre = vb and tvb(0, vb) or tvb

    -- Filter LP strings to drop routing names (best effort — we don't have
    -- those values here, so we just show what we found).
    local strings = extract_lp_strings(pre)
    if #strings >= 2 then
        local s_dev = strings[#strings - 1]
        local s_pt  = strings[#strings]
        tree:add(f.device_name, tvb(s_dev.offset + 3, s_dev.length - 3), s_dev.value)
        tree:add(f.point_name,  tvb(s_pt.offset  + 3, s_pt.length  - 3), s_pt.value)
        pinfo.cols.info:append(string.format(" %s/%s", s_dev.value, s_pt.value))
    end

    if vb then
        local vtree = tree:add(p2, tvb(vb, 14), "Value Block")
        vtree:add(tvb(vb, 3),     "Marker (01 00 00)")
        vtree:add(tvb(vb + 3, 4), "Property State Sentinel: 0x" .. tvb(vb + 3, 4):bytes():tohex())
        vtree:add(tvb(vb + 6, 3), "Status (online + dtype)")
        vtree:add(f.float_value, tvb(vb + 10, 4))
        local val = tvb(vb + 10, 4):float()
        pinfo.cols.info:append(string.format(" = %g", val))

        -- Units after value block, if present
        local after = tvb(vb + 14, tvb:len() - vb - 14)
        local units_strings = extract_lp_strings(after)
        if #units_strings >= 1 then
            local u = units_strings[1]
            tree:add(f.units, after(u.offset + 3, u.length - 3), u.value)
            pinfo.cols.info:append(" " .. u.value)
        end
    end
end

local function dissect_cov_or_write(tvb, tree, pinfo, opcode)
    -- 0x0274 (COV / value push) and 0x0240 (write w/ quality) both put
    -- two LP strings (device, point) in the body followed by a u32-BE float.
    -- We'll just pull strings + a candidate float.
    local strings = extract_lp_strings(tvb)
    if #strings >= 2 then
        tree:add(f.device_name, tvb(strings[1].offset + 3, strings[1].length - 3), strings[1].value)
        tree:add(f.point_name,  tvb(strings[2].offset + 3, strings[2].length - 3), strings[2].value)
        pinfo.cols.info:append(string.format(" %s/%s", strings[1].value, strings[2].value))
        -- Float lives just after the second LP string
        local foffset = strings[2].offset + strings[2].length
        if foffset + 4 <= tvb:len() then
            tree:add(f.float_value, tvb(foffset, 4))
            pinfo.cols.info:append(string.format(" = %g", tvb(foffset, 4):float()))
        end
    end
end

local function dissect_identify(tvb, tree, pinfo)
    -- Identity TLVs: [01 00 LL scanner][01 00 LL site][01 00 LL network][...]
    local strings = extract_lp_strings(tvb)
    local labels = { f.scanner_name, f.site_name, f.network_name }
    for i, s in ipairs(strings) do
        if i <= #labels then
            tree:add(labels[i], tvb(s.offset + 3, s.length - 3), s.value)
        end
    end
    if #strings >= 1 then
        pinfo.cols.info:append(" scanner=" .. strings[1].value)
    end
end

local function dissect_sysinfo_response(tvb, tree, pinfo)
    -- Strings here are u16-BE-prefixed (different from LP-strings)
    local strings = extract_u16lp_strings(tvb)
    if #strings >= 1 then
        tree:add(p2, tvb, "Firmware: " .. strings[1].value)
        pinfo.cols.info:append(" fw=" .. strings[1].value)
    end
    if #strings >= 2 then
        tree:add(p2, tvb, "Model: " .. strings[2].value)
        pinfo.cols.info:append(" model=" .. strings[2].value)
    end
end

local function dissect_routing_table(tvb, tree, pinfo)
    -- 0x4634 — list of peer panels with cost/metric. Format isn't fully
    -- documented in PROTOCOL.md, so just dump the strings we find.
    local strings = extract_lp_strings(tvb)
    if #strings > 0 then
        local stree = tree:add(p2, tvb, "Routing Table Entries")
        for _, s in ipairs(strings) do
            stree:add(p2, tvb(s.offset, s.length), s.value)
        end
        pinfo.cols.info:append(string.format(" (%d peer strings)", #strings))
    end
end

------------------------------------------------------------------------
-- Single-frame dissector
------------------------------------------------------------------------

local function dissect_one_frame(tvb, pinfo, root)
    local total_len = tvb(0, 4):uint()
    local msg_type  = tvb(4, 4):uint()
    local sequence  = tvb(8, 4):uint()

    local tree = root:add(p2, tvb(0, total_len), "Siemens P2")

    local htree = tree:add(p2, tvb(0, 12), "Frame Header")
    htree:add(f.total_len, tvb(0, 4))
    htree:add(f.msg_type,  tvb(4, 4))
    htree:add(f.sequence,  tvb(8, 4))

    pinfo.cols.protocol = "P2"

    local mt_label = MSG_TYPES[msg_type] or string.format("0x%X", msg_type)
    pinfo.cols.info:set(string.format("seq=%d %s", sequence, mt_label))

    if total_len <= 12 then
        return total_len
    end

    local payload = tvb(12, total_len - 12)
    if payload:len() < 1 then
        return total_len
    end

    local dir_byte = payload(0, 1):uint()

    -- Routing header (always present in DATA/HEARTBEAT/CONNECT/ANNOUNCE)
    local body_off = dissect_routing(payload, tree)
    if not body_off then return total_len end

    if msg_type ~= 0x33 and msg_type ~= 0x34 then
        -- CONNECT/ANNOUNCE — no opcode after routing
        pinfo.cols.info:append(" [" .. (DIR_BYTES[dir_byte] or "?") .. "]")
        return total_len
    end

    if payload:len() <= body_off + 2 then
        return total_len
    end

    local body = payload(body_off, payload:len() - body_off)

    -- Opcodes are only meaningful for REQUESTS (dir=0x00). Responses don't
    -- echo the opcode — they're matched to requests by sequence number.
    -- For response frames we just dispatch on direction and parse the body
    -- by shape (find_value_block, error code, TLV strings).
    if dir_byte == 0x00 then
        local opcode = body(0, 2):uint()
        local op_name = OPCODES[opcode] or string.format("unknown_0x%04X", opcode)
        local btree = tree:add(p2, body, "Request — " .. op_name)
        btree:add(f.opcode, body(0, 2))
        pinfo.cols.info:append(string.format(" %s [Request]", op_name))

        local rest = body(2, body:len() - 2)
        if opcode == 0x0271 or opcode == 0x0220 then
            local strings = extract_lp_strings(rest)
            if #strings >= 2 then
                btree:add(f.device_name,
                    rest(strings[1].offset + 3, strings[1].length - 3), strings[1].value)
                btree:add(f.point_name,
                    rest(strings[2].offset + 3, strings[2].length - 3), strings[2].value)
                pinfo.cols.info:append(string.format(" %s/%s",
                    strings[1].value, strings[2].value))
            elseif #strings == 1 then
                -- BLN virtual: device-name LP-string is empty, only point name appears
                btree:add(f.point_name,
                    rest(strings[1].offset + 3, strings[1].length - 3), strings[1].value)
                pinfo.cols.info:append(string.format(" (BLN virtual) %s", strings[1].value))
            end
        elseif opcode == 0x4640 then
            dissect_identify(rest, btree, pinfo)
        elseif opcode == 0x0508 or opcode == 0x0509 then
            dissect_alarm_record(rest, btree, pinfo)
        elseif opcode == 0x0273 then
            -- WriteNoValue — just a point name with no value. Same wire shape
            -- as 0x0271 for BLN virtuals: LP-string "BLR3.LOW.DIFF" etc.
            local strings = extract_lp_strings(rest)
            if #strings >= 1 then
                btree:add(f.point_name,
                    rest(strings[1].offset + 3, strings[1].length - 3), strings[1].value)
                pinfo.cols.info:append(string.format(" %s", strings[1].value))
            end
        else
            -- Generic: dump strings for analysis
            local strings = extract_lp_strings(rest)
            if #strings > 0 then
                local raw = ""
                for i, s in ipairs(strings) do
                    if i > 1 then raw = raw .. ", " end
                    raw = raw .. s.value
                end
                btree:add(f.lp_strings, rest, raw)
            end
        end
    elseif dir_byte == 0x05 then
        -- Error response: u16 BE error code immediately after routing
        local btree = tree:add(p2, body, "Error Response")
        if body:len() >= 2 then
            btree:add(f.error_code, body(0, 2))
            local code = body(0, 2):uint()
            local name = STATUS_ERRORS[code] or string.format("unknown_0x%04X", code)
            pinfo.cols.info:append(" [ERROR " .. name .. "]")
        end
    else
        -- Success response (dir=0x01). No opcode echo. The response shape
        -- depends on which request it answers, but we can't see that here
        -- without a request/response correlation table. Heuristics:
        --   - find_value_block hit  → ReadProperty response
        --   - 0x0274/0x0240 marker  → COV/value push (unsolicited or async)
        --   - else                  → identify echo / sysinfo / generic
        local btree = tree:add(p2, body, "Success Response")
        local vb = find_value_block(payload)
        if vb then
            -- Read response — pull device/point/value
            local pre = payload(0, vb)
            local strings = extract_lp_strings(pre)
            if #strings >= 2 then
                local sd = strings[#strings - 1]
                local sp = strings[#strings]
                btree:add(f.device_name, payload(sd.offset + 3, sd.length - 3), sd.value)
                btree:add(f.point_name,  payload(sp.offset + 3, sp.length - 3), sp.value)
                pinfo.cols.info:append(string.format(" %s/%s", sd.value, sp.value))
            end
            local vtree = btree:add(p2, payload(vb, 14), "Value Block")
            vtree:add(payload(vb,     3), "Marker (01 00 00)")
            vtree:add(payload(vb + 3, 4), "Property State Sentinel: 0x"
                                          .. payload(vb + 3, 4):bytes():tohex())
            vtree:add(payload(vb + 6, 3), "Status (online + dtype)")
            vtree:add(f.float_value, payload(vb + 10, 4))
            local val = payload(vb + 10, 4):float()
            pinfo.cols.info:append(string.format(" = %g", val))
            -- Units after value block
            if payload:len() > vb + 14 then
                local after = payload(vb + 14, payload:len() - vb - 14)
                local units_strings = extract_lp_strings(after)
                if #units_strings >= 1 then
                    local u = units_strings[1]
                    btree:add(f.units, after(u.offset + 3, u.length - 3), u.value)
                    pinfo.cols.info:append(" " .. u.value)
                end
            end
        else
            -- No value block → likely identify echo or sysinfo response.
            -- Try LP-strings first, fall back to u16-LL prefixed.
            local strings = extract_lp_strings(body)
            if #strings == 0 then
                strings = extract_u16lp_strings(body)
            end
            if #strings > 0 then
                local raw = ""
                for i, s in ipairs(strings) do
                    if i > 1 then raw = raw .. ", " end
                    raw = raw .. s.value
                end
                btree:add(f.lp_strings, body, raw)
                pinfo.cols.info:append(" [" .. raw .. "]")
            end
        end
    end

    return total_len
end

------------------------------------------------------------------------
-- Top-level dissector with TCP reassembly
------------------------------------------------------------------------

function p2.dissector(tvb, pinfo, tree)
    local offset = 0
    local len = tvb:len()
    if len < 12 then
        -- Not enough for a header — request reassembly
        pinfo.desegment_offset = 0
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    while offset + 12 <= len do
        local total_len = tvb(offset, 4):uint()
        if total_len < 12 or total_len > 65536 then
            -- Garbage — give up on this segment
            return
        end
        if offset + total_len > len then
            -- Need more bytes for this frame
            pinfo.desegment_offset = offset
            pinfo.desegment_len = (offset + total_len) - len
            return
        end
        dissect_one_frame(tvb(offset, total_len), pinfo, tree)
        offset = offset + total_len
    end
end

-- Bind to the known P2 ports
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(5033, p2)
tcp_table:add(5034, p2)
