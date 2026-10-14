-- Copyright [2024-2026] MapsMessaging B.V.
-- Licensed under Apache-2.0 with Commons Clause; see ../LICENSE.
-- MQTT-SN 2.0 CSD01, 14 August 2026. Pinned source: ../SPECIFICATION.md.
-- No heuristics: v1.2 and v2 share framing but use different type values.

local proto = Proto("mqttsn2", "MQTT-SN 2.0 (CSD01)")
local band = bit.band -- Wireshark's BitOp supports Lua 5.2 through 5.4.
local types = {
    [0x01] = "CONNECT", [0x02] = "CONNACK", [0x03] = "PUBLISH",
    [0x04] = "PUBACK", [0x05] = "PUBREC", [0x06] = "PUBREL",
    [0x07] = "PUBCOMP", [0x08] = "SUBSCRIBE", [0x09] = "SUBACK",
    [0x0a] = "UNSUBSCRIBE", [0x0b] = "UNSUBACK", [0x0c] = "PINGREQ",
    [0x0d] = "PINGRESP", [0x0e] = "DISCONNECT", [0x0f] = "AUTH",
    [0x10] = "REGISTER", [0x11] = "REGACK", [0x12] = "PUBWOS",
    [0x13] = "SLEEPREQ", [0x14] = "SLEEPRESP", [0x15] = "WAKEUP",
    [0x16] = "ADVERTISE", [0x17] = "SEARCHGW", [0x18] = "GWINFO",
    [0xfc] = "Forwarder Encapsulation", [0xfe] = "Connection Encapsulation",
    [0xff] = "Protection Encapsulation"
}
local topic_types = {[0] = "Session Topic Alias", [1] = "Predefined Topic Alias", [2] = "Reserved", [3] = "Topic Name/Filter"}
local f = {}
local fields = {}
local function field(key, constructor, label, ...)
    f[key] = constructor("mqttsn2." .. key, label, ...)
    fields[#fields + 1] = f[key]
end
field("length", ProtoField.uint16, "Packet Length", base.DEC)
field("msg_type", ProtoField.uint8, "Packet Type", base.HEX, types)
field("flags", ProtoField.uint8, "Flags", base.HEX)
field("packet_id", ProtoField.uint16, "Packet Identifier", base.DEC)
field("version", ProtoField.uint8, "Protocol Version", base.DEC)
field("reason_code", ProtoField.uint8, "Reason Code", base.HEX)
field("topic_type", ProtoField.uint8, "Topic Type", base.DEC, topic_types, 0x03)
field("qos", ProtoField.uint8, "QoS", base.DEC, nil, 0x60)
field("dup", ProtoField.bool, "Duplicate", 8, nil, 0x80)
field("retain", ProtoField.bool, "Retain", 8, nil, 0x10)
field("topic_alias", ProtoField.uint16, "Topic Alias", base.DEC)
field("topic_length", ProtoField.uint16, "Topic Name Length", base.DEC)
field("topic_name", ProtoField.string, "Topic Name")
field("topic_filter", ProtoField.string, "Topic Filter")
field("payload", ProtoField.bytes, "Payload")
field("client_id", ProtoField.string, "Client Identifier")
field("client_id_length", ProtoField.uint16, "Client Identifier Length", base.DEC)
field("assigned_client_id", ProtoField.string, "Assigned Client Identifier")
field("auth_method_length", ProtoField.uint8, "Authentication Method Length", base.DEC)
field("auth_method", ProtoField.string, "Authentication Method")
field("auth_data_length", ProtoField.uint16, "Authentication Data Length", base.DEC)
field("auth_data", ProtoField.bytes, "Authentication Data")
field("keep_alive", ProtoField.uint16, "Keep Alive (s)", base.DEC)
field("maximum_packet_size", ProtoField.uint16, "Maximum Packet Size", base.DEC)
field("maximum_awake_messages", ProtoField.uint8, "Maximum Number of Awake Messages", base.DEC)
field("session_expiry", ProtoField.uint32, "Session Expiry Interval (s)", base.DEC)
field("server_keep_alive", ProtoField.uint16, "Server Keep Alive (s)", base.DEC)
field("messages_remaining", ProtoField.uint8, "Application Messages Remaining", base.DEC)
field("sleep_duration", ProtoField.uint32, "Sleep Duration (s)", base.DEC)
field("reason_string", ProtoField.string, "Reason String")
field("gateway_id", ProtoField.uint8, "Gateway Identifier", base.DEC)
field("duration", ProtoField.uint16, "Advertisement Duration (s)", base.DEC)
field("network_info", ProtoField.bytes, "Additional Network Information")
field("gateway_address", ProtoField.bytes, "Gateway Address")
field("addressing_length", ProtoField.uint8, "Client Addressing Information Length", base.DEC)
field("addressing", ProtoField.bytes, "Client Addressing Information")
field("raw", ProtoField.bytes, "Undecoded Data")
field("no_local", ProtoField.bool, "No Local", 8, nil, 0x80)
field("retain_as_published", ProtoField.bool, "Retain As Published", 8, nil, 0x10)
field("retain_handling", ProtoField.uint8, "Retain Handling", base.DEC, nil, 0x0c)
field("retain_topic_aliases", ProtoField.bool, "Retain Topic Aliases", 8, nil, 0x01)
for _, flag in ipairs({
    {"connect.clean_start", "Clean Start", 1}, {"connect.will", "Will Present", 2},
    {"connect.auth", "Authentication Present", 4}, {"connect.session_expiry", "Session Expiry Present", 8},
    {"connect.maximum_awake_messages", "Maximum Awake Messages Present", 16},
    {"connect.network_address_changes", "Allow Network Address Changes", 32},
    {"connect.server_suggested_values", "Allow Server Suggested Values", 64},
    {"connack.session_present", "Session Present", 1}, {"connack.session_expiry", "Session Expiry Present", 2},
    {"connack.server_keep_alive", "Server Keep Alive Present", 4}, {"connack.auth", "Authentication Present", 8},
    {"disconnect.packet_id", "Packet Identifier Present", 1}, {"disconnect.session_expiry", "Session Expiry Present", 2},
    {"disconnect.reason_code", "Reason Code Present", 4}, {"topic_alias_present", "Topic Alias Present", 4},
    {"register.topic_alias_present", "Topic Alias Present", 1}, {"sleep_duration_present", "Sleep Duration Present", 1}
}) do
    field(flag[1], ProtoField.bool, flag[2], 8, nil, flag[3])
end
field("will.flags", ProtoField.uint8, "Will Flags", base.HEX)
field("will.topic_type", ProtoField.uint8, "Will Topic Type", base.DEC, topic_types, 0x03)
field("will.qos", ProtoField.uint8, "Will QoS", base.DEC, nil, 0x0c)
field("will.retain", ProtoField.bool, "Will Retain", 8, nil, 0x10)
field("will.topic_alias", ProtoField.uint16, "Will Topic Alias", base.DEC)
field("will.topic_length", ProtoField.uint16, "Will Topic Name Length", base.DEC)
field("will.topic_name", ProtoField.string, "Will Topic Name")
field("will.payload_length", ProtoField.uint16, "Will Payload Length", base.DEC)
field("will.payload", ProtoField.bytes, "Will Payload")
field("protection.counter_code", ProtoField.uint8, "Counter Length Code", base.DEC, nil, 0x03)
field("protection.crypto_code", ProtoField.uint8, "Cryptographic Material Length Code", base.DEC, nil, 0x0c)
field("protection.tag_code", ProtoField.uint8, "Authentication Tag Length Code", base.DEC, nil, 0xf0)
local schemes = {[0] = "HMAC-SHA256", [1] = "HMAC-SHA3-256", [2] = "CMAC-128", [3] = "CMAC-192", [4] = "CMAC-256",
    [0x40] = "AES-CCM-64-128", [0x41] = "AES-CCM-64-192", [0x42] = "AES-CCM-64-256",
    [0x43] = "AES-CCM-128-128", [0x44] = "AES-CCM-128-192", [0x45] = "AES-CCM-128-256",
    [0x46] = "AES-GCM-128-128", [0x47] = "AES-GCM-128-192", [0x48] = "AES-GCM-128-256", [0x49] = "ChaCha20/Poly1305"}
field("protection.scheme", ProtoField.uint8, "Protection Scheme", base.HEX, schemes)
field("protection.sender_id", ProtoField.bytes, "Sender Identifier")
field("protection.random", ProtoField.bytes, "Random")
field("protection.crypto", ProtoField.bytes, "Cryptographic Material")
field("protection.counter", ProtoField.uint32, "Monotonic Counter", base.DEC)
field("protection.payload", ProtoField.bytes, "Protected MQTT-SN Packet")
field("protection.tag", ProtoField.bytes, "Authentication Tag")
field("protection.verified", ProtoField.bool, "Authentication Verified")
proto.fields = fields
local malformed = ProtoExpert.new("mqttsn2.malformed", "Malformed MQTT-SN 2.0 packet", expert.group.MALFORMED, expert.severity.ERROR)
local unverified = ProtoExpert.new("mqttsn2.unverified", "Protection authentication not verified", expert.group.SECURITY, expert.severity.NOTE)
local opaque = ProtoExpert.new("mqttsn2.opaque", "Provider-defined protection tag size unknown", expert.group.UNDECODED, expert.severity.NOTE)
proto.experts = {malformed, unverified, opaque}
proto.prefs.udp_ports = Pref.range("UDP ports", "1884", "Ports dedicated to MQTT-SN 2.0; use Decode As on mixed captures", 65535)

local function invalid(message)
    error({malformed = message}, 0)
end
local function check(condition, message)
    if not condition then invalid(message) end
end

-- CSD01 1.8.4: strict UTF-8; reject NUL, overlong, surrogate and out-of-range sequences.
local function valid_utf8(text)
    local i = 1
    while i <= #text do
        local a = text:byte(i)
        if a == 0 then return false end
        if a < 0x80 then
            i = i + 1
        else
            local count, minimum, value
            if a >= 0xc2 and a <= 0xdf then count, minimum, value = 1, 0x80, a - 0xc0
            elseif a >= 0xe0 and a <= 0xef then count, minimum, value = 2, 0x800, a - 0xe0
            elseif a >= 0xf0 and a <= 0xf4 then count, minimum, value = 3, 0x10000, a - 0xf0
            else return false end
            if i + count > #text then return false end
            for j = 1, count do
                local b = text:byte(i + j)
                if b < 0x80 or b > 0xbf then return false end
                value = value * 64 + b - 0x80
            end
            if value < minimum or value > 0x10ffff or (value >= 0xd800 and value <= 0xdfff) then return false end
            i = i + count + 1
        end
    end
    return true
end

local Cursor = {}
Cursor.__index = Cursor
function Cursor:take(key, size, text)
    check(size >= 0 and self.pos + size <= self.limit, key .. " is truncated")
    local range = self.buf(self.pos, size)
    self.pos = self.pos + size
    local value
    if text then
        value = range:bytes():raw()
        check(valid_utf8(value), key .. " contains invalid UTF-8 (section 1.8.4)")
        self.tree:add(f[key], range, value)
    else
        self.tree:add(f[key], range)
        if size > 0 and size <= 4 then value = range:uint() end
    end
    return value, range
end
function Cursor:rest(key, text)
    return self:take(key, self.limit - self.pos, text)
end
function Cursor:identifier()
    local value = self:take("packet_id", 2)
    check(value ~= 0, "Packet Identifier must be non-zero (MQTT-SN-2.2-1/-3)")
end
function Cursor:flags(reserved, keys)
    local flags, range = self:take("flags", 1)
    for _, key in ipairs(keys or {}) do self.tree:add(f[key], range) end
    check(band(flags, reserved) == 0, "Reserved flags are non-zero")
    return flags
end
function Cursor:finish()
    check(self.pos == self.limit, "Unexpected trailing packet bytes")
end
function Cursor:auth(length_prefixed)
    local size = self:take("auth_method_length", 1)
    self:take("auth_method", size, true)
    if length_prefixed then
        size = self:take("auth_data_length", 2)
        self:take("auth_data", size)
    else
        self:rest("auth_data")
    end
end
function Cursor:topic(topic_type, prefix, filter, remainder)
    prefix = prefix or ""
    check(topic_type ~= 2, "Reserved Topic Type (section 2.4)")
    if topic_type == 3 then
        local name
        if remainder then name = self:rest(filter and "topic_filter" or prefix .. "topic_name", true)
        else
            local length = self:take(prefix .. "topic_length", 2)
            name = self:take(prefix .. "topic_name", length, true)
        end
        check(#name > 0, "Topic Name/Filter must not be empty (section 4.7)")
        if not filter then
            check(not name:find("[+#]"), "Topic Name must not contain wildcards (section 4.7)")
        else
            -- Wildcards must occupy complete levels; # must be the final level.
            for level in (name .. "/"):gmatch("(.-)/") do
                check(not level:find("[+#]") or level == "+" or level == "#", "Invalid Topic Filter wildcard")
            end
            local hash = name:find("#", 1, true)
            check(not hash or hash == #name, "Multi-level wildcard must be last")
        end
    else
        check(self:take(prefix .. "topic_alias", 2) ~= 0, "Topic Alias must be non-zero (section 4.7)")
    end
end

local decode
local function inner(c, depth, allowed, forbid_forwarder)
    check(depth < 8, "Encapsulation depth exceeds dissector limit (8)")
    local remaining = c.limit - c.pos
    check(remaining >= 2, "Encapsulated MQTT-SN packet is missing or truncated")
    local first = c.buf(c.pos, 1):uint()
    local header = first == 1 and 4 or 2
    check(remaining >= header, "Encapsulated header is truncated")
    local size = first == 1 and c.buf(c.pos + 1, 2):uint() or first
    check(size == remaining, "Encapsulation must contain exactly one packet")
    local kind = c.buf(c.pos + header - 1, 1):uint()
    check(not allowed or allowed[kind], "Packet type not allowed in Connection Encapsulation (MQTT-SN-3.18-3)")
    check(not forbid_forwarder or kind ~= 0xfc, "Forwarder Encapsulation must not be protected (MQTT-SN-3.17.8-1)")
    decode(c.buf(c.pos, remaining):tvb(), c.tree, depth + 1)
    c.pos = c.limit
end

local function protection(c, depth)
    -- CSD01 3.17: unknown provider tags remain opaque; never guess boundaries.
    local flags = c:flags(0, {"protection.counter_code", "protection.crypto_code", "protection.tag_code"})
    local counter_code, crypto_code, tag_code = band(flags, 3), band(flags, 12) / 4, math.floor(flags / 16)
    check(counter_code ~= 3 and tag_code ~= 2 and tag_code ~= 3, "Reserved protection length code")
    local scheme = c:take("protection.scheme", 1)
    check(not ((scheme >= 5 and scheme <= 0x3b) or (scheme >= 0x4a and scheme <= 0xef)), "Reserved Protection Scheme")
    local auth_only = scheme < 0x40
    check(auth_only or tag_code == 1, "AEAD requires nominal tag code 1 (MQTT-SN-3.17.2.3-1)")
    c:take("protection.sender_id", 8)
    c:take("protection.random", 4)
    local crypto_size = ({[0] = 0, 2, 4, 12})[crypto_code]
    if crypto_size > 0 then c:take("protection.crypto", crypto_size) end
    local counter_size = counter_code * 2
    if counter_size > 0 then c:take("protection.counter", counter_size) end
    c.tree:add(f["protection.verified"], false):set_generated()
    c.tree:add_proto_expert_info(unverified)
    local nominal
    if scheme <= 1 then nominal = 32
    elseif scheme <= 4 then nominal = 16
    elseif scheme >= 0x40 and scheme <= 0x42 then nominal = 8
    elseif scheme >= 0x43 and scheme <= 0x49 then nominal = 16 end
    local tag_size
    if tag_code >= 4 then
        tag_size = tag_code * 2
        check(not nominal or tag_size <= nominal, "Tag exceeds nominal size (MQTT-SN-3.17.2.3-8)")
    elseif tag_code == 1 then tag_size = nominal end
    if not tag_size then
        check(c.pos < c.limit, "Protected packet/tag is missing")
        c.tree:add_proto_expert_info(opaque)
        c:rest("protection.payload")
        return
    end
    local payload_end = c.limit - tag_size
    check(payload_end > c.pos, "Protected payload or tag is truncated")
    local payload_start = c.pos
    c:take("protection.payload", payload_end - payload_start)
    c:take("protection.tag", tag_size)
    if auth_only then
        -- Plaintext is inspectable, but no cryptographic validity is asserted.
        local nested = setmetatable({buf = c.buf, tree = c.tree, pos = payload_start, limit = payload_end}, Cursor)
        inner(nested, depth, nil, true)
    end
end

local handlers = {}
handlers[1] = function(c)
    -- 3.1: Will Flags precede Packet Identifier; fields follow prose order.
    local flags = c:flags(0x80, {"connect.clean_start", "connect.will", "connect.auth", "connect.session_expiry",
        "connect.maximum_awake_messages", "connect.network_address_changes", "connect.server_suggested_values"})
    local will
    if band(flags, 2) ~= 0 then
        local range
        will, range = c:take("will.flags", 1)
        for _, key in ipairs({"will.topic_type", "will.qos", "will.retain"}) do c.tree:add(f[key], range) end
        check(band(will, 0xe0) == 0 and band(will, 0x0c) ~= 0x0c, "Invalid Will Flags")
    end
    c:identifier()
    check(c:take("version", 1) == 2, "Expected Protocol Version 2 (MQTT-SN-3.1.5-1)")
    check(c:take("keep_alive", 2) > 0, "Keep Alive must be positive (MQTT-SN-3.1.6-4)")
    local maximum = c:take("maximum_packet_size", 2)
    check(maximum == 0 or maximum >= 10, "Maximum Packet Size must be 0 or >=10 (MQTT-SN-3.1.7-1)")
    if band(flags, 16) ~= 0 then c:take("maximum_awake_messages", 1) end
    if band(flags, 8) ~= 0 then c:take("session_expiry", 4) end
    if will then
        c:topic(band(will, 3), "will.")
        local size = c:take("will.payload_length", 2)
        c:take("will.payload", size)
    end
    if band(flags, 4) ~= 0 then c:auth(true) end
    c:rest("client_id", true)
end
handlers[2] = function(c)
    -- 3.2 CONNACK
    local flags = c:flags(0xf0, {"connack.session_present", "connack.session_expiry", "connack.server_keep_alive", "connack.auth"})
    c:identifier()
    local reason = c:take("reason_code", 1)
    check(band(flags, 1) == 0 or reason == 0, "Session Present must be zero on failure (section 3.2.2.1)")
    if band(flags, 2) ~= 0 then c:take("session_expiry", 4) end
    if band(flags, 4) ~= 0 then check(c:take("server_keep_alive", 2) > 0, "Server Keep Alive must be positive") end
    if band(flags, 8) ~= 0 then c:auth(true) end
    c:rest("assigned_client_id", true)
end
local function publish(c, without_session)
    -- 3.6.1 PUBWOS / 3.6.2 PUBLISH; QoS 0 carries no Packet Identifier.
    local flags = c:flags(without_session and 0xec or 0x0c, without_session and {"topic_type", "retain"} or {"topic_type", "qos", "retain", "dup"})
    local qos = band(flags, 0x60) / 32
    check(qos ~= 3, "Reserved QoS")
    check(band(flags, 0x80) == 0 or qos == 2, "DUP is only valid for QoS 2 (section 3.6.2.2.1)")
    if qos > 0 then c:identifier() end
    local topic_type = band(flags, 3)
    check(not without_session or topic_type ~= 0, "PUBWOS cannot use Session Topic Alias")
    c:topic(topic_type)
    c:rest("payload")
end
handlers[3] = function(c) publish(c, false) end
handlers[18] = function(c) publish(c, true) end
local function optional_reason(c)
    if c.pos < c.limit then c:take("reason_code", 1) end
    c:finish()
end
for _, kind in ipairs({4, 5, 6, 7, 11}) do
    -- 3.6.3-6 and 3.10: identifier, optional reason; no flags or alias.
    handlers[kind] = function(c) c:identifier(); optional_reason(c) end
end
handlers[12] = function(c) c:identifier(); c:finish() end -- 3.11 PINGREQ
handlers[13] = function(c)
    -- 3.12 PINGRESP, optional Application Messages Remaining.
    c:identifier()
    if c.pos < c.limit then c:take("messages_remaining", 1) end
    c:finish()
end
local function subscription(c, unsubscribe)
    -- 3.7 / 3.9: name/filter occupies the remainder, without a length prefix.
    local flags = c:flags(unsubscribe and 0xfc or 0, unsubscribe and {"topic_type"} or {"topic_type", "qos", "no_local", "retain_as_published", "retain_handling"})
    if not unsubscribe then
        check(band(flags, 0x60) ~= 0x60 and band(flags, 0x0c) ~= 0x0c, "Reserved subscription QoS/Retain Handling")
    end
    c:identifier()
    c:topic(band(flags, 3), nil, true, true)
    c:finish()
end
handlers[8] = function(c) subscription(c, false) end
handlers[10] = function(c) subscription(c, true) end
local function alias_ack(c)
    -- 3.5 REGACK / 3.8 SUBACK share the same wire layout.
    local flags = c:flags(0xf8, {"topic_type", "topic_alias_present"})
    check(band(flags, 3) <= 1, "Acknowledgement Topic Type must be an alias")
    c:identifier()
    if band(flags, 4) ~= 0 then check(c:take("topic_alias", 2) ~= 0, "Topic Alias must be non-zero") end
    optional_reason(c)
end
handlers[9], handlers[17] = alias_ack, alias_ack
handlers[14] = function(c)
    -- 3.13.3-6 prose: Packet Id, Reason Code, Session Expiry, Reason String.
    -- The pinned draft's diagram lists expiry before reason; see README.
    local flags = c:flags(0xf8, {"disconnect.packet_id", "disconnect.session_expiry", "disconnect.reason_code"})
    if band(flags, 1) ~= 0 then c:identifier() end
    if band(flags, 4) ~= 0 then c:take("reason_code", 1) end
    if band(flags, 2) ~= 0 then c:take("session_expiry", 4) end
    c:rest("reason_string", true)
end
handlers[15] = function(c)
    -- 3.3 AUTH: data occupies the remainder (no Authentication Data Length).
    c:identifier(); c:take("reason_code", 1); c:auth(false)
end
handlers[16] = function(c)
    -- 3.4 REGISTER
    local flags = c:flags(0xfe, {"register.topic_alias_present"})
    c:identifier()
    if band(flags, 1) ~= 0 then check(c:take("topic_alias", 2) ~= 0, "Topic Alias must be non-zero") end
    local name = c:rest("topic_name", true)
    check(#name > 0 and not name:find("[+#]"), "Invalid REGISTER Topic Name")
end
handlers[19] = function(c)
    -- 3.15 SLEEPREQ
    c:flags(0xfe, {"retain_topic_aliases"}); c:identifier(); c:take("sleep_duration", 4); c:finish()
end
handlers[20] = function(c)
    -- 3.16 SLEEPRESP
    local flags = c:flags(0xfe, {"sleep_duration_present"})
    c:identifier()
    if band(flags, 1) ~= 0 then c:take("sleep_duration", 4) end
    optional_reason(c)
end
handlers[21] = function(c) c:finish() end -- 3.14 WAKEUP
handlers[22] = function(c) c:take("gateway_id", 1); c:take("duration", 2); c:finish() end -- 3.20.1
handlers[23] = function(c) c:rest("network_info") end -- 3.20.2 SEARCHGW, no radius in v2.
handlers[24] = function(c) c:take("gateway_id", 1); c:rest("gateway_address") end -- 3.20.3
handlers[252] = function(c, depth)
    -- 3.19 Forwarder Encapsulation
    local size = c:take("addressing_length", 1)
    c:take("addressing", size)
    inner(c, depth)
end
local connection_allowed = {[3] = true, [8] = true, [10] = true, [16] = true, [14] = true, [19] = true, [12] = true}
handlers[254] = function(c, depth)
    -- 3.18 Connection Encapsulation
    local size = c:take("client_id_length", 2)
    c:take("client_id", size, true)
    inner(c, depth, connection_allowed)
end
handlers[255] = protection

decode = function(buf, parent, depth)
    local tree = parent:add(proto, buf(), "MQTT-SN 2.0 (CSD01)")
    local c = setmetatable({buf = buf, tree = tree, pos = 0, limit = buf:len()}, Cursor)
    local name = "Malformed"
    local ok, err = pcall(function()
        check(buf:len() >= 1, "Length field is missing")
        local first = buf(0, 1):uint()
        local header = first == 1 and 4 or 2
        check(buf:len() >= header, "Packet header is truncated")
        local length = first == 1 and buf(1, 2):uint() or first
        tree:add(f.length, first == 1 and buf(1, 2) or buf(0, 1), length)
        local kind = buf(header - 1, 1):uint()
        name = types[kind] or string.format("Reserved type 0x%02x", kind)
        tree:add(f.msg_type, buf(header - 1, 1))
        tree:set_text("MQTT-SN 2.0 " .. name)
        -- 2.1.2: bounded single UDP packet; do not parse bytes outside its length.
        check(length >= header, "Packet length is smaller than its header")
        check(length <= buf:len(), "Packet is truncated")
        check(length == buf:len(), "Unexpected bytes after MQTT-SN packet")
        check(handlers[kind] ~= nil, "Reserved packet type (section 2.1.3)")
        c.pos, c.limit = header, length
        handlers[kind](c, depth)
        c:finish()
    end)
    if not ok then
        if type(err) ~= "table" or not err.malformed then error(err, 0) end
        tree:add_proto_expert_info(malformed, err.malformed)
        if c.pos < buf:len() then tree:add(f.raw, buf(c.pos)) end
    end
    return name
end

function proto.dissector(buf, pinfo, tree)
    pinfo.cols.protocol = "MQTT-SN2"
    pinfo.cols.info = decode(buf, tree, 0)
    return buf:len()
end
local udp = DissectorTable.get("udp.port")
udp:add_for_decode_as(proto)
local ports = proto.prefs.udp_ports
udp:add(ports, proto)
function proto.prefs_changed()
    udp:remove(ports, proto)
    ports = proto.prefs.udp_ports
    udp:add(ports, proto)
end
