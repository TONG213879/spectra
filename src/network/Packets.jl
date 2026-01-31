# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Network Packets
# ═══════════════════════════════════════════════════════════════════════════════
# Packet construction and parsing utilities
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              PACKET STRUCTURES
# ───────────────────────────────────────────────────────────────────────────────

"""
    IPv4Header

IPv4 packet header structure.
"""
struct IPv4Header
    version::UInt8
    ihl::UInt8
    dscp::UInt8
    ecn::UInt8
    total_length::UInt16
    identification::UInt16
    flags::UInt8
    fragment_offset::UInt16
    ttl::UInt8
    protocol::UInt8
    checksum::UInt16
    src_addr::NTuple{4, UInt8}
    dst_addr::NTuple{4, UInt8}
end

"""
    TCPHeader

TCP packet header structure.
"""
struct TCPHeader
    src_port::UInt16
    dst_port::UInt16
    seq_num::UInt32
    ack_num::UInt32
    data_offset::UInt8
    flags::UInt8
    window::UInt16
    checksum::UInt16
    urgent_pointer::UInt16
end

"""
    UDPHeader

UDP packet header structure.
"""
struct UDPHeader
    src_port::UInt16
    dst_port::UInt16
    length::UInt16
    checksum::UInt16
end

"""
    ICMPHeader

ICMP packet header structure.
"""
struct ICMPHeader
    type::UInt8
    code::UInt8
    checksum::UInt16
    identifier::UInt16
    sequence::UInt16
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PROTOCOL CONSTANTS
# ───────────────────────────────────────────────────────────────────────────────

const IP_PROTOCOLS = Dict{UInt8, String}(
    1 => "ICMP",
    6 => "TCP",
    17 => "UDP",
    47 => "GRE",
    50 => "ESP",
    51 => "AH",
    58 => "ICMPv6",
    89 => "OSPF",
    132 => "SCTP",
)

const TCP_FLAGS = Dict{UInt8, String}(
    0x01 => "FIN",
    0x02 => "SYN",
    0x04 => "RST",
    0x08 => "PSH",
    0x10 => "ACK",
    0x20 => "URG",
    0x40 => "ECE",
    0x80 => "CWR",
)

# ───────────────────────────────────────────────────────────────────────────────
#                              PACKET PARSING
# ───────────────────────────────────────────────────────────────────────────────

"""
    parse_ipv4_header(data::Vector{UInt8})

Parse IPv4 header from raw bytes.
"""
function parse_ipv4_header(data::Vector{UInt8})::Union{IPv4Header, Nothing}
    length(data) < 20 && return nothing
    
    version = (data[1] >> 4) & 0x0f
    version != 4 && return nothing
    
    ihl = data[1] & 0x0f
    dscp = (data[2] >> 2) & 0x3f
    ecn = data[2] & 0x03
    total_length = UInt16(data[3]) << 8 | UInt16(data[4])
    identification = UInt16(data[5]) << 8 | UInt16(data[6])
    flags = (data[7] >> 5) & 0x07
    fragment_offset = (UInt16(data[7] & 0x1f) << 8) | UInt16(data[8])
    ttl = data[9]
    protocol = data[10]
    checksum = UInt16(data[11]) << 8 | UInt16(data[12])
    src_addr = (data[13], data[14], data[15], data[16])
    dst_addr = (data[17], data[18], data[19], data[20])
    
    return IPv4Header(version, ihl, dscp, ecn, total_length, identification,
                      flags, fragment_offset, ttl, protocol, checksum,
                      src_addr, dst_addr)
end

"""
    parse_tcp_header(data::Vector{UInt8})

Parse TCP header from raw bytes.
"""
function parse_tcp_header(data::Vector{UInt8})::Union{TCPHeader, Nothing}
    length(data) < 20 && return nothing
    
    src_port = UInt16(data[1]) << 8 | UInt16(data[2])
    dst_port = UInt16(data[3]) << 8 | UInt16(data[4])
    seq_num = UInt32(data[5]) << 24 | UInt32(data[6]) << 16 | 
              UInt32(data[7]) << 8 | UInt32(data[8])
    ack_num = UInt32(data[9]) << 24 | UInt32(data[10]) << 16 | 
              UInt32(data[11]) << 8 | UInt32(data[12])
    data_offset = (data[13] >> 4) & 0x0f
    flags = data[14]
    window = UInt16(data[15]) << 8 | UInt16(data[16])
    checksum = UInt16(data[17]) << 8 | UInt16(data[18])
    urgent_pointer = UInt16(data[19]) << 8 | UInt16(data[20])
    
    return TCPHeader(src_port, dst_port, seq_num, ack_num, data_offset,
                     flags, window, checksum, urgent_pointer)
end

"""
    parse_udp_header(data::Vector{UInt8})

Parse UDP header from raw bytes.
"""
function parse_udp_header(data::Vector{UInt8})::Union{UDPHeader, Nothing}
    length(data) < 8 && return nothing
    
    src_port = UInt16(data[1]) << 8 | UInt16(data[2])
    dst_port = UInt16(data[3]) << 8 | UInt16(data[4])
    len = UInt16(data[5]) << 8 | UInt16(data[6])
    checksum = UInt16(data[7]) << 8 | UInt16(data[8])
    
    return UDPHeader(src_port, dst_port, len, checksum)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PACKET CONSTRUCTION
# ───────────────────────────────────────────────────────────────────────────────

"""
    build_tcp_packet(src_ip::String, dst_ip::String, 
                     src_port::Int, dst_port::Int,
                     flags::UInt8 = 0x02)

Build a TCP packet (header only).
"""
function build_tcp_packet(src_ip::String, dst_ip::String,
                          src_port::Int, dst_port::Int,
                          flags::UInt8 = 0x02)::Vector{UInt8}
    
    packet = UInt8[]
    
    # TCP Header
    append!(packet, [(src_port >> 8) % UInt8, src_port % UInt8])  # Source port
    append!(packet, [(dst_port >> 8) % UInt8, dst_port % UInt8])  # Dest port
    append!(packet, zeros(UInt8, 4))  # Sequence number
    append!(packet, zeros(UInt8, 4))  # Ack number
    push!(packet, 0x50)  # Data offset (5 * 4 = 20 bytes)
    push!(packet, flags)  # Flags
    append!(packet, [0xff, 0xff])  # Window
    append!(packet, zeros(UInt8, 2))  # Checksum (placeholder)
    append!(packet, zeros(UInt8, 2))  # Urgent pointer
    
    return packet
end

"""
    build_icmp_echo(identifier::UInt16, sequence::UInt16)

Build ICMP echo request packet.
"""
function build_icmp_echo(identifier::UInt16, sequence::UInt16)::Vector{UInt8}
    packet = UInt8[]
    
    push!(packet, 0x08)  # Type (Echo Request)
    push!(packet, 0x00)  # Code
    append!(packet, zeros(UInt8, 2))  # Checksum (placeholder)
    append!(packet, [(identifier >> 8) % UInt8, identifier % UInt8])
    append!(packet, [(sequence >> 8) % UInt8, sequence % UInt8])
    
    # Add some data
    append!(packet, Vector{UInt8}("Spectra"))
    
    # Calculate checksum
    checksum = calculate_checksum(packet)
    packet[3] = (checksum >> 8) % UInt8
    packet[4] = checksum % UInt8
    
    return packet
end

"""
    calculate_checksum(data::Vector{UInt8})

Calculate IP/ICMP checksum.
"""
function calculate_checksum(data::Vector{UInt8})::UInt16
    sum = UInt32(0)
    
    # Sum 16-bit words
    for i in 1:2:length(data)
        word = UInt16(data[i]) << 8
        if i < length(data)
            word |= UInt16(data[i + 1])
        end
        sum += word
    end
    
    # Add carry
    while sum >> 16 > 0
        sum = (sum & 0xffff) + (sum >> 16)
    end
    
    return ~UInt16(sum)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              UTILITY FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────

"""
    ip_to_bytes(ip::String)

Convert IP string to bytes.
"""
function ip_to_bytes(ip::String)::Vector{UInt8}
    parts = split(ip, '.')
    return [parse(UInt8, p) for p in parts]
end

"""
    bytes_to_ip(bytes::NTuple{4, UInt8})

Convert bytes to IP string.
"""
function bytes_to_ip(bytes::NTuple{4, UInt8})::String
    return join([string(b) for b in bytes], '.')
end

"""
    decode_tcp_flags(flags::UInt8)

Decode TCP flags to string.
"""
function decode_tcp_flags(flags::UInt8)::Vector{String}
    result = String[]
    for (bit, name) in TCP_FLAGS
        if flags & bit != 0
            push!(result, name)
        end
    end
    return result
end

"""
    format_packet(ip::IPv4Header, tcp::Union{TCPHeader, Nothing} = nothing)

Format packet for display.
"""
function format_packet(ip::IPv4Header, tcp::Union{TCPHeader, Nothing} = nothing)
    src = bytes_to_ip(ip.src_addr)
    dst = bytes_to_ip(ip.dst_addr)
    proto = get(IP_PROTOCOLS, ip.protocol, "Unknown")
    
    lines = String[]
    push!(lines, themed("IP: $src → $dst", :cyan))
    push!(lines, themed("    Protocol: $proto, TTL: $(ip.ttl), Length: $(ip.total_length)", :dim))
    
    if !isnothing(tcp)
        flags = join(decode_tcp_flags(tcp.flags), ",")
        push!(lines, themed("TCP: $(tcp.src_port) → $(tcp.dst_port)", :yellow))
        push!(lines, themed("     Flags: [$flags], Seq: $(tcp.seq_num)", :dim))
    end
    
    return join(lines, "\n")
end
