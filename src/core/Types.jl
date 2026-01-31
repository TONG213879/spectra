# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Core Types
# ═══════════════════════════════════════════════════════════════════════════════
# Advanced type definitions for the security framework
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              THREAT OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    Threat

Represents a detected security threat with full context.

# Fields
- `id::UUID`: Unique identifier
- `level::ThreatLevel`: Severity level
- `category::Symbol`: Threat category
- `source::String`: Origin of the threat
- `description::String`: Human-readable description
- `indicators::Vector{String}`: Indicators of compromise
- `timestamp::DateTime`: Detection timestamp
- `metadata::Dict{String, Any}`: Additional data
"""
struct Threat
    id::UUID
    level::ThreatLevel
    category::Symbol
    source::String
    description::String
    indicators::Vector{String}
    timestamp::DateTime
    metadata::Dict{String, Any}
    
    function Threat(level::ThreatLevel, category::Symbol, source::String, desc::String;
                    indicators::Vector{String} = String[],
                    metadata::Dict{String, Any} = Dict{String, Any}())
        new(uuid4(), level, category, source, desc, indicators, now(), metadata)
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              NETWORK OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    Service

Detected network service information.
"""
struct Service
    name::String
    version::Union{String, Nothing}
    protocol::Symbol
    port::Int
    banner::Union{String, Nothing}
    cpe::Union{String, Nothing}
    vulnerabilities::Vector{String}
end

"""
    Host

Network host with full discovery data.
"""
struct Host
    ip::String
    hostname::Union{String, Nothing}
    mac::Union{String, Nothing}
    os::Union{String, Nothing}
    services::Vector{Service}
    open_ports::Vector{Int}
    filtered_ports::Vector{Int}
    closed_ports::Vector{Int}
    last_seen::DateTime
    ttl::Int
    hop_count::Int
end

"""
    NetworkRange

CIDR network range for scanning.
"""
struct NetworkRange
    network::String
    prefix::Int
    hosts::Int
    
    function NetworkRange(cidr::String)
        parts = split(cidr, '/')
        network = parts[1]
        prefix = length(parts) > 1 ? parse(Int, parts[2]) : 32
        hosts = 2^(32 - prefix) - 2
        new(network, prefix, hosts)
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              CRYPTO OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    HashIdentification

Result of hash identification analysis.
"""
struct HashIdentification
    input::String
    possible_types::Vector{Symbol}
    confidence::Float64
    length::Int
    charset::Symbol
end

"""
    EntropyResult

Entropy analysis result.
"""
struct EntropyResult
    data::Union{String, Vector{UInt8}}
    entropy::Float64
    max_entropy::Float64
    ratio::Float64
    classification::Symbol
    is_random::Bool
    is_encrypted::Bool
    is_compressed::Bool
end

"""
    CipherAnalysis

Cipher detection and analysis result.
"""
struct CipherAnalysis
    ciphertext::Vector{UInt8}
    detected_cipher::Symbol
    confidence::Float64
    block_size::Union{Int, Nothing}
    key_length::Union{Int, Nothing}
    mode::Union{Symbol, Nothing}
    recommendations::Vector{String}
end

# ───────────────────────────────────────────────────────────────────────────────
#                              ANALYSIS OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    Pattern

Pattern definition for detection.
"""
struct Pattern
    name::String
    regex::Regex
    category::Symbol
    severity::ThreatLevel
    description::String
    tags::Vector{Symbol}
end

"""
    Match

Pattern match result.
"""
struct Match
    pattern::Pattern
    text::String
    position::UnitRange{Int}
    context::String
    confidence::Float64
end

"""
    AnalysisReport

Complete analysis report.
"""
struct AnalysisReport
    id::UUID
    timestamp::DateTime
    duration::Float64
    target::Union{Target, String}
    threats::Vector{Threat}
    findings::Vector{Match}
    score::Float64
    grade::Symbol
    summary::String
    recommendations::Vector{String}
end

# ───────────────────────────────────────────────────────────────────────────────
#                              SCANNING OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    ScanConfig

Configuration for scanning operations.
"""
struct ScanConfig
    scan_type::Symbol
    timing::Symbol
    parallel::Bool
    threads::Int
    timeout::Float64
    retries::Int
    randomize::Bool
    stealth::Bool
    aggressive::Bool
end

"""
    PortRange

Efficient port range specification.
"""
struct PortRange
    start::Int
    stop::Int
    excluded::Set{Int}
    
    function PortRange(start::Int, stop::Int; exclude::Vector{Int} = Int[])
        @assert 1 <= start <= 65535 "Invalid port range start"
        @assert 1 <= stop <= 65535 "Invalid port range end"
        @assert start <= stop "Start must be <= stop"
        new(start, stop, Set(exclude))
    end
end

# Common port ranges
const PORTS_TOP_100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443
]

const PORTS_TOP_1000 = collect(1:1000)

const PORTS_WEB = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

const PORTS_DB = [1433, 1521, 3306, 5432, 27017, 6379, 9200, 5984]

const PORTS_ADMIN = [22, 23, 3389, 5900, 5985, 5986]

# ───────────────────────────────────────────────────────────────────────────────
#                              RECON OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    DNSRecord

DNS record data.
"""
struct DNSRecord
    name::String
    type::Symbol
    value::String
    ttl::Int
    priority::Union{Int, Nothing}
end

"""
    Subdomain

Discovered subdomain information.
"""
struct Subdomain
    name::String
    ip::Union{String, Nothing}
    status::Int
    title::Union{String, Nothing}
    technologies::Vector{String}
    is_alive::Bool
end

"""
    WhoisData

WHOIS lookup result.
"""
struct WhoisData
    domain::String
    registrar::Union{String, Nothing}
    created_date::Union{DateTime, Nothing}
    updated_date::Union{DateTime, Nothing}
    expiry_date::Union{DateTime, Nothing}
    nameservers::Vector{String}
    registrant::Dict{String, String}
    raw::String
end

# ───────────────────────────────────────────────────────────────────────────────
#                              FORENSICS OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    FileMetadata

File forensic metadata.
"""
struct FileMetadata
    path::String
    size::Int
    md5::String
    sha256::String
    ssdeep::Union{String, Nothing}
    mime_type::String
    magic_bytes::Vector{UInt8}
    created::Union{DateTime, Nothing}
    modified::DateTime
    accessed::DateTime
    permissions::Int
    owner::Union{String, Nothing}
    attributes::Dict{String, Any}
end

"""
    MemoryRegion

Memory region for forensic analysis.
"""
struct MemoryRegion
    address::UInt64
    size::Int
    protection::Symbol
    data::Vector{UInt8}
    strings::Vector{String}
    entropy::Float64
end

"""
    Artifact

Forensic artifact.
"""
struct Artifact
    id::UUID
    type::Symbol
    source::String
    data::Any
    timestamp::DateTime
    confidence::Float64
    tags::Vector{Symbol}
    notes::String
end

# ───────────────────────────────────────────────────────────────────────────────
#                              FUZZING OBJECTS
# ───────────────────────────────────────────────────────────────────────────────

"""
    FuzzTarget

Target for fuzzing operations.
"""
struct FuzzTarget
    name::String
    protocol::Symbol
    host::String
    port::Int
    endpoint::String
    method::Symbol
    headers::Dict{String, String}
    parameters::Dict{String, String}
end

"""
    FuzzPayload

Fuzzing payload definition.
"""
struct FuzzPayload
    name::String
    category::Symbol
    data::Vector{String}
    encodings::Vector{Symbol}
    mutators::Vector{Function}
end

"""
    FuzzResult

Fuzzing test result.
"""
struct FuzzResult
    target::FuzzTarget
    payload::String
    response_code::Int
    response_time::Float64
    response_size::Int
    is_anomaly::Bool
    is_crash::Bool
    is_interesting::Bool
    notes::String
end

# ───────────────────────────────────────────────────────────────────────────────
#                              HELPER FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────

"""
    iterate(pr::PortRange)

Make PortRange iterable, excluding specified ports.
"""
Base.iterate(pr::PortRange) = iterate(pr, pr.start)
function Base.iterate(pr::PortRange, state::Int)
    state > pr.stop && return nothing
    while state in pr.excluded && state <= pr.stop
        state += 1
    end
    state > pr.stop && return nothing
    return (state, state + 1)
end
Base.length(pr::PortRange) = pr.stop - pr.start + 1 - length(pr.excluded)

"""
    show(io, t::Threat)

Pretty print Threat objects.
"""
function Base.show(io::IO, t::Threat)
    level_colors = Dict(
        CRITICAL => COLORS[:red],
        HIGH => COLORS[:yellow],
        MEDIUM => COLORS[:cyan],
        LOW => COLORS[:blue],
        INFO => COLORS[:dim]
    )
    color = get(level_colors, t.level, COLORS[:reset])
    print(io, "$color[$(t.level)]$(COLORS[:reset]) $(t.category): $(t.description)")
end

"""
    show(io, sr::ScanResult)

Pretty print ScanResult objects.
"""
function Base.show(io::IO, sr::ScanResult)
    state_color = sr.state == OPEN ? COLORS[:green] : 
                  sr.state == FILTERED ? COLORS[:yellow] : COLORS[:red]
    service = something(sr.service, "unknown")
    print(io, "$(sr.port)/$(sr.target.protocol) $state_color$(sr.state)$(COLORS[:reset]) $service")
end

"""
    show(io, er::EntropyResult)

Pretty print EntropyResult objects.
"""
function Base.show(io::IO, er::EntropyResult)
    ratio_pct = round(er.ratio * 100, digits=1)
    print(io, "Entropy: $(round(er.entropy, digits=4)) bits/byte ($(ratio_pct)% of max) - $(er.classification)")
end
