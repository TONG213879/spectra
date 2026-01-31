# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Protocol Handlers
# ═══════════════════════════════════════════════════════════════════════════════
# Protocol-specific communication utilities
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              HTTP UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    HTTPRequest

HTTP request structure.
"""
struct HTTPRequest
    method::String
    path::String
    version::String
    headers::Dict{String, String}
    body::String
end

"""
    HTTPResponse

HTTP response structure.
"""
struct HTTPResponse
    status_code::Int
    status_text::String
    version::String
    headers::Dict{String, String}
    body::String
end

"""
    build_http_request(method::String, path::String, host::String;
                       headers::Dict{String, String} = Dict(),
                       body::String = "")

Build HTTP request string.
"""
function build_http_request(method::String, path::String, host::String;
                            headers::Dict{String, String} = Dict(),
                            body::String = "")::String
    
    default_headers = Dict(
        "Host" => host,
        "User-Agent" => "Spectra/1.0",
        "Accept" => "*/*",
        "Connection" => "close"
    )
    
    merged_headers = merge(default_headers, headers)
    
    if !isempty(body)
        merged_headers["Content-Length"] = string(length(body))
    end
    
    lines = ["$method $path HTTP/1.1"]
    for (k, v) in merged_headers
        push!(lines, "$k: $v")
    end
    push!(lines, "")
    push!(lines, body)
    
    return join(lines, "\r\n")
end

"""
    parse_http_response(data::String)

Parse HTTP response.
"""
function parse_http_response(data::String)::Union{HTTPResponse, Nothing}
    isempty(data) && return nothing
    
    parts = split(data, "\r\n\r\n", limit=2)
    header_section = parts[1]
    body = length(parts) > 1 ? parts[2] : ""
    
    lines = split(header_section, "\r\n")
    isempty(lines) && return nothing
    
    # Parse status line
    status_match = match(r"HTTP/([\d.]+)\s+(\d+)\s*(.*)?", lines[1])
    isnothing(status_match) && return nothing
    
    version = status_match.captures[1]
    status_code = parse(Int, status_match.captures[2])
    status_text = something(status_match.captures[3], "")
    
    # Parse headers
    headers = Dict{String, String}()
    for line in lines[2:end]
        if occursin(":", line)
            kv = split(line, ":", limit=2)
            if length(kv) == 2
                headers[strip(kv[1])] = strip(kv[2])
            end
        end
    end
    
    return HTTPResponse(status_code, status_text, version, headers, body)
end

"""
    http_get(url::String; headers::Dict{String, String} = Dict())

Perform HTTP GET request.
"""
function http_get(url::String; headers::Dict{String, String} = Dict())::Union{HTTPResponse, Nothing}
    parsed = parse_url(url)
    
    request = build_http_request("GET", parsed[:path], parsed[:host]; headers=headers)
    response = tcp_send_recv(parsed[:host], parsed[:port], request, timeout=10.0)
    
    isnothing(response) && return nothing
    return parse_http_response(String(response))
end

"""
    http_post(url::String, body::String;
              content_type::String = "application/x-www-form-urlencoded",
              headers::Dict{String, String} = Dict())

Perform HTTP POST request.
"""
function http_post(url::String, body::String;
                   content_type::String = "application/x-www-form-urlencoded",
                   headers::Dict{String, String} = Dict())::Union{HTTPResponse, Nothing}
    
    parsed = parse_url(url)
    
    merged_headers = merge(headers, Dict("Content-Type" => content_type))
    request = build_http_request("POST", parsed[:path], parsed[:host]; 
                                 headers=merged_headers, body=body)
    response = tcp_send_recv(parsed[:host], parsed[:port], request, timeout=10.0)
    
    isnothing(response) && return nothing
    return parse_http_response(String(response))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              DNS PROTOCOL
# ───────────────────────────────────────────────────────────────────────────────

const DNS_RECORD_TYPES = Dict{UInt16, Symbol}(
    1 => :A,
    2 => :NS,
    5 => :CNAME,
    6 => :SOA,
    12 => :PTR,
    15 => :MX,
    16 => :TXT,
    28 => :AAAA,
    33 => :SRV,
    255 => :ANY,
)

"""
    build_dns_query(domain::String, record_type::Symbol = :A)

Build DNS query packet.
"""
function build_dns_query(domain::String, record_type::Symbol = :A)::Vector{UInt8}
    packet = UInt8[]
    
    # Transaction ID (random)
    tid = rand(UInt16)
    append!(packet, [(tid >> 8) % UInt8, tid % UInt8])
    
    # Flags (standard query)
    append!(packet, [0x01, 0x00])
    
    # Questions (1)
    append!(packet, [0x00, 0x01])
    
    # Answer RRs, Authority RRs, Additional RRs (0)
    append!(packet, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    
    # Domain name
    for part in split(domain, '.')
        push!(packet, length(part) % UInt8)
        append!(packet, Vector{UInt8}(part))
    end
    push!(packet, 0x00)  # Null terminator
    
    # Query type
    type_num = findfirst(x -> x == record_type, DNS_RECORD_TYPES)
    type_num = isnothing(type_num) ? UInt16(1) : type_num
    append!(packet, [(type_num >> 8) % UInt8, type_num % UInt8])
    
    # Query class (IN)
    append!(packet, [0x00, 0x01])
    
    return packet
end

# ───────────────────────────────────────────────────────────────────────────────
#                              SMTP UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    smtp_banner(host::String, port::Int = 25)

Get SMTP server banner.
"""
function smtp_banner(host::String, port::Int = 25)::Union{String, Nothing}
    sock, _ = tcp_connect(host, port, timeout=5.0)
    isnothing(sock) && return nothing
    
    try
        sleep(0.5)
        banner = ""
        if bytesavailable(sock) > 0
            banner = String(read(sock, min(bytesavailable(sock), 1024)))
        end
        close(sock)
        return strip(banner)
    catch
        try close(sock) catch end
        return nothing
    end
end

"""
    smtp_vrfy(host::String, email::String, port::Int = 25)

Attempt SMTP VRFY command (user enumeration).
"""
function smtp_vrfy(host::String, email::String, port::Int = 25)::Dict{Symbol, Any}
    result = Dict{Symbol, Any}(
        :email => email,
        :valid => false,
        :response => ""
    )
    
    sock, _ = tcp_connect(host, port, timeout=5.0)
    isnothing(sock) && return result
    
    try
        # Read banner
        sleep(0.3)
        bytesavailable(sock) > 0 && read(sock, bytesavailable(sock))
        
        # Send HELO
        write(sock, "HELO spectra\r\n")
        sleep(0.3)
        bytesavailable(sock) > 0 && read(sock, bytesavailable(sock))
        
        # Send VRFY
        write(sock, "VRFY $email\r\n")
        sleep(0.5)
        
        if bytesavailable(sock) > 0
            response = String(read(sock, min(bytesavailable(sock), 1024)))
            result[:response] = strip(response)
            
            # 250, 251, 252 indicate valid user
            if startswith(response, "250") || startswith(response, "251") || startswith(response, "252")
                result[:valid] = true
            end
        end
        
        # Send QUIT
        write(sock, "QUIT\r\n")
        close(sock)
        
    catch
        try close(sock) catch end
    end
    
    return result
end

# ───────────────────────────────────────────────────────────────────────────────
#                              FTP UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    ftp_anonymous_check(host::String, port::Int = 21)

Check if FTP allows anonymous login.
"""
function ftp_anonymous_check(host::String, port::Int = 21)::Dict{Symbol, Any}
    result = Dict{Symbol, Any}(
        :anonymous_allowed => false,
        :banner => "",
        :message => ""
    )
    
    sock, _ = tcp_connect(host, port, timeout=5.0)
    isnothing(sock) && return result
    
    try
        # Read banner
        sleep(0.5)
        if bytesavailable(sock) > 0
            result[:banner] = strip(String(read(sock, min(bytesavailable(sock), 1024))))
        end
        
        # Try anonymous login
        write(sock, "USER anonymous\r\n")
        sleep(0.3)
        bytesavailable(sock) > 0 && read(sock, bytesavailable(sock))
        
        write(sock, "PASS anonymous@spectra.local\r\n")
        sleep(0.5)
        
        if bytesavailable(sock) > 0
            response = String(read(sock, min(bytesavailable(sock), 1024)))
            result[:message] = strip(response)
            
            if startswith(response, "230")  # Login successful
                result[:anonymous_allowed] = true
            end
        end
        
        write(sock, "QUIT\r\n")
        close(sock)
        
    catch
        try close(sock) catch end
    end
    
    return result
end

# ───────────────────────────────────────────────────────────────────────────────
#                              REDIS UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    redis_info(host::String, port::Int = 6379)

Get Redis INFO (if unauthenticated access allowed).
"""
function redis_info(host::String, port::Int = 6379)::Dict{Symbol, Any}
    result = Dict{Symbol, Any}(
        :unauthenticated => false,
        :info => Dict{String, String}(),
        :version => nothing
    )
    
    response = tcp_send_recv(host, port, "INFO\r\n", timeout=5.0)
    isnothing(response) && return result
    
    text = String(response)
    
    if !occursin("-NOAUTH", text) && !occursin("-ERR", text)
        result[:unauthenticated] = true
        
        # Parse INFO output
        for line in split(text, '\n')
            line = strip(line)
            if occursin(':', line) && !startswith(line, '#')
                parts = split(line, ':', limit=2)
                if length(parts) == 2
                    result[:info][strip(parts[1])] = strip(parts[2])
                end
            end
        end
        
        result[:version] = get(result[:info], "redis_version", nothing)
    end
    
    return result
end

# ───────────────────────────────────────────────────────────────────────────────
#                              MEMCACHED UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    memcached_stats(host::String, port::Int = 11211)

Get Memcached stats (if accessible).
"""
function memcached_stats(host::String, port::Int = 11211)::Dict{Symbol, Any}
    result = Dict{Symbol, Any}(
        :accessible => false,
        :stats => Dict{String, String}(),
        :version => nothing
    )
    
    response = tcp_send_recv(host, port, "stats\r\n", timeout=5.0)
    isnothing(response) && return result
    
    text = String(response)
    
    if occursin("STAT", text)
        result[:accessible] = true
        
        for line in split(text, '\n')
            if startswith(strip(line), "STAT")
                parts = split(strip(line))
                if length(parts) >= 3
                    result[:stats][parts[2]] = parts[3]
                end
            end
        end
        
        result[:version] = get(result[:stats], "version", nothing)
    end
    
    return result
end
