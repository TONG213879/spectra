# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Socket Operations
# ═══════════════════════════════════════════════════════════════════════════════
# Advanced socket operations and connection handling
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              SOCKET UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    tcp_connect(host::String, port::Int; timeout::Float64 = 5.0)

Establish TCP connection with timeout.

Returns (socket, latency) or (nothing, 0.0) on failure.
"""
function tcp_connect(host::String, port::Int; timeout::Float64 = 5.0)::Tuple{Union{TCPSocket, Nothing}, Float64}
    start_time = time()
    
    try
        sock = Ref{Union{TCPSocket, Nothing}}(nothing)
        done = Atomic{Bool}(false)
        
        @async begin
            try
                sock[] = connect(host, port)
            catch
            end
            atomic_xchg!(done, true)
        end
        
        while !done[] && (time() - start_time) < timeout
            sleep(0.01)
        end
        
        latency = time() - start_time
        
        if done[] && !isnothing(sock[]) && isopen(sock[])
            return (sock[], latency)
        else
            return (nothing, 0.0)
        end
        
    catch
        return (nothing, 0.0)
    end
end

"""
    tcp_send_recv(host::String, port::Int, data::Union{String, Vector{UInt8}};
                  timeout::Float64 = 5.0)

Send data and receive response.
"""
function tcp_send_recv(host::String, port::Int, data::Union{String, Vector{UInt8}};
                       timeout::Float64 = 5.0)::Union{Vector{UInt8}, Nothing}
    
    sock, _ = tcp_connect(host, port, timeout=timeout)
    isnothing(sock) && return nothing
    
    try
        # Send data
        write(sock, isa(data, String) ? data : data)
        
        # Wait for response
        sleep(0.5)
        
        response = UInt8[]
        while bytesavailable(sock) > 0
            append!(response, read(sock, bytesavailable(sock)))
            sleep(0.1)
        end
        
        close(sock)
        return isempty(response) ? nothing : response
        
    catch e
        try close(sock) catch end
        return nothing
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              CONNECTION TESTING
# ───────────────────────────────────────────────────────────────────────────────

"""
    test_connectivity(host::String, port::Int; 
                      count::Int = 3,
                      timeout::Float64 = 2.0)

Test connectivity to host:port with latency measurements.
"""
function test_connectivity(host::String, port::Int;
                           count::Int = 3,
                           timeout::Float64 = 2.0)::Dict{Symbol, Any}
    
    results = Dict{Symbol, Any}(
        :host => host,
        :port => port,
        :success_count => 0,
        :fail_count => 0,
        :latencies => Float64[],
        :avg_latency => 0.0,
        :min_latency => Inf,
        :max_latency => 0.0,
        :status => :unknown
    )
    
    for i in 1:count
        sock, latency = tcp_connect(host, port, timeout=timeout)
        
        if !isnothing(sock)
            results[:success_count] += 1
            push!(results[:latencies], latency * 1000)  # Convert to ms
            close(sock)
        else
            results[:fail_count] += 1
        end
        
        i < count && sleep(0.1)
    end
    
    if !isempty(results[:latencies])
        results[:avg_latency] = mean(results[:latencies])
        results[:min_latency] = minimum(results[:latencies])
        results[:max_latency] = maximum(results[:latencies])
    end
    
    results[:status] = if results[:success_count] == count
        :up
    elseif results[:success_count] > 0
        :degraded
    else
        :down
    end
    
    return results
end

"""
    display_connectivity_results(results::Dict{Symbol, Any})

Display connectivity test results.
"""
function display_connectivity_results(results::Dict{Symbol, Any})
    status_color = Dict(:up => :green, :degraded => :yellow, :down => :red)
    
    println()
    println(themed("Connectivity Test: $(results[:host]):$(results[:port])", :primary))
    println(themed(repeat("─", 50), :dim))
    
    status = results[:status]
    println("Status: ", themed(uppercase(string(status)), get(status_color, status, :dim)))
    println("Success: $(results[:success_count]) / $(results[:success_count] + results[:fail_count])")
    
    if !isempty(results[:latencies])
        println()
        println("Latency (ms):")
        println("  Min: ", themed(@sprintf("%.2f", results[:min_latency]), :green))
        println("  Avg: ", themed(@sprintf("%.2f", results[:avg_latency]), :yellow))
        println("  Max: ", themed(@sprintf("%.2f", results[:max_latency]), :red))
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PROBE FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────

"""
    http_probe(host::String, port::Int = 80; 
               path::String = "/",
               timeout::Float64 = 5.0)

Send HTTP probe and return response info.
"""
function http_probe(host::String, port::Int = 80;
                    path::String = "/",
                    timeout::Float64 = 5.0)::Dict{Symbol, Any}
    
    result = Dict{Symbol, Any}(
        :status => 0,
        :server => nothing,
        :content_length => 0,
        :response_time => 0.0,
        :headers => Dict{String, String}(),
        :success => false
    )
    
    start_time = time()
    
    request = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: Spectra/1.0\r\nConnection: close\r\n\r\n"
    
    response = tcp_send_recv(host, port, request, timeout=timeout)
    
    result[:response_time] = (time() - start_time) * 1000
    
    if !isnothing(response)
        text = String(response)
        
        # Parse status
        m = match(r"HTTP/[\d.]+ (\d+)", text)
        if !isnothing(m)
            result[:status] = parse(Int, m.captures[1])
            result[:success] = result[:status] < 400
        end
        
        # Parse headers
        header_section = split(text, "\r\n\r\n")[1]
        for line in split(header_section, "\r\n")[2:end]
            if occursin(":", line)
                parts = split(line, ":", limit=2)
                if length(parts) == 2
                    key = strip(parts[1])
                    value = strip(parts[2])
                    result[:headers][key] = value
                    
                    if lowercase(key) == "server"
                        result[:server] = value
                    elseif lowercase(key) == "content-length"
                        result[:content_length] = parse(Int, value)
                    end
                end
            end
        end
    end
    
    return result
end

"""
    ssl_probe(host::String, port::Int = 443)

Probe SSL/TLS service (basic check).
"""
function ssl_probe(host::String, port::Int = 443)::Dict{Symbol, Any}
    result = Dict{Symbol, Any}(
        :ssl_available => false,
        :error => nothing
    )
    
    # Simple check - try to connect and see if it accepts
    sock, _ = tcp_connect(host, port, timeout=3.0)
    
    if !isnothing(sock)
        result[:ssl_available] = true
        close(sock)
    end
    
    return result
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PROTOCOL PROBES
# ───────────────────────────────────────────────────────────────────────────────

const PROTOCOL_PROBES = Dict{Symbol, NamedTuple{(:port, :probe, :match), 
                                                 Tuple{Int, String, Regex}}}(
    :ssh => (port=22, probe="", match=r"^SSH-"),
    :ftp => (port=21, probe="", match=r"^220.*FTP"),
    :smtp => (port=25, probe="", match=r"^220"),
    :pop3 => (port=110, probe="", match=r"^\+OK"),
    :imap => (port=143, probe="", match=r"^\* OK"),
    :mysql => (port=3306, probe="", match=r"mysql|MariaDB"),
    :redis => (port=6379, probe="PING\r\n", match=r"\+PONG"),
    :memcached => (port=11211, probe="stats\r\n", match=r"STAT"),
)

"""
    detect_service(host::String, port::Int)

Attempt to detect service running on port.
"""
function detect_service(host::String, port::Int)::Union{Symbol, Nothing}
    # First try banner grab
    sock, _ = tcp_connect(host, port, timeout=2.0)
    isnothing(sock) && return nothing
    
    try
        # Wait for banner
        sleep(0.5)
        
        banner = ""
        if bytesavailable(sock) > 0
            banner = String(read(sock, min(bytesavailable(sock), 1024)))
        end
        
        close(sock)
        
        # Match against known protocols
        for (proto, info) in PROTOCOL_PROBES
            if occursin(info.match, banner)
                return proto
            end
        end
        
        # Try active probes
        for (proto, info) in PROTOCOL_PROBES
            if !isempty(info.probe)
                response = tcp_send_recv(host, port, info.probe, timeout=2.0)
                if !isnothing(response) && occursin(info.match, String(response))
                    return proto
                end
            end
        end
        
    catch
    end
    
    return nothing
end

# ───────────────────────────────────────────────────────────────────────────────
#                              SOCKET SERVER UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    create_listener(port::Int; host::String = "0.0.0.0")

Create a TCP listener.
"""
function create_listener(port::Int; host::String = "0.0.0.0")::TCPServer
    return listen(IPv4(host), port)
end

"""
    echo_server(port::Int; timeout::Float64 = 30.0)

Simple echo server for testing.
"""
function echo_server(port::Int; timeout::Float64 = 30.0)
    server = create_listener(port)
    println(themed("[*] Echo server listening on port $port", :info))
    
    start_time = time()
    
    while (time() - start_time) < timeout
        try
            sock = accept(server)
            println(themed("[+] Connection from $(sock.host)", :success))
            
            @async begin
                try
                    while isopen(sock)
                        data = readline(sock)
                        println(themed("    Received: $data", :dim))
                        write(sock, "Echo: $data\n")
                    end
                catch
                end
            end
        catch e
            break
        end
    end
    
    close(server)
    println(themed("[*] Server stopped", :info))
end
