# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Network Scanner
# ═══════════════════════════════════════════════════════════════════════════════
# High-performance port scanning and service detection
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              PORT SCANNING
# ───────────────────────────────────────────────────────────────────────────────

"""
    port_scan(host::String, port::Int; 
              timeout::Float64 = CONFIG.timeout,
              protocol::Symbol = :tcp)

Scan a single port on a host.

# Arguments
- `host::String`: Target hostname or IP
- `port::Int`: Port number to scan
- `timeout::Float64`: Connection timeout in seconds
- `protocol::Symbol`: Protocol (:tcp or :udp)

# Returns
- `ScanResult`: Scan result with port state
"""
function port_scan(host::String, port::Int;
                   timeout::Float64 = CONFIG.timeout,
                   protocol::Symbol = :tcp)::ScanResult
    
    target = Target(host; ports=[port], protocol=protocol, timeout=timeout)
    start_time = time()
    state = CLOSED
    service = nothing
    banner_text = nothing
    
    if protocol == :tcp
        try
            sock = connect(host, port)
            state = OPEN
            
            # Attempt banner grab with short timeout
            try
                t = @async begin
                    sleep(0.5)
                    if isopen(sock)
                        available = bytesavailable(sock)
                        if available > 0
                            return String(read(sock, min(available, 1024)))
                        end
                    end
                    return nothing
                end
                
                result = timedwait(() -> istaskdone(t), 1.0)
                if result == :ok
                    banner_text = fetch(t)
                end
            catch
            end
            
            close(sock)
            
            # Detect service from port or banner
            service = detect_service_from_port(port, banner_text)
            
        catch e
            if isa(e, Base.IOError) || isa(e, Base.DNSError)
                state = CLOSED
            else
                state = FILTERED
            end
        end
    end
    
    latency = time() - start_time
    
    return ScanResult(target, port, state, service, banner_text, now(), latency)
end

"""
    scan(target::Union{String, Target}; 
         ports::AbstractVector{<:Integer} = PORTS_TOP_100,
         timeout::Float64 = CONFIG.timeout,
         verbose::Bool = CONFIG.verbose)

Perform port scan on target.

# Arguments
- `target`: Hostname, IP, or Target object
- `ports`: Ports to scan
- `timeout`: Connection timeout
- `verbose`: Show progress and results

# Returns
- `Vector{ScanResult}`: All scan results

# Example
```julia
# Quick scan of common ports
results = scan("example.com")

# Full scan
results = scan("192.168.1.1", ports=1:65535)

# Custom ports
results = scan("example.com", ports=[22, 80, 443, 8080])
```
"""
function scan(target::Union{String, Target};
              ports::AbstractVector{<:Integer} = PORTS_TOP_100,
              timeout::Float64 = CONFIG.timeout,
              verbose::Bool = CONFIG.verbose)::Vector{ScanResult}
    
    host = isa(target, String) ? target : target.host
    port_list = isa(target, Target) ? target.ports : collect(ports)
    
    if verbose
        module_banner(:scanner)
        println(themed("[*] Scanning: $host", :info))
        println(themed("[*] Ports: $(length(port_list))", :dim))
        println()
    end
    
    # Rate-limited parallel scanning
    init_rate_limiter(CONFIG.rate_limit)
    
    scan_port = port -> rate_limited() do
        port_scan(host, port; timeout=timeout)
    end
    
    results = parallel_map(scan_port, port_list, show_progress=verbose)
    
    # Filter out nothing values
    results = filter(!isnothing, results)
    
    if verbose
        display_scan_results(results)
    end
    
    return results
end

"""
    quick_scan(host::String)

Quick scan of most common ports.
"""
function quick_scan(host::String)::Vector{ScanResult}
    scan(host, ports=PORTS_TOP_100, verbose=true)
end

"""
    full_scan(host::String)

Full scan of all TCP ports.
"""
function full_scan(host::String)::Vector{ScanResult}
    scan(host, ports=1:65535, verbose=true)
end

"""
    stealth_scan(host::String; ports::AbstractVector{<:Integer} = PORTS_TOP_100)

Slower, randomized scan for stealth.
"""
function stealth_scan(host::String; ports::AbstractVector{<:Integer} = PORTS_TOP_100)::Vector{ScanResult}
    shuffled = shuffle(collect(ports))
    
    results = ScanResult[]
    
    for port in shuffled
        push!(results, port_scan(host, port, timeout=3.0))
        sleep(rand() * 0.5)  # Random delay
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              SERVICE DETECTION
# ───────────────────────────────────────────────────────────────────────────────

const PORT_SERVICES = Dict{Int, String}(
    20 => "ftp-data", 21 => "ftp", 22 => "ssh", 23 => "telnet",
    25 => "smtp", 53 => "dns", 67 => "dhcp", 68 => "dhcp",
    69 => "tftp", 80 => "http", 110 => "pop3", 111 => "rpcbind",
    119 => "nntp", 123 => "ntp", 135 => "msrpc", 137 => "netbios-ns",
    138 => "netbios-dgm", 139 => "netbios-ssn", 143 => "imap",
    161 => "snmp", 162 => "snmptrap", 179 => "bgp", 194 => "irc",
    389 => "ldap", 443 => "https", 445 => "microsoft-ds", 464 => "kpasswd",
    465 => "smtps", 500 => "isakmp", 514 => "syslog", 515 => "printer",
    520 => "rip", 521 => "ripng", 543 => "klogin", 544 => "kshell",
    546 => "dhcpv6-client", 547 => "dhcpv6-server", 554 => "rtsp",
    587 => "submission", 631 => "ipp", 636 => "ldaps", 646 => "ldp",
    873 => "rsync", 902 => "vmware", 989 => "ftps-data", 990 => "ftps",
    993 => "imaps", 995 => "pop3s", 1080 => "socks", 1194 => "openvpn",
    1433 => "mssql", 1434 => "mssql-m", 1521 => "oracle", 1723 => "pptp",
    1812 => "radius", 1813 => "radius-acct", 2049 => "nfs", 2082 => "cpanel",
    2083 => "cpanel-ssl", 2086 => "whm", 2087 => "whm-ssl", 2181 => "zookeeper",
    2375 => "docker", 2376 => "docker-ssl", 3000 => "grafana", 3128 => "squid",
    3306 => "mysql", 3389 => "rdp", 3690 => "svn", 4369 => "epmd",
    5000 => "upnp", 5060 => "sip", 5061 => "sips", 5432 => "postgresql",
    5672 => "amqp", 5900 => "vnc", 5984 => "couchdb", 6379 => "redis",
    6443 => "kubernetes", 6660 => "irc", 6661 => "irc", 6662 => "irc",
    6663 => "irc", 6664 => "irc", 6665 => "irc", 6666 => "irc",
    6667 => "irc", 6668 => "irc", 6669 => "irc", 6697 => "ircs",
    7001 => "weblogic", 7002 => "weblogic-ssl", 8000 => "http-alt",
    8008 => "http-alt", 8080 => "http-proxy", 8081 => "http-alt",
    8443 => "https-alt", 8888 => "http-alt", 9000 => "cslistener",
    9090 => "zeus-admin", 9200 => "elasticsearch", 9300 => "elasticsearch",
    9418 => "git", 9999 => "abyss", 10000 => "webmin", 11211 => "memcached",
    27017 => "mongodb", 27018 => "mongodb", 27019 => "mongodb",
    28015 => "rethinkdb", 50000 => "db2",
)

const SERVICE_BANNERS = Dict{Regex, String}(
    r"SSH-\d\.\d" => "ssh",
    r"220.*FTP" => "ftp",
    r"220.*SMTP|220.*Postfix|220.*Sendmail" => "smtp",
    r"HTTP/\d\.\d" => "http",
    r"^\* OK.*IMAP" => "imap",
    r"\+OK.*POP3|^\+OK Dovecot" => "pop3",
    r"mysql_native_password|MariaDB" => "mysql",
    r"PostgreSQL" => "postgresql",
    r"Redis" => "redis",
    r"MongoDB" => "mongodb",
    r"OpenSSH" => "ssh",
    r"Apache|nginx|Microsoft-IIS|lighttpd" => "http",
)

"""
    detect_service_from_port(port::Int, banner::Union{String, Nothing} = nothing)

Detect service from port number and optional banner.
"""
function detect_service_from_port(port::Int, banner::Union{String, Nothing} = nothing)::Union{String, Nothing}
    # First try banner detection
    if !isnothing(banner)
        for (pattern, service) in SERVICE_BANNERS
            if occursin(pattern, banner)
                return service
            end
        end
    end
    
    # Fall back to port-based detection
    return get(PORT_SERVICES, port, nothing)
end

"""
    service_detect(host::String, port::Int; timeout::Float64 = 5.0)

Detect service running on port with banner grabbing.
"""
function service_detect(host::String, port::Int; timeout::Float64 = 5.0)::Service
    result = port_scan(host, port, timeout=timeout)
    
    vulnerabilities = String[]
    
    # Check for known vulnerable services
    if !isnothing(result.service)
        if result.service == "telnet"
            push!(vulnerabilities, "Telnet transmits credentials in cleartext")
        elseif result.service == "ftp" && !isnothing(result.banner) && occursin("anonymous", lowercase(result.banner))
            push!(vulnerabilities, "Anonymous FTP access may be enabled")
        end
    end
    
    return Service(
        something(result.service, "unknown"),
        nothing,  # version
        :tcp,
        port,
        result.banner,
        nothing,  # CPE
        vulnerabilities
    )
end

# ───────────────────────────────────────────────────────────────────────────────
#                              BANNER GRABBING
# ───────────────────────────────────────────────────────────────────────────────

"""
    banner_grab(host::String, port::Int; timeout::Float64 = 5.0)

Grab banner from service.
"""
function banner_grab(host::String, port::Int; timeout::Float64 = 5.0)::Union{String, Nothing}
    try
        sock = connect(host, port)
        
        # Send probe for HTTP
        if port in [80, 8080, 8000, 8888]
            write(sock, "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n")
        end
        
        # Wait for response
        sleep(0.5)
        
        if bytesavailable(sock) > 0
            banner = String(read(sock, min(bytesavailable(sock), 4096)))
            close(sock)
            return banner
        end
        
        close(sock)
        return nothing
        
    catch
        return nothing
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              HOST DISCOVERY
# ───────────────────────────────────────────────────────────────────────────────

"""
    ping_check(host::String; timeout::Float64 = 2.0)

Check if host responds to common probes.
"""
function ping_check(host::String; timeout::Float64 = 2.0)::Bool
    # Try common ports for host discovery
    for port in [80, 443, 22, 445]
        try
            sock = connect(host, port)
            close(sock)
            return true
        catch
            continue
        end
    end
    
    return false
end

"""
    discover_hosts(network::String; verbose::Bool = CONFIG.verbose)

Discover live hosts on a network.

# Arguments
- `network`: CIDR notation (e.g., "192.168.1.0/24")

# Returns
- `Vector{String}`: List of responding hosts
"""
function discover_hosts(network::String; verbose::Bool = CONFIG.verbose)::Vector{String}
    range = NetworkRange(network)
    
    verbose && println(themed("[*] Discovering hosts on $network ($(range.hosts) possible)", :info))
    
    # Parse base IP
    parts = split(range.network, '.')
    base_ip = [parse(Int, p) for p in parts]
    
    hosts = String[]
    
    for i in 1:min(range.hosts, 254)
        ip = "$(base_ip[1]).$(base_ip[2]).$(base_ip[3]).$i"
        
        if ping_check(ip, timeout=1.0)
            push!(hosts, ip)
            verbose && println(themed("[+] Found: $ip", :success))
        end
    end
    
    verbose && println(themed("\n[*] Discovered $(length(hosts)) hosts", :info))
    
    return hosts
end

# ───────────────────────────────────────────────────────────────────────────────
#                              NETWORK SWEEP
# ───────────────────────────────────────────────────────────────────────────────

"""
    network_sweep(network::String; ports::Vector{Int} = [22, 80, 443])

Sweep network for hosts with specific open ports.
"""
function network_sweep(network::String; ports::Vector{Int} = [22, 80, 443])::Dict{String, Vector{Int}}
    range = NetworkRange(network)
    results = Dict{String, Vector{Int}}()
    
    println(themed("[*] Sweeping $network for ports: $(join(ports, ", "))", :info))
    
    parts = split(range.network, '.')
    base_ip = [parse(Int, p) for p in parts]
    
    for i in 1:min(range.hosts, 254)
        ip = "$(base_ip[1]).$(base_ip[2]).$(base_ip[3]).$i"
        open_ports = Int[]
        
        for port in ports
            result = port_scan(ip, port, timeout=1.0)
            if result.state == OPEN
                push!(open_ports, port)
            end
        end
        
        if !isempty(open_ports)
            results[ip] = open_ports
            println(themed("[+] $ip: $(join(open_ports, ", "))", :success))
        end
    end
    
    return results
end
