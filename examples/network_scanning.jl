#!/usr/bin/env julia
# ═══════════════════════════════════════════════════════════════════════════════
#                         SPECTRA - Network Scanning Example
# ═══════════════════════════════════════════════════════════════════════════════
# Demonstrates network reconnaissance capabilities
# ═══════════════════════════════════════════════════════════════════════════════

push!(LOAD_PATH, dirname(dirname(@__FILE__)))

using Spectra

# ─────────────────────────────────────────────────────────────────────────────
# Initialize
# ─────────────────────────────────────────────────────────────────────────────

Spectra.banner(:scanner)
config = Spectra.init()

# ─────────────────────────────────────────────────────────────────────────────
# Port Scanning
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * themed("PORT SCANNING", :info))
println(themed("─"^40, :dim))

# Quick scan common ports
target = "localhost"
println("\nScanning $target for common ports...")

result = quick_scan(target)
display_scan_result(result)

# ─────────────────────────────────────────────────────────────────────────────
# Service Detection
# ─────────────────────────────────────────────────────────────────────────────

if !isempty(result.open_ports)
    println("\n" * themed("SERVICE DETECTION", :info))
    println(themed("─"^40, :dim))
    
    for port in result.open_ports[1:min(5, length(result.open_ports))]
        println("\nProbing port $port...")
        service = detect_service(target, port)
        println("  Service: $service")
    end
end

# ─────────────────────────────────────────────────────────────────────────────
# DNS Enumeration
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * themed("DNS ENUMERATION", :info))
println(themed("─"^40, :dim))

domain = "google.com"
println("\nLooking up DNS records for $domain...")

records = dns_lookup(domain)
for record in records
    println("  [$(record.record_type)] $(record.name) → $(record.value)")
end

# ─────────────────────────────────────────────────────────────────────────────
# HTTP Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * themed("HTTP FINGERPRINTING", :info))
println(themed("─"^40, :dim))

url = "http://example.com"
println("\nFingerprinting $url...")

fingerprint = http_fingerprint(url)

if fingerprint !== nothing
    println("  Status: $(fingerprint[:status_code])")
    println("  Server: $(get(fingerprint, :server, "Unknown"))")
    
    if haskey(fingerprint, :technologies)
        println("  Technologies detected:")
        for tech in fingerprint[:technologies]
            println("    → $tech")
        end
    end
end

println("\n" * themed("✓ Network scan complete", :success))
