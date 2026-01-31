# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Quick Start Guide
# ═══════════════════════════════════════════════════════════════════════════════

# Installation

First, ensure you have Julia 1.10 or later installed:

```bash
julia --version
```

Then activate and instantiate the project:

```julia
using Pkg
Pkg.activate(".")
Pkg.instantiate()
```

# Basic Usage

## Initialization

```julia
using Spectra

# Show banner
Spectra.banner()

# Initialize with default settings
config = Spectra.init()

# Or configure specific options
config = Spectra.configure(
    verbose = true,
    threads = 8,
    timeout = 10.0
)
```

## Hash Analysis

```julia
# Identify hash type
results = hash_identify("5d41402abc4b2a76b9719d911017c592")
# → [HashIdentification("md5", 1.0)]

# Compute hashes
md5 = compute_hash("hello", :md5)
sha256 = compute_hash("hello", :sha256)

# File hashes
file_hash("/path/to/file", :sha256)
```

## Entropy Analysis

```julia
# Analyze byte array
data = read("suspicious.bin")
result = entropy_analyze(data)

println("Entropy: $(result.entropy) bits/byte")
println("Encrypted: $(result.likely_encrypted)")
```

## Port Scanning

```julia
# Quick scan common ports
result = quick_scan("target.com")
display_scan_result(result)

# Custom port scan
result = scan("target.com", ports=[22, 80, 443, 8080])

# Full port scan (1-65535)
result = full_scan("target.com")
```

## Security Pattern Detection

```julia
# Scan text for vulnerabilities
content = read("source.php", String)
matches = scan_for_patterns(content)

for m in matches
    println("[$(m.pattern.severity)] $(m.pattern.name)")
    println("  Match: $(m.matched_text)")
end

# Scan entire directory
patterns = scan_directory_patterns("/path/to/project")
```

## Threat Scoring

```julia
# Create threats
threats = [
    Threat("SQLi", "SQL injection in login", CRITICAL, :injection, now()),
    Threat("XSS", "Reflected XSS", HIGH, :injection, now()),
]

# Get risk assessment
assessment = assess_risk("target.com", threats)
display_risk_assessment(assessment)
```

## NullSec Integration

```julia
# Initialize NullSec integration
init_nullsec!()

# Check status
display_nullsec_status()

# List available modules
modules = list_modules()

# Run a NullSec module
output = run_nullsec_module("scanner", ["--target", "192.168.1.1"])

# Log scan results
log_scan_result("target.com", scan_result)
```

# Advanced Topics

## Parallel Processing

```julia
using Spectra: parallel_map, parallel_foreach

# Process multiple targets in parallel
targets = ["host1.com", "host2.com", "host3.com"]
results = parallel_map(quick_scan, targets)

# Rate-limited operations
limiter = RateLimiter(10)  # 10 requests/second
for target in targets
    rate_limit!(limiter)
    scan(target)
end
```

## Custom Patterns

```julia
# Add custom pattern
add_pattern!(
    :my_pattern,
    r"SECRET_[A-Z0-9]{32}",
    "Custom secret pattern",
    HIGH
)

# Scan with custom patterns
matches = scan_for_patterns(content)
```

## Anomaly Detection

```julia
# Detect anomalies in time series
values = [1.0, 1.1, 1.2, 5.0, 1.1, 1.0]  # 5.0 is anomaly
anomalies = detect_zscore_anomalies(values, threshold=2.0)

# Network traffic analysis
stats = NetworkStats(...)
anomalies = analyze_traffic_anomalies(stats)
```

# Examples

See the `examples/` directory for complete working examples:

- `basic_usage.jl` - Core functionality demonstration
- `network_scanning.jl` - Network reconnaissance
- `forensics_example.jl` - File forensics analysis

Run an example:

```bash
julia examples/basic_usage.jl
```

# Contributing

Spectra is designed to be extensible. Add new modules to:

- `src/crypto/` - Cryptographic analysis
- `src/network/` - Network protocols
- `src/analysis/` - Security analysis
- `src/modules/` - Standalone tools
- `src/integrations/` - External integrations

# License

MIT License - See LICENSE for details
