#!/usr/bin/env julia
# ═══════════════════════════════════════════════════════════════════════════════
#                         SPECTRA - Basic Usage Example
# ═══════════════════════════════════════════════════════════════════════════════
# Demonstrates core Spectra functionality
# ═══════════════════════════════════════════════════════════════════════════════

# Add parent directory to load path
push!(LOAD_PATH, dirname(dirname(@__FILE__)))

using Spectra

# ─────────────────────────────────────────────────────────────────────────────
# Initialize Spectra
# ─────────────────────────────────────────────────────────────────────────────

Spectra.banner()
config = Spectra.init()
println("\n✓ Spectra initialized with $(config.threads) threads")

# ─────────────────────────────────────────────────────────────────────────────
# Hash Identification
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * "="^60)
println("HASH IDENTIFICATION DEMO")
println("="^60)

test_hashes = [
    "5d41402abc4b2a76b9719d911017c592",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "\$2a\$12\$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
]

for hash in test_hashes
    println("\nHash: $hash")
    results = hash_identify(hash)
    for r in results
        println("  → $(r.hash_type) (confidence: $(Int(r.confidence * 100))%)")
    end
end

# ─────────────────────────────────────────────────────────────────────────────
# Entropy Analysis
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * "="^60)
println("ENTROPY ANALYSIS DEMO")
println("="^60)

# Low entropy data
low_entropy = Vector{UInt8}("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
result = entropy_analyze(low_entropy)
println("\nLow entropy string:")
println("  Entropy: $(round(result.entropy, digits=2)) bits/byte")
println("  Encrypted: $(result.likely_encrypted ? "Likely" : "Unlikely")")

# High entropy data (random)
high_entropy = rand(UInt8, 64)
result = entropy_analyze(high_entropy)
println("\nRandom bytes:")
println("  Entropy: $(round(result.entropy, digits=2)) bits/byte")
println("  Encrypted: $(result.likely_encrypted ? "Likely" : "Unlikely")")

# ─────────────────────────────────────────────────────────────────────────────
# Pattern Detection
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * "="^60)
println("SECURITY PATTERN DETECTION DEMO")
println("="^60)

test_content = """
-- SQL Injection Example
SELECT * FROM users WHERE id = '1' OR '1'='1';

-- XSS Example
<script>document.cookie</script>

-- Path Traversal
../../etc/passwd

-- AWS Key (fake)
AKIAIOSFODNN7EXAMPLE

-- Internal IP
Connect to 192.168.1.100 for testing
"""

println("\nScanning content for security issues...")
matches = scan_for_patterns(test_content)

for m in matches
    println("\n  [$(uppercase(string(m.pattern.severity)))] $(m.pattern.name)")
    println("    Matched: \"$(m.matched_text[1:min(40, length(m.matched_text))])...\"")
    println("    $(m.pattern.description)")
end

# ─────────────────────────────────────────────────────────────────────────────
# Threat Scoring
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * "="^60)
println("THREAT SCORING DEMO")
println("="^60)

# Create some threats
threats = [
    Threat("SQL Injection", "Found SQL injection in login form", CRITICAL, :injection, now()),
    Threat("XSS Reflected", "Reflected XSS in search parameter", HIGH, :injection, now()),
    Threat("Information Disclosure", "Server version exposed", LOW, :info_disclosure, now()),
]

println("\nAssessing $(length(threats)) threats...")

assessment = assess_risk("example.com", threats)
display_risk_assessment(assessment)

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * "="^60)
println("DEMO COMPLETE")
println("="^60)
println("\n✓ Spectra demonstration finished successfully!")
println("  See the documentation for more advanced usage.")
