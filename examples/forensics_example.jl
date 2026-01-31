#!/usr/bin/env julia
# ═══════════════════════════════════════════════════════════════════════════════
#                         SPECTRA - File Forensics Example
# ═══════════════════════════════════════════════════════════════════════════════
# Demonstrates forensic analysis capabilities
# ═══════════════════════════════════════════════════════════════════════════════

push!(LOAD_PATH, dirname(dirname(@__FILE__)))

using Spectra

# ─────────────────────────────────────────────────────────────────────────────
# Initialize
# ─────────────────────────────────────────────────────────────────────────────

Spectra.banner(:forensics)
config = Spectra.init()

# ─────────────────────────────────────────────────────────────────────────────
# File Type Identification
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * themed("FILE TYPE IDENTIFICATION", :info))
println(themed("─"^40, :dim))

# Analyze a file if provided as argument
if length(ARGS) > 0
    filepath = ARGS[1]
    
    if isfile(filepath)
        println("\nAnalyzing: $filepath")
        
        file_type = identify_file(filepath)
        println("  Type: $file_type")
        
        metadata = analyze_file(filepath)
        println("  Size: $(metadata.size) bytes")
        println("  Created: $(metadata.created)")
        println("  Modified: $(metadata.modified)")
        
        if metadata.entropy > 0
            println("  Entropy: $(round(metadata.entropy, digits=2)) bits/byte")
            
            if metadata.entropy > 7.5
                println(themed("  ⚠ High entropy - may be encrypted/compressed", :warning))
            end
        end
        
        # Extract strings
        println("\n" * themed("STRING EXTRACTION", :info))
        println(themed("─"^40, :dim))
        
        strings = extract_strings(filepath)
        println("\nFound $(length(strings)) interesting strings:")
        for s in strings[1:min(20, length(strings))]
            println("  → $s")
        end
        
        # Scan for patterns
        println("\n" * themed("SECURITY PATTERN SCAN", :info))
        println(themed("─"^40, :dim))
        
        patterns = scan_file_for_patterns(filepath)
        
        if !isempty(patterns)
            println("\nSecurity findings:")
            for (line_num, line, matches) in patterns
                for m in matches
                    println("  Line $line_num: [$(m.pattern.name)]")
                    println("    $(m.matched_text)")
                end
            end
        else
            println("\n  ✓ No security patterns detected")
        end
    else
        println(themed("Error: File not found - $filepath", :error))
    end
else
    println("\nUsage: julia forensics_example.jl <filepath>")
    println("\nDemo mode - analyzing this script file...")
    
    # Analyze self
    filepath = @__FILE__
    
    strings = extract_strings(filepath)
    println("\nFound $(length(strings)) strings in this file")
    
    patterns = scan_file_for_patterns(filepath)
    println("Security patterns found: $(length(patterns))")
end

# ─────────────────────────────────────────────────────────────────────────────
# Hash Computation
# ─────────────────────────────────────────────────────────────────────────────

println("\n" * themed("FILE HASHING", :info))
println(themed("─"^40, :dim))

# Create temp file for demo
temp_file = tempname()
write(temp_file, "This is test content for Spectra forensics demo")

println("\nComputing hashes for demo file...")
println("  MD5:    $(file_hash(temp_file, :md5))")
println("  SHA1:   $(file_hash(temp_file, :sha1))")
println("  SHA256: $(file_hash(temp_file, :sha256))")

rm(temp_file)

println("\n" * themed("✓ Forensic analysis complete", :success))
