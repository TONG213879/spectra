# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Entropy Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Shannon entropy calculation and randomness detection
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              ENTROPY CALCULATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    shannon_entropy(data::Vector{UInt8})

Calculate Shannon entropy of byte data.

Shannon entropy measures the average information content per symbol.
Maximum entropy for bytes is 8 bits (perfectly random).

# Returns
- `Float64`: Entropy in bits per byte (0.0 to 8.0)
"""
function shannon_entropy(data::Vector{UInt8})::Float64
    isempty(data) && return 0.0
    
    n = length(data)
    freq = zeros(Int, 256)
    
    for byte in data
        freq[byte + 1] += 1
    end
    
    entropy = 0.0
    for count in freq
        count == 0 && continue
        p = count / n
        entropy -= p * log2(p)
    end
    
    return entropy
end

"""
    shannon_entropy(data::String)

Calculate Shannon entropy of string.
"""
function shannon_entropy(data::String)::Float64
    shannon_entropy(Vector{UInt8}(data))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              ENTROPY ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

const ENTROPY_THRESHOLDS = Dict(
    :random => 7.5,         # Highly random data (encrypted, compressed)
    :high => 6.0,           # High entropy (keys, tokens, compressed)
    :medium => 4.0,         # Moderate entropy (mixed content)
    :low => 2.0,            # Low entropy (structured data)
    :very_low => 0.5,       # Very low entropy (repetitive)
)

"""
    classify_entropy(entropy::Float64)

Classify entropy level.
"""
function classify_entropy(entropy::Float64)::Symbol
    entropy >= ENTROPY_THRESHOLDS[:random] && return :random
    entropy >= ENTROPY_THRESHOLDS[:high] && return :high
    entropy >= ENTROPY_THRESHOLDS[:medium] && return :medium
    entropy >= ENTROPY_THRESHOLDS[:low] && return :low
    return :very_low
end

"""
    entropy_analyze(data::Union{String, Vector{UInt8}}; verbose::Bool = CONFIG.verbose)

Perform comprehensive entropy analysis.

# Arguments
- `data`: Data to analyze
- `verbose`: Show detailed output

# Returns
- `EntropyResult`: Complete entropy analysis

# Example
```julia
result = entropy_analyze("This is a test string")
result = entropy_analyze(read("suspicious_file"))
```
"""
function entropy_analyze(data::Union{String, Vector{UInt8}}; verbose::Bool = CONFIG.verbose)::EntropyResult
    bytes = isa(data, String) ? Vector{UInt8}(data) : data
    
    entropy = shannon_entropy(bytes)
    max_entropy = 8.0
    ratio = entropy / max_entropy
    classification = classify_entropy(entropy)
    
    # Heuristics for detection
    is_random = entropy >= ENTROPY_THRESHOLDS[:random]
    is_encrypted = entropy >= 7.8 && length(bytes) >= 16
    is_compressed = entropy >= 7.5 && entropy < 7.9 && length(bytes) >= 100
    
    result = EntropyResult(
        data, entropy, max_entropy, ratio,
        classification, is_random, is_encrypted, is_compressed
    )
    
    if verbose
        display_entropy_result(result)
    end
    
    return result
end

"""
    display_entropy_result(er::EntropyResult)

Display formatted entropy analysis results.
"""
function display_entropy_result(er::EntropyResult)
    data_len = isa(er.data, String) ? length(er.data) : length(er.data)
    
    # Color based on classification
    class_color = Dict(
        :random => :red,
        :high => :yellow,
        :medium => :cyan,
        :low => :green,
        :very_low => :dim,
    )
    
    # Visual entropy bar
    bar_width = 40
    filled = round(Int, er.ratio * bar_width)
    bar = themed(repeat("█", filled), get(class_color, er.classification, :white)) * 
          themed(repeat("░", bar_width - filled), :dim)
    
    println()
    println(themed("╔═══════════════════════════════════════════════════════╗", :primary))
    println(themed("║              ENTROPY ANALYSIS                         ║", :primary))
    println(themed("╠═══════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), " Data Size: ", themed("$data_len bytes", :cyan))
    println(themed("║", :primary), " Entropy: ", themed(@sprintf("%.4f", er.entropy), :yellow), " bits/byte")
    println(themed("║", :primary), " Max Entropy: ", themed(@sprintf("%.1f", er.max_entropy), :dim), " bits/byte")
    println(themed("║", :primary), " Ratio: ", themed(@sprintf("%.1f%%", er.ratio * 100), :yellow))
    println(themed("║", :primary))
    println(themed("║", :primary), " [$bar] ", themed(string(er.classification), get(class_color, er.classification, :white)))
    println(themed("╠═══════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), themed(" Detection Results:", :secondary))
    
    indicators = [
        ("Random Data", er.is_random),
        ("Encrypted", er.is_encrypted),
        ("Compressed", er.is_compressed),
    ]
    
    for (label, detected) in indicators
        icon = detected ? themed("✓", :success) : themed("✗", :dim)
        println(themed("║", :primary), "   $icon $label")
    end
    
    println(themed("╚═══════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              BLOCK ENTROPY
# ───────────────────────────────────────────────────────────────────────────────

"""
    block_entropy(data::Vector{UInt8}, block_size::Int = 256)

Calculate entropy for each block of data.

Useful for detecting encrypted/compressed sections in files.
"""
function block_entropy(data::Vector{UInt8}, block_size::Int = 256)::Vector{Float64}
    isempty(data) && return Float64[]
    
    n_blocks = ceil(Int, length(data) / block_size)
    entropies = Float64[]
    
    for i in 1:n_blocks
        start_idx = (i - 1) * block_size + 1
        end_idx = min(i * block_size, length(data))
        block = data[start_idx:end_idx]
        push!(entropies, shannon_entropy(block))
    end
    
    return entropies
end

"""
    find_high_entropy_regions(data::Vector{UInt8}, block_size::Int = 256, threshold::Float64 = 7.0)

Find regions of high entropy in data.

Returns vector of (start_index, end_index, entropy) tuples.
"""
function find_high_entropy_regions(data::Vector{UInt8}, block_size::Int = 256, 
                                   threshold::Float64 = 7.0)::Vector{Tuple{Int, Int, Float64}}
    entropies = block_entropy(data, block_size)
    regions = Tuple{Int, Int, Float64}[]
    
    in_region = false
    region_start = 0
    
    for (i, e) in enumerate(entropies)
        if e >= threshold
            if !in_region
                in_region = true
                region_start = (i - 1) * block_size + 1
            end
        else
            if in_region
                in_region = false
                region_end = (i - 1) * block_size
                region_entropy = mean(entropies[div(region_start - 1, block_size) + 1 : i - 1])
                push!(regions, (region_start, region_end, region_entropy))
            end
        end
    end
    
    # Handle case where high entropy extends to end
    if in_region
        region_end = length(data)
        region_entropy = mean(entropies[div(region_start - 1, block_size) + 1 : end])
        push!(regions, (region_start, region_end, region_entropy))
    end
    
    return regions
end

# ───────────────────────────────────────────────────────────────────────────────
#                              FILE ENTROPY
# ───────────────────────────────────────────────────────────────────────────────

"""
    file_entropy(filepath::String; verbose::Bool = CONFIG.verbose)

Analyze entropy of file contents.
"""
function file_entropy(filepath::String; verbose::Bool = CONFIG.verbose)::EntropyResult
    isfile(filepath) || error("File not found: $filepath")
    
    data = read(filepath)
    result = entropy_analyze(data, verbose=false)
    
    if verbose
        filesize_str = @sprintf("%.2f KB", length(data) / 1024)
        println(themed("\n[*] File: $filepath ($filesize_str)", :info))
        display_entropy_result(result)
    end
    
    return result
end

"""
    file_entropy_map(filepath::String, block_size::Int = 256)

Generate entropy map of file for visualization.
"""
function file_entropy_map(filepath::String, block_size::Int = 256)::Vector{Float64}
    isfile(filepath) || error("File not found: $filepath")
    
    data = read(filepath)
    return block_entropy(data, block_size)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              RANDOM DATA GENERATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    random_bytes(n::Int)

Generate cryptographically secure random bytes.
"""
function random_bytes(n::Int)::Vector{UInt8}
    n > 0 || error("Number of bytes must be positive")
    return rand(RandomDevice(), UInt8, n)
end

"""
    random_hex(n::Int)

Generate random hexadecimal string.
"""
function random_hex(n::Int)::String
    return bytes2hex(random_bytes(div(n + 1, 2)))[1:n]
end

"""
    random_base64(n::Int)

Generate random base64 string.
"""
function random_base64(n::Int)::String
    bytes = random_bytes(div(n * 3, 4) + 3)
    return base64encode(bytes)[1:n]
end

"""
    random_alphanumeric(n::Int)

Generate random alphanumeric string.
"""
function random_alphanumeric(n::Int)::String
    chars = vcat(collect('A':'Z'), collect('a':'z'), collect('0':'9'))
    return String([chars[rand(1:length(chars))] for _ in 1:n])
end

# ───────────────────────────────────────────────────────────────────────────────
#                              ENTROPY VISUALIZATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    entropy_sparkline(entropies::Vector{Float64}; width::Int = 60)

Generate sparkline visualization of entropy values.
"""
function entropy_sparkline(entropies::Vector{Float64}; width::Int = 60)::String
    isempty(entropies) && return ""
    
    # Normalize and resample to width
    n = length(entropies)
    resampled = if n > width
        [mean(entropies[round(Int, (i-1)*n/width)+1 : min(round(Int, i*n/width), n)]) 
         for i in 1:width]
    elseif n < width
        # Stretch
        [entropies[min(round(Int, i*n/width) + 1, n)] for i in 1:width]
    else
        entropies
    end
    
    # Map to sparkline characters
    blocks = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    
    chars = String[]
    for e in resampled
        normalized = min(max(e / 8.0, 0.0), 1.0)
        idx = round(Int, normalized * (length(blocks) - 1)) + 1
        
        # Color based on entropy level
        color = if e >= 7.5
            :red
        elseif e >= 6.0
            :yellow
        elseif e >= 4.0
            :cyan
        else
            :green
        end
        
        push!(chars, themed(blocks[idx], color))
    end
    
    return join(chars)
end

"""
    display_entropy_map(filepath::String, block_size::Int = 256)

Display visual entropy map of file.
"""
function display_entropy_map(filepath::String, block_size::Int = 256)
    entropies = file_entropy_map(filepath, block_size)
    
    println(themed("\n[*] Entropy Map: $filepath", :info))
    println(themed("    Block size: $block_size bytes", :dim))
    println()
    
    sparkline = entropy_sparkline(entropies)
    println("    ", sparkline)
    
    # Legend
    println()
    println("    ", themed("█ High (>7.5)", :red), "  ", 
            themed("█ Medium (6-7.5)", :yellow), "  ",
            themed("█ Normal (4-6)", :cyan), "  ",
            themed("█ Low (<4)", :green))
    
    # Statistics
    println()
    println(themed("    Min: ", :dim), @sprintf("%.2f", minimum(entropies)))
    println(themed("    Max: ", :dim), @sprintf("%.2f", maximum(entropies)))
    println(themed("    Avg: ", :dim), @sprintf("%.2f", mean(entropies)))
    println(themed("    Std: ", :dim), @sprintf("%.2f", std(entropies)))
end
