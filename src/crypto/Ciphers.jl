# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Cipher Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Cipher detection, analysis, and cryptographic utilities
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              CIPHER SIGNATURES
# ───────────────────────────────────────────────────────────────────────────────

const CIPHER_SIGNATURES = Dict{Symbol, NamedTuple{(:block_size, :key_sizes, :mode_detectable, :description),
                                                   Tuple{Int, Vector{Int}, Bool, String}}}(
    :aes => (block_size=16, key_sizes=[16, 24, 32], mode_detectable=true, description="AES (Rijndael)"),
    :des => (block_size=8, key_sizes=[8], mode_detectable=true, description="DES"),
    :triple_des => (block_size=8, key_sizes=[16, 24], mode_detectable=true, description="Triple DES (3DES)"),
    :blowfish => (block_size=8, key_sizes=collect(4:56), mode_detectable=true, description="Blowfish"),
    :twofish => (block_size=16, key_sizes=[16, 24, 32], mode_detectable=true, description="Twofish"),
    :chacha20 => (block_size=64, key_sizes=[32], mode_detectable=false, description="ChaCha20"),
    :rc4 => (block_size=1, key_sizes=collect(1:256), mode_detectable=false, description="RC4 (Stream)"),
    :camellia => (block_size=16, key_sizes=[16, 24, 32], mode_detectable=true, description="Camellia"),
    :serpent => (block_size=16, key_sizes=[16, 24, 32], mode_detectable=true, description="Serpent"),
)

# ───────────────────────────────────────────────────────────────────────────────
#                              BLOCK CIPHER MODES
# ───────────────────────────────────────────────────────────────────────────────

const BLOCK_MODES = Dict{Symbol, NamedTuple{(:iv_required, :padding, :description), 
                                            Tuple{Bool, Bool, String}}}(
    :ecb => (iv_required=false, padding=true, description="Electronic Codebook (Insecure)"),
    :cbc => (iv_required=true, padding=true, description="Cipher Block Chaining"),
    :ctr => (iv_required=true, padding=false, description="Counter Mode"),
    :gcm => (iv_required=true, padding=false, description="Galois/Counter Mode (Authenticated)"),
    :cfb => (iv_required=true, padding=false, description="Cipher Feedback"),
    :ofb => (iv_required=true, padding=false, description="Output Feedback"),
    :xts => (iv_required=true, padding=false, description="XEX-based Tweaked CodeBook (Disk Encryption)"),
)

# ───────────────────────────────────────────────────────────────────────────────
#                              CIPHER ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

"""
    analyze_ciphertext(data::Vector{UInt8}; verbose::Bool = CONFIG.verbose)

Analyze ciphertext to detect cipher and mode.

# Arguments
- `data`: Encrypted data to analyze
- `verbose`: Show detailed output

# Returns
- `CipherAnalysis`: Analysis results

# Example
```julia
result = analyze_ciphertext(read("encrypted.bin"))
println("Detected: ", result.detected_cipher)
```
"""
function analyze_ciphertext(data::Vector{UInt8}; verbose::Bool = CONFIG.verbose)::CipherAnalysis
    len = length(data)
    
    # Calculate entropy
    entropy = shannon_entropy(data)
    
    # Detect block size
    block_size = detect_block_size(data)
    
    # Analyze patterns for ECB detection
    is_ecb = detect_ecb_mode(data, block_size)
    
    # Detect cipher type based on characteristics
    detected_cipher = :unknown
    confidence = 0.0
    detected_mode = nothing
    key_length = nothing
    recommendations = String[]
    
    # High entropy suggests encryption
    if entropy >= 7.9
        confidence = 0.7
        
        if !isnothing(block_size)
            if block_size == 16
                detected_cipher = :aes
                confidence = 0.8
                
                if is_ecb
                    detected_mode = :ecb
                    push!(recommendations, "ECB mode detected - highly insecure, identical plaintext blocks produce identical ciphertext")
                else
                    # Could be CBC, CTR, GCM, etc.
                    detected_mode = len % 16 == 0 ? :cbc : :ctr
                end
                
            elseif block_size == 8
                # Could be DES, 3DES, or Blowfish
                detected_cipher = :triple_des
                confidence = 0.6
                push!(recommendations, "8-byte block cipher detected - consider upgrading to AES")
            end
        else
            # Stream cipher likely
            detected_cipher = :chacha20
            confidence = 0.5
        end
    elseif entropy >= 7.0
        detected_cipher = :unknown
        confidence = 0.4
        push!(recommendations, "Entropy is high but not consistent with strong encryption")
    else
        detected_cipher = :none
        confidence = 0.8
        push!(recommendations, "Data does not appear to be encrypted")
    end
    
    result = CipherAnalysis(
        data, detected_cipher, confidence, 
        block_size, key_length, detected_mode,
        recommendations
    )
    
    if verbose
        display_cipher_analysis(result)
    end
    
    return result
end

"""
    detect_block_size(data::Vector{UInt8})

Detect block cipher block size.
"""
function detect_block_size(data::Vector{UInt8})::Union{Int, Nothing}
    len = length(data)
    
    # Common block sizes
    for block_size in [16, 8, 32]
        if len % block_size == 0 && len >= block_size * 2
            return block_size
        end
    end
    
    return nothing
end

"""
    detect_ecb_mode(data::Vector{UInt8}, block_size::Union{Int, Nothing})

Detect if ECB mode is being used (repeating blocks).
"""
function detect_ecb_mode(data::Vector{UInt8}, block_size::Union{Int, Nothing})::Bool
    isnothing(block_size) && return false
    length(data) < block_size * 2 && return false
    
    n_blocks = div(length(data), block_size)
    blocks = Set{Vector{UInt8}}()
    
    for i in 1:n_blocks
        start_idx = (i - 1) * block_size + 1
        end_idx = i * block_size
        block = data[start_idx:end_idx]
        
        if block in blocks
            return true
        end
        push!(blocks, block)
    end
    
    return false
end

"""
    display_cipher_analysis(ca::CipherAnalysis)

Display formatted cipher analysis results.
"""
function display_cipher_analysis(ca::CipherAnalysis)
    println()
    println(themed("╔═══════════════════════════════════════════════════════╗", :primary))
    println(themed("║              CIPHER ANALYSIS                          ║", :primary))
    println(themed("╠═══════════════════════════════════════════════════════╣", :primary))
    
    # Data info
    println(themed("║", :primary), " Data Size: ", themed("$(length(ca.ciphertext)) bytes", :cyan))
    
    # Detected cipher
    cipher_str = ca.detected_cipher == :unknown ? "Unknown" :
                 ca.detected_cipher == :none ? "Not Encrypted" :
                 string(ca.detected_cipher)
    cipher_color = ca.detected_cipher == :aes ? :green :
                   ca.detected_cipher == :none ? :red : :yellow
    println(themed("║", :primary), " Cipher: ", themed(uppercase(cipher_str), cipher_color))
    
    # Block size
    if !isnothing(ca.block_size)
        println(themed("║", :primary), " Block Size: ", themed("$(ca.block_size) bytes", :yellow))
    end
    
    # Mode
    if !isnothing(ca.mode)
        mode_color = ca.mode == :ecb ? :red : :green
        println(themed("║", :primary), " Mode: ", themed(uppercase(string(ca.mode)), mode_color))
    end
    
    # Confidence
    conf_color = ca.confidence >= 0.7 ? :green : ca.confidence >= 0.5 ? :yellow : :red
    println(themed("║", :primary), " Confidence: ", themed(@sprintf("%.1f%%", ca.confidence * 100), conf_color))
    
    # Recommendations
    if !isempty(ca.recommendations)
        println(themed("╠═══════════════════════════════════════════════════════╣", :primary))
        println(themed("║", :primary), themed(" Recommendations:", :warning))
        for rec in ca.recommendations
            println(themed("║", :primary), "   • ", themed(rec, :dim))
        end
    end
    
    println(themed("╚═══════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PADDING ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

"""
    detect_padding(data::Vector{UInt8}, block_size::Int)

Detect padding scheme used.
"""
function detect_padding(data::Vector{UInt8}, block_size::Int)::Symbol
    isempty(data) && return :none
    
    last_byte = data[end]
    
    # PKCS#7 padding check
    if last_byte > 0 && last_byte <= block_size
        is_pkcs7 = all(b == last_byte for b in data[end-last_byte+1:end])
        is_pkcs7 && return :pkcs7
    end
    
    # Zero padding check
    if last_byte == 0
        zero_count = 0
        for i in length(data):-1:1
            data[i] == 0 ? zero_count += 1 : break
        end
        zero_count > 0 && return :zero
    end
    
    # ISO 10126 (random padding with length in last byte)
    if last_byte > 0 && last_byte <= block_size
        return :iso10126
    end
    
    return :unknown
end

"""
    strip_padding(data::Vector{UInt8}, padding::Symbol)

Remove padding from decrypted data.
"""
function strip_padding(data::Vector{UInt8}, padding::Symbol)::Vector{UInt8}
    isempty(data) && return data
    
    if padding == :pkcs7
        pad_len = data[end]
        return data[1:end-pad_len]
    elseif padding == :zero
        last_nonzero = findlast(!=(0), data)
        return isnothing(last_nonzero) ? UInt8[] : data[1:last_nonzero]
    else
        return data
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              XOR ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

"""
    xor_bytes(a::Vector{UInt8}, b::Vector{UInt8})

XOR two byte arrays.
"""
function xor_bytes(a::Vector{UInt8}, b::Vector{UInt8})::Vector{UInt8}
    min_len = min(length(a), length(b))
    return [xor(a[i], b[i]) for i in 1:min_len]
end

"""
    repeating_key_xor(data::Vector{UInt8}, key::Vector{UInt8})

Apply repeating-key XOR encryption/decryption.
"""
function repeating_key_xor(data::Vector{UInt8}, key::Vector{UInt8})::Vector{UInt8}
    key_len = length(key)
    return [xor(data[i], key[mod1(i, key_len)]) for i in 1:length(data)]
end

"""
    detect_xor_key_length(ciphertext::Vector{UInt8}, max_key_len::Int = 40)

Detect likely XOR key length using Hamming distance.
"""
function detect_xor_key_length(ciphertext::Vector{UInt8}, max_key_len::Int = 40)::Vector{Tuple{Int, Float64}}
    len = length(ciphertext)
    results = Tuple{Int, Float64}[]
    
    for keysize in 2:min(max_key_len, div(len, 4))
        # Take multiple blocks and compare
        n_blocks = min(4, div(len, keysize))
        n_blocks < 2 && continue
        
        total_distance = 0.0
        n_comparisons = 0
        
        for i in 1:n_blocks-1
            for j in i+1:n_blocks
                block1 = ciphertext[(i-1)*keysize+1 : i*keysize]
                block2 = ciphertext[(j-1)*keysize+1 : j*keysize]
                total_distance += hamming_distance(block1, block2)
                n_comparisons += 1
            end
        end
        
        normalized = (total_distance / n_comparisons) / keysize
        push!(results, (keysize, normalized))
    end
    
    # Sort by normalized distance (lower is better)
    sort!(results, by = x -> x[2])
    return results[1:min(5, length(results))]
end

"""
    hamming_distance(a::Vector{UInt8}, b::Vector{UInt8})

Calculate Hamming distance (number of differing bits).
"""
function hamming_distance(a::Vector{UInt8}, b::Vector{UInt8})::Int
    min_len = min(length(a), length(b))
    distance = 0
    
    for i in 1:min_len
        xored = xor(a[i], b[i])
        distance += count_ones(xored)
    end
    
    return distance
end

# ───────────────────────────────────────────────────────────────────────────────
#                              FREQUENCY ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

# English letter frequency (from most to least common)
const ENGLISH_FREQ = Dict{Char, Float64}(
    'e' => 12.702, 't' => 9.056, 'a' => 8.167, 'o' => 7.507, 'i' => 6.966,
    'n' => 6.749, 's' => 6.327, 'h' => 6.094, 'r' => 5.987, 'd' => 4.253,
    'l' => 4.025, 'c' => 2.782, 'u' => 2.758, 'm' => 2.406, 'w' => 2.360,
    'f' => 2.228, 'g' => 2.015, 'y' => 1.974, 'p' => 1.929, 'b' => 1.492,
    'v' => 0.978, 'k' => 0.772, 'j' => 0.153, 'x' => 0.150, 'q' => 0.095,
    'z' => 0.074, ' ' => 13.0  # Space is very common
)

"""
    english_score(text::String)

Score text based on English character frequency.
Higher score = more likely to be English.
"""
function english_score(text::String)::Float64
    text = lowercase(text)
    score = 0.0
    
    for char in text
        score += get(ENGLISH_FREQ, char, -2.0)
    end
    
    return score / length(text)
end

"""
    single_byte_xor_break(ciphertext::Vector{UInt8})

Attempt to break single-byte XOR encryption.
"""
function single_byte_xor_break(ciphertext::Vector{UInt8})::Tuple{UInt8, String, Float64}
    best_key = UInt8(0)
    best_plaintext = ""
    best_score = -Inf
    
    for key in 0x00:0xff
        plaintext_bytes = [xor(b, key) for b in ciphertext]
        
        # Check if mostly printable
        if all(b -> (b >= 0x20 && b <= 0x7e) || b in [0x0a, 0x0d, 0x09], plaintext_bytes)
            plaintext = String(plaintext_bytes)
            score = english_score(plaintext)
            
            if score > best_score
                best_score = score
                best_key = key
                best_plaintext = plaintext
            end
        end
    end
    
    return (best_key, best_plaintext, best_score)
end
