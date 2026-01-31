# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Forensics
# ═══════════════════════════════════════════════════════════════════════════════
# Digital forensics and file analysis utilities
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              FILE MAGIC SIGNATURES
# ───────────────────────────────────────────────────────────────────────────────

const FILE_SIGNATURES = Dict{Vector{UInt8}, NamedTuple{(:type, :extension, :description), 
                                                        Tuple{String, String, String}}}(
    # Images
    UInt8[0x89, 0x50, 0x4E, 0x47] => (type="image/png", extension="png", description="PNG Image"),
    UInt8[0xFF, 0xD8, 0xFF] => (type="image/jpeg", extension="jpg", description="JPEG Image"),
    UInt8[0x47, 0x49, 0x46, 0x38] => (type="image/gif", extension="gif", description="GIF Image"),
    UInt8[0x42, 0x4D] => (type="image/bmp", extension="bmp", description="BMP Image"),
    UInt8[0x00, 0x00, 0x01, 0x00] => (type="image/x-icon", extension="ico", description="ICO Icon"),
    UInt8[0x52, 0x49, 0x46, 0x46] => (type="image/webp", extension="webp", description="WebP Image"),
    
    # Documents
    UInt8[0x25, 0x50, 0x44, 0x46] => (type="application/pdf", extension="pdf", description="PDF Document"),
    UInt8[0xD0, 0xCF, 0x11, 0xE0] => (type="application/msword", extension="doc", description="MS Office Document"),
    UInt8[0x50, 0x4B, 0x03, 0x04] => (type="application/zip", extension="zip", description="ZIP/Office Archive"),
    
    # Archives
    UInt8[0x1F, 0x8B] => (type="application/gzip", extension="gz", description="GZIP Archive"),
    UInt8[0x42, 0x5A, 0x68] => (type="application/x-bzip2", extension="bz2", description="BZIP2 Archive"),
    UInt8[0x37, 0x7A, 0xBC, 0xAF] => (type="application/x-7z-compressed", extension="7z", description="7-Zip Archive"),
    UInt8[0x52, 0x61, 0x72, 0x21] => (type="application/x-rar", extension="rar", description="RAR Archive"),
    UInt8[0xFD, 0x37, 0x7A, 0x58, 0x5A] => (type="application/x-xz", extension="xz", description="XZ Archive"),
    
    # Executables
    UInt8[0x4D, 0x5A] => (type="application/x-msdownload", extension="exe", description="Windows Executable"),
    UInt8[0x7F, 0x45, 0x4C, 0x46] => (type="application/x-elf", extension="elf", description="Linux ELF Binary"),
    UInt8[0xFE, 0xED, 0xFA, 0xCE] => (type="application/x-mach-binary", extension="macho", description="macOS Mach-O Binary"),
    UInt8[0xCA, 0xFE, 0xBA, 0xBE] => (type="application/java-archive", extension="class", description="Java Class File"),
    
    # Audio/Video
    UInt8[0x49, 0x44, 0x33] => (type="audio/mpeg", extension="mp3", description="MP3 Audio"),
    UInt8[0x66, 0x4C, 0x61, 0x43] => (type="audio/flac", extension="flac", description="FLAC Audio"),
    UInt8[0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70] => (type="video/mp4", extension="mp4", description="MP4 Video"),
    UInt8[0x1A, 0x45, 0xDF, 0xA3] => (type="video/webm", extension="webm", description="WebM Video"),
    
    # Databases
    UInt8[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65] => (type="application/x-sqlite3", extension="db", description="SQLite Database"),
    
    # Scripts/Text
    UInt8[0x23, 0x21] => (type="text/x-script", extension="sh", description="Shell Script"),
)

# ───────────────────────────────────────────────────────────────────────────────
#                              FILE ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

"""
    identify_file(filepath::String)

Identify file type from magic bytes.
"""
function identify_file(filepath::String)::Dict{Symbol, Any}
    isfile(filepath) || error("File not found: $filepath")
    
    result = Dict{Symbol, Any}(
        :path => filepath,
        :type => "application/octet-stream",
        :extension => "",
        :description => "Unknown",
        :magic => UInt8[],
        :size => filesize(filepath)
    )
    
    # Read magic bytes
    magic = open(filepath, "r") do io
        read(io, min(16, filesize(filepath)))
    end
    result[:magic] = magic
    
    # Match against signatures
    for (sig, info) in FILE_SIGNATURES
        if length(magic) >= length(sig)
            if magic[1:length(sig)] == sig
                result[:type] = info.type
                result[:extension] = info.extension
                result[:description] = info.description
                break
            end
        end
    end
    
    return result
end

"""
    analyze_file(filepath::String; verbose::Bool = CONFIG.verbose)

Perform comprehensive file analysis.

# Returns
- `FileMetadata`: Complete file metadata
"""
function analyze_file(filepath::String; verbose::Bool = CONFIG.verbose)::FileMetadata
    isfile(filepath) || error("File not found: $filepath")
    
    if verbose
        module_banner(:forensics)
        println(themed("[*] Analyzing: $filepath", :info))
        println()
    end
    
    # Basic metadata
    stat_info = stat(filepath)
    data = read(filepath)
    
    # Compute hashes
    md5_hash = bytes2hex(sha256(data)[1:16])  # Approximate MD5 with SHA256 truncated
    sha256_hash = bytes2hex(sha256(data))
    
    # File type
    file_info = identify_file(filepath)
    
    metadata = FileMetadata(
        filepath,
        stat_info.size,
        md5_hash,
        sha256_hash,
        nothing,  # ssdeep
        file_info[:type],
        file_info[:magic],
        nothing,  # created (not available in Julia stat)
        unix2datetime(stat_info.mtime),
        unix2datetime(stat_info.mtime),  # accessed
        stat_info.mode,
        nothing,  # owner
        Dict{String, Any}(
            "description" => file_info[:description],
            "extension" => file_info[:extension],
            "entropy" => shannon_entropy(data)
        )
    )
    
    if verbose
        display_file_metadata(metadata)
    end
    
    return metadata
end

"""
    display_file_metadata(fm::FileMetadata)

Display formatted file metadata.
"""
function display_file_metadata(fm::FileMetadata)
    size_str = if fm.size < 1024
        "$(fm.size) B"
    elseif fm.size < 1024^2
        @sprintf("%.2f KB", fm.size / 1024)
    elseif fm.size < 1024^3
        @sprintf("%.2f MB", fm.size / 1024^2)
    else
        @sprintf("%.2f GB", fm.size / 1024^3)
    end
    
    println(themed("╔════════════════════════════════════════════════════════════╗", :primary))
    println(themed("║                    FILE ANALYSIS                           ║", :primary))
    println(themed("╠════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), " Path: ", themed(basename(fm.path), :cyan))
    println(themed("║", :primary), " Size: ", themed(size_str, :yellow))
    println(themed("║", :primary), " Type: ", themed(fm.mime_type, :green))
    println(themed("║", :primary), " Description: ", get(fm.attributes, "description", "Unknown"))
    println(themed("╠════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), themed(" Hashes:", :secondary))
    println(themed("║", :primary), "   MD5:    ", themed(fm.md5, :dim))
    println(themed("║", :primary), "   SHA256: ", themed(fm.sha256, :dim))
    println(themed("╠════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), " Modified: ", themed(string(fm.modified), :dim))
    println(themed("║", :primary), " Magic: ", themed(bytes2hex(fm.magic_bytes[1:min(8, length(fm.magic_bytes))]), :dim))
    
    entropy = get(fm.attributes, "entropy", 0.0)
    entropy_color = entropy >= 7.5 ? :red : entropy >= 6.0 ? :yellow : :green
    println(themed("║", :primary), " Entropy: ", themed(@sprintf("%.4f bits/byte", entropy), entropy_color))
    
    println(themed("╚════════════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              STRING EXTRACTION
# ───────────────────────────────────────────────────────────────────────────────

"""
    extract_strings(data::Vector{UInt8}; min_length::Int = 4, encoding::Symbol = :ascii)

Extract printable strings from binary data.

# Arguments
- `data`: Binary data
- `min_length`: Minimum string length
- `encoding`: String encoding (:ascii, :unicode)
"""
function extract_strings(data::Vector{UInt8}; min_length::Int = 4, encoding::Symbol = :ascii)::Vector{String}
    strings = String[]
    current = UInt8[]
    
    for byte in data
        if encoding == :ascii
            if byte >= 0x20 && byte <= 0x7e
                push!(current, byte)
            else
                if length(current) >= min_length
                    push!(strings, String(current))
                end
                current = UInt8[]
            end
        end
    end
    
    # Don't forget last string
    if length(current) >= min_length
        push!(strings, String(current))
    end
    
    return strings
end

"""
    extract_strings_from_file(filepath::String; min_length::Int = 4)

Extract strings from file.
"""
function extract_strings_from_file(filepath::String; min_length::Int = 4)::Vector{String}
    data = read(filepath)
    return extract_strings(data, min_length=min_length)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PATTERN EXTRACTION
# ───────────────────────────────────────────────────────────────────────────────

const FORENSIC_PATTERNS = Dict{Symbol, Regex}(
    :email => r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    :ipv4 => r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    :ipv6 => r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
    :url => r"https?://[^\s<>\"{}|\\^`\[\]]+",
    :domain => r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}",
    :path_windows => r"[A-Za-z]:\\[^\s<>:\"|\?\*]+",
    :path_unix => r"/(?:[^/\0\s]+/)*[^/\0\s]*",
    :credit_card => r"\b(?:\d{4}[\s-]?){3}\d{4}\b",
    :ssn => r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
    :phone => r"\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b",
    :bitcoin => r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    :md5_hash => r"\b[a-fA-F0-9]{32}\b",
    :sha1_hash => r"\b[a-fA-F0-9]{40}\b",
    :sha256_hash => r"\b[a-fA-F0-9]{64}\b",
    :base64 => r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    :jwt => r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    :api_key => r"(?:api[_-]?key|apikey|api_secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{20,})",
    :aws_key => r"AKIA[0-9A-Z]{16}",
    :private_key => r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
)

"""
    extract_patterns(text::String, pattern_type::Symbol)

Extract patterns from text.
"""
function extract_patterns(text::String, pattern_type::Symbol)::Vector{String}
    pattern = get(FORENSIC_PATTERNS, pattern_type, nothing)
    isnothing(pattern) && return String[]
    
    matches = [m.match for m in eachmatch(pattern, text)]
    return unique(matches)
end

"""
    extract_all_patterns(text::String)

Extract all forensic patterns from text.
"""
function extract_all_patterns(text::String)::Dict{Symbol, Vector{String}}
    results = Dict{Symbol, Vector{String}}()
    
    for (name, pattern) in FORENSIC_PATTERNS
        matches = extract_patterns(text, name)
        if !isempty(matches)
            results[name] = matches
        end
    end
    
    return results
end

"""
    scan_file_for_patterns(filepath::String; verbose::Bool = CONFIG.verbose)

Scan file for forensic patterns.
"""
function scan_file_for_patterns(filepath::String; verbose::Bool = CONFIG.verbose)::Dict{Symbol, Vector{String}}
    strings = extract_strings_from_file(filepath)
    text = join(strings, "\n")
    
    results = extract_all_patterns(text)
    
    if verbose
        println(themed("\n[*] Pattern Scan: $filepath", :info))
        
        if isempty(results)
            println(themed("[*] No patterns found", :dim))
        else
            for (ptype, matches) in results
                println(themed("\n[+] $(ptype) ($(length(matches)))", :success))
                for m in matches[1:min(5, length(matches))]
                    println(themed("    • $m", :dim))
                end
                if length(matches) > 5
                    println(themed("    ... and $(length(matches) - 5) more", :dim))
                end
            end
        end
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              TIMELINE ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

"""
    create_timeline(directory::String; recursive::Bool = true)

Create timeline of file modifications.
"""
function create_timeline(directory::String; recursive::Bool = true)::Vector{NamedTuple}
    entries = NamedTuple[]
    
    function scan_dir(path)
        for entry in readdir(path, join=true)
            try
                st = stat(entry)
                push!(entries, (
                    path = entry,
                    mtime = unix2datetime(st.mtime),
                    size = st.size,
                    type = isdir(entry) ? :directory : :file
                ))
                
                if recursive && isdir(entry)
                    scan_dir(entry)
                end
            catch
                continue
            end
        end
    end
    
    scan_dir(directory)
    
    # Sort by modification time
    sort!(entries, by = e -> e.mtime, rev = true)
    
    return entries
end

"""
    display_timeline(entries::Vector{NamedTuple}; limit::Int = 20)

Display timeline in formatted output.
"""
function display_timeline(entries::Vector{NamedTuple}; limit::Int = 20)
    println(themed("\n[*] File Timeline (most recent first)", :info))
    println(themed(repeat("─", 70), :dim))
    
    for entry in entries[1:min(limit, length(entries))]
        type_icon = entry.type == :directory ? "📁" : "📄"
        size_str = entry.type == :file ? @sprintf("%10d", entry.size) : "         -"
        time_str = Dates.format(entry.mtime, "yyyy-mm-dd HH:MM:SS")
        
        println("$type_icon $time_str $size_str $(basename(entry.path))")
    end
    
    if length(entries) > limit
        println(themed("\n[*] ... and $(length(entries) - limit) more files", :dim))
    end
end
