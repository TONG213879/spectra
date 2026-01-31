# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Pattern Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Pattern recognition and matching for security analysis
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              SECURITY PATTERNS
# ───────────────────────────────────────────────────────────────────────────────

const SECURITY_PATTERNS = Dict{Symbol, Pattern}(
    :sql_injection => Pattern(
        "SQL Injection",
        r"(?i)(?:UNION\s+SELECT|ORDER\s+BY\s+\d|'\s*OR\s*'|'\s*OR\s+\d|WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\()",
        :injection,
        HIGH,
        "Potential SQL injection payload detected",
        [:sql, :injection, :web]
    ),
    
    :xss => Pattern(
        "Cross-Site Scripting",
        r"(?i)<script[^>]*>|javascript:|onerror\s*=|onload\s*=|onclick\s*=",
        :injection,
        HIGH,
        "Potential XSS payload detected",
        [:xss, :injection, :web]
    ),
    
    :path_traversal => Pattern(
        "Path Traversal",
        r"(?:\.\./|\.\.\\|%2e%2e[%/\\])",
        :injection,
        HIGH,
        "Path traversal attempt detected",
        [:traversal, :file, :web]
    ),
    
    :command_injection => Pattern(
        "Command Injection",
        r"(?i)(?:;\s*(?:ls|cat|id|whoami|wget|curl)|`[^`]+`|\$\([^)]+\)|&&\s*\w+|\|\s*\w+)",
        :injection,
        CRITICAL,
        "Command injection attempt detected",
        [:command, :injection, :rce]
    ),
    
    :ldap_injection => Pattern(
        "LDAP Injection",
        r"(?i)(?:\*\)\(|\)\(|\|\(|\)\|)",
        :injection,
        HIGH,
        "LDAP injection attempt detected",
        [:ldap, :injection]
    ),
    
    :xxe => Pattern(
        "XML External Entity",
        r"(?i)<!ENTITY\s+\S+\s+SYSTEM|<!ENTITY\s+%",
        :injection,
        CRITICAL,
        "XXE attack attempt detected",
        [:xxe, :xml, :injection]
    ),
    
    :ssti => Pattern(
        "Server-Side Template Injection",
        r"(?:\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\})",
        :injection,
        HIGH,
        "SSTI payload detected",
        [:ssti, :template, :injection]
    ),
    
    :credential_leak => Pattern(
        "Credential Leak",
        r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?[\w\-_]+",
        :sensitive,
        MEDIUM,
        "Potential credential in data",
        [:credential, :sensitive, :leak]
    ),
    
    :private_key => Pattern(
        "Private Key",
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        :sensitive,
        CRITICAL,
        "Private key detected",
        [:key, :sensitive, :crypto]
    ),
    
    :aws_key => Pattern(
        "AWS Access Key",
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        :sensitive,
        CRITICAL,
        "AWS access key detected",
        [:aws, :cloud, :sensitive]
    ),
    
    :jwt_token => Pattern(
        "JWT Token",
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        :token,
        MEDIUM,
        "JWT token detected",
        [:jwt, :token, :auth]
    ),
    
    :internal_ip => Pattern(
        "Internal IP Address",
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        :network,
        LOW,
        "Internal IP address detected",
        [:ip, :internal, :network]
    ),
    
    :error_disclosure => Pattern(
        "Error Disclosure",
        r"(?i)(?:SQL syntax.*?MySQL|PostgreSQL.*ERROR|ORA-[0-9]+|stack trace|Traceback|Exception in thread)",
        :disclosure,
        MEDIUM,
        "Application error disclosure",
        [:error, :disclosure, :info]
    ),
    
    :directory_listing => Pattern(
        "Directory Listing",
        r"(?i)(?:Index of /|Parent Directory|Directory Listing)",
        :disclosure,
        LOW,
        "Directory listing enabled",
        [:directory, :disclosure]
    ),
)

# ───────────────────────────────────────────────────────────────────────────────
#                              PATTERN MATCHING
# ───────────────────────────────────────────────────────────────────────────────

"""
    match_pattern(text::String, pattern::Pattern)

Match a single pattern against text.
"""
function match_pattern(text::String, pattern::Pattern)::Vector{Match}
    matches = Match[]
    
    for m in eachmatch(pattern.regex, text)
        # Get context (surrounding text)
        start_idx = max(1, m.offset - 20)
        end_idx = min(length(text), m.offset + length(m.match) + 20)
        context = text[start_idx:end_idx]
        
        push!(matches, Match(
            pattern,
            m.match,
            m.offset:m.offset + length(m.match) - 1,
            context,
            1.0
        ))
    end
    
    return matches
end

"""
    scan_for_patterns(text::String; 
                      patterns::Dict{Symbol, Pattern} = SECURITY_PATTERNS,
                      min_severity::ThreatLevel = LOW)

Scan text for security patterns.

# Arguments
- `text`: Text to scan
- `patterns`: Pattern dictionary to use
- `min_severity`: Minimum severity to report

# Returns
- `Vector{Match}`: All matches found
"""
function scan_for_patterns(text::String;
                           patterns::Dict{Symbol, Pattern} = SECURITY_PATTERNS,
                           min_severity::ThreatLevel = LOW)::Vector{Match}
    
    all_matches = Match[]
    
    for (name, pattern) in patterns
        Int(pattern.severity) >= Int(min_severity) || continue
        
        matches = match_pattern(text, pattern)
        append!(all_matches, matches)
    end
    
    # Sort by severity (highest first)
    sort!(all_matches, by = m -> -Int(m.pattern.severity))
    
    return all_matches
end

"""
    display_pattern_matches(matches::Vector{Match})

Display formatted pattern match results.
"""
function display_pattern_matches(matches::Vector{Match})
    isempty(matches) && return println(themed("[*] No patterns detected", :info))
    
    println()
    println(themed("╔═══════════════════════════════════════════════════════════╗", :primary))
    println(themed("║                  PATTERN ANALYSIS                         ║", :primary))
    println(themed("╠═══════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), " Found: ", themed("$(length(matches)) matches", :yellow))
    println(themed("╠═══════════════════════════════════════════════════════════╣", :primary))
    
    for match in matches
        badge = threat_badge(match.pattern.severity)
        println(themed("║", :primary))
        println(themed("║", :primary), " ", badge, " ", themed(match.pattern.name, :cyan))
        println(themed("║", :primary), "   Match: ", themed(match.text, :yellow))
        println(themed("║", :primary), "   ", themed(match.pattern.description, :dim))
    end
    
    println(themed("║", :primary))
    println(themed("╚═══════════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              FILE PATTERN SCANNING
# ───────────────────────────────────────────────────────────────────────────────

"""
    scan_file_patterns(filepath::String; verbose::Bool = CONFIG.verbose)

Scan file for security patterns.
"""
function scan_file_patterns(filepath::String; verbose::Bool = CONFIG.verbose)::Vector{Match}
    isfile(filepath) || error("File not found: $filepath")
    
    text = read(filepath, String)
    matches = scan_for_patterns(text)
    
    if verbose
        println(themed("\n[*] Pattern Scan: $filepath", :info))
        display_pattern_matches(matches)
    end
    
    return matches
end

"""
    scan_directory_patterns(directory::String;
                            extensions::Vector{String} = [".txt", ".log", ".conf", ".json", ".xml", ".yaml", ".yml"],
                            verbose::Bool = CONFIG.verbose)

Scan directory for security patterns.
"""
function scan_directory_patterns(directory::String;
                                 extensions::Vector{String} = [".txt", ".log", ".conf", ".json", ".xml", ".yaml", ".yml"],
                                 verbose::Bool = CONFIG.verbose)::Dict{String, Vector{Match}}
    
    isdir(directory) || error("Directory not found: $directory")
    
    results = Dict{String, Vector{Match}}()
    
    verbose && println(themed("[*] Scanning directory: $directory", :info))
    
    for (root, dirs, files) in walkdir(directory)
        for file in files
            ext = lowercase(splitext(file)[2])
            ext in extensions || continue
            
            filepath = joinpath(root, file)
            try
                matches = scan_file_patterns(filepath, verbose=false)
                if !isempty(matches)
                    results[filepath] = matches
                    verbose && println(themed("[+] $(length(matches)) matches in $filepath", :success))
                end
            catch
                continue
            end
        end
    end
    
    verbose && println(themed("\n[*] Scanned $(length(results)) files with findings", :info))
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              CUSTOM PATTERNS
# ───────────────────────────────────────────────────────────────────────────────

"""
    create_pattern(name::String, regex::Regex, category::Symbol,
                   severity::ThreatLevel, description::String;
                   tags::Vector{Symbol} = Symbol[])

Create custom pattern for scanning.
"""
function create_pattern(name::String, regex::Regex, category::Symbol,
                        severity::ThreatLevel, description::String;
                        tags::Vector{Symbol} = Symbol[])::Pattern
    return Pattern(name, regex, category, severity, description, tags)
end

"""
    add_pattern!(patterns::Dict{Symbol, Pattern}, name::Symbol, pattern::Pattern)

Add pattern to pattern dictionary.
"""
function add_pattern!(patterns::Dict{Symbol, Pattern}, name::Symbol, pattern::Pattern)
    patterns[name] = pattern
end

"""
    load_patterns_from_file(filepath::String)

Load patterns from TOML file.
"""
function load_patterns_from_file(filepath::String)::Dict{Symbol, Pattern}
    isfile(filepath) || error("Pattern file not found: $filepath")
    
    config = TOML.parsefile(filepath)
    patterns = Dict{Symbol, Pattern}()
    
    for (name, def) in get(config, "patterns", Dict())
        severity = Symbol(get(def, "severity", "medium"))
        severity_level = Dict(
            :critical => CRITICAL,
            :high => HIGH,
            :medium => MEDIUM,
            :low => LOW,
            :info => INFO
        )[severity]
        
        pattern = Pattern(
            get(def, "name", name),
            Regex(def["regex"]),
            Symbol(get(def, "category", "custom")),
            severity_level,
            get(def, "description", ""),
            Symbol.(get(def, "tags", String[]))
        )
        
        patterns[Symbol(name)] = pattern
    end
    
    return patterns
end
