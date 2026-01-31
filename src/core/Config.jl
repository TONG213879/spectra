# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Configuration
# ═══════════════════════════════════════════════════════════════════════════════
# Advanced configuration management system
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              CONFIGURATION PATHS
# ───────────────────────────────────────────────────────────────────────────────

const CONFIG_PATHS = [
    joinpath(homedir(), ".config", "spectra", "config.toml"),
    joinpath(homedir(), ".spectra.toml"),
    "spectra.toml",
    "/etc/spectra/config.toml"
]

# ───────────────────────────────────────────────────────────────────────────────
#                              CONFIGURATION DEFAULTS
# ───────────────────────────────────────────────────────────────────────────────

const DEFAULTS = Dict{String, Any}(
    "general" => Dict(
        "theme" => "hacker",
        "verbose" => true,
        "parallel" => true,
        "max_threads" => 8,
        "log_level" => "info"
    ),
    "network" => Dict(
        "timeout" => 5.0,
        "rate_limit" => 1000,
        "max_retries" => 3,
        "backoff_factor" => 1.5,
        "user_agent" => "Spectra/1.0"
    ),
    "scanning" => Dict(
        "default_ports" => "1-1000",
        "timing" => "normal",
        "randomize" => true,
        "stealth" => false
    ),
    "crypto" => Dict(
        "hash_all_algorithms" => true,
        "entropy_threshold" => 7.5,
        "block_sizes" => [8, 16, 32]
    ),
    "output" => Dict(
        "colors" => true,
        "unicode" => true,
        "json" => false,
        "quiet" => false
    ),
    "nullsec" => Dict(
        "enabled" => true,
        "path" => "/opt/nullsec",
        "sync" => false
    )
)

# ───────────────────────────────────────────────────────────────────────────────
#                              CONFIGURATION API
# ───────────────────────────────────────────────────────────────────────────────

"""
    find_config()

Search for configuration file in standard locations.
"""
function find_config()::Union{String, Nothing}
    for path in CONFIG_PATHS
        isfile(path) && return path
    end
    return nothing
end

"""
    load_config(path::Union{String, Nothing} = nothing)

Load configuration from file or use defaults.
"""
function load_config(path::Union{String, Nothing} = nothing)::Dict{String, Any}
    config = deepcopy(DEFAULTS)
    
    cfg_path = something(path, find_config())
    
    if !isnothing(cfg_path) && isfile(cfg_path)
        try
            user_config = TOML.parsefile(cfg_path)
            merge_config!(config, user_config)
            CONFIG.verbose && println(colorize("[+] Loaded config: $cfg_path", :green))
        catch e
            @warn "Failed to parse config file" exception=e
        end
    end
    
    return config
end

"""
    merge_config!(base::Dict, override::Dict)

Recursively merge configuration dictionaries.
"""
function merge_config!(base::Dict, override::Dict)
    for (key, value) in override
        if haskey(base, key) && isa(base[key], Dict) && isa(value, Dict)
            merge_config!(base[key], value)
        else
            base[key] = value
        end
    end
end

"""
    save_config(config::Dict, path::String)

Save configuration to TOML file.
"""
function save_config(config::Dict, path::String)
    dir = dirname(path)
    !isdir(dir) && mkpath(dir)
    
    open(path, "w") do io
        println(io, "# Spectra Configuration File")
        println(io, "# Generated: $(now())")
        println(io)
        TOML.print(io, config)
    end
    
    CONFIG.verbose && println(colorize("[+] Configuration saved: $path", :green))
end

"""
    create_default_config(path::String = CONFIG_PATHS[1])

Create default configuration file.
"""
function create_default_config(path::String = CONFIG_PATHS[1])
    save_config(DEFAULTS, path)
end

"""
    get_config(section::String, key::String, default = nothing)

Get configuration value with fallback.
"""
function get_config(section::String, key::String, default = nothing)
    config = load_config()
    return get(get(config, section, Dict()), key, default)
end

"""
    set_config!(section::String, key::String, value)

Set configuration value in memory.
"""
function set_config!(section::String, key::String, value)
    if section == "general"
        key == "verbose" && (CONFIG.verbose = value)
        key == "parallel" && (CONFIG.parallel = value)
        key == "max_threads" && (CONFIG.max_threads = value)
        key == "theme" && (CONFIG.theme = Symbol(value))
    elseif section == "network"
        key == "timeout" && (CONFIG.timeout = value)
        key == "rate_limit" && (CONFIG.rate_limit = value)
    elseif section == "output"
        key == "colors" && (CONFIG.colors = value)
        key == "unicode" && (CONFIG.unicode = value)
    elseif section == "nullsec"
        key == "enabled" && (CONFIG.nullsec_integration = value)
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              THEMES
# ───────────────────────────────────────────────────────────────────────────────

const THEMES = Dict{Symbol, Dict{Symbol, Symbol}}(
    :hacker => Dict(
        :primary => :green,
        :secondary => :cyan,
        :accent => :magenta,
        :warning => :yellow,
        :error => :red,
        :success => :green,
        :info => :blue,
        :dim => :dim
    ),
    :minimal => Dict(
        :primary => :white,
        :secondary => :dim,
        :accent => :cyan,
        :warning => :yellow,
        :error => :red,
        :success => :green,
        :info => :blue,
        :dim => :dim
    ),
    :colorful => Dict(
        :primary => :magenta,
        :secondary => :cyan,
        :accent => :yellow,
        :warning => :yellow,
        :error => :red,
        :success => :green,
        :info => :blue,
        :dim => :dim
    ),
    :nullsec => Dict(
        :primary => :red,
        :secondary => :cyan,
        :accent => :magenta,
        :warning => :yellow,
        :error => :red,
        :success => :green,
        :info => :cyan,
        :dim => :dim
    )
)

"""
    get_theme_color(role::Symbol)

Get color for current theme and role.
"""
function get_theme_color(role::Symbol)::Symbol
    theme = get(THEMES, CONFIG.theme, THEMES[:hacker])
    return get(theme, role, :white)
end

"""
    themed(text::String, role::Symbol)

Apply themed color to text.
"""
function themed(text::String, role::Symbol)
    colorize(text, get_theme_color(role))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              ENVIRONMENT
# ───────────────────────────────────────────────────────────────────────────────

"""
    from_env!(config::Dict)

Override config from environment variables.

Supports:
- SPECTRA_VERBOSE
- SPECTRA_PARALLEL
- SPECTRA_TIMEOUT
- SPECTRA_COLORS
- SPECTRA_THEME
- SPECTRA_NULLSEC_PATH
"""
function from_env!(config::Dict)
    env_mappings = Dict(
        "SPECTRA_VERBOSE" => ("general", "verbose", x -> lowercase(x) in ["true", "1", "yes"]),
        "SPECTRA_PARALLEL" => ("general", "parallel", x -> lowercase(x) in ["true", "1", "yes"]),
        "SPECTRA_TIMEOUT" => ("network", "timeout", x -> parse(Float64, x)),
        "SPECTRA_COLORS" => ("output", "colors", x -> lowercase(x) in ["true", "1", "yes"]),
        "SPECTRA_THEME" => ("general", "theme", identity),
        "SPECTRA_NULLSEC_PATH" => ("nullsec", "path", identity),
    )
    
    for (env_var, (section, key, parser)) in env_mappings
        val = get(ENV, env_var, nothing)
        if !isnothing(val)
            try
                config[section][key] = parser(val)
            catch e
                @warn "Failed to parse env var $env_var" exception=e
            end
        end
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              VALIDATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    validate_config(config::Dict)

Validate configuration values.
"""
function validate_config(config::Dict)::Tuple{Bool, Vector{String}}
    errors = String[]
    
    # Validate timeout
    timeout = get(get(config, "network", Dict()), "timeout", 5.0)
    if timeout <= 0 || timeout > 300
        push!(errors, "network.timeout must be between 0 and 300 seconds")
    end
    
    # Validate rate limit
    rate_limit = get(get(config, "network", Dict()), "rate_limit", 1000)
    if rate_limit <= 0 || rate_limit > 100000
        push!(errors, "network.rate_limit must be between 1 and 100000")
    end
    
    # Validate max threads
    max_threads = get(get(config, "general", Dict()), "max_threads", 8)
    if max_threads < 1 || max_threads > 256
        push!(errors, "general.max_threads must be between 1 and 256")
    end
    
    # Validate theme
    theme = Symbol(get(get(config, "general", Dict()), "theme", "hacker"))
    if !haskey(THEMES, theme)
        push!(errors, "Invalid theme: $theme. Available: $(join(keys(THEMES), ", "))")
    end
    
    return (isempty(errors), errors)
end
