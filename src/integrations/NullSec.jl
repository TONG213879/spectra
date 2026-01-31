# ═══════════════════════════════════════════════════════════════════════════════
#                           SPECTRA - NullSec Integration
# ═══════════════════════════════════════════════════════════════════════════════
# Integration bridge for NullSec Linux security platform
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              CONFIGURATION
# ───────────────────────────────────────────────────────────────────────────────

const NULLSEC_DEFAULT_PATHS = Dict{Symbol, String}(
    :home => expanduser("~/nullsec"),
    :modules => expanduser("~/nullsec/nullsecurity"),
    :resources => expanduser("~/nullsec/resources"),
    :logs => expanduser("~/nullsec/logs"),
    :targets => expanduser("~/nullsec/logs/targets"),
    :config => expanduser("~/.config/nullsec"),
)

"""
    NullSecConfig

Configuration for NullSec integration.
"""
mutable struct NullSecConfig
    enabled::Bool
    base_path::String
    modules_path::String
    logs_path::String
    auto_log::Bool
    sync_config::Bool
    api_endpoint::Union{String, Nothing}
end

function NullSecConfig()
    NullSecConfig(
        false,
        get(ENV, "NULLSEC_HOME", NULLSEC_DEFAULT_PATHS[:home]),
        get(ENV, "NULLSEC_MODULES", NULLSEC_DEFAULT_PATHS[:modules]),
        get(ENV, "NULLSEC_LOGS", NULLSEC_DEFAULT_PATHS[:logs]),
        true,
        true,
        nothing
    )
end

# Global NullSec config
const NULLSEC_CONFIG = Ref{NullSecConfig}(NullSecConfig())

# ───────────────────────────────────────────────────────────────────────────────
#                              DETECTION & INIT
# ───────────────────────────────────────────────────────────────────────────────

"""
    detect_nullsec()

Detect if NullSec Linux environment is available.
"""
function detect_nullsec()::Bool
    # Check common paths
    for path in values(NULLSEC_DEFAULT_PATHS)
        isdir(path) && return true
    end
    
    # Check environment variables
    haskey(ENV, "NULLSEC_HOME") && return true
    haskey(ENV, "NULLSEC_VERSION") && return true
    
    # Check for nullsec command
    try
        run(pipeline(`which nullsec-ai`, stdout=devnull, stderr=devnull))
        return true
    catch
        # Not found
    end
    
    return false
end

"""
    init_nullsec!()

Initialize NullSec integration.
"""
function init_nullsec!()::Bool
    config = NULLSEC_CONFIG[]
    
    if !detect_nullsec()
        config.enabled = false
        return false
    end
    
    # Update paths if needed
    if haskey(ENV, "NULLSEC_HOME")
        config.base_path = ENV["NULLSEC_HOME"]
        config.modules_path = joinpath(config.base_path, "nullsecurity")
        config.logs_path = joinpath(config.base_path, "logs")
    end
    
    config.enabled = true
    
    # Create integration directory if needed
    spectra_dir = joinpath(config.logs_path, "spectra")
    !isdir(spectra_dir) && mkpath(spectra_dir)
    
    return true
end

"""
    nullsec_status()

Get NullSec integration status.
"""
function nullsec_status()::Dict{Symbol, Any}
    config = NULLSEC_CONFIG[]
    
    status = Dict{Symbol, Any}(
        :enabled => config.enabled,
        :detected => detect_nullsec(),
        :base_path => config.base_path,
        :modules_available => isdir(config.modules_path),
        :logs_available => isdir(config.logs_path),
    )
    
    if status[:modules_available]
        status[:module_count] = length(filter(
            f -> endswith(f, ".py") || endswith(f, ".sh") || endswith(f, ".json"),
            readdir(config.modules_path)
        ))
    end
    
    return status
end

# ───────────────────────────────────────────────────────────────────────────────
#                              MODULE MANAGEMENT
# ───────────────────────────────────────────────────────────────────────────────

"""
    NullSecModule

Information about a NullSec module.
"""
struct NullSecModule
    name::String
    path::String
    type::Symbol
    description::String
    category::Symbol
end

"""
    list_modules()

List available NullSec modules.
"""
function list_modules()::Vector{NullSecModule}
    config = NULLSEC_CONFIG[]
    modules = NullSecModule[]
    
    !config.enabled && return modules
    !isdir(config.modules_path) && return modules
    
    for entry in readdir(config.modules_path)
        path = joinpath(config.modules_path, entry)
        
        if isfile(path)
            ext = splitext(entry)[2]
            name = splitext(entry)[1]
            
            type = if ext == ".py"
                :python
            elseif ext == ".sh"
                :bash
            elseif ext == ".json"
                :config
            else
                continue  # Skip unknown types
            end
            
            # Try to get module info from JSON config
            desc, cat = get_module_info(name, config.modules_path)
            
            push!(modules, NullSecModule(name, path, type, desc, cat))
        end
    end
    
    return modules
end

"""
    get_module_info(name::String, path::String)

Get module description and category from JSON config.
"""
function get_module_info(name::String, path::String)::Tuple{String, Symbol}
    json_path = joinpath(path, "$name.json")
    
    if isfile(json_path)
        try
            content = read(json_path, String)
            data = JSON3.read(content)
            desc = get(data, :description, "NullSec module")
            cat = Symbol(get(data, :category, "other"))
            return (desc, cat)
        catch
            # Fall through
        end
    end
    
    return ("NullSec module", :other)
end

"""
    find_module(name::String)

Find a specific NullSec module.
"""
function find_module(name::String)::Union{NullSecModule, Nothing}
    modules = list_modules()
    
    for mod in modules
        if lowercase(mod.name) == lowercase(name)
            return mod
        end
    end
    
    return nothing
end

# ───────────────────────────────────────────────────────────────────────────────
#                              LOGGING INTEGRATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    SpectraLog

Spectra log entry for NullSec integration.
"""
struct SpectraLog
    timestamp::DateTime
    operation::Symbol
    target::String
    results::Dict{Symbol, Any}
    threats::Vector{Threat}
end

"""
    log_to_nullsec(log::SpectraLog)

Save Spectra log to NullSec logs directory.
"""
function log_to_nullsec(log::SpectraLog)::String
    config = NULLSEC_CONFIG[]
    
    !config.enabled && return ""
    !config.auto_log && return ""
    
    spectra_dir = joinpath(config.logs_path, "spectra")
    !isdir(spectra_dir) && mkpath(spectra_dir)
    
    timestamp_str = Dates.format(log.timestamp, "yyyy-mm-dd_HH-MM-SS")
    filename = "spectra_$(log.operation)_$(timestamp_str).json"
    filepath = joinpath(spectra_dir, filename)
    
    # Prepare log data
    log_data = Dict{Symbol, Any}(
        :spectra_version => "1.0.0",
        :timestamp => string(log.timestamp),
        :operation => string(log.operation),
        :target => log.target,
        :results => log.results,
        :threat_count => length(log.threats),
        :threats => [
            Dict(
                :type => t.type,
                :description => t.description,
                :level => string(t.level),
                :category => string(t.category),
                :timestamp => string(t.timestamp)
            ) for t in log.threats
        ]
    )
    
    # Write JSON
    open(filepath, "w") do io
        JSON3.write(io, log_data)
    end
    
    return filepath
end

"""
    log_scan_result(target::String, result::ScanResult)

Log a scan result to NullSec.
"""
function log_scan_result(target::String, result::ScanResult)::String
    threats = Threat[]
    
    # Convert open ports to threats based on service
    for port in result.open_ports
        # High-risk ports
        if port in [21, 23, 512, 513, 514, 1433, 3306, 3389, 5432]
            push!(threats, Threat(
                "Sensitive Service Exposed",
                "Port $port is open and may expose sensitive data",
                MEDIUM,
                :info_disclosure,
                now()
            ))
        end
    end
    
    log = SpectraLog(
        now(), :scan, target,
        Dict{Symbol, Any}(
            :open_ports => result.open_ports,
            :services => result.services,
            :duration_ms => result.duration_ms
        ),
        threats
    )
    
    return log_to_nullsec(log)
end

"""
    get_nullsec_logs(;operation::Union{Symbol, Nothing} = nothing,
                     days::Int = 7)

Retrieve Spectra logs from NullSec.
"""
function get_nullsec_logs(;operation::Union{Symbol, Nothing} = nothing,
                          days::Int = 7)::Vector{SpectraLog}
    config = NULLSEC_CONFIG[]
    logs = SpectraLog[]
    
    !config.enabled && return logs
    
    spectra_dir = joinpath(config.logs_path, "spectra")
    !isdir(spectra_dir) && return logs
    
    cutoff = now() - Day(days)
    
    for file in readdir(spectra_dir)
        !endswith(file, ".json") && continue
        
        filepath = joinpath(spectra_dir, file)
        
        try
            content = read(filepath, String)
            data = JSON3.read(content)
            
            timestamp = DateTime(data[:timestamp])
            timestamp < cutoff && continue
            
            op = Symbol(data[:operation])
            operation !== nothing && op != operation && continue
            
            threats = [
                Threat(
                    t[:type],
                    t[:description],
                    parse_threat_level(string(t[:level])),
                    Symbol(t[:category]),
                    DateTime(t[:timestamp])
                ) for t in get(data, :threats, [])
            ]
            
            push!(logs, SpectraLog(
                timestamp, op,
                data[:target],
                Dict{Symbol, Any}(pairs(data[:results])),
                threats
            ))
        catch e
            # Skip malformed logs
            continue
        end
    end
    
    # Sort by timestamp descending
    sort!(logs, by = l -> l.timestamp, rev = true)
    
    return logs
end

"""
    parse_threat_level(s::String)

Parse threat level from string.
"""
function parse_threat_level(s::String)::ThreatLevel
    s = uppercase(s)
    s == "CRITICAL" && return CRITICAL
    s == "HIGH" && return HIGH
    s == "MEDIUM" && return MEDIUM
    s == "LOW" && return LOW
    return INFO
end

# ───────────────────────────────────────────────────────────────────────────────
#                              TARGET MANAGEMENT
# ───────────────────────────────────────────────────────────────────────────────

"""
    NullSecTarget

Target from NullSec target list.
"""
struct NullSecTarget
    name::String
    ip::String
    ports::Vector{Int}
    notes::String
    added::DateTime
end

"""
    get_targets()

Get targets from NullSec target list.
"""
function get_targets()::Vector{NullSecTarget}
    config = NULLSEC_CONFIG[]
    targets = NullSecTarget[]
    
    !config.enabled && return targets
    
    targets_dir = joinpath(config.logs_path, "targets")
    !isdir(targets_dir) && return targets
    
    for file in readdir(targets_dir)
        !endswith(file, ".json") && continue
        
        filepath = joinpath(targets_dir, file)
        
        try
            content = read(filepath, String)
            data = JSON3.read(content)
            
            push!(targets, NullSecTarget(
                get(data, :name, splitext(file)[1]),
                get(data, :ip, "unknown"),
                get(data, :ports, Int[]),
                get(data, :notes, ""),
                DateTime(get(data, :added, string(now())))
            ))
        catch
            continue
        end
    end
    
    return targets
end

"""
    add_target(target::Target)

Add a target to NullSec target list.
"""
function add_target(target::Target)::String
    config = NULLSEC_CONFIG[]
    
    !config.enabled && return ""
    
    targets_dir = joinpath(config.logs_path, "targets")
    !isdir(targets_dir) && mkpath(targets_dir)
    
    # Create safe filename
    safe_name = replace(target.host, r"[^a-zA-Z0-9_.-]" => "_")
    filename = "$(safe_name).json"
    filepath = joinpath(targets_dir, filename)
    
    target_data = Dict{Symbol, Any}(
        :name => target.host,
        :ip => target.host,
        :port => target.port,
        :ports => Int[target.port],
        :protocol => string(target.protocol),
        :notes => "",
        :added => string(now()),
        :source => "spectra"
    )
    
    open(filepath, "w") do io
        JSON3.write(io, target_data)
    end
    
    return filepath
end

# ───────────────────────────────────────────────────────────────────────────────
#                              CLI INTEGRATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    run_nullsec_module(name::String, args::Vector{String} = String[];
                       capture::Bool = true)

Execute a NullSec module.
"""
function run_nullsec_module(name::String, args::Vector{String} = String[];
                            capture::Bool = true)::Union{String, Nothing}
    mod = find_module(name)
    
    mod === nothing && return nothing
    
    cmd = if mod.type == :python
        `python3 $(mod.path) $args`
    elseif mod.type == :bash
        `bash $(mod.path) $args`
    else
        return nothing
    end
    
    try
        if capture
            return read(cmd, String)
        else
            run(cmd)
            return ""
        end
    catch e
        return "Error: $(e)"
    end
end

"""
    display_nullsec_status()

Display NullSec integration status.
"""
function display_nullsec_status()
    status = nullsec_status()
    
    println()
    println(themed("╔═══════════════════════════════════════════════════════════════╗", :primary))
    println(themed("║              NULLSEC INTEGRATION STATUS                       ║", :primary))
    println(themed("╠═══════════════════════════════════════════════════════════════╣", :primary))
    
    detected_icon = status[:detected] ? "✓" : "✗"
    detected_color = status[:detected] ? :green : :red
    println(themed("║", :primary), " Detected: ", themed(detected_icon, detected_color), 
            status[:detected] ? " NullSec environment found" : " NullSec not found")
    
    enabled_icon = status[:enabled] ? "✓" : "✗"
    enabled_color = status[:enabled] ? :green : :red
    println(themed("║", :primary), " Enabled:  ", themed(enabled_icon, enabled_color),
            status[:enabled] ? " Integration active" : " Integration disabled")
    
    if status[:detected]
        println(themed("╠───────────────────────────────────────────────────────────────╣", :dim))
        println(themed("║", :primary), " Base Path: ", themed(status[:base_path], :cyan))
        
        if status[:modules_available]
            println(themed("║", :primary), " Modules:   ", themed("$(status[:module_count]) available", :green))
        end
        
        if status[:logs_available]
            println(themed("║", :primary), " Logs:      ", themed("Available", :green))
        end
    end
    
    println(themed("╚═══════════════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              BANNER
# ───────────────────────────────────────────────────────────────────────────────

const NULLSEC_BANNER = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗███████╗ ██████╗              ║
║     ████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔════╝              ║
║     ██╔██╗ ██║██║   ██║██║     ██║     ███████╗█████╗  ██║                   ║
║     ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██╔══╝  ██║                   ║
║     ██║ ╚████║╚██████╔╝███████╗███████╗███████║███████╗╚██████╗              ║
║     ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝              ║
║                                                                               ║
║            ╔═══════════════════════════════════════════════════╗             ║
║            ║   SPECTRA × NULLSEC INTEGRATION ACTIVE           ║             ║
║            ║       Security Protocol Bridge v1.0.0            ║             ║
║            ╚═══════════════════════════════════════════════════╝             ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

"""
    show_nullsec_banner()

Display NullSec integration banner.
"""
function show_nullsec_banner()
    for line in split(NULLSEC_BANNER, '\n')
        println(themed(line, :primary))
    end
end
