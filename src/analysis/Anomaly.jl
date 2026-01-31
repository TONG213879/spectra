# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════════
# Statistical anomaly detection for security analysis
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              STATISTICAL FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────

"""
    zscore(data::Vector{<:Real}, value::Real)

Calculate z-score for a value given a dataset.
"""
function zscore(data::Vector{<:Real}, value::Real)::Float64
    μ = mean(data)
    σ = std(data)
    σ == 0 && return 0.0
    return (value - μ) / σ
end

"""
    zscore_array(data::Vector{<:Real})

Calculate z-scores for all values in dataset.
"""
function zscore_array(data::Vector{<:Real})::Vector{Float64}
    μ = mean(data)
    σ = std(data)
    σ == 0 && return zeros(length(data))
    return [(x - μ) / σ for x in data]
end

"""
    iqr_bounds(data::Vector{<:Real}; k::Float64 = 1.5)

Calculate IQR-based outlier bounds.

Returns (lower_bound, upper_bound).
"""
function iqr_bounds(data::Vector{<:Real}; k::Float64 = 1.5)::Tuple{Float64, Float64}
    sorted = sort(data)
    n = length(sorted)
    
    q1_idx = ceil(Int, n * 0.25)
    q3_idx = ceil(Int, n * 0.75)
    
    q1 = sorted[q1_idx]
    q3 = sorted[q3_idx]
    iqr = q3 - q1
    
    lower = q1 - k * iqr
    upper = q3 + k * iqr
    
    return (lower, upper)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              ANOMALY DETECTORS
# ───────────────────────────────────────────────────────────────────────────────

"""
    AnomalyResult

Result of anomaly detection.
"""
struct AnomalyResult
    value::Real
    is_anomaly::Bool
    score::Float64
    method::Symbol
    threshold::Float64
    context::Dict{Symbol, Any}
end

"""
    detect_zscore_anomalies(data::Vector{<:Real}; threshold::Float64 = 3.0)

Detect anomalies using z-score method.
"""
function detect_zscore_anomalies(data::Vector{<:Real}; threshold::Float64 = 3.0)::Vector{AnomalyResult}
    zscores = zscore_array(data)
    results = AnomalyResult[]
    
    for (i, (value, z)) in enumerate(zip(data, zscores))
        is_anomaly = abs(z) > threshold
        push!(results, AnomalyResult(
            value,
            is_anomaly,
            abs(z),
            :zscore,
            threshold,
            Dict(:index => i, :zscore => z)
        ))
    end
    
    return results
end

"""
    detect_iqr_anomalies(data::Vector{<:Real}; k::Float64 = 1.5)

Detect anomalies using IQR method.
"""
function detect_iqr_anomalies(data::Vector{<:Real}; k::Float64 = 1.5)::Vector{AnomalyResult}
    lower, upper = iqr_bounds(data, k=k)
    results = AnomalyResult[]
    
    for (i, value) in enumerate(data)
        is_anomaly = value < lower || value > upper
        
        # Score based on distance from bounds
        if value < lower
            score = (lower - value) / max(abs(lower), 1)
        elseif value > upper
            score = (value - upper) / max(abs(upper), 1)
        else
            score = 0.0
        end
        
        push!(results, AnomalyResult(
            value,
            is_anomaly,
            score,
            :iqr,
            k,
            Dict(:index => i, :lower => lower, :upper => upper)
        ))
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              TIME SERIES ANOMALIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    detect_spike_anomalies(data::Vector{<:Real}; 
                           window::Int = 5,
                           threshold::Float64 = 2.0)

Detect sudden spikes in time series data.
"""
function detect_spike_anomalies(data::Vector{<:Real};
                                window::Int = 5,
                                threshold::Float64 = 2.0)::Vector{AnomalyResult}
    n = length(data)
    results = AnomalyResult[]
    
    for i in (window + 1):n
        window_data = data[i-window:i-1]
        window_mean = mean(window_data)
        window_std = std(window_data)
        
        if window_std > 0
            deviation = abs(data[i] - window_mean) / window_std
        else
            deviation = 0.0
        end
        
        is_anomaly = deviation > threshold
        
        push!(results, AnomalyResult(
            data[i],
            is_anomaly,
            deviation,
            :spike,
            threshold,
            Dict(:index => i, :window_mean => window_mean, :window_std => window_std)
        ))
    end
    
    return results
end

"""
    detect_trend_change(data::Vector{<:Real}; 
                        window::Int = 10,
                        threshold::Float64 = 0.5)

Detect significant trend changes.
"""
function detect_trend_change(data::Vector{<:Real};
                             window::Int = 10,
                             threshold::Float64 = 0.5)::Vector{AnomalyResult}
    n = length(data)
    n < 2 * window && return AnomalyResult[]
    
    results = AnomalyResult[]
    
    for i in (window + 1):(n - window + 1)
        # Calculate slopes before and after point
        before = data[i-window:i-1]
        after = data[i:i+window-1]
        
        slope_before = (before[end] - before[1]) / window
        slope_after = (after[end] - after[1]) / window
        
        # Significant change if slopes differ substantially
        slope_change = abs(slope_after - slope_before)
        
        is_anomaly = slope_change > threshold
        
        push!(results, AnomalyResult(
            data[i],
            is_anomaly,
            slope_change,
            :trend_change,
            threshold,
            Dict(:index => i, :slope_before => slope_before, :slope_after => slope_after)
        ))
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              NETWORK TRAFFIC ANOMALIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    NetworkStats

Network traffic statistics.
"""
struct NetworkStats
    timestamp::DateTime
    packets::Int
    bytes::Int
    connections::Int
    unique_ips::Int
    protocols::Dict{Symbol, Int}
end

"""
    analyze_traffic_anomalies(stats::Vector{NetworkStats}; 
                              verbose::Bool = CONFIG.verbose)

Analyze network traffic for anomalies.
"""
function analyze_traffic_anomalies(stats::Vector{NetworkStats};
                                   verbose::Bool = CONFIG.verbose)::Dict{Symbol, Vector{AnomalyResult}}
    
    results = Dict{Symbol, Vector{AnomalyResult}}()
    
    # Extract time series
    packets = Float64[s.packets for s in stats]
    bytes = Float64[s.bytes for s in stats]
    connections = Float64[s.connections for s in stats]
    unique_ips = Float64[s.unique_ips for s in stats]
    
    # Detect anomalies in each metric
    results[:packets] = detect_zscore_anomalies(packets)
    results[:bytes] = detect_zscore_anomalies(bytes)
    results[:connections] = detect_spike_anomalies(connections)
    results[:unique_ips] = detect_spike_anomalies(unique_ips)
    
    if verbose
        total_anomalies = sum(count(r -> r.is_anomaly, v) for (_, v) in results)
        println(themed("\n[*] Traffic Anomaly Analysis", :info))
        println(themed("[*] Total anomalies detected: $total_anomalies", :warning))
        
        for (metric, anomalies) in results
            anomaly_count = count(r -> r.is_anomaly, anomalies)
            if anomaly_count > 0
                println(themed("    $metric: $anomaly_count anomalies", :yellow))
            end
        end
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              LOG ANOMALY DETECTION
# ───────────────────────────────────────────────────────────────────────────────

"""
    LogEntry

Parsed log entry.
"""
struct LogEntry
    timestamp::Union{DateTime, Nothing}
    level::Symbol
    source::String
    message::String
    raw::String
end

"""
    parse_log_entry(line::String)

Parse common log formats.
"""
function parse_log_entry(line::String)::LogEntry
    # Try common formats
    
    # Syslog-style
    m = match(r"^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s*(.*)$", line)
    if !isnothing(m)
        timestamp = nothing  # Would need proper parsing
        source = m.captures[3]
        message = m.captures[4]
        level = detect_log_level(message)
        return LogEntry(timestamp, level, source, message, line)
    end
    
    # Apache/nginx style
    m = match(r"^\[(.*?)\]\s*\[(\w+)\]\s*(.*)$", line)
    if !isnothing(m)
        level = Symbol(lowercase(m.captures[2]))
        return LogEntry(nothing, level, "", m.captures[3], line)
    end
    
    # Default
    return LogEntry(nothing, detect_log_level(line), "", line, line)
end

"""
    detect_log_level(message::String)

Detect log level from message content.
"""
function detect_log_level(message::String)::Symbol
    msg_lower = lowercase(message)
    
    if occursin(r"\b(error|fatal|critical|fail)\b", msg_lower)
        return :error
    elseif occursin(r"\b(warn|warning)\b", msg_lower)
        return :warning
    elseif occursin(r"\b(debug|trace)\b", msg_lower)
        return :debug
    else
        return :info
    end
end

"""
    detect_log_anomalies(entries::Vector{LogEntry}; 
                         verbose::Bool = CONFIG.verbose)

Detect anomalies in log entries.
"""
function detect_log_anomalies(entries::Vector{LogEntry};
                              verbose::Bool = CONFIG.verbose)::Dict{Symbol, Any}
    
    results = Dict{Symbol, Any}(
        :error_rate => 0.0,
        :unusual_patterns => String[],
        :frequency_anomalies => LogEntry[],
        :summary => Dict{Symbol, Int}()
    )
    
    # Count by level
    level_counts = Dict{Symbol, Int}()
    for entry in entries
        level_counts[entry.level] = get(level_counts, entry.level, 0) + 1
    end
    results[:summary] = level_counts
    
    # Calculate error rate
    total = length(entries)
    errors = get(level_counts, :error, 0) + get(level_counts, :fatal, 0)
    results[:error_rate] = total > 0 ? errors / total : 0.0
    
    # Detect unusual patterns
    unusual_patterns = [
        r"authentication fail",
        r"permission denied",
        r"access denied",
        r"invalid credentials",
        r"connection refused",
        r"timeout",
        r"out of memory",
        r"disk full",
        r"segmentation fault",
        r"stack trace",
    ]
    
    for entry in entries
        for pattern in unusual_patterns
            if occursin(pattern, lowercase(entry.message))
                push!(results[:unusual_patterns], entry.raw)
                break
            end
        end
    end
    
    if verbose
        println(themed("\n[*] Log Anomaly Analysis", :info))
        println(themed("[*] Total entries: $total", :dim))
        println(themed("[*] Error rate: $(round(results[:error_rate] * 100, digits=1))%", 
                       results[:error_rate] > 0.1 ? :red : :green))
        println(themed("[*] Unusual patterns: $(length(results[:unusual_patterns]))", :yellow))
    end
    
    return results
end

# ───────────────────────────────────────────────────────────────────────────────
#                              BEHAVIORAL ANALYSIS
# ───────────────────────────────────────────────────────────────────────────────

"""
    UserBehavior

User behavior profile.
"""
struct UserBehavior
    user_id::String
    login_times::Vector{DateTime}
    ip_addresses::Vector{String}
    actions::Vector{Symbol}
    data_accessed::Vector{String}
end

"""
    analyze_user_behavior(current::UserBehavior, 
                          baseline::UserBehavior)

Compare current behavior against baseline.
"""
function analyze_user_behavior(current::UserBehavior,
                               baseline::UserBehavior)::Dict{Symbol, Any}
    
    results = Dict{Symbol, Any}(
        :anomalies => Symbol[],
        :risk_score => 0.0,
        :details => Dict{Symbol, Any}()
    )
    
    # Check for new IP addresses
    new_ips = setdiff(Set(current.ip_addresses), Set(baseline.ip_addresses))
    if !isempty(new_ips)
        push!(results[:anomalies], :new_ip)
        results[:details][:new_ips] = collect(new_ips)
        results[:risk_score] += 0.3
    end
    
    # Check for unusual actions
    unusual_actions = setdiff(Set(current.actions), Set(baseline.actions))
    if !isempty(unusual_actions)
        push!(results[:anomalies], :unusual_actions)
        results[:details][:unusual_actions] = collect(unusual_actions)
        results[:risk_score] += 0.4
    end
    
    # Check for unusual data access
    unusual_data = setdiff(Set(current.data_accessed), Set(baseline.data_accessed))
    if !isempty(unusual_data)
        push!(results[:anomalies], :unusual_data_access)
        results[:details][:unusual_data] = collect(unusual_data)
        results[:risk_score] += 0.3
    end
    
    return results
end
