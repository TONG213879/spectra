# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Processing Engine
# ═══════════════════════════════════════════════════════════════════════════════
# Core processing engine with parallel execution and task management
# ═══════════════════════════════════════════════════════════════════════════════

using Base.Threads

# ───────────────────────────────────────────────────────────────────────────────
#                              TASK MANAGEMENT
# ───────────────────────────────────────────────────────────────────────────────

"""
    TaskResult{T}

Result container for async operations.
"""
struct TaskResult{T}
    success::Bool
    value::Union{T, Nothing}
    error::Union{Exception, Nothing}
    duration::Float64
    task_id::UUID
end

"""
    TaskQueue

Managed task queue for parallel operations.
"""
mutable struct TaskQueue
    tasks::Vector{Task}
    results::Vector{TaskResult}
    max_concurrent::Int
    lock::ReentrantLock
    completed::Int
    failed::Int
end

TaskQueue(max_concurrent::Int = Threads.nthreads()) = TaskQueue(
    Task[], TaskResult[], max_concurrent, ReentrantLock(), 0, 0
)

# ───────────────────────────────────────────────────────────────────────────────
#                              PARALLEL EXECUTION
# ───────────────────────────────────────────────────────────────────────────────

"""
    parallel_map(f::Function, items::AbstractVector; 
                 max_workers::Int = CONFIG.max_threads,
                 progress::Bool = CONFIG.verbose)

Map function over items in parallel with progress tracking.

# Example
```julia
results = parallel_map(scan_port, ports, progress=true)
```
"""
function parallel_map(f::Function, items::AbstractVector;
                      max_workers::Int = CONFIG.max_threads,
                      show_progress::Bool = CONFIG.verbose)
    
    n = length(items)
    n == 0 && return []
    
    results = Vector{Any}(undef, n)
    completed = Atomic{Int}(0)
    lock = ReentrantLock()
    
    if show_progress
        print("\r", progress(0, n, label="Processing"))
    end
    
    if CONFIG.parallel && nthreads() > 1
        # Parallel execution
        Threads.@threads for i in 1:n
            try
                results[i] = f(items[i])
            catch e
                results[i] = nothing
                @warn "Task $i failed" exception=e
            end
            
            atomic_add!(completed, 1)
            if show_progress
                print("\r", progress(completed[], n, label="Processing"))
            end
        end
    else
        # Sequential execution
        for i in 1:n
            try
                results[i] = f(items[i])
            catch e
                results[i] = nothing
            end
            
            if show_progress
                print("\r", progress(i, n, label="Processing"))
            end
        end
    end
    
    show_progress && println()
    return results
end

"""
    parallel_foreach(f::Function, items::AbstractVector;
                     max_workers::Int = CONFIG.max_threads)

Apply function to each item in parallel (no return values).
"""
function parallel_foreach(f::Function, items::AbstractVector;
                          max_workers::Int = CONFIG.max_threads)
    
    if CONFIG.parallel && nthreads() > 1
        Threads.@threads for item in items
            try
                f(item)
            catch e
                @warn "Task failed" exception=e
            end
        end
    else
        for item in items
            try
                f(item)
            catch
            end
        end
    end
end

"""
    parallel_reduce(f::Function, items::AbstractVector, init;
                    reducer::Function = +)

Parallel map-reduce operation.
"""
function parallel_reduce(f::Function, items::AbstractVector, init;
                         reducer::Function = +)
    
    mapped = parallel_map(f, items, show_progress=false)
    return reduce(reducer, filter(!isnothing, mapped); init=init)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              RATE LIMITING
# ───────────────────────────────────────────────────────────────────────────────

"""
    RateLimiter

Token bucket rate limiter.
"""
mutable struct RateLimiter
    rate::Int           # Tokens per second
    capacity::Int       # Maximum tokens
    tokens::Float64     # Current tokens
    last_update::Float64
    lock::ReentrantLock
end

function RateLimiter(rate::Int, capacity::Int = rate)
    RateLimiter(rate, capacity, Float64(capacity), time(), ReentrantLock())
end

"""
    acquire!(limiter::RateLimiter, n::Int = 1)

Acquire tokens, blocking if necessary.
"""
function acquire!(limiter::RateLimiter, n::Int = 1)
    lock(limiter.lock) do
        while true
            now = time()
            elapsed = now - limiter.last_update
            limiter.tokens = min(limiter.capacity, limiter.tokens + elapsed * limiter.rate)
            limiter.last_update = now
            
            if limiter.tokens >= n
                limiter.tokens -= n
                return
            end
            
            # Wait for tokens
            wait_time = (n - limiter.tokens) / limiter.rate
            sleep(wait_time)
        end
    end
end

# Global rate limiter
const RATE_LIMITER = Ref{Union{RateLimiter, Nothing}}(nothing)

"""
    init_rate_limiter(rate::Int = CONFIG.rate_limit)

Initialize the global rate limiter.
"""
function init_rate_limiter(rate::Int = CONFIG.rate_limit)
    RATE_LIMITER[] = RateLimiter(rate)
end

"""
    rate_limited(f::Function)

Execute function with rate limiting.
"""
function rate_limited(f::Function)
    if !isnothing(RATE_LIMITER[])
        acquire!(RATE_LIMITER[])
    end
    return f()
end

# ───────────────────────────────────────────────────────────────────────────────
#                              TIMEOUT HANDLING
# ───────────────────────────────────────────────────────────────────────────────

"""
    with_timeout(f::Function, timeout::Float64)

Execute function with timeout.

Returns (success::Bool, result::Any)
"""
function with_timeout(f::Function, timeout::Float64)
    result = Ref{Any}(nothing)
    completed = Atomic{Bool}(false)
    
    task = @async begin
        try
            result[] = f()
            atomic_xchg!(completed, true)
        catch e
            result[] = e
        end
    end
    
    start = time()
    while !completed[] && (time() - start) < timeout
        sleep(0.01)
    end
    
    if completed[]
        return (true, result[])
    else
        # Attempt to interrupt
        try
            Base.throwto(task, InterruptException())
        catch
        end
        return (false, nothing)
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              RETRY LOGIC
# ───────────────────────────────────────────────────────────────────────────────

"""
    with_retry(f::Function; max_retries::Int = 3, backoff::Float64 = 1.0)

Execute function with exponential backoff retry.
"""
function with_retry(f::Function; max_retries::Int = 3, backoff::Float64 = 1.0)
    last_error = nothing
    
    for attempt in 1:max_retries
        try
            return f()
        catch e
            last_error = e
            if attempt < max_retries
                sleep(backoff * (2^(attempt - 1)))
            end
        end
    end
    
    throw(last_error)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              CACHING
# ───────────────────────────────────────────────────────────────────────────────

"""
    Cache{K, V}

Thread-safe LRU cache.
"""
mutable struct Cache{K, V}
    data::Dict{K, Tuple{V, Float64}}
    max_size::Int
    ttl::Float64
    lock::ReentrantLock
end

function Cache{K, V}(max_size::Int = 1000, ttl::Float64 = 300.0) where {K, V}
    Cache{K, V}(Dict{K, Tuple{V, Float64}}(), max_size, ttl, ReentrantLock())
end

"""
    get_cached(cache::Cache{K,V}, key::K, default::V) where {K, V}

Get value from cache or return default.
"""
function get_cached(cache::Cache{K,V}, key::K, default::V) where {K, V}
    lock(cache.lock) do
        if haskey(cache.data, key)
            value, timestamp = cache.data[key]
            if (time() - timestamp) < cache.ttl
                return value
            else
                delete!(cache.data, key)
            end
        end
        return default
    end
end

"""
    set_cached!(cache::Cache{K,V}, key::K, value::V) where {K, V}

Store value in cache.
"""
function set_cached!(cache::Cache{K,V}, key::K, value::V) where {K, V}
    lock(cache.lock) do
        # Evict oldest if full
        if length(cache.data) >= cache.max_size
            oldest_key = first(sort(collect(cache.data), by=x->x[2][2]))[1]
            delete!(cache.data, oldest_key)
        end
        cache.data[key] = (value, time())
    end
end

"""
    cached(f::Function, cache::Cache{K,V}, key::K) where {K, V}

Execute function with caching.
"""
function cached(f::Function, cache::Cache{K,V}, key::K) where {K, V}
    existing = get_cached(cache, key, nothing)
    if !isnothing(existing)
        return existing
    end
    
    result = f()
    set_cached!(cache, key, result)
    return result
end

# Global caches
const DNS_CACHE = Cache{String, Vector{String}}(10000, 3600.0)
const SERVICE_CACHE = Cache{Tuple{String, Int}, Union{String, Nothing}}(10000, 300.0)

# ───────────────────────────────────────────────────────────────────────────────
#                              PIPELINE PROCESSING
# ───────────────────────────────────────────────────────────────────────────────

"""
    Pipeline

Processing pipeline with stages.
"""
struct Pipeline
    name::String
    stages::Vector{Pair{String, Function}}
end

"""
    |>(data, pipeline::Pipeline)

Execute pipeline on data.
"""
function Base.:|>(data, pipeline::Pipeline)
    result = data
    for (name, stage) in pipeline.stages
        CONFIG.verbose && println(themed("[*] Stage: $name", :dim))
        result = stage(result)
    end
    return result
end

"""
    create_pipeline(name::String, stages::Pair{String, Function}...)

Create a processing pipeline.

# Example
```julia
scan_pipeline = create_pipeline("FullScan",
    "Discovery" => discover_hosts,
    "PortScan" => scan_ports,
    "ServiceDetection" => detect_services,
    "Analysis" => analyze_results
)
results = target |> scan_pipeline
```
"""
function create_pipeline(name::String, stages::Pair{String, Function}...)
    Pipeline(name, collect(stages))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              WORKFLOW ENGINE
# ───────────────────────────────────────────────────────────────────────────────

"""
    Workflow

Complex workflow with dependencies.
"""
struct Workflow
    name::String
    steps::Vector{NamedTuple{(:name, :func, :deps), Tuple{String, Function, Vector{String}}}}
end

"""
    execute_workflow(wf::Workflow, initial_data::Dict)

Execute workflow respecting dependencies.
"""
function execute_workflow(wf::Workflow, initial_data::Dict = Dict())
    results = copy(initial_data)
    completed = Set{String}()
    
    while length(completed) < length(wf.steps)
        for step in wf.steps
            step.name in completed && continue
            
            # Check dependencies
            if all(dep in completed for dep in step.deps)
                CONFIG.verbose && println(themed("[>] Executing: $(step.name)", :primary))
                
                try
                    results[step.name] = step.func(results)
                    push!(completed, step.name)
                    CONFIG.verbose && println(themed("[+] Completed: $(step.name)", :success))
                catch e
                    error_msg("Step $(step.name) failed: $e")
                    rethrow(e)
                end
            end
        end
    end
    
    return results
end
