# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Threat Scoring
# ═══════════════════════════════════════════════════════════════════════════════
# Risk assessment and threat scoring algorithms
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              SCORING WEIGHTS
# ───────────────────────────────────────────────────────────────────────────────

const SEVERITY_SCORES = Dict{ThreatLevel, Float64}(
    CRITICAL => 10.0,
    HIGH => 7.5,
    MEDIUM => 5.0,
    LOW => 2.5,
    INFO => 1.0,
)

const CATEGORY_WEIGHTS = Dict{Symbol, Float64}(
    :rce => 2.0,           # Remote Code Execution
    :injection => 1.5,     # SQL/Command Injection
    :auth_bypass => 1.8,   # Authentication Bypass
    :data_leak => 1.3,     # Data Exposure
    :dos => 1.0,           # Denial of Service
    :info_disclosure => 0.8, # Information Disclosure
    :misc => 0.5,          # Miscellaneous
)

const EXPLOITABILITY_FACTORS = Dict{Symbol, Float64}(
    :network => 1.0,       # Network exploitable
    :local => 0.6,         # Local only
    :physical => 0.3,      # Physical access required
    :none => 0.0,          # Not exploitable
)

# ───────────────────────────────────────────────────────────────────────────────
#                              THREAT SCORING
# ───────────────────────────────────────────────────────────────────────────────

"""
    ThreatScore

Comprehensive threat score.
"""
struct ThreatScore
    base_score::Float64
    adjusted_score::Float64
    severity::ThreatLevel
    category::Symbol
    exploitability::Symbol
    confidence::Float64
    components::Dict{Symbol, Float64}
end

"""
    calculate_threat_score(threat::Threat;
                           exploitability::Symbol = :network,
                           confidence::Float64 = 1.0)

Calculate comprehensive threat score.
"""
function calculate_threat_score(threat::Threat;
                                exploitability::Symbol = :network,
                                confidence::Float64 = 1.0)::ThreatScore
    
    # Base score from severity
    base_score = get(SEVERITY_SCORES, threat.level, 5.0)
    
    # Apply category weight
    category_weight = get(CATEGORY_WEIGHTS, threat.category, 1.0)
    
    # Apply exploitability factor
    exploit_factor = get(EXPLOITABILITY_FACTORS, exploitability, 1.0)
    
    # Calculate adjusted score
    adjusted_score = base_score * category_weight * exploit_factor * confidence
    
    # Clamp to 0-10 range
    adjusted_score = clamp(adjusted_score, 0.0, 10.0)
    
    components = Dict{Symbol, Float64}(
        :base => base_score,
        :category_weight => category_weight,
        :exploit_factor => exploit_factor,
        :confidence => confidence
    )
    
    return ThreatScore(
        base_score, adjusted_score,
        threat.level, threat.category, exploitability,
        confidence, components
    )
end

"""
    score_to_grade(score::Float64)

Convert numeric score to letter grade.
"""
function score_to_grade(score::Float64)::Symbol
    score >= 9.0 && return :F
    score >= 7.0 && return :D
    score >= 5.0 && return :C
    score >= 3.0 && return :B
    return :A
end

# ───────────────────────────────────────────────────────────────────────────────
#                              AGGREGATE SCORING
# ───────────────────────────────────────────────────────────────────────────────

"""
    AggregateScore

Aggregate score for multiple threats.
"""
struct AggregateScore
    total_score::Float64
    average_score::Float64
    max_score::Float64
    threat_count::Int
    critical_count::Int
    high_count::Int
    medium_count::Int
    low_count::Int
    grade::Symbol
    risk_level::Symbol
end

"""
    aggregate_scores(threats::Vector{Threat})

Calculate aggregate score for multiple threats.
"""
function aggregate_scores(threats::Vector{Threat})::AggregateScore
    isempty(threats) && return AggregateScore(0.0, 0.0, 0.0, 0, 0, 0, 0, 0, :A, :minimal)
    
    scores = [calculate_threat_score(t) for t in threats]
    adjusted_scores = [s.adjusted_score for s in scores]
    
    total = sum(adjusted_scores)
    avg = mean(adjusted_scores)
    max_score = maximum(adjusted_scores)
    
    # Count by severity
    critical_count = count(t -> t.level == CRITICAL, threats)
    high_count = count(t -> t.level == HIGH, threats)
    medium_count = count(t -> t.level == MEDIUM, threats)
    low_count = count(t -> t.level == LOW, threats)
    
    # Determine overall grade (weighted by severity)
    weighted_score = if critical_count > 0
        max_score
    elseif high_count > 0
        max(avg, 7.0)
    else
        avg
    end
    
    grade = score_to_grade(weighted_score)
    
    # Determine risk level
    risk_level = if critical_count > 0 || weighted_score >= 9.0
        :critical
    elseif high_count > 0 || weighted_score >= 7.0
        :high
    elseif medium_count > 0 || weighted_score >= 5.0
        :medium
    elseif low_count > 0 || weighted_score >= 2.0
        :low
    else
        :minimal
    end
    
    return AggregateScore(
        total, avg, max_score,
        length(threats),
        critical_count, high_count, medium_count, low_count,
        grade, risk_level
    )
end

# ───────────────────────────────────────────────────────────────────────────────
#                              RISK ASSESSMENT
# ───────────────────────────────────────────────────────────────────────────────

"""
    RiskAssessment

Complete risk assessment.
"""
struct RiskAssessment
    target::String
    timestamp::DateTime
    aggregate::AggregateScore
    threats::Vector{Threat}
    recommendations::Vector{String}
    executive_summary::String
end

"""
    assess_risk(target::String, threats::Vector{Threat})

Perform complete risk assessment.
"""
function assess_risk(target::String, threats::Vector{Threat})::RiskAssessment
    aggregate = aggregate_scores(threats)
    
    # Generate recommendations based on findings
    recommendations = String[]
    
    if aggregate.critical_count > 0
        push!(recommendations, "IMMEDIATE ACTION REQUIRED: Address critical vulnerabilities before any other work")
    end
    
    if aggregate.high_count > 0
        push!(recommendations, "Schedule remediation of high-severity issues within 48 hours")
    end
    
    # Add specific recommendations based on threat categories
    categories = Set(t.category for t in threats)
    
    if :injection in categories
        push!(recommendations, "Implement input validation and parameterized queries")
    end
    if :auth_bypass in categories
        push!(recommendations, "Review authentication mechanisms and implement MFA")
    end
    if :data_leak in categories
        push!(recommendations, "Review data handling procedures and encryption at rest")
    end
    if :rce in categories
        push!(recommendations, "Isolate affected systems and patch immediately")
    end
    
    # Generate executive summary
    summary = generate_executive_summary(target, aggregate)
    
    return RiskAssessment(
        target, now(),
        aggregate, threats,
        recommendations, summary
    )
end

"""
    generate_executive_summary(target::String, aggregate::AggregateScore)

Generate executive summary text.
"""
function generate_executive_summary(target::String, aggregate::AggregateScore)::String
    risk_descriptions = Dict(
        :critical => "is at critical risk and requires immediate attention",
        :high => "has significant security concerns that should be addressed urgently",
        :medium => "has moderate security issues that should be remediated",
        :low => "has minor security findings that should be reviewed",
        :minimal => "has minimal security concerns"
    )
    
    desc = get(risk_descriptions, aggregate.risk_level, "has been assessed")
    
    summary = """
    Security Assessment Summary for $target

    Overall Grade: $(aggregate.grade) (Score: $(round(aggregate.average_score, digits=1))/10)
    
    The target $desc.
    
    Findings Summary:
    - Total Issues: $(aggregate.threat_count)
    - Critical: $(aggregate.critical_count)
    - High: $(aggregate.high_count)
    - Medium: $(aggregate.medium_count)
    - Low: $(aggregate.low_count)
    
    Risk Level: $(uppercase(string(aggregate.risk_level)))
    """
    
    return strip(summary)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              DISPLAY FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────

const GRADE_COLORS = Dict(
    :A => :green,
    :B => :cyan,
    :C => :yellow,
    :D => :red,
    :F => :bg_red,
)

"""
    display_risk_assessment(assessment::RiskAssessment)

Display formatted risk assessment.
"""
function display_risk_assessment(assessment::RiskAssessment)
    agg = assessment.aggregate
    grade_color = get(GRADE_COLORS, agg.grade, :white)
    
    println()
    println(themed("╔═══════════════════════════════════════════════════════════════╗", :primary))
    println(themed("║                    RISK ASSESSMENT                            ║", :primary))
    println(themed("╠═══════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), " Target: ", themed(assessment.target, :cyan))
    println(themed("║", :primary), " Date: ", themed(string(assessment.timestamp), :dim))
    println(themed("╠═══════════════════════════════════════════════════════════════╣", :primary))
    
    # Grade display
    grade_str = "   $(agg.grade)   "
    println(themed("║", :primary), "                                                             ", themed("║", :primary))
    println(themed("║", :primary), "     Overall Grade: ", themed(grade_str, grade_color), "  Score: ", 
            themed(@sprintf("%.1f/10", agg.average_score), :yellow), "               ", themed("║", :primary))
    println(themed("║", :primary), "                                                             ", themed("║", :primary))
    
    println(themed("╠═══════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), themed(" Findings Breakdown:", :secondary))
    println(themed("║", :primary), "   ", threat_badge(CRITICAL), " Critical: ", themed(string(agg.critical_count), :red))
    println(themed("║", :primary), "   ", threat_badge(HIGH), " High: ", themed(string(agg.high_count), :yellow))
    println(themed("║", :primary), "   ", threat_badge(MEDIUM), " Medium: ", themed(string(agg.medium_count), :cyan))
    println(themed("║", :primary), "   ", threat_badge(LOW), " Low: ", themed(string(agg.low_count), :dim))
    
    println(themed("╠═══════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), themed(" Recommendations:", :secondary))
    for (i, rec) in enumerate(assessment.recommendations[1:min(5, length(assessment.recommendations))])
        println(themed("║", :primary), "   $(i). ", themed(rec, :dim))
    end
    
    println(themed("╚═══════════════════════════════════════════════════════════════╝", :primary))
end

"""
    display_score_breakdown(score::ThreatScore)

Display threat score breakdown.
"""
function display_score_breakdown(score::ThreatScore)
    println(themed("\nThreat Score Breakdown:", :info))
    println(themed("─────────────────────────────", :dim))
    println("  Base Score:       ", themed(@sprintf("%.1f", score.base_score), :yellow))
    println("  Category Weight:  ", themed(@sprintf("%.1f", score.components[:category_weight]), :dim))
    println("  Exploit Factor:   ", themed(@sprintf("%.1f", score.components[:exploit_factor]), :dim))
    println("  Confidence:       ", themed(@sprintf("%.0f%%", score.confidence * 100), :dim))
    println(themed("─────────────────────────────", :dim))
    println("  Adjusted Score:   ", themed(@sprintf("%.1f", score.adjusted_score), :cyan))
    println("  Grade:            ", themed(string(score_to_grade(score.adjusted_score)), get(GRADE_COLORS, score_to_grade(score.adjusted_score), :white)))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              COMPARISON & TRENDING
# ───────────────────────────────────────────────────────────────────────────────

"""
    compare_assessments(previous::RiskAssessment, current::RiskAssessment)

Compare two risk assessments.
"""
function compare_assessments(previous::RiskAssessment, current::RiskAssessment)::Dict{Symbol, Any}
    prev_agg = previous.aggregate
    curr_agg = current.aggregate
    
    return Dict{Symbol, Any}(
        :score_change => curr_agg.average_score - prev_agg.average_score,
        :grade_change => (prev_agg.grade, curr_agg.grade),
        :threat_change => curr_agg.threat_count - prev_agg.threat_count,
        :critical_change => curr_agg.critical_count - prev_agg.critical_count,
        :improved => curr_agg.average_score < prev_agg.average_score,
        :days_between => Dates.value(curr_agg.timestamp - prev_agg.timestamp) / 86400000
    )
end
