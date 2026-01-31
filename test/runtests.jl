# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Test Suite
# ═══════════════════════════════════════════════════════════════════════════════

using Test
using Dates

# Include the main module
include("../src/Spectra.jl")
using .Spectra

@testset "Spectra Core Tests" begin
    
    @testset "Types" begin
        # Test Target creation
        target = Target("example.com", 443, :tcp)
        @test target.host == "example.com"
        @test target.port == 443
        @test target.protocol == :tcp
        
        # Test ThreatLevel ordering
        @test Int(CRITICAL) > Int(HIGH)
        @test Int(HIGH) > Int(MEDIUM)
        @test Int(MEDIUM) > Int(LOW)
        @test Int(LOW) > Int(INFO)
    end
    
    @testset "Configuration" begin
        # Test config initialization
        config = Spectra.init()
        @test config isa SpectraConfig
        @test config.verbose isa Bool
        @test config.threads >= 1
        
        # Test configuration update
        new_config = Spectra.configure(verbose = true)
        @test new_config.verbose == true
    end
    
    @testset "Crypto - Hash Identification" begin
        # Test MD5 detection
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = hash_identify(md5_hash)
        @test length(result) > 0
        @test any(r -> r.hash_type == "md5", result)
        
        # Test SHA256 detection
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = hash_identify(sha256_hash)
        @test any(r -> r.hash_type == "sha256", result)
    end
    
    @testset "Crypto - Entropy" begin
        # Test low entropy
        low_entropy_data = UInt8[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        result = entropy_analyze(low_entropy_data)
        @test result.entropy < 1.0
        @test !result.likely_encrypted
        
        # Test high entropy
        high_entropy_data = collect(UInt8, 0:255)
        result = entropy_analyze(high_entropy_data)
        @test result.entropy > 7.0
    end
    
    @testset "Network - Packet Structures" begin
        # Test IPv4 header parsing
        ipv4_data = UInt8[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x01, 0x02
        ]
        header = parse_ipv4(ipv4_data)
        @test header.version == 4
        @test header.protocol == 6  # TCP
    end
    
    @testset "Analysis - Patterns" begin
        # Test SQL injection detection
        sqli_test = "SELECT * FROM users WHERE id='1' OR '1'='1'"
        results = scan_for_patterns(sqli_test)
        @test length(results) > 0
        
        # Test XSS detection
        xss_test = "<script>alert('XSS')</script>"
        results = scan_for_patterns(xss_test)
        @test length(results) > 0
    end
    
    @testset "Scoring" begin
        # Test threat scoring
        threat = Threat(
            "SQL Injection",
            "Found SQL injection vulnerability",
            HIGH,
            :injection,
            now()
        )
        score = calculate_threat_score(threat)
        @test score.base_score == 7.5  # HIGH = 7.5
        @test score.adjusted_score > 0
        
        # Test aggregate scoring
        threats = [
            Threat("Test 1", "Desc 1", MEDIUM, :misc, now()),
            Threat("Test 2", "Desc 2", HIGH, :injection, now()),
        ]
        agg = aggregate_scores(threats)
        @test agg.threat_count == 2
        @test agg.high_count == 1
        @test agg.medium_count == 1
    end
end

println("\n✓ All Spectra tests passed!")
