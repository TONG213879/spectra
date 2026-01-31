# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Display Engine
# ═══════════════════════════════════════════════════════════════════════════════
# Beautiful terminal output with ASCII art and animations
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              BOX CHARACTERS
# ───────────────────────────────────────────────────────────────────────────────

const BOX = CONFIG.unicode ? Dict(
    :tl => "╭", :tr => "╮", :bl => "╰", :br => "╯",
    :h  => "─", :v  => "│",
    :lt => "├", :rt => "┤", :tt => "┬", :bt => "┴",
    :x  => "┼",
    :dtl => "╔", :dtr => "╗", :dbl => "╚", :dbr => "╝",
    :dh => "═", :dv => "║"
) : Dict(
    :tl => "+", :tr => "+", :bl => "+", :br => "+",
    :h  => "-", :v  => "|",
    :lt => "+", :rt => "+", :tt => "+", :bt => "+",
    :x  => "+",
    :dtl => "+", :dtr => "+", :dbl => "+", :dbr => "+",
    :dh => "=", :dv => "|"
)

# ───────────────────────────────────────────────────────────────────────────────
#                              PROGRESS INDICATORS
# ───────────────────────────────────────────────────────────────────────────────

const SPINNERS = Dict(
    :dots => ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    :line => ["-", "\\", "|", "/"],
    :arrow => ["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"],
    :pulse => ["█", "▓", "▒", "░", "▒", "▓"],
    :dots2 => ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"],
    :bounce => ["⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"],
)

const PROGRESS_CHARS = Dict(
    :filled => "█",
    :empty => "░",
    :partial => ["▏", "▎", "▍", "▌", "▋", "▊", "▉"],
    :block => ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"],
)

# ───────────────────────────────────────────────────────────────────────────────
#                              ICONS
# ───────────────────────────────────────────────────────────────────────────────

const ICONS = CONFIG.unicode ? Dict(
    :success => "✓",
    :error => "✗",
    :warning => "⚠",
    :info => "ℹ",
    :question => "?",
    :bullet => "•",
    :arrow => "→",
    :star => "★",
    :lock => "🔒",
    :unlock => "🔓",
    :key => "🔑",
    :fire => "🔥",
    :shield => "🛡",
    :target => "◎",
    :network => "🌐",
    :folder => "📁",
    :file => "📄",
    :scan => "🔍",
    :exploit => "💥",
    :vuln => "⚡",
    :secure => "✔",
    :threat => "☠",
) : Dict(
    :success => "[+]",
    :error => "[-]",
    :warning => "[!]",
    :info => "[i]",
    :question => "[?]",
    :bullet => "*",
    :arrow => "->",
    :star => "*",
    :lock => "[L]",
    :unlock => "[U]",
    :key => "[K]",
    :fire => "[F]",
    :shield => "[S]",
    :target => "[T]",
    :network => "[N]",
    :folder => "[D]",
    :file => "[F]",
    :scan => "[S]",
    :exploit => "[E]",
    :vuln => "[V]",
    :secure => "[OK]",
    :threat => "[!!]",
)

# ───────────────────────────────────────────────────────────────────────────────
#                              DISPLAY FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────

"""
    clear_screen()

Clear terminal screen.
"""
function clear_screen()
    print("\e[2J\e[H")
end

"""
    move_cursor(row::Int, col::Int)

Move cursor to position.
"""
function move_cursor(row::Int, col::Int)
    print("\e[$row;$(col)H")
end

"""
    hide_cursor()

Hide the cursor.
"""
hide_cursor() = print("\e[?25l")

"""
    show_cursor()

Show the cursor.
"""
show_cursor() = print("\e[?25h")

"""
    box(title::String, content::String; width::Int = 50, style::Symbol = :single)

Draw a box around content.
"""
function box(title::String, content::String; width::Int = 50, style::Symbol = :single)
    chars = style == :double ? 
        (BOX[:dtl], BOX[:dtr], BOX[:dbl], BOX[:dbr], BOX[:dh], BOX[:dv]) :
        (BOX[:tl], BOX[:tr], BOX[:bl], BOX[:br], BOX[:h], BOX[:v])
    
    tl, tr, bl, br, h, v = chars
    
    # Title bar
    title_display = isempty(title) ? "" : " $title "
    padding = width - 2 - length(title_display)
    left_pad = div(padding, 2)
    right_pad = padding - left_pad
    
    result = themed("$tl$(repeat(h, left_pad))$title_display$(repeat(h, right_pad))$tr\n", :primary)
    
    # Content lines
    for line in split(content, '\n')
        line_len = textwidth(line)
        line_pad = width - 2 - line_len
        result *= themed(v, :primary) * " " * line * repeat(" ", max(0, line_pad - 1)) * themed(v, :primary) * "\n"
    end
    
    # Bottom bar
    result *= themed("$bl$(repeat(h, width - 2))$br", :primary)
    
    return result
end

"""
    table(headers::Vector{String}, rows::Vector{Vector{String}}; align::Vector{Symbol} = Symbol[])

Create a formatted table.
"""
function table(headers::Vector{String}, rows::Vector{Vector{String}}; 
               align::Vector{Symbol} = fill(:left, length(headers)))
    
    ncols = length(headers)
    widths = [maximum([length(headers[i]); [length(row[i]) for row in rows if length(row) >= i]]) 
              for i in 1:ncols]
    
    # Helper to pad cell
    function pad_cell(text::String, width::Int, alignment::Symbol)
        len = length(text)
        if alignment == :right
            return repeat(" ", width - len) * text
        elseif alignment == :center
            left = div(width - len, 2)
            return repeat(" ", left) * text * repeat(" ", width - len - left)
        else
            return text * repeat(" ", width - len)
        end
    end
    
    # Build table
    sep = themed(BOX[:lt], :dim) * themed(join([repeat(BOX[:h], w + 2) for w in widths], BOX[:x]), :dim) * themed(BOX[:rt], :dim)
    top = themed(BOX[:tl], :dim) * themed(join([repeat(BOX[:h], w + 2) for w in widths], BOX[:tt]), :dim) * themed(BOX[:tr], :dim)
    bot = themed(BOX[:bl], :dim) * themed(join([repeat(BOX[:h], w + 2) for w in widths], BOX[:bt]), :dim) * themed(BOX[:br], :dim)
    
    result = top * "\n"
    
    # Headers
    header_cells = [themed(pad_cell(headers[i], widths[i], :center), :primary) for i in 1:ncols]
    result *= themed(BOX[:v], :dim) * " " * join(header_cells, themed(" $(BOX[:v]) ", :dim)) * " " * themed(BOX[:v], :dim) * "\n"
    result *= sep * "\n"
    
    # Rows
    for row in rows
        cells = [pad_cell(get(row, i, ""), widths[i], get(align, i, :left)) for i in 1:ncols]
        result *= themed(BOX[:v], :dim) * " " * join(cells, themed(" $(BOX[:v]) ", :dim)) * " " * themed(BOX[:v], :dim) * "\n"
    end
    
    result *= bot
    return result
end

"""
    progress(current::Int, total::Int; width::Int = 40, label::String = "")

Create a progress bar.
"""
function progress(current::Int, total::Int; width::Int = 40, label::String = "")
    pct = total > 0 ? current / total : 0.0
    filled = round(Int, pct * width)
    empty = width - filled
    
    bar = themed(repeat(PROGRESS_CHARS[:filled], filled), :success) * 
          themed(repeat(PROGRESS_CHARS[:empty], empty), :dim)
    
    pct_str = @sprintf("%.1f%%", pct * 100)
    
    if !isempty(label)
        return "$label [$bar] $pct_str"
    else
        return "[$bar] $pct_str"
    end
end

"""
    spinner(message::String; style::Symbol = :dots)

Create a spinner animation (returns function to update).
"""
function spinner(message::String; style::Symbol = :dots)
    frames = get(SPINNERS, style, SPINNERS[:dots])
    idx = Ref(1)
    
    return function(done::Bool = false)
        if done
            print("\r$(ICONS[:success]) $message $(themed("done", :success))            \n")
        else
            frame = frames[idx[]]
            print("\r$(themed(frame, :primary)) $message")
            idx[] = mod1(idx[] + 1, length(frames))
        end
    end
end

# ───────────────────────────────────────────────────────────────────────────────
#                              STATUS MESSAGES
# ───────────────────────────────────────────────────────────────────────────────

"""
    info(message::String)

Print info message.
"""
function info(message::String)
    println(themed("[$(ICONS[:info])]", :info), " ", message)
end

"""
    success(message::String)

Print success message.
"""
function success(message::String)
    println(themed("[$(ICONS[:success])]", :success), " ", message)
end

"""
    warn_msg(message::String)

Print warning message.
"""
function warn_msg(message::String)
    println(themed("[$(ICONS[:warning])]", :warning), " ", message)
end

"""
    error_msg(message::String)

Print error message.
"""
function error_msg(message::String)
    println(themed("[$(ICONS[:error])]", :error), " ", message)
end

"""
    step(number::Int, message::String)

Print step indicator.
"""
function step(number::Int, message::String)
    println(themed("[$number]", :accent), " ", message)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              THREAT DISPLAY
# ───────────────────────────────────────────────────────────────────────────────

const THREAT_BADGES = Dict(
    CRITICAL => ("CRITICAL", :bg_red),
    HIGH     => ("HIGH", :red),
    MEDIUM   => ("MEDIUM", :yellow),
    LOW      => ("LOW", :cyan),
    INFO     => ("INFO", :dim),
)

"""
    threat_badge(level::ThreatLevel)

Create a threat level badge.
"""
function threat_badge(level::ThreatLevel)
    label, color = get(THREAT_BADGES, level, ("UNKNOWN", :dim))
    return colorize(" $label ", color)
end

"""
    display_threat(threat::Threat)

Display a threat with full formatting.
"""
function display_threat(threat::Threat)
    badge = threat_badge(threat.level)
    
    println()
    println(themed("$(BOX[:tl])$(repeat(BOX[:h], 60))$(BOX[:tr])", :warning))
    println(themed(BOX[:v], :warning), " ", badge, " ", themed(string(threat.category), :primary))
    println(themed("$(BOX[:lt])$(repeat(BOX[:h], 60))$(BOX[:rt])", :warning))
    println(themed(BOX[:v], :warning), " Source: ", themed(threat.source, :secondary))
    println(themed(BOX[:v], :warning), " ", threat.description)
    
    if !isempty(threat.indicators)
        println(themed(BOX[:v], :warning), " Indicators:")
        for ioc in threat.indicators
            println(themed(BOX[:v], :warning), "   $(ICONS[:bullet]) ", themed(ioc, :dim))
        end
    end
    
    println(themed("$(BOX[:bl])$(repeat(BOX[:h], 60))$(BOX[:br])", :warning))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              SCAN RESULTS DISPLAY
# ───────────────────────────────────────────────────────────────────────────────

"""
    display_scan_results(results::Vector{ScanResult})

Display formatted scan results.
"""
function display_scan_results(results::Vector{ScanResult})
    isempty(results) && return println(themed("[!] No results", :warning))
    
    open_ports = filter(r -> r.state == OPEN, results)
    filtered_ports = filter(r -> r.state == FILTERED, results)
    
    println()
    println(themed("╔════════════════════════════════════════════════════════════╗", :primary))
    println(themed("║                     SCAN RESULTS                           ║", :primary))
    println(themed("╠════════════════════════════════════════════════════════════╣", :primary))
    println(themed("║", :primary), " Target: ", themed(results[1].target.host, :secondary), 
            repeat(" ", 60 - 10 - length(results[1].target.host)), themed("║", :primary))
    println(themed("║", :primary), " Ports:  ", themed("$(length(open_ports)) open", :success), ", ",
            themed("$(length(filtered_ports)) filtered", :warning), ", ",
            themed("$(length(results) - length(open_ports) - length(filtered_ports)) closed", :dim),
            repeat(" ", 20), themed("║", :primary))
    println(themed("╠════════════════════════════════════════════════════════════╣", :primary))
    
    if !isempty(open_ports)
        println(themed("║", :primary), themed(" OPEN PORTS:", :success), repeat(" ", 47), themed("║", :primary))
        for r in open_ports
            service = something(r.service, "unknown")
            port_str = @sprintf("%5d/%-4s", r.port, r.target.protocol)
            println(themed("║", :primary), "   ", themed(port_str, :success), " → ", service, 
                    repeat(" ", max(1, 50 - length(port_str) - length(service))), themed("║", :primary))
        end
    end
    
    println(themed("╚════════════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              ASCII ART BANNERS
# ───────────────────────────────────────────────────────────────────────────────

const MODULE_BANNERS = Dict(
    :scanner => """
    ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
    ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
    ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═
    """,
    :crypto => """
    ╔═╗╦═╗╦ ╦╔═╗╔╦╗╔═╗
    ║  ╠╦╝╚╦╝╠═╝ ║ ║ ║
    ╚═╝╩╚═ ╩ ╩   ╩ ╚═╝
    """,
    :recon => """
    ╦═╗╔═╗╔═╗╔═╗╔╗╔
    ╠╦╝║╣ ║  ║ ║║║║
    ╩╚═╚═╝╚═╝╚═╝╝╚╝
    """,
    :analysis => """
    ╔═╗╔╗╔╔═╗╦  ╦ ╦╔═╗╦╔═╗
    ╠═╣║║║╠═╣║  ╚╦╝╚═╗║╚═╗
    ╩ ╩╝╚╝╩ ╩╩═╝ ╩ ╚═╝╩╚═╝
    """,
    :forensics => """
    ╔═╗╔═╗╦═╗╔═╗╔╗╔╔═╗╦╔═╗╔═╗
    ╠╣ ║ ║╠╦╝║╣ ║║║╚═╗║║  ╚═╗
    ╚  ╚═╝╩╚═╚═╝╝╚╝╚═╝╩╚═╝╚═╝
    """,
    :fuzzer => """
    ╔═╗╦ ╦╔═╗╔═╗╔═╗╦═╗
    ╠╣ ║ ║╔═╝╔═╝║╣ ╠╦╝
    ╚  ╚═╝╚═╝╚═╝╚═╝╩╚═
    """
)

"""
    module_banner(mod::Symbol)

Display module-specific banner.
"""
function module_banner(mod::Symbol)
    banner_art = get(MODULE_BANNERS, mod, "")
    if !isempty(banner_art)
        for line in split(banner_art, '\n')
            println(themed(line, :primary))
        end
    end
end
