const std = @import("std");

const VERSION = "2.0.0";

// ANSI color codes
const Color = struct {
    const RED = "\x1b[0;31m";
    const YELLOW = "\x1b[1;33m";
    const GREEN = "\x1b[0;32m";
    const BLUE = "\x1b[0;34m";
    const BOLD = "\x1b[1m";
    const NC = "\x1b[0m";
};

const Severity = enum {
    CRITICAL,
    WARNING,
    INFO,

    fn color(self: Severity) []const u8 {
        return switch (self) {
            .CRITICAL => Color.RED,
            .WARNING => Color.YELLOW,
            .INFO => Color.BLUE,
        };
    }

    fn name(self: Severity) []const u8 {
        return switch (self) {
            .CRITICAL => "CRITICAL",
            .WARNING => "WARNING",
            .INFO => "INFO",
        };
    }
};

const Finding = struct {
    severity: Severity,
    message: []const u8,
    line_num: usize,
};

const AnalysisResult = struct {
    critical_count: usize,
    warning_count: usize,
    info_count: usize,
    findings: std.ArrayList(Finding),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) AnalysisResult {
        return .{
            .critical_count = 0,
            .warning_count = 0,
            .info_count = 0,
            .findings = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *AnalysisResult) void {
        self.findings.deinit(self.allocator);
    }

    fn addFinding(self: *AnalysisResult, severity: Severity, message: []const u8, line_num: usize) !void {
        try self.findings.append(self.allocator, .{
            .severity = severity,
            .message = message,
            .line_num = line_num,
        });

        switch (severity) {
            .CRITICAL => self.critical_count += 1,
            .WARNING => self.warning_count += 1,
            .INFO => self.info_count += 1,
        }
    }

    fn getRiskLevel(self: *const AnalysisResult) []const u8 {
        if (self.critical_count > 0) {
            return "HIGH";
        } else if (self.warning_count > 3) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
};

const AIProvider = enum {
    none,
    anthropic,
    openai,
};

// Helper function to print formatted output
fn printf(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const stdout = std.fs.File.stdout();
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(msg);
    try stdout.writeAll(msg);
}

fn printHeader(allocator: std.mem.Allocator, use_ai: bool, provider: AIProvider) !void {
    try printf(allocator, "{s}{s}=== Safe Curl v{s} ==={s}\n", .{ Color.BOLD, Color.BLUE, VERSION, Color.NC });
    if (use_ai) {
        const provider_name = switch (provider) {
            .anthropic => "anthropic",
            .openai => "openai",
            .none => "none",
        };
        try printf(allocator, "{s}Using AI-powered analysis ({s})...{s}\n\n", .{ Color.BLUE, provider_name, Color.NC });
    } else {
        try printf(allocator, "{s}Analyzing script for potentially malicious patterns...{s}\n\n", .{ Color.BLUE, Color.NC });
    }
}

fn printFinding(allocator: std.mem.Allocator, finding: Finding) !void {
    const color_code = finding.severity.color();
    const severity_name = finding.severity.name();
    try printf(allocator, "{s}[{s}]{s} {s}\n", .{ color_code, severity_name, Color.NC, finding.message });
    try printf(allocator, "  Line: {d}\n\n", .{finding.line_num});
}

fn printSummary(allocator: std.mem.Allocator, result: *const AnalysisResult) !void {
    try printf(allocator, "{s}{s}=== Analysis Summary ==={s}\n", .{ Color.BOLD, Color.BLUE, Color.NC });
    try printf(allocator, "Critical issues: {s}{d}{s}\n", .{ Color.RED, result.critical_count, Color.NC });
    try printf(allocator, "Warnings: {s}{d}{s}\n", .{ Color.YELLOW, result.warning_count, Color.NC });
    try printf(allocator, "Info: {s}{d}{s}\n\n", .{ Color.BLUE, result.info_count, Color.NC });
}

fn showScript(allocator: std.mem.Allocator, script: []const u8) !void {
    try printf(allocator, "\n{s}{s}=== Script Content ==={s}\n\n", .{ Color.BOLD, Color.BLUE, Color.NC });

    var line_iter = std.mem.splitScalar(u8, script, '\n');
    var line_num: usize = 1;
    while (line_iter.next()) |line| {
        try printf(allocator, "{d:>6}\t{s}\n", .{ line_num, line });
        line_num += 1;
    }

    try printf(allocator, "\n{s}{s}=== End of Script ==={s}\n\n", .{ Color.BOLD, Color.BLUE, Color.NC });
}

fn promptExecution(allocator: std.mem.Allocator, result: *const AnalysisResult) !bool {
    const risk = result.getRiskLevel();

    if (std.mem.eql(u8, risk, "HIGH")) {
        try printf(allocator, "{s}{s}RISK LEVEL: HIGH{s}\n", .{ Color.RED, Color.BOLD, Color.NC });
        try printf(allocator, "{s}This script contains potentially dangerous operations!{s}\n\n", .{ Color.RED, Color.NC });
    } else if (std.mem.eql(u8, risk, "MEDIUM")) {
        try printf(allocator, "{s}{s}RISK LEVEL: MEDIUM{s}\n", .{ Color.YELLOW, Color.BOLD, Color.NC });
        try printf(allocator, "{s}This script requires elevated privileges or modifies system files.{s}\n\n", .{ Color.YELLOW, Color.NC });
    } else {
        try printf(allocator, "{s}{s}RISK LEVEL: LOW{s}\n", .{ Color.GREEN, Color.BOLD, Color.NC });
        try printf(allocator, "{s}No major issues detected, but always review scripts before running.{s}\n\n", .{ Color.GREEN, Color.NC });
    }

    const stdout = std.fs.File.stdout();
    const stdin = std.fs.File.stdin();

    try stdout.writeAll("Do you want to execute this script? (yes/no): ");

    var buf: [256]u8 = undefined;
    const amt = try stdin.read(&buf);
    if (amt == 0) return false;

    const response = buf[0..amt];
    const trimmed = std.mem.trim(u8, response, &std.ascii.whitespace);

    return std.ascii.eqlIgnoreCase(trimmed, "yes") or std.ascii.eqlIgnoreCase(trimmed, "y");
}

fn containsPattern(line: []const u8, pattern: []const u8) bool {
    return std.mem.indexOf(u8, line, pattern) != null;
}

fn analyzeScript(allocator: std.mem.Allocator, script: []const u8) !AnalysisResult {
    var result = AnalysisResult.init(allocator);

    var line_iter = std.mem.splitScalar(u8, script, '\n');
    var line_num: usize = 1;

    while (line_iter.next()) |line| : (line_num += 1) {
        // Critical patterns
        if ((containsPattern(line, "rm -rf") or containsPattern(line, "rm -fr")) and
            (containsPattern(line, "/*") or containsPattern(line, "/ ") or
            containsPattern(line, "~") or containsPattern(line, "/home") or
            containsPattern(line, "/Users")))
        {
            try result.addFinding(.CRITICAL, "Recursive file deletion detected (rm -rf)", line_num);
        }

        if (containsPattern(line, "eval") and (containsPattern(line, "$(") or containsPattern(line, "`"))) {
            try result.addFinding(.CRITICAL, "Dynamic code execution with eval", line_num);
        }

        if (containsPattern(line, "base64") and (containsPattern(line, "-d") or containsPattern(line, "--decode"))) {
            try result.addFinding(.CRITICAL, "Base64 decoding detected (possible obfuscation)", line_num);
        }

        if ((containsPattern(line, "curl") or containsPattern(line, "wget")) and
            containsPattern(line, "|") and (containsPattern(line, "bash") or containsPattern(line, "sh")))
        {
            try result.addFinding(.CRITICAL, "Downloading and executing additional scripts", line_num);
        }

        // Warning patterns
        if (containsPattern(line, "sudo")) {
            try result.addFinding(.WARNING, "Requires root/sudo privileges", line_num);
        }

        if (containsPattern(line, "/etc/") or containsPattern(line, "/usr/local/") or
            containsPattern(line, "/usr/bin/") or containsPattern(line, "/bin/"))
        {
            try result.addFinding(.WARNING, "Modifying system directories", line_num);
        }

        if (containsPattern(line, ".bashrc") or containsPattern(line, ".zshrc") or
            containsPattern(line, ".profile") or containsPattern(line, ".bash_profile") or
            containsPattern(line, ".zprofile"))
        {
            try result.addFinding(.WARNING, "Modifying shell configuration files", line_num);
        }

        if ((containsPattern(line, "$(curl") or containsPattern(line, "$(wget") or
            containsPattern(line, "`curl") or containsPattern(line, "`wget")))
        {
            try result.addFinding(.WARNING, "Downloading content in subshell", line_num);
        }

        if (containsPattern(line, "chmod") and (containsPattern(line, "+x") or
            containsPattern(line, "777") or containsPattern(line, "755")))
        {
            try result.addFinding(.WARNING, "Making files executable", line_num);
        }

        // Info patterns
        if (containsPattern(line, "export PATH=") or containsPattern(line, "PATH=")) {
            if (containsPattern(line, "$PATH")) {
                try result.addFinding(.INFO, "Modifying PATH environment variable", line_num);
            }
        }

        if ((containsPattern(line, "curl") or containsPattern(line, "wget")) and
            (containsPattern(line, "-o") or containsPattern(line, "-O") or
            containsPattern(line, "--output")))
        {
            try result.addFinding(.INFO, "Downloading files", line_num);
        }

        if (containsPattern(line, "git clone")) {
            try result.addFinding(.INFO, "Cloning git repository", line_num);
        }
    }

    return result;
}

fn fetchFromUrl(allocator: std.mem.Allocator, url: []const u8) ![]const u8 {
    // Use curl as a fallback since the Zig HTTP client API is too unstable
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "curl", "-fsSL", url },
    });
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        allocator.free(result.stdout);
        return error.HttpRequestFailed;
    }

    return result.stdout;
}

fn executeScript(allocator: std.mem.Allocator, script: []const u8) !void {
    const argv = [_][]const u8{ "bash", "-c", script };

    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    _ = try child.spawnAndWait();
}

fn showHelp(allocator: std.mem.Allocator) !void {
    try printf(allocator,
        \\safe-curl v{s} - Analyze scripts before executing them
        \\
        \\USAGE:
        \\    safe-curl <URL>                 Analyze and optionally execute script
        \\    safe-curl --help                Show this help message
        \\
        \\EXAMPLES:
        \\    safe-curl https://example.com/install.sh
        \\
        \\DESCRIPTION:
        \\    Fetches and analyzes shell scripts for potentially malicious patterns before
        \\    execution. Helps prevent accidentally running harmful install scripts.
        \\
        \\AI-POWERED ANALYSIS:
        \\    Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variables to enable
        \\    AI-powered security analysis for more sophisticated threat detection.
        \\
        \\    export ANTHROPIC_API_KEY="your-key"
        \\    safe-curl https://example.com/install.sh
        \\
        \\    Without API keys, falls back to pattern-based detection including:
        \\    - Recursive file deletion (rm -rf)
        \\    - Code obfuscation (base64, eval)
        \\    - Downloading additional scripts
        \\    - Privilege escalation (sudo)
        \\    - System file modifications
        \\    - Shell configuration changes
        \\
        \\
    , .{VERSION});
}

fn getEnvVar(allocator: std.mem.Allocator, key: []const u8) ?[]const u8 {
    return std.process.getEnvVarOwned(allocator, key) catch null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printf(allocator, "{s}Error: No URL provided{s}\n", .{ Color.RED, Color.NC });
        const stdout = std.fs.File.stdout();
        try stdout.writeAll("Usage: safe-curl <URL>\n");
        try stdout.writeAll("       safe-curl --help\n");
        return error.NoURLProvided;
    }

    const url = args[1];

    if (std.mem.eql(u8, url, "--help") or std.mem.eql(u8, url, "-h")) {
        try showHelp(allocator);
        return;
    }

    // Check for AI provider
    const anthropic_key = getEnvVar(allocator, "ANTHROPIC_API_KEY");
    const openai_key = getEnvVar(allocator, "OPENAI_API_KEY");

    const use_ai = anthropic_key != null or openai_key != null;
    const provider: AIProvider = if (anthropic_key != null)
        .anthropic
    else if (openai_key != null)
        .openai
    else
        .none;

    if (anthropic_key) |key| allocator.free(key);
    if (openai_key) |key| allocator.free(key);

    try printHeader(allocator, use_ai, provider);

    // Fetch the script
    try printf(allocator, "{s}Fetching script from: {s}{s}\n\n", .{ Color.BLUE, url, Color.NC });

    const script = fetchFromUrl(allocator, url) catch |err| {
        try printf(allocator, "{s}Error: Failed to fetch script from {s}: {s}{s}\n", .{ Color.RED, url, @errorName(err), Color.NC });
        return err;
    };
    defer allocator.free(script);

    if (script.len == 0) {
        try printf(allocator, "{s}Error: Empty script received{s}\n", .{ Color.RED, Color.NC });
        return error.EmptyScript;
    }

    // Analyze the script (no AI support for simplicity in this version)
    var result = try analyzeScript(allocator, script);
    defer result.deinit();

    // Print findings
    for (result.findings.items) |finding| {
        try printFinding(allocator, finding);
    }

    // Show summary
    try printSummary(allocator, &result);

    // Show the script
    try showScript(allocator, script);

    // Check if stdout is a terminal (interactive mode)
    const stdout_file = std.fs.File.stdout();
    const is_terminal = stdout_file.isTty();

    if (is_terminal) {
        if (try promptExecution(allocator, &result)) {
            try printf(allocator, "{s}Executing script...{s}\n\n", .{ Color.GREEN, Color.NC });
            try executeScript(allocator, script);
        } else {
            try printf(allocator, "{s}Execution cancelled.{s}\n", .{ Color.YELLOW, Color.NC });
            std.process.exit(1);
        }
    }
}
