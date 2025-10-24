# safe-curl

A command-line tool that analyzes shell scripts before executing them to detect potentially malicious patterns. Helps prevent accidentally running harmful `curl | bash` install scripts.

**Two implementations available**:
- **Bash version** (recommended): Full-featured with AI-powered analysis
- **Zig version**: Work-in-progress native implementation

## Features

### Bash Version (`./safe-curl`)

- **🤖 AI-Powered Analysis**: Uses Claude (Anthropic) or GPT-4 (OpenAI) for intelligent threat detection
  - Context-aware security analysis
  - Natural language explanations
  - Sophisticated pattern recognition
  - Detailed recommendations

- **Pattern-Based Fallback**: Works without API keys using regex patterns
  - Recursive file deletion (`rm -rf`)
  - Code obfuscation (base64 decoding, eval)
  - Downloading and executing additional scripts
  - Privilege escalation (sudo)
  - System file modifications
  - Shell configuration changes
  - PATH modifications

- **Minimal Dependencies**: Pure bash script (Python optional for JSON parsing)
- **Color-coded Output**: Critical issues, warnings, and info messages
- **Interactive Execution**: Prompts before executing analyzed scripts
- **Risk Assessment**: Automatically calculates risk level (HIGH/MEDIUM/LOW)

### Zig Version (`zig-out/bin/safe-curl`)

- **Pattern-based Analysis**: Core detection patterns implemented
- **Zero Dependencies**: Single compiled binary
- **Type Safety**: Zig's compile-time guarantees
- **AI Analysis**: Detected but not yet implemented

## Quick Start

### Using the Bash Version (Recommended)

The bash version is production-ready with full AI support:

```bash
# Make executable
chmod +x safe-curl

# With AI-powered analysis (recommended)
export ANTHROPIC_API_KEY="your-anthropic-api-key"
# OR
export OPENAI_API_KEY="your-openai-api-key"

# Analyze a script
./safe-curl https://example.com/install.sh

# Without API keys (pattern matching)
./safe-curl https://example.com/install.sh
```

**Installation**:
```bash
# Copy to your PATH
sudo cp safe-curl /usr/local/bin/
# Or user-local
mkdir -p ~/.local/bin && cp safe-curl ~/.local/bin/
```

See [EXAMPLES.md](EXAMPLES.md) for detailed usage examples.

### AI-Powered Analysis

Set up your API key for intelligent threat detection:

```bash
# For Anthropic Claude (recommended, ~$0.003 per analysis)
export ANTHROPIC_API_KEY="sk-ant-..."

# Or for OpenAI GPT-4 (~$0.0015 per analysis)
export OPENAI_API_KEY="sk-..."
```

**What AI analysis provides**:
- Context-aware security findings
- Natural language explanations of what the script does
- Specific line numbers and security implications
- Overall risk assessment with reasoning
- Recommendations for safe usage

**Without API keys**: Falls back to regex pattern matching (free, works offline)

## Why Two Versions?

**Bash version**: Production-ready with full AI integration. Use this for actual security analysis.

**Zig version**: Educational experiment exploring systems programming with Zig 0.15. Demonstrates:
- Memory management patterns
- Error handling with try/catch
- Struct-based architecture
- Standard library usage
- Cross-compilation capabilities

## Building the Zig Version

Requires Zig 0.15.x:

```bash
cd safe-curl-zig
zig build
```

For an optimized release build:

```bash
# Balanced (342KB)
zig build -Doptimize=ReleaseSafe

# Smallest (120KB)
zig build -Doptimize=ReleaseSmall

# Fastest (larger size)
zig build -Doptimize=ReleaseFast
```

The binary will be created at `zig-out/bin/safe-curl`.

## Installation

### macOS/Linux

Recommended for user-specific installation (no sudo required):

```bash
# Build optimized binary
zig build -Doptimize=ReleaseSmall

# Install to user bin directory
mkdir -p ~/.local/bin
cp zig-out/bin/safe-curl ~/.local/bin/

# Add to PATH (add to ~/.zshrc or ~/.bash_profile)
export PATH="$HOME/.local/bin:$PATH"
```

Or for system-wide installation:

```bash
sudo cp zig-out/bin/safe-curl /usr/local/bin/
```

### Cross-compilation

Build for different platforms:

```bash
# macOS Intel
zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-macos

# macOS Apple Silicon
zig build -Doptimize=ReleaseSmall -Dtarget=aarch64-macos

# Linux x86_64
zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-linux

# Windows
zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-windows
```

## Usage

### Bash Version

```bash
# With AI analysis
export ANTHROPIC_API_KEY="your-key"
./safe-curl https://example.com/install.sh

# Read from stdin
curl https://example.com/install.sh | ./safe-curl -

# Show help
./safe-curl --help
```

### Zig Version

```bash
# Analyze a script from a URL
zig-out/bin/safe-curl https://example.com/install.sh

# Show help
zig-out/bin/safe-curl --help
```

Both versions:
1. Fetch the script from the URL
2. Analyze it for malicious patterns
3. Display color-coded findings
4. Show the risk level
5. Display the full script with line numbers
6. Prompt you to execute (or cancel)

## Example Output

### Bash Version with AI

```bash
$ export ANTHROPIC_API_KEY="your-key"
$ ./safe-curl https://raw.githubusercontent.com/tristanisham/zvm/master/install.sh

=== Safe Curl v2.0.0 ===
Using AI-powered analysis (anthropic)...

Fetching script from: https://raw.githubusercontent.com/...

Contacting anthropic API...

=== AI Analysis Results ===

[WARNING] Downloads files over HTTPS without checksum verification (Lines: 22-24, 43-45)
[WARNING] Modifies PATH environment variable with user-writable directories (Lines: 119-131)
[INFO] Creates directories in user's home without checking available space (Line: 28, 47)
[INFO] Uses potentially unsafe pattern matching for SHELL variable (Lines: 96, 98, 116, 134)

Script Purpose:
This is an installer script for ZVM (Zig Version Manager). The script detects OS and
architecture, downloads appropriate ZVM binary from GitHub releases, extracts it to
~/.zvm/self, and configures shell environment variables. While there are some security
considerations, the overall risk is low because downloads are from GitHub releases over
HTTPS and only operates in user's home directory.

=== Analysis Summary ===
Critical issues: 0
Warnings: 2
Info: 2

RISK LEVEL: LOW
No major issues detected, but always review scripts before running.

Do you want to execute this script? (yes/no):
```

### Pattern-Based Analysis (No API Key)

```bash
$ ./safe-curl https://example.com/install.sh

=== Safe Curl v2.0.0 ===
Analyzing script for potentially malicious patterns...

Fetching script from: https://example.com/install.sh

[WARNING] Requires root/sudo privileges
  Line: 15

[WARNING] Modifying system directories
  Line: 23

[INFO] Downloading files
  Line: 8

=== Analysis Summary ===
Critical issues: 0
Warnings: 2
Info: 1

RISK LEVEL: MEDIUM
This script requires elevated privileges or modifies system files.

Do you want to execute this script? (yes/no):
```

## Detection Patterns

### Critical Issues (Risk: HIGH)
- `rm -rf` on system/home directories
- Dynamic code execution with `eval`
- Base64 decoding (possible obfuscation)
- Downloading and piping to bash/sh

### Warnings (Risk: MEDIUM if >3)
- Sudo/root privilege usage
- System directory modifications (`/etc`, `/usr`, `/bin`)
- Shell configuration file changes (`.bashrc`, `.zshrc`)
- Subshell downloads
- Making files executable

### Info (Always shown)
- File downloads
- Git clones
- PATH modifications

## Dependencies

### Bash Version
- **Required**: bash, curl
- **Optional**: python3 (for reliable JSON parsing in AI mode)
- **For AI**: ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable

### Zig Version
- **Build**: Zig 0.15.x
- **Runtime**: Uses curl subprocess for HTTP requests (present on all systems)

## Security Notes

- This tool is designed for **defensive security** and **educational purposes**
- Helps users review scripts before execution
- **Does NOT guarantee complete security**
- Always review the script content yourself
- Use caution with scripts from unknown sources
- **AI mode**: Script content is sent to third-party APIs (Anthropic/OpenAI)

## Cost Considerations (Bash Version)

- **Anthropic Claude**: ~$0.003 per analysis (Claude Sonnet 3.5)
- **OpenAI GPT-4o-mini**: ~$0.0015 per analysis
- **Pattern matching**: Free (no API calls)

## Project Structure

```
safe-curl-zig/
├── safe-curl          # Bash implementation (production-ready, AI-enabled)
├── EXAMPLES.md        # Usage examples for bash version
├── README.md          # This file
├── build.zig          # Zig build configuration
├── src/
│   └── main.zig      # Zig implementation (~413 lines, WIP)
├── tests/             # Test files
├── zig-out/
│   └── bin/
│       └── safe-curl  # Compiled Zig binary
└── .gitignore
```

## Development

```bash
# Run without installing
zig build run -- https://example.com/install.sh

# Run tests (if you add them)
zig build test

# Clean build artifacts
rm -rf zig-cache/ zig-out/
```

## License

Free to use for security testing, educational purposes, and personal use.

## Contributing

Both implementations welcome contributions:

**Bash version**:
- Additional detection patterns
- Support for more AI providers
- Improved error handling
- Better JSON parsing without python dependency

**Zig version**:
- Add AI analysis support (port from bash)
- Native HTTP client implementation
- Add stdin support
- Comprehensive test suite
- Performance optimizations

## Future Improvements

### Bash Version
- [ ] Support for more AI providers (Gemini, etc.)
- [ ] Configurable pattern rules via config file
- [ ] JSON output mode for CI/CD integration

### Zig Version
- [ ] Native HTTP client (remove curl dependency)
- [ ] AI-powered analysis integration
- [ ] Stdin support (`curl | safe-curl -`)
- [ ] Comprehensive test suite
- [ ] Man page documentation
