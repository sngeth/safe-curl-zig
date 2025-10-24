# safe-curl (Zig Implementation)

A Zig implementation of `safe-curl` - a tool that analyzes shell scripts before executing them to detect potentially malicious patterns.

## Features

- **Pattern-based Analysis**: Detects dangerous operations like:
  - Recursive file deletion (`rm -rf`)
  - Code obfuscation (base64 decoding)
  - Dynamic code execution (`eval`)
  - Downloading and executing additional scripts
  - Privilege escalation (`sudo`)
  - System file modifications
  - Shell configuration changes

- **Color-coded Output**: Critical issues, warnings, and info messages with ANSI colors
- **Interactive Execution**: Prompts before executing analyzed scripts
- **Risk Assessment**: Automatically calculates risk level (HIGH/MEDIUM/LOW)
- **Zero Dependencies**: Single binary, no external dependencies required

## Why Zig?

Advantages over the bash implementation:

1. **Single Binary**: No dependencies on bash, curl, or python - everything is compiled into one binary
2. **Better Performance**: Compiled code is faster than interpreted bash
3. **Type Safety**: Zig's type system catches errors at compile time
4. **More Transparent**: All code is in one language (~413 lines), easier to audit
5. **Highly Portable**: Single binary can be distributed without worrying about dependencies
6. **Small Size**: Only 120KB-342KB depending on optimization level

## Building

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

```bash
# Analyze a script from a URL
safe-curl https://example.com/install.sh

# Show help
safe-curl --help
```

The tool will:
1. Fetch the script from the URL
2. Analyze it for malicious patterns
3. Display color-coded findings
4. Show the risk level
5. Display the full script with line numbers
6. Prompt you to execute (or cancel)

## Example Output

```bash
$ safe-curl https://example.com/install.sh

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

=== Script Content ===
     1  #!/bin/bash
     2  # Installation script
     ...

=== End of Script ===

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

## Comparison with Bash Version

| Feature | Bash | Zig |
|---------|------|-----|
| Dependencies | bash, curl, python (optional) | None |
| Binary Size | N/A (script) | 120KB-342KB |
| Execution Speed | Slower (interpreted) | Faster (compiled) |
| Distribution | Need to ensure dependencies | Single binary |
| AI Analysis | Supported | Detected but not yet implemented |
| Code Lines | ~500 | ~413 |
| Audit Complexity | Multiple tools/languages | Single language |

## Security Notes

- This tool is designed for **defensive security** and **educational purposes**
- Helps users review scripts before execution
- **Does NOT guarantee complete security**
- Always review the script content yourself
- Use caution with scripts from unknown sources
- The tool uses `curl` subprocess for HTTP fetching (standard on all systems)

## Project Structure

```
safe-curl-zig/
├── build.zig          # Zig build configuration
├── src/
│   └── main.zig      # Main implementation (~413 lines)
├── .gitignore
└── README.md
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

This is a Zig port of the original bash `safe-curl`. Contributions welcome:
- Add more detection patterns
- Improve pattern matching
- Add proper Zig HTTP client implementation (currently uses curl subprocess)
- Add AI analysis support
- Add tests
- Performance improvements

## Future Improvements

- [ ] Native HTTP client (remove curl dependency)
- [ ] AI-powered analysis integration
- [ ] Configurable pattern rules
- [ ] JSON output mode
- [ ] CI/CD integration examples
- [ ] Comprehensive test suite
- [ ] Man page documentation
