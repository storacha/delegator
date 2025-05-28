# Makefile Documentation

This project includes a comprehensive Makefile that provides standardized commands for building, testing, and managing the Delegator Service.

## Quick Reference

```bash
make help          # Show all available targets
make build         # Build both server and client binaries
make quick         # Format, vet, and build (fast development cycle)
make demo          # Run a complete demo of the onboarding flow
make dev           # Full development setup and run server
make test          # Run tests
make clean         # Remove built artifacts
```

## Development Workflow

### Daily Development
```bash
make quick         # Fast build after making changes
make dev-server    # Run development server with config
make demo          # Test the complete flow
```

### Code Quality
```bash
make fmt           # Format Go code
make vet           # Run go vet
make lint          # Run golangci-lint (requires installation)
make test          # Run tests
make test-coverage # Run tests with coverage report
make check         # Run all quality checks
```

### Build Targets

#### Standard Builds
- `make build` - Build both server and client binaries
- `make build-server` - Build only server binary
- `make build-client` - Build only client binary
- `make build-race` - Build with race detection enabled

#### Release Builds
- `make release` - Build cross-platform release binaries
- `make install` - Install binaries to $GOPATH/bin

#### Docker
- `make docker-build` - Build Docker image
- `make docker-run` - Run Docker container

### Testing Targets

- `make test` - Standard test run
- `make test-race` - Tests with race detection
- `make test-coverage` - Tests with coverage report (generates coverage.html)
- `make benchmark` - Run benchmarks

### Utility Targets

#### Development Tools
- `make tools` - Install development tools (golangci-lint, gosec, godoc)
- `make deps` - Download and tidy dependencies
- `make mod-update` - Update all dependencies to latest versions

#### Code Quality
- `make security-check` - Run security analysis with gosec
- `make docs` - Start documentation server

#### Monitoring
- `make health-check` - Check if server is healthy
- `make version` - Show build version information

#### File Watching
- `make watch` - Watch for file changes and rebuild (requires `entr`)

### CI/CD Targets

- `make ci` - Complete CI pipeline (deps, fmt, vet, lint, test-race, test-coverage)
- `make all` - Run all checks and build binaries

## Version Information

The Makefile automatically injects build information into binaries:

- **Version**: Git tag or commit hash
- **Commit**: Short git commit hash
- **Build Time**: UTC timestamp

This information is available via:
```bash
./bin/delegator-client version
./bin/delegator-server version
make version
```

## Build Configuration

### Environment Variables
- `VERSION` - Override version (defaults to git describe)
- `GOOS` / `GOARCH` - Cross-compilation targets

### Build Flags
The Makefile uses optimized build flags:
- `-ldflags` for version injection and binary optimization
- `-race` flag for race detection builds
- Cross-compilation support for multiple platforms

## Platform Support

### Supported Platforms (release target)
- Linux AMD64
- macOS AMD64 
- macOS ARM64 (Apple Silicon)
- Windows AMD64

### Dependencies
- Go 1.23+
- Git (for version information)
- Optional: golangci-lint, gosec, entr, docker

## File Structure

```
bin/                    # Built binaries
├── delegator-server   # Server binary
├── delegator-client   # Client binary
└── release/           # Cross-platform release binaries
```

## Integration with Development Tools

### IDE Integration
Most IDEs can be configured to use Makefile targets:
- **VSCode**: Tasks can call `make` targets
- **GoLand**: Can run Makefile targets directly
- **Vim/Neovim**: Can use `:make` with targets

### Git Hooks
Consider adding git hooks that run quality checks:
```bash
# .git/hooks/pre-commit
#!/bin/sh
make check
```

### CI/CD Integration
The Makefile is designed for CI/CD pipelines:
```yaml
# Example GitHub Actions step
- name: Run CI checks
  run: make ci
```

## Customization

The Makefile can be extended by:
1. Adding new targets following the pattern
2. Modifying build flags in variables section
3. Adding platform-specific targets
4. Integrating additional tools

## Best Practices

1. **Use `make help`** to discover available targets
2. **Use `make quick`** for fast development cycles
3. **Use `make ci`** before committing code
4. **Use `make demo`** to test end-to-end functionality
5. **Keep dependencies updated** with `make mod-update`

## Troubleshooting

### Common Issues
- **golangci-lint not found**: Run `make tools` to install
- **entr not found**: Install via package manager for `make watch`
- **Build fails**: Try `make clean deps` to reset state

### Clean State
```bash
make clean             # Remove built artifacts
go clean -modcache     # Clean module cache (if needed)
make deps              # Restore dependencies
```