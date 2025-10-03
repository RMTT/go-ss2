# Claude Code Instructions

This is a Go implementation of Shadowsocks, a secure proxy protocol.

## Project Structure
- `core/` - Core cipher implementations
- `shadowaead/` - AEAD cipher implementations  
- `shadowaead_2022/` - 2022 AEAD cipher implementations
- `internal/` - Internal utilities (bloom filter, salt filter)
- `socks/` - SOCKS5 proxy implementation
- `main.go` - Entry point and CLI handling

## Build and Test Commands
```bash
# Build the project
go build -o go-shadowsocks2

# Run tests
go test ./...

# Run specific cipher tests
go run test_ciphers.go
go run test_2022_cipher.go
go run test_2022_compliance.go

# Format code
go fmt ./...

# Vet code
go vet ./...
```

## Development Notes
- Uses Go 1.23
- Implements multiple cipher types (AEAD, 2022 spec)
- Includes replay attack mitigation via bloom filters
- Supports SOCKS5 proxy, TCP/UDP tunneling, and platform-specific redirects
- SIP003 plugin support