# Hunnypot

Hunnypot is a whimsical honeypot web server that fabricates irresistible but bogus secrets for would-be bots. Fights malicious attackers with humor + deception. All in good fun 🕵️‍♀️

## What's New 🐝

- **Security Headers**: Added X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, and Strict-Transport-Security headers
- **Cache Protection**: LRU cache eviction to protect against memory leaks with configurable max size via HUNNYPOT_MAX_CACHE
- **Enhanced Logging**: Request IDs, timestamps, and request correlation through logs
- **Bug Fixes**: Fixed syntax errors in cache eviction logic
- **Code Quality**: Refactored for better maintainability

## Features

- Serves playful payloads for dozens of file types (`.env`, `.json`, `.sql`, `.pem`, `.csv`, `.xml`, `.md`, and more)
- Streams responses from an Ollama model with configurable token budgets
- Caches recent responses for a short TTL to keep curious crawlers engaged while saving tokens
- Automatically falls back to themed placeholders if the model call fails
- Added security headers to make the honeypot more convincing
- Memory-safe cache with configurable maximum size

## Prerequisites

- Go 1.22 or newer
- [Ollama](https://ollama.com/) installed locally with at least one chat-capable model pulled (e.g. `ollama pull llama3.2`)

## Quick Start

1. Install dependencies:

```bash
go mod tidy
```

2. Ensure Ollama is running:

```sh
ollama serve
```

3. Run the server:

```bash
export OLLAMA_MODEL=llama3.2
go run main.go
```

## Configuration

Set these optional environment variables:

- `OLLAMA_MODEL` (default: "llama3.2"): Ollama model name to query
- `HONEYPOT_REQUEST_TIMEOUT` (default: 45s): Maximum time for downstream requests
- `HUNNYPOT_CACHE_TTL` (default: 30s): Duration to cache model responses (0 to disable)
- `HUNNYPOT_MAX_CACHE` (default: 1000): Maximum number of cache entries
- `PORT` (default: 8080): Listening address

## Testing

Visit these endpoints to see the honeypot in action:

- Visit: `http://localhost:8080/secret.env`
- Try: `curl -s http://localhost:8080/loot.json`
- Test: `curl -s http://localhost:8080/.env`

## Development

- Format: `gofmt -w *.go`
- Build: `go build main.go`
- Run: `./hunnypot`

## Security Improvements

- **Security Headers**: Added comprehensive security headers
- **Cache Size Limiting**: Implemented LRU eviction to prevent memory leaks
- **Request Logging**: Added request IDs and correlation for better monitoring
- **Input Validation**: Improved path handling and request validation

## License

This project is released under the MIT License. See [`LICENSE`](LICENSE).

---

*Happy hunting! 🍯*
