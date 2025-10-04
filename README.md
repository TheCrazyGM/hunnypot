# Hunnypot

Hunnypot is a whimsical honeypot web server that fabricates irresistible but bogus secrets for would-be bots. It fronts a simple HTTP server, routes payload requests by file extension, and streams handcrafted nonsense from a local Ollama model.

## Features

- Serves playful payloads for dozens of file types (`.env`, `.json`, `.sql`, `.pem`, `.csv`, `.xml`, `.md`, and more).
- Streams responses from an Ollama model with configurable token budgets.
- Caches recent responses for a short TTL to keep curious crawlers engaged while saving tokens.
- Automatically falls back to themed placeholders if the model call fails.

## Prerequisites

- Go 1.22 or newer (module built with Go 1.24).
- [Ollama](https://ollama.com/) installed locally with at least one chat-capable model pulled (e.g. `ollama pull llama3.2`).

## Getting Started

1. Install dependencies:

```sh
go mod tidy
```

2. Ensure Ollama is running locally:

```sh
ollama serve
```

3. Export optional environment variables:

```sh
export OLLAMA_MODEL=llama3.2
export HONEYPOT_REQUEST_TIMEOUT=45s
export HUNNYPOT_CACHE_TTL=30s
export PORT=8080
```

4. Run the server:

```sh
go run ./...
```

5. Visit `http://localhost:8080/` or hit specific bait paths, e.g. `http://localhost:8080/secret.env`.

## Configuration

- `OLLAMA_MODEL`: Ollama model name to query (defaults to `llama3.2`).
- `HUNNYPOT_CACHE_TTL`: Duration to cache model responses (`30s` by default). Set to `0` to disable caching.
- `HONEYPOT_REQUEST_TIMEOUT`: Maximum time for downstream requests (`45s` by default).
- `PORT`: Listening address (supports bare port or `host:port`).

## Development

- Format: `gofmt -w *.go`
- Build: `go build ./...`
- Test locally with `curl`:

```sh
curl -s http://localhost:8080/loot.json
```

## License

This project is released under the MIT License. See [`LICENSE`](LICENSE).
