package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "embed"

	"github.com/google/uuid"
	"github.com/ollama/ollama/api"
)

//go:embed web/index.html
var indexPage string

const (
	defaultModel          = "llama3.2"
	defaultListenAddr     = ":8080"
	defaultRequestTimeout = 45 * time.Second
	defaultCacheTTL       = 30 * time.Second
	maxResponseBytes      = 8192
)

var errResponseTooLarge = errors.New("hunnypot: response limit reached")

type payloadProfile struct {
	kind         string
	contentType  string
	instructions string
	fallback     string
}

type cacheEntry struct {
	body   string
	expiry time.Time
}

type honeypotServer struct {
	client       *api.Client
	model        string
	logger       *log.Logger
	timeout      time.Duration
	cacheMu      sync.RWMutex
	cache        map[string]cacheEntry
	cacheTTL     time.Duration
	maxCache     int
	requestCount int64
	startTime    time.Time
}

func main() {
	logger := log.New(os.Stdout, "[hunnypot] ", log.LstdFlags|log.Lshortfile)

	client, err := api.ClientFromEnvironment()
	if err != nil {
		logger.Fatalf("failed to init Ollama client: %v", err)
	}

	srv := &honeypotServer{
		client:    client,
		model:     envOrDefault("OLLAMA_MODEL", defaultModel),
		logger:    logger,
		timeout:   loadRequestTimeout(logger),
		cache:     make(map[string]cacheEntry),
		cacheTTL:  loadCacheTTL(logger),
		maxCache:  loadMaxCache(logger),
		startTime: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleRoot)

	addr := envOrDefault("PORT", defaultListenAddr)
	writeTimeout := srv.timeout
	if writeTimeout > 0 {
		writeTimeout += 2 * time.Second
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      writeTimeout,
	}

	go func() {
		logger.Printf("serving hunnypot on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
}

func (s *honeypotServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = fmt.Fprint(w, indexPage)
		return
	}

	profile := selectProfile(r.URL.Path)
	requestID := uuid.New().String()
	s.logger.Printf("%s %s from %s ua=%q request_id=%s", r.Method, r.URL.Path, r.RemoteAddr, r.Header.Get("User-Agent"), requestID)

	ctx, cancel := s.contextWithTimeout(r.Context())
	defer cancel()

	cacheKey := buildCacheKey(r, profile, s.model)
	if body, ok := s.lookupCache(cacheKey); ok {
		if len(body) > maxResponseBytes {
			body = body[:maxResponseBytes]
		}
		w.Header().Set("Content-Type", profile.contentType)
		w.Header().Set("X-Hunnypot-Request-ID", requestID)
		w.Header().Set("X-Hunnypot-Flair", profile.kind)
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, body)
		}
		return
	}

	body, err := s.generateHoney(ctx, profile, r)
	if err != nil {
		s.logger.Printf("fallback payload for %s (%s): %v", r.URL.Path, requestID, err)
		body = profile.fallback
	}

	if len(body) > maxResponseBytes {
		body = body[:maxResponseBytes]
	}

	if err == nil {
		s.storeCache(cacheKey, body)
	}

	w.Header().Set("Content-Type", profile.contentType)
	w.Header().Set("X-Hunnypot-Request-ID", requestID)
	w.Header().Set("X-Hunnypot-Flair", profile.kind)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = fmt.Fprint(w, body)
	}
}

func (s *honeypotServer) generateHoney(ctx context.Context, profile payloadProfile, r *http.Request) (string, error) {
	stream := true
	predictTokens := predictTokensForLimit(maxResponseBytes)
	req := &api.GenerateRequest{
		Model:   s.model,
		Prompt:  buildPrompt(profile, r),
		Stream:  &stream,
		Options: map[string]any{"num_predict": predictTokens},
	}

	var sb strings.Builder
	err := s.client.Generate(ctx, req, func(resp api.GenerateResponse) error {
		if len(resp.Response) == 0 {
			return nil
		}
		if sb.Len()+len(resp.Response) > maxResponseBytes {
			remaining := maxResponseBytes - sb.Len()
			if remaining > 0 {
				sb.WriteString(resp.Response[:remaining])
			}
			return errResponseTooLarge
		}
		sb.WriteString(resp.Response)
		return nil
	})

	if err != nil && !errors.Is(err, errResponseTooLarge) {
		return "", err
	}

	output := strings.TrimSpace(sb.String())
	if output == "" {
		return "", fmt.Errorf("empty response from model")
	}
	return output, nil
}

func (s *honeypotServer) contextWithTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if s.timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, s.timeout)
}

func buildPrompt(profile payloadProfile, r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "unknown scrawler"
	}
	target := r.URL.Path
	if target == "" {
		target = "/"
	}
	params := r.URL.RawQuery
	var queryNote string
	if params != "" {
		queryNote = fmt.Sprintf("The request included query parameters: %s\n\n", params)
	}

	return fmt.Sprintf(`You are the whimsical caretaker of a honeypot web server that delights in fibbing to suspicious bots.
Craft a %s payload that looks juicy and legit but is actually nonsense.
Rules:
- Include playful hints that it is bogus, but hide them subtly in comments, odd values, or whimsical notes.
- Keep it under about 200 lines.
- Never leak real secrets.
- If there are fields like tokens or keys, make them obviously fake but not trivially so.
- Respond with only the raw %s content, no introductions, commentary, Markdown formatting, or code fences.
- Output must be valid %s with no Markdown or code fences.
- Sprinkle in at least one silly reference to honey, bees, or Winnie-the-Pooh.

Request Path: %s
User-Agent: %s
%s
Format guidance: %s
`, profile.kind, profile.kind, profile.kind, target, ua, queryNote, profile.instructions)
}

func selectProfile(requestPath string) payloadProfile {
	cleaned := strings.ToLower(strings.TrimSpace(requestPath))
	base := filepath.Base(cleaned)
	ext := strings.ToLower(filepath.Ext(base))

	profile := payloadProfile{
		kind:         "mysterious artifact",
		contentType:  "text/plain; charset=utf-8",
		instructions: "Return a text document resembling a secret memo or credentials list with playful absurdities. Do not add Markdown, explanations, or code fences.",
		fallback:     `# Hunnypot Secret Scroll

access_token=HUNNY-` + uuid.New().String() + `
comment=Absolutely authentic. Bees love it.
`,
	}

	switch ext {
	case ".env":
		profile.kind = ".env configuration"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Write environment variable pairs, each on its own line as KEY=VALUE. Include whimsical secrets. Provide only the raw .env content without Markdown or commentary."
		profile.fallback = `# Winnie-approved environment
API_KEY=HUNNY-` + uuid.New().String() + `
DB_PASSWORD=beekeeperB@dge
COMMENT="beware dripping honey"
`
	case ".json":
		profile.kind = "JSON config"
		profile.contentType = "application/json"
		profile.instructions = "Return pretty-printed JSON resembling credentials or configuration. Include strings, numbers, nested objects, and comments as faux fields. Do not wrap in Markdown or explain the response."
		profile.fallback = `{
  "apiKey": "HNY-` + uuid.New().String() + `",
  "secrets": {
    "primary": "sticky-bear-hug",
    "comment": "do not feed the bots"
  }
}`
	case ".yml", ".yaml":
		profile.kind = "YAML manifest"
		profile.contentType = "application/x-yaml"
		profile.instructions = "Produce a YAML services config loaded with tantalizing secrets, comments, and honey references. Return only YAML with no Markdown fences or extra narration."
		profile.fallback = "" +
			"services:\n" +
			"  beekeeper:\n" +
			"    token: HNY-" + uuid.New().String() + "\n" +
			"    note: \"beware of sticky fingers\"\n"
	case ".sql":
		profile.kind = "SQL dump"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Return SQL statements that pretend to dump a secrets table, with sugary inserts and comments. Output just the SQL, no Markdown fences or explanatory text."
		profile.fallback = "-- Super serious secret dump\nCREATE TABLE honeypot_tokens (id serial, token text, note text);\nINSERT INTO honeypot_tokens VALUES (1, 'HNY-" + uuid.New().String() + "', 'sweet deception');\n"
	case ".pem", ".key", ".crt":
		profile.kind = "PEM key"
		profile.contentType = "application/x-pem-file"
		profile.instructions = "Produce a PEM-like block with convincing but bogus contents and honey jokes tucked into comments. Respond only with the PEM block, no Markdown or commentary."
		profile.fallback = "-----BEGIN HUNNYPOT KEY-----\n" + strings.Repeat("BEE", 20) + "\n-----END HUNNYPOT KEY-----\n"
	case ".txt":
		profile.kind = "text ledger"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Produce a plain text dossier packed with faux secrets, curious notes, and honey puns. Avoid Markdown or extra framing."
		profile.fallback = "Top secret honey log\n- bearer token: HNY-" + uuid.New().String() + "\n- memo: sticky situation imminent\n"
	case ".log":
		profile.kind = "application log"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Invent a server log showcasing suspicious activity, timestamps, and playful bee references. Stick to plain log formatting without Markdown."
		profile.fallback = time.Now().Format(time.RFC3339) + " [WARN] beekeeper auth failed for api-key HNY-" + uuid.New().String() + "\n"
	case ".csv":
		profile.kind = "CSV export"
		profile.contentType = "text/csv; charset=utf-8"
		profile.instructions = "Output comma-separated values that mimic a credential spreadsheet with whimsical honey data. No Markdown or commentary, only CSV rows."
		profile.fallback = "username,token,note\npoohbear,HNY-" + uuid.New().String() + ",sticky paws only\n"
	case ".xml":
		profile.kind = "XML payload"
		profile.contentType = "application/xml"
		profile.instructions = "Craft XML with bogus secrets and honey hints. Ensure well-formed tags and no extra narration."
		profile.fallback = "<hunnypot><token>HNY-" + uuid.New().String() + "</token><note>sweet deception</note></hunnypot>"
	case ".html", ".htm":
		profile.kind = "HTML treasure"
		profile.contentType = "text/html; charset=utf-8"
		profile.instructions = "Return self-contained HTML pretending to host secret data, with playful honey-themed comments. No Markdown wrappers."
		profile.fallback = "<html><body><!-- sticky secret stash --><p>HNY-" + uuid.New().String() + "</p></body></html>"
	case ".md":
		profile.kind = "Markdown memo"
		profile.contentType = "text/markdown; charset=utf-8"
		profile.instructions = "Write a Markdown document full of deceptive secrets and honey jokes. Keep it as raw Markdown without extra formatting wrappers."
		profile.fallback = "# Honey Credentials\n- api: HNY-" + uuid.New().String() + "\n- note: sweet as can bee\n"
	case ".ini", ".cfg", ".conf":
		profile.kind = "config file"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Generate an INI-style configuration with sections and key/value pairs, dripping with fake secrets. No Markdown fences."
		profile.fallback = "[honeypot]\napi_key=HNY-" + uuid.New().String() + "\ncomment=keep it sticky\n"
	case ".toml":
		profile.kind = "TOML config"
		profile.contentType = "application/toml"
		profile.instructions = "Produce TOML-formatted settings containing playful bogus secrets. Respond with only TOML content."
		profile.fallback = "[hunnypot]\napi_key = \"HNY-" + uuid.New().String() + "\"\ncomment = \"sweet configuration\"\n"
	case ".properties":
		profile.kind = "properties file"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Return a .properties style key=value set full of fake secrets and honey humor."
		profile.fallback = "token=HNY-" + uuid.New().String() + "\ncomment=bees only beyond this point\n"
	case ".py":
		profile.kind = "Python script"
		profile.contentType = "text/x-python; charset=utf-8"
		profile.instructions = "Emit a Python script containing bogus credentials and whimsical comments. Do not wrap in Markdown or explain the code."
		profile.fallback = "HONEY_TOKEN = \"HNY-" + uuid.New().String() + "\"\n# beware the buzzing debugger\n"
	case ".sh", ".bash":
		profile.kind = "shell script"
		profile.contentType = "text/x-shellscript; charset=utf-8"
		profile.instructions = "Create a shell script that pretends to manage secret keys, peppered with bee jokes. Raw script only."
		profile.fallback = "#!/bin/bash\nexport HONEY_TOKEN=HNY-" + uuid.New().String() + "\necho \"buzz buzz\"\n"
	case ".bat", ".cmd":
		profile.kind = "batch script"
		profile.contentType = "text/plain; charset=utf-8"
		profile.instructions = "Generate a Windows batch file staging fake secrets with honey references. Output only the batch commands."
		profile.fallback = "@echo off\nset HONEY_TOKEN=HNY-" + uuid.New().String() + "\necho buzzing secrets\n"
	case ".js":
		profile.kind = "JavaScript bundle"
		profile.contentType = "application/javascript"
		profile.instructions = "Provide JavaScript code embedding silly secret objects and honey hints. Raw JS only."
		profile.fallback = "const honeySecrets = { token: 'HNY-" + uuid.New().String() + "', note: 'keep it sticky' };\n"
	case ".go":
		profile.kind = "Go source"
		profile.contentType = "text/x-go; charset=utf-8"
		profile.instructions = "Return Go code that hides absurd secrets and bee jokes in comments. Respond with only Go source."
		profile.fallback = "package main\nconst honeyToken = \"HNY-" + uuid.New().String() + "\"\n"
	case ".php":
		profile.kind = "PHP payload"
		profile.contentType = "application/x-php"
		profile.instructions = "Invent a PHP script full of sham secrets and honey humor. No Markdown wrappers."
		profile.fallback = "<?php\n$honeyToken = 'HNY-" + uuid.New().String() + "';\n// buzz buzz\n"
	default:
		if ext != "" {
			if ctype := mime.TypeByExtension(ext); ctype != "" {
				profile.contentType = ctype
			}
		}
	}

	if profile.kind == "mysterious artifact" && ext != "" {
		extName := strings.TrimPrefix(ext, ".")
		profile.kind = fmt.Sprintf("%s file", extName)
		if profile.instructions == "" || strings.Contains(profile.instructions, "mysterious") {
			profile.instructions = fmt.Sprintf("Generate a %s file loaded with mischievous secrets and honey references. Respond using only valid %s content.", extName, extName)
		}
		profile.fallback = fmt.Sprintf("# suspicious %s artifact\nHNY-%s\n", extName, uuid.New().String())
	}

	return profile
}

func envOrDefault(key, fallback string) string {
	val := os.Getenv(key)
	if strings.TrimSpace(val) == "" {
		return fallback
	}
	if key == "PORT" && !strings.Contains(val, ":") {
		return ":" + val
	}
	return val
}

func predictTokensForLimit(limit int) int {
	if limit <= 0 {
		return 256
	}
	approx := limit / 4
	if approx < 128 {
		approx = 128
	}
	if approx > 4096 {
		approx = 4096
	}
	return approx
}

func loadRequestTimeout(logger *log.Logger) time.Duration {
	val := strings.TrimSpace(os.Getenv("HONEYPOT_REQUEST_TIMEOUT"))
	if val == "" {
		return defaultRequestTimeout
	}
	dur, err := time.ParseDuration(val)
	if err != nil {
		logger.Printf("invalid HONEYPOT_REQUEST_TIMEOUT %q, using default %s: %v", val, defaultRequestTimeout, err)
		return defaultRequestTimeout
	}
	return dur
}

func loadCacheTTL(logger *log.Logger) time.Duration {
	val := strings.TrimSpace(os.Getenv("HUNNYPOT_CACHE_TTL"))
	if val == "" {
		return defaultCacheTTL
	}
	dur, err := time.ParseDuration(val)
	if err != nil {
		logger.Printf("invalid HUNNYPOT_CACHE_TTL %q, using default %s: %v", val, defaultCacheTTL, err)
		return defaultCacheTTL
	}
	if dur <= 0 {
		return 0
	}
	return dur
}

func buildCacheKey(r *http.Request, profile payloadProfile, model string) string {
	var sb strings.Builder
	sb.WriteString(strings.ToUpper(r.Method))
	sb.WriteString("|")
	sb.WriteString(strings.ToLower(r.URL.Path))
	sb.WriteString("?")
	sb.WriteString(r.URL.RawQuery)
	sb.WriteString("|")
	sb.WriteString(profile.kind)
	sb.WriteString("|")
	sb.WriteString(model)
	return sb.String()
}

func (s *honeypotServer) lookupCache(key string) (string, bool) {
	if s.cacheTTL <= 0 {
		return "", false
	}
	s.cacheMu.RLock()
	entry, ok := s.cache[key]
	s.cacheMu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiry) {
		s.cacheMu.Lock()
		delete(s.cache, key)
		s.cacheMu.Unlock()
		return "", false
	}
	return entry.body, true
}

func (s *honeypotServer) storeCache(key, body string) {
	if s.cacheTTL <= 0 || s.maxCache <= 0 {
		return
	}
	entry := cacheEntry{
		body:   body,
		expiry: time.Now().Add(s.cacheTTL),
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	
	// Implement simple LRU eviction and stats
	if len(s.cache) >= s.maxCache {
		// Find oldest entry for eviction
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range s.cache {
			if first || v.expiry.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.expiry
				first = false
			}
		}
		if oldestKey != "" {
			delete(s.cache, oldestKey)
			s.logger.Printf("[hunnypot] cache eviction: removed oldest entry %q", oldestKey)
		}
	}
	s.cache[key] = entry
	s.requestCount++
}

func loadMaxCache(logger *log.Logger) int {
	val := strings.TrimSpace(os.Getenv("HUNNYPOT_MAX_CACHE"))
	if val == "" {
		return 1000
	}
	maxCache, err := strconv.Atoi(val)
	if err != nil {
		logger.Printf("invalid HUNNYPOT_MAX_CACHE %q, using default 1000: %v", val, err)
		return 1000
	}
	if maxCache <= 0 {
		return 1000
	}
	return maxCache
}
