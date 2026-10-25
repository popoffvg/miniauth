package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"unicode"
	"uuid"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/popoffvg/miniauth/internal/sessions"
)

const httpTracerName = "github.com/popoffvg/miniauth/internal/api"

type loggerKey struct{}

func withLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func loggerFrom(ctx context.Context) *slog.Logger {
	logger, _ := ctx.Value(loggerKey{}).(*slog.Logger)
	if logger == nil {
		return slog.Default()
	}
	return logger
}

// logRequests is the outermost HTTP layer.
// It writes one line per request. The line has no headers and no body.
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID(r)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("Cache-Control", "no-store")
		requestLogger := logger.With("request_id", id)
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		ctx, span := startHTTPSpan(r, id)
		ctx = withLogger(ctx, requestLogger)
		//nolint:contextcheck // ctx is the request context with the span.
		next.ServeHTTP(recorder, r.WithContext(ctx))
		finishHTTPSpan(span, r, recorder.status)
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Duration("duration", time.Since(start)),
		}
		if span.SpanContext().IsValid() {
			attrs = append(attrs, slog.String("trace_id", span.SpanContext().TraceID().String()))
		}
		//nolint:contextcheck // ctx is the request context with the span.
		requestLogger.LogAttrs(ctx, slog.LevelInfo, "http request", attrs...)
	})
}

// startHTTPSpan records the method, the path, and the request id.
// The query string and the headers are omitted: they can hold a token or a password.
func startHTTPSpan(r *http.Request, requestID string) (context.Context, trace.Span) {
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := otel.Tracer(httpTracerName).Start(ctx, r.Method+" "+r.URL.Path,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(r.Method),
			semconv.URLPath(r.URL.Path),
			attribute.String("http.request_id", requestID),
		),
	)
	return ctx, span
}

func finishHTTPSpan(span trace.Span, r *http.Request, status int) {
	if r.Pattern != "" {
		span.SetName(r.Pattern)
		span.SetAttributes(semconv.HTTPRoute(r.Pattern))
	}
	span.SetAttributes(semconv.HTTPResponseStatusCode(status))
	if status >= http.StatusInternalServerError {
		span.SetStatus(codes.Error, http.StatusText(status))
	}
	span.End()
}

// requestID reads X-Request-ID when it is a short token.
// It generates an id when the header is missing, unsafe, or equal to the bearer token.
func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-ID")
	if validRequestID(id) && !echoesCredential(r, id) {
		return id
	}
	return uuid.New().String()
}

// echoesCredential reports whether id is the bearer token or a query value.
// A client can put a secret in X-Request-ID. That value MUST NOT be logged.
func echoesCredential(r *http.Request, id string) bool {
	if token, ok := bearerToken(r); ok && secretEqual(token.raw, id) {
		return true
	}
	if cookie, err := r.Cookie(sessions.CookieName); err == nil && secretEqual(cookie.Value, id) {
		return true
	}
	for _, values := range r.URL.Query() {
		for _, value := range values {
			if secretEqual(value, id) {
				return true
			}
		}
	}
	return false
}

func secretEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func validRequestID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if r > unicode.MaxASCII || !requestIDRune(r) {
			return false
		}
	}
	return true
}

func requestIDRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wrote {
		return
	}
	s.status = code
	s.wrote = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(b)
	if err != nil {
		return n, fmt.Errorf("api: write response: %w", err)
	}
	return n, nil
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
