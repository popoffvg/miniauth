package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/popoffvg/miniauth/internal/postgres"

// queryTracer records a span for each query.
// SQL arguments are not attributes: a password hash is an argument.
type queryTracer struct{}

func (queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	name := operationName(data.SQL)
	ctx, _ = otel.Tracer(tracerName).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.DBSystemNamePostgreSQL,
			attribute.String("db.operation.name", name),
			attribute.String("db.query.text", data.SQL),
		),
	)
	return ctx
}

func (queryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	span := trace.SpanFromContext(ctx)
	if data.Err != nil {
		var pgErr *pgconn.PgError
		if errors.As(data.Err, &pgErr) {
			span.SetAttributes(attribute.String("db.response.status_code", pgErr.Code))
			if pgErr.ConstraintName != "" {
				span.SetAttributes(attribute.String("db.postgres.constraint", pgErr.ConstraintName))
			}
			span.SetStatus(codes.Error, pgErr.Code)
		} else {
			span.SetStatus(codes.Error, "query failed")
		}
	}
	span.End()
}

func operationName(sql string) string {
	sql = skipSQLComments(sql)
	fields := strings.Fields(sql)
	if len(fields) == 0 {
		return "query"
	}
	switch strings.ToUpper(fields[0]) {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH":
		return strings.ToUpper(fields[0])
	default:
		return "query"
	}
}

func skipSQLComments(sql string) string {
	for {
		sql = strings.TrimSpace(sql)
		if !strings.HasPrefix(sql, "--") {
			return sql
		}
		newline := strings.IndexByte(sql, '\n')
		if newline < 0 {
			return ""
		}
		sql = sql[newline+1:]
	}
}
