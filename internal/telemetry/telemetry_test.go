package telemetry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	stop, err := Install(t.Context())
	require.NoError(t, err)
	require.NoError(t, stop(t.Context()))
}
