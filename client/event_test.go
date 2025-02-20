package client_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ghetzel/testify/require"
	"github.com/google/uuid"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
	"github.com/stretchr/testify/assert"
)

func TestIngestEvent(t *testing.T) {
	ctx := context.Background()
	withToken := testclient.WithToken(t)

	t.Run("ok", func(t *testing.T) {
		event := types.Event{
			ID:      uuid.New().String(),
			AgentID: uuid.New().String(),
			Kind:    types.EventKindDropDomain,
			Data: types.EventData{
				Process: &types.Process{
					Cmd: ptr("test-cmd"),
					PID: ptr(1234),
				},
			},
		}

		{
			got, err := withToken.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		}

		// update event with same ID
		event.Data.Process.Cmd = ptr("updated-cmd")

		{
			got, err := withToken.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		}
	})

	t.Run("invalid event kind", func(t *testing.T) {
		event := types.Event{
			Kind: types.EventKind("invalid"),
		}

		_, err := withToken.IngestEvent(ctx, event)
		assert.Error(t, err)
	})
}

func ptr[T any](v T) *T {
	return &v
}

func TestIngestUnmarshaledEvents(t *testing.T) {
	type test struct {
		name string
		file string
	}

	tests := []test{
		{name: "adult_domain_access", file: "./testdata/adult_domain_access.json"},
		{name: "flow", file: "./testdata/flow.json"},
		{name: "drop_ip", file: "./testdata/drop_ip.json"},
		{name: "filesystem_fingerprint", file: "./testdata/filesystem_fingerprint.json"},
		{name: "exec_from_unusual_dir", file: "./testdata/exec_from_unusual_dir.json"},
		{name: "net_scan_tool_exec", file: "./testdata/net_scan_tool_exec.json"},
		{name: "sudoers_modification", file: "./testdata/sudoers_modification.json"},
		{name: "interpreter_shell_spawn", file: "./testdata/interpreter_shell_spawn.json"},
		{name: "net_suspicious_tool_exec", file: "./testdata/net_suspicious_tool_exec.json"},
		{name: "os_status_fingerprint", file: "./testdata/os_status_fingerprint.json"},
		{name: "crypto_miner_files", file: "./testdata/crypto_miner_files.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)

			ctx := context.Background()
			withToken := testclient.WithToken(t)

			var event types.Event

			require.NoError(t, json.Unmarshal(data, &event))

			got, err := withToken.IngestEvent(ctx, event)
			require.NoError(t, err)
			assert.NotZero(t, got.ID)
		})
	}
}
