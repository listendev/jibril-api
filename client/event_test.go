package client_test

import (
	"context"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/listendev/jibril-server/client/testclient"
	"github.com/listendev/jibril-server/types"
)

func TestIngestEvent(t *testing.T) {
	ctx := context.Background()
	withToken := testclient.WithToken(t)

	t.Run("ok", func(t *testing.T) {
		event := types.Event{
			ID:   "test-id",
			Kind: types.EventKindDropDomain,
			Data: types.EventData{
				Process: &types.Process{
					Cmd: ptr("test-cmd"),
					PID: ptr(1234),
				},
			},
		}

		got, err := withToken.IngestEvent(ctx, event)
		assert.NoError(t, err)
		assert.NotZero(t, got.ID)
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
