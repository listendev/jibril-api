package client

import (
	"context"
	"net/http"

	"github.com/listendev/jibril-server/types"
)

func (c *Client) IngestEvent(ctx context.Context, event types.Event) (types.IngestedEvent, error) {
	var out types.IngestedEvent

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/events", event)
}
