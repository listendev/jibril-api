package client

import (
	"context"
	"net/http"

	"github.com/listendev/jibril-api/types"
)

func (c *Client) IngestEvent(ctx context.Context, event types.CreateOrUpdateEvent) (types.EventCreatedOrUpdated, error) {
	var out types.EventCreatedOrUpdated

	return out, c.do(ctx, &out, http.MethodPut, "/api/v1/events", event)
}

// Event retrieves an event by ID.
func (c *Client) Event(ctx context.Context, eventID string) (types.Event, error) {
	var result types.Event

	err := c.do(ctx, &result, http.MethodGet, "/api/v1/events/"+eventID, nil)
	if err != nil {
		return result, err
	}

	return result, nil
}
