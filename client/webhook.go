package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/listendev/jibril-api/types"
)

func (c *Client) CreateWebhook(ctx context.Context, in types.WebhookCreate) (types.WebhookCreated, error) {
	var out types.WebhookCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/webhooks", in)
}

func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/webhooks/"+id, nil)
}

func (c *Client) ListWebhooks(ctx context.Context, in types.WebhookList) (types.Page[types.Webhook], error) {
	var out types.Page[types.Webhook]

	q := url.Values{}

	// Add pagination parameters
	if in.PageArgs.First != nil {
		q.Set("first", strconv.FormatUint(uint64(*in.PageArgs.First), 10))
	}
	if in.PageArgs.Last != nil {
		q.Set("last", strconv.FormatUint(uint64(*in.PageArgs.Last), 10))
	}
	if in.PageArgs.After != nil {
		q.Set("after", string(*in.PageArgs.After))
	}
	if in.PageArgs.Before != nil {
		q.Set("before", string(*in.PageArgs.Before))
	}

	url := "/api/v1/webhooks"
	if len(q) > 0 {
		url += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, url, nil)
}

func (c *Client) UpdateWebhook(ctx context.Context, id string, in types.WebhookUpdate) (types.WebhookUpdated, error) {
	var out types.WebhookUpdated

	return out, c.do(ctx, &out, http.MethodPatch, "/api/v1/webhooks/"+id, in)
}

func (c *Client) Webhook(ctx context.Context, id string) (types.Webhook, error) {
	var out types.Webhook

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/webhooks/"+id, nil)
}

func (c *Client) TestWebhook(ctx context.Context, id string) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/webhooks/"+id+"/test", nil)
}
