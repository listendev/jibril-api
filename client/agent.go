package client

import (
	"context"
	"maps"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/listendev/jibril-server/types"
)

func (c *Client) CreateAgent(ctx context.Context, agent types.CreateAgent) (types.AgentCreated, error) {
	var out types.AgentCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/agents", agent)
}

func (c *Client) Agent(ctx context.Context, agentID string) (types.Agent, error) {
	var out types.Agent

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/agents/"+agentID, nil)
}

func (c *Client) DeleteAgent(ctx context.Context, agentID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/agents/"+agentID, nil)
}

func (c *Client) UpdateAgent(ctx context.Context, agentID string, agent types.UpdateAgent) error {
	return c.do(ctx, nil, http.MethodPatch, "/api/v1/agents/"+agentID, agent)
}

func (c *Client) Agents(ctx context.Context, in types.ListAgents) (types.Page[types.Agent], error) {
	var out types.Page[types.Agent]

	q := url.Values{}
	q1 := in.Filters.Encode()
	q2 := in.Labels.Encode()

	maps.Copy(q, q1)
	maps.Copy(q, q2)

	if in.After != nil {
		q.Set("after", string(*in.After))
	}

	if in.Before != nil {
		q.Set("before", string(*in.Before))
	}

	if in.First != nil {
		firstVal := *in.First
		if firstVal <= uint(math.MaxInt64) {
			int64Conv := int64(firstVal)
			intConv := int(int64Conv)
			q.Set("first", strconv.Itoa(intConv))
		} else {
			q.Set("first", strconv.FormatUint(uint64(firstVal), 10))
		}
	}

	if in.Last != nil {
		lastVal := *in.Last
		if lastVal <= uint(math.MaxInt64) {
			int64Conv := int64(lastVal)
			intConv := int(int64Conv)
			q.Set("last", strconv.Itoa(intConv))
		} else {
			q.Set("last", strconv.FormatUint(uint64(lastVal), 10))
		}
	}

	path := "/api/v1/agents?" + q.Encode()

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}
