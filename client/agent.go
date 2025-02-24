package client

import (
	"context"
	"net/http"

	"github.com/listendev/jibril-server/types"
)

func (c *Client) CreateAgent(ctx context.Context, agent types.CreateAgent) (types.AgentCreated, error) {
	var out types.AgentCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/agents", agent)
}

func (c *Client) GetAgent(ctx context.Context, agentID string) (types.Agent, error) {
	var out types.Agent

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/agents/"+agentID, nil)
}

func (c *Client) DeleteAgent(ctx context.Context, agentID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/agents/"+agentID, nil)
}

func (c *Client) UpdateAgent(ctx context.Context, agentID string, agent types.UpdateAgent) error {
	return c.do(ctx, nil, http.MethodPatch, "/api/v1/agents/"+agentID, agent)
}
