package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/go-playground/form/v4"
)

type Client struct {
	BaseClient  *http.Client
	BaseURL     string
	JWT         string
	AgentToken  string
	Debug       bool
	formEncoder *form.Encoder
}

func New(baseURL, pat string) *Client {
	return &Client{
		BaseClient:  http.DefaultClient,
		BaseURL:     baseURL,
		JWT:         pat,
		formEncoder: form.NewEncoder(),
	}
}

// Clone creates a copy of the client.
func (c *Client) Clone() *Client {
	return &Client{
		BaseClient:  c.BaseClient,
		BaseURL:     c.BaseURL,
		JWT:         c.JWT,
		AgentToken:  c.AgentToken,
		Debug:       c.Debug,
		formEncoder: form.NewEncoder(),
	}
}

// SetToken sets the JWT token for authentication.
func (c *Client) SetToken(token string) {
	c.JWT = token
}

// SetAgentToken sets the agent token for authentication.
func (c *Client) SetAgentToken(token string) {
	c.AgentToken = token
}

// WithAgentToken creates a new client with the specified agent token.
func (c *Client) WithAgentToken(token string) *Client {
	client := c.Clone()
	client.SetAgentToken(token)
	return client
}

func (c *Client) do(ctx context.Context, out any, method, path string, body any) error {
	var bodyReader io.Reader

	if body != nil {
		var buff bytes.Buffer
		if err := json.NewEncoder(&buff).Encode(body); err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}

		bodyReader = &buff
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if c.JWT != "" {
		req.Header.Set("Authorization", "Bearer "+c.JWT)
	}

	if c.AgentToken != "" {
		req.Header.Set("X-Agent-Token", c.AgentToken)
	}

	if c.Debug {
		rawReq, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			fmt.Println(string(rawReq))
		}
	}

	resp, err := c.BaseClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read error response body: %w", err)
		}

		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(b))
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		if errors.Is(err, io.EOF) { // no body returned
			return nil
		}

		return fmt.Errorf("decode response body: %w", err)
	}

	return nil
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
}
