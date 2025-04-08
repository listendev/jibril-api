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
)

type Client struct {
	BaseClient *http.Client
	BaseURL    string
	AuthToken  string // Generic authentication token
	TokenType  TokenType
	Debug      bool
}

type TokenType int

const (
	TokenTypeNone TokenType = iota
	TokenTypeUser
	TokenTypeAgent
	TokenTypeProject
)

func New(baseURL, token string) *Client {
	client := &Client{
		BaseClient: http.DefaultClient,
		BaseURL:    baseURL,
		AuthToken:  token,
	}

	// If a token is provided, assume it's a user token
	if token != "" {
		client.TokenType = TokenTypeUser
	}

	return client
}

// Clone creates a copy of the client.
func (c *Client) Clone() *Client {
	return &Client{
		BaseClient: c.BaseClient,
		BaseURL:    c.BaseURL,
		AuthToken:  c.AuthToken,
		TokenType:  c.TokenType,
		Debug:      c.Debug,
	}
}

// WithUserToken configures the client to use a user token for authentication.
func (c *Client) WithUserToken(token string) *Client {
	client := c.Clone()
	client.AuthToken = token
	client.TokenType = TokenTypeUser
	return client
}

// WithAgentToken configures the client to use an agent token for authentication.
func (c *Client) WithAgentToken(token string) *Client {
	client := c.Clone()
	client.AuthToken = token
	client.TokenType = TokenTypeAgent
	return client
}

// WithProjectToken configures the client to use a project token for authentication.
func (c *Client) WithProjectToken(token string) *Client {
	client := c.Clone()
	client.AuthToken = token
	client.TokenType = TokenTypeProject
	return client
}

// SetAuth is a generic method to set both the token and type at once.
func (c *Client) SetAuth(token string, tokenType TokenType) {
	c.AuthToken = token
	c.TokenType = tokenType
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

	// Set auth headers based on token type
	if c.AuthToken != "" {
		switch c.TokenType {
		case TokenTypeUser:
			// Check if it's already a bearer token
			if strings.HasPrefix(c.AuthToken, "Bearer ") {
				req.Header.Set("Authorization", c.AuthToken)
			} else {
				req.Header.Set("Authorization", "Bearer "+c.AuthToken)
			}
		case TokenTypeAgent:
			req.Header.Set("X-Agent-Token", c.AuthToken)
		case TokenTypeProject:
			req.Header.Set("X-Project-Token", c.AuthToken)
		case TokenTypeNone:
			// No headers added for TokenTypeNone
		}
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
