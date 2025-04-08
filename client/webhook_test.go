package client_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ghetzel/testify/assert"
	"github.com/google/uuid"
	"github.com/listendev/jibril-api/client/testclient"
	"github.com/listendev/jibril-api/types"
	"github.com/stretchr/testify/require"
)

func TestWebhook(t *testing.T) { //nolint:gocognit,maintidx
	ctx := t.Context()
	client := testclient.WithToken(t)

	t.Run("empty name", func(t *testing.T) {
		_, err := client.CreateWebhook(ctx, types.WebhookCreate{
			URL:  "http://example.com",
			Kind: types.WebhookKindSlack,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), `{"error":"invalid argument"}`)
	})

	t.Run("invalid url", func(t *testing.T) {
		_, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "test",
			URL:  "example.com",
			Kind: types.WebhookKindSlack,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), `{"error":"invalid argument"}`)
	})

	t.Run("delete not found", func(t *testing.T) {
		err := client.DeleteWebhook(ctx, uuid.New().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), `{"error":"webhook not found"}`)
	})

	var id string

	t.Run("ok", func(t *testing.T) {
		wh, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "slack",
			URL:  "http://example.com",
			Kind: types.WebhookKindSlack,
		})
		require.NoError(t, err)
		require.NotZero(t, wh.ID)

		id = wh.ID
	})

	t.Run("list webhooks", func(t *testing.T) {
		out, err := client.ListWebhooks(ctx, types.WebhookList{})
		require.NoError(t, err)

		require.Len(t, out.Items, 1)
		require.Equal(t, id, out.Items[0].ID)
	})

	t.Run("get specific webhook", func(t *testing.T) {
		out, err := client.Webhook(ctx, id)
		require.NoError(t, err)
		require.Equal(t, id, out.ID)
		require.Equal(t, "slack", out.Name)
		require.Equal(t, "http://example.com", out.URL)
		require.Equal(t, types.WebhookKindSlack, out.Kind)
		require.NotZero(t, out.CreatedAt)
	})

	t.Run("update webhook name ", func(t *testing.T) {
		out, err := client.UpdateWebhook(ctx, id, types.WebhookUpdate{
			Name: ptr("slack2"),
		})
		require.NoError(t, err)
		require.Equal(t, id, out.ID)
		require.Equal(t, "slack2", out.Name)
		require.Equal(t, "http://example.com", out.URL)
	})

	t.Run("update webhook url", func(t *testing.T) {
		out, err := client.UpdateWebhook(ctx, id, types.WebhookUpdate{
			URL: ptr("http://example2.com"),
		})
		require.NoError(t, err)
		require.Equal(t, id, out.ID)
		require.Equal(t, "slack2", out.Name)
		require.Equal(t, "http://example2.com", out.URL)
	})

	t.Run("update webhook kind", func(t *testing.T) {
		out, err := client.UpdateWebhook(ctx, id, types.WebhookUpdate{
			Kind: ptr(types.WebhookKindSlack),
		})
		require.NoError(t, err)
		require.Equal(t, id, out.ID)
		require.Equal(t, "slack2", out.Name)
		require.Equal(t, "http://example2.com", out.URL)
		require.Equal(t, types.WebhookKindSlack, out.Kind)
	})

	t.Run("pagination", func(t *testing.T) {
		var firstPageSize uint = 4

		for i := range 10 {
			wh, err := client.CreateWebhook(ctx, types.WebhookCreate{
				Name: fmt.Sprintf("slack%d", i),
				URL:  "http://example.com",
				Kind: types.WebhookKindSlack,
			})

			require.NoError(t, err)
			require.NotZero(t, wh.ID)
		}

		out, err := client.ListWebhooks(ctx, types.WebhookList{
			PageArgs: types.PageArgs{
				First: &firstPageSize,
			},
		})
		require.NoError(t, err)
		require.Len(t, out.Items, 4)

		out, err = client.ListWebhooks(ctx, types.WebhookList{
			PageArgs: types.PageArgs{
				First: &firstPageSize,
				After: out.PageInfo.EndCursor,
			},
		})

		require.NoError(t, err)
		require.Len(t, out.Items, 4)

		out, err = client.ListWebhooks(ctx, types.WebhookList{
			PageArgs: types.PageArgs{
				First: &firstPageSize,
				After: out.PageInfo.EndCursor,
			},
		})

		require.NoError(t, err)
		require.Len(t, out.Items, 3)

		for _, wh := range out.Items {
			assert.NotEmpty(t, wh.ID)
			assert.NotEmpty(t, wh.Name)
			assert.NotEmpty(t, wh.URL)
			assert.NotEmpty(t, wh.Kind)
			assert.NotEmpty(t, wh.CreatedAt)
		}
	})

	t.Run("delete ok", func(t *testing.T) {
		err := client.DeleteWebhook(ctx, id)
		require.NoError(t, err)
	})

	t.Run("delete not found", func(t *testing.T) {
		err := client.DeleteWebhook(ctx, uuid.New().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), `{"error":"webhook not found"}`)
	})

	t.Run("webhook of slack", func(t *testing.T) {
		mockHandler := func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(r.Body)
			assert.NoError(t, err)

			defer r.Body.Close()

			// Convert JSON body to a map
			var requestBody map[string]any
			err = json.Unmarshal(data, &requestBody)
			assert.NoError(t, err)

			// Loop through "blocks" and remove unreliable fields
			if blocks, ok := requestBody["blocks"].([]any); ok {
				for _, block := range blocks {
					if blockMap, ok := block.(map[string]any); ok {
						if fields, exists := blockMap["fields"].([]any); exists {
							var cleanedFields []any // New slice to store filtered fields

							for _, field := range fields {
								if fieldMap, ok := field.(map[string]any); ok {
									text, hasText := fieldMap["text"].(string)

									// Skip fields with unreliable values
									if hasText && (text[:8] == "*Project" || text[:3] == "*ID" || text[:5] == "*Time") {
										continue
									}

									cleanedFields = append(cleanedFields, fieldMap) // Keep valid fields
								}
							}

							blockMap["fields"] = cleanedFields // Update fields with cleaned list
						}
					}
				}
			}

			// Convert modified JSON back to string
			modifiedBody, err := json.Marshal(requestBody)
			assert.NoError(t, err)

			expectedBody := `{
		"attachments": [{"color": "#FF0000", "blocks": []}],
		"blocks": [{
			"type": "section",
			"text": { "type": "mrkdwn", "text": "⚠️ *garnet* runtime monitor detected a potential security issue" }
		}, {
			"type": "section",
			"fields": [
				{"type": "mrkdwn", "text": "*Class:*\ncrypto_miner"},
				{"type": "mrkdwn", "text": "*Description:*\nTest webhook"},
				{"type": "mrkdwn", "text": "*Priority:*\n"},
				{"type": "mrkdwn", "text": "*Status:*\n"}
			]
		}, {
			"type": "divider"
		}],
		"replace_original": false,
		"delete_original": false,
		"reply_broadcast": true
	}`

			assert.JSONEq(t, expectedBody, string(modifiedBody))

			w.WriteHeader(http.StatusOK)
		}

		ts := httptest.NewServer(http.HandlerFunc(mockHandler))
		defer ts.Close()

		created, err := client.CreateWebhook(ctx, types.WebhookCreate{
			Name: "slack",
			URL:  ts.URL + "/test",
			Kind: types.WebhookKindSlack,
		})

		require.NoError(t, err)
		require.NotZero(t, created)

		err = client.TestWebhook(ctx, created.ID)
		require.NoError(t, err)
	})
}
