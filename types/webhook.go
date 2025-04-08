package types

import (
	"net/url"
	"time"

	"github.com/listendev/jibril-api/types/errs"
)

var (
	ErrWebhookNotFound           = errs.NotFoundError("webhook not found")
	ErrUnauthorizedWebhookAccess = errs.UnauthorizedError("permission denied for webhook access")
	ErrWebHookInvalidKind        = errs.InvalidArgumentError("invalid webhook kind")
)

type WebhookKind string

func (k WebhookKind) String() string {
	return string(k)
}

func (k WebhookKind) IsValid() bool {
	switch k {
	case WebhookKindSlack:
		return true
	default:
		return false
	}
}

const (
	WebhookKindSlack WebhookKind = "slack"
)

// WebhookCreate represents a webhook configuration.
type WebhookCreate struct {
	Kind WebhookKind `json:"kind"`
	Name string      `json:"name"`
	URL  string      `json:"url"`
}

func isValidURL(testURL string) bool {
	parsedURL, err := url.ParseRequestURI(testURL)
	return err == nil && parsedURL.Scheme != "" && parsedURL.Host != ""
}

func (w *WebhookCreate) Validate() error {
	if !w.Kind.IsValid() {
		return ErrWebHookInvalidKind
	}

	if w.Name == "" {
		return errs.ErrInvalidArgument
	}

	if w.URL == "" {
		return errs.ErrInvalidArgument
	}

	if !isValidURL(w.URL) {
		return errs.ErrInvalidArgument
	}

	return nil
}

type Webhook struct {
	ID        string `json:"id"`
	ProjectID string `json:"-"`
	WebhookCreate
	CreatedAt time.Time `json:"created_at"`
}

type WebhookCreated struct {
	ID string `json:"id"`
	WebhookCreate
}

type WebhookList struct {
	PageArgs
}

type WebhookUpdate struct {
	Name *string      `json:"name,omitempty"`
	Kind *WebhookKind `json:"kind,omitempty"`
	URL  *string      `json:"url,omitempty"`
}

func (w *WebhookUpdate) Validate() error {
	if w.Name == nil && w.URL == nil && w.Kind == nil {
		return errs.ErrInvalidArgument
	}

	if w.Name != nil && *w.Name == "" {
		return errs.ErrInvalidArgument
	}

	if w.URL != nil && *w.URL == "" {
		return errs.ErrInvalidArgument
	}

	if w.URL != nil && !isValidURL(*w.URL) {
		return ErrWebHookInvalidKind
	}

	if w.Kind != nil && !w.Kind.IsValid() {
		return errs.ErrInvalidArgument
	}

	return nil
}

type WebhookUpdated struct {
	WebhookCreated
	UpdatedAt time.Time `json:"updated_at"`
}
