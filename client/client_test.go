package client_test

import (
	"testing"

	"github.com/listendev/jibril-server/client/testclient"
)

func TestMain(m *testing.M) {
	testclient.MustSetup(m)
}

// Helper for returning pointer to any type.
func ptr[T any](v T) *T {
	return &v
}
