package client_test

import (
	"testing"

	"github.com/listendev/jibril-server/client/testclient"
)

func TestMain(m *testing.M) {
	testclient.MustSetup(m)
}
