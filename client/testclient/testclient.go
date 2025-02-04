// Package testclient implements the full test server harness and client to unit tests on client side.
package testclient

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/server"
	"github.com/listendev/jibril-server/service"
	"github.com/listendev/jibril-server/store"
)

var testHarness *harness

type harness struct {
	mongoDB    *mongo.Client
	server     *httptest.Server
	client     *client.Client
	dockerPool *dockertest.Pool
	closeFns   []func() error
}

func (h *harness) registerStop(fn func() error) {
	h.closeFns = append(h.closeFns, fn)
}

func (h *harness) stop() error {
	h.server.Close()
	for _, fn := range h.closeFns {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

// MustSetup initializes the test harness. Should be called from TestMain.
func MustSetup(m *testing.M) {
	flag.Parse()
	code, err := setup(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

func setup(m *testing.M) (int, error) {
	if testing.Short() {
		return m.Run(), nil
	}

	ctx := context.Background()
	h, err := newHarness(ctx)
	if err != nil {
		return 0, fmt.Errorf("create test harness: %w", err)
	}
	testHarness = h
	defer func() {
		err := h.stop()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	return m.Run(), nil
}

// WithToken returns a new test client with a test token
func WithToken(t *testing.T) *client.Client {
	t.Helper()
	c := testHarness.client.Clone()
	c.SetToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmF0aW9uIjoxNzcwMjE4ODg3OTA1LCJmcm9udGVuZCI6dHJ1ZSwib3JnX2lkIjoibXktb3JnIiwicHJvamVjdF9pZCI6Im15LXByb2plY3QiLCJ1c2VyX2lkIjoibXktdXNlciJ9.LF-MTbCrdB7CYvthnA38MSYrZIrIBOIgBoiJO8WGiNA")
	return c
}

func newHarness(ctx context.Context) (*harness, error) {
	h := &harness{}
	var err error

	h.dockerPool, err = setupDockerPool()
	if err != nil {
		return nil, fmt.Errorf("setup docker pool: %w", err)
	}

	mongoContainer, err := setupMongoContainer(h.dockerPool)
	if err != nil {
		return nil, fmt.Errorf("setup mongodb container: %w", err)
	}
	h.registerStop(mongoContainer.Close)

	h.mongoDB, err = connectToMongo(ctx, mongoContainer)
	if err != nil {
		return nil, fmt.Errorf("connect to mongodb: %w", err)
	}
	h.registerStop(func() error {
		return h.mongoDB.Disconnect(ctx)
	})

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	mongoStore := store.NewMongoStore(h.mongoDB)
	svc := &service.Service{Store: mongoStore}
	handler := server.NewHandler(logger, svc, "")

	h.server = httptest.NewServer(handler)
	h.client = client.New(h.server.URL, "")

	return h, nil
}

func setupDockerPool() (*dockertest.Pool, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, err
	}
	return pool, pool.Client.Ping()
}

func setupMongoContainer(pool *dockertest.Pool) (*dockertest.Resource, error) {
	return pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mongo",
		Tag:        "4.4",
		Env: []string{
			"MONGO_INITDB_DATABASE=core",
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
}

func connectToMongo(ctx context.Context, resource *dockertest.Resource) (*mongo.Client, error) {
	mongoURL := fmt.Sprintf("mongodb://localhost:%s", resource.GetPort("27017/tcp"))
	mongoClient, err := mongo.Connect(options.Client().ApplyURI(mongoURL))
	if err != nil {
		return nil, fmt.Errorf("connect to mongodb: %w", err)
	}
	return mongoClient, nil
}
