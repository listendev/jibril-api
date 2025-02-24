// Package testclient implements the full test server harness and client to unit tests on client side.
package testclient

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	dbDriver "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Import file driver to load migrations
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/postgres"
	"github.com/listendev/jibril-server/server"
	"github.com/listendev/jibril-server/service"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var testHarness *harness

type harness struct {
	psqlDB     *pgxpool.Pool
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

// WithToken returns a new test client with a test token.
func WithToken(t *testing.T) *client.Client {
	t.Helper()

	c := testHarness.client.Clone()
	c.SetToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmF0aW9uIjoxNzcwMjE4ODg3OTA1LCJmcm9udGVuZCI6dHJ1ZSwib3JnX2lkIjoibXktb3JnIiwicHJvamVjdF9pZCI6Im15LXByb2plY3QiLCJ1c2VyX2lkIjoibXktdXNlciJ9.LF-MTbCrdB7CYvthnA38MSYrZIrIBOIgBoiJO8WGiNA")

	return c
}

func newHarness(ctx context.Context) (*harness, error) {
	h := &harness{}

	var err error

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	h.dockerPool, err = setupDockerPool()
	if err != nil {
		return nil, fmt.Errorf("setup docker pool: %w", err)
	}

	psqlContainer, err := setupPsqlContainer(h.dockerPool)
	if err != nil {
		return nil, fmt.Errorf("setup postgres container: %w", err)
	}

	h.registerStop(psqlContainer.Close)

	logger.Info("Starting PostgreSQL container")

	h.psqlDB, err = connectToPSQL(ctx, psqlContainer, logger)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	h.registerStop(func() error {
		h.psqlDB.Close()

		return nil
	})

	logger.Info("Connected to PostgreSQL")

	logger.Info("Running migrations")

	dbURL := fmt.Sprintf("postgres://user:password@%s/postgres?sslmode=disable", psqlContainer.GetHostPort("5432/tcp"))

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres connection: %w", err)
	}

	driver, err := dbDriver.WithInstance(db, &dbDriver.Config{})
	if err != nil {
		return nil, fmt.Errorf("create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance("file://../postgres/migrations", "postgres", driver)
	if err != nil {
		return nil, fmt.Errorf("create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	logger.Info("Migrations complete")
	svc := &service.Service{Repo: postgres.NewRepository(h.psqlDB)}
	handler := server.NewHandler(logger, svc, "", 1)

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

func setupPsqlContainer(pool *dockertest.Pool) (*dockertest.Resource, error) {
	return pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "17",
		Env: []string{
			"POSTGRES_USER=user",
			"POSTGRES_PASSWORD=password",
			"POSTGRES_DB=postgres",
			"listen_addresses = '*'",
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
}

func connectToPSQL(ctx context.Context, resource *dockertest.Resource, logger *slog.Logger) (*pgxpool.Pool, error) {
	hostAndPort := resource.GetHostPort("5432/tcp")
	databaseURL := fmt.Sprintf("postgres://user:password@%s/postgres?sslmode=disable", hostAndPort)

	var err error

	for i := range 3 {
		time.Sleep(2 * time.Second) // Wait before retrying

		client, err := pgxpool.New(ctx, databaseURL)
		if err == nil {
			err = client.Ping(ctx)
			if err == nil {
				return client, nil // Connection successful
			}
		}

		logger.Error("Failed to connect to PostgreSQL", "retry", i, "error", err)
	}

	return nil, fmt.Errorf("failed to connect to PostgreSQL after retries: %w", err)
}
