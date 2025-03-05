// Package testclient implements a test server harness and client for unit tests.
package testclient

//nolint:goimports
import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/golang-migrate/migrate/v4"
	dbDriver "github.com/golang-migrate/migrate/v4/database/postgres"
	// Import file driver to load migrations from filesystem.
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/listendev/jibril-server/client"
	"github.com/listendev/jibril-server/postgres"
	"github.com/listendev/jibril-server/server"
	"github.com/listendev/jibril-server/service"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var (
	testHarness *harness
	jwtSecret   []byte
	jwtExpDays  = 365 // JWT token expiration in days
)

type harness struct {
	psqlDB     *pgxpool.Pool
	server     *httptest.Server
	client     *client.Client
	dockerPool *dockertest.Pool
	closeFns   []func() error
}

// MustSetup initializes the test harness. Should be called from TestMain.
func MustSetup(m *testing.M) {
	flag.Parse()

	// Generate JWT secret once
	var err error
	jwtSecret = make([]byte, 32) // 32 bytes for a 256-bit key
	if _, err = rand.Read(jwtSecret); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate JWT secret: %v\n", err)
		os.Exit(1)
	}

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
		if err := h.stop(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	return m.Run(), nil
}

// WithToken returns a new test client with a token for a new project.
func WithToken(t *testing.T) *client.Client {
	t.Helper()
	return WithProject(t, uuid.New().String())
}

// WithProject returns a client with a token for the specified project ID.
func WithProject(t *testing.T, projectID string) *client.Client {
	t.Helper()

	token, err := createToken(projectID, "", "")
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	c := testHarness.client.Clone()
	c.SetToken(token)
	return c
}

// Helper to create a JWT token with the global secret.
func createToken(projectID, userID, orgID string) (string, error) {
	if userID == "" {
		userID = uuid.New().String()
	}
	if orgID == "" {
		orgID = uuid.New().String()
	}

	claims := jwt.MapClaims{
		"frontend":   true,
		"expiration": time.Now().UTC().Add(time.Hour * 24 * time.Duration(jwtExpDays)).UnixMilli(),
		"project_id": projectID,
		"user_id":    userID,
		"org_id":     orgID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
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

func (h *harness) registerStop(fn func() error) {
	h.closeFns = append(h.closeFns, fn)
}

func newHarness(ctx context.Context) (*harness, error) {
	h := &harness{closeFns: make([]func() error, 0)}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Setup Docker
	var err error
	if h.dockerPool, err = dockertest.NewPool(""); err != nil {
		return nil, fmt.Errorf("setup docker pool: %w", err)
	}
	if err = h.dockerPool.Client.Ping(); err != nil {
		return nil, fmt.Errorf("ping docker: %w", err)
	}

	// Setup PostgreSQL
	psqlContainer, err := h.dockerPool.RunWithOptions(&dockertest.RunOptions{
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
	if err != nil {
		return nil, fmt.Errorf("start postgres: %w", err)
	}
	h.registerStop(psqlContainer.Close)

	// Connect to PostgreSQL
	logger.Info("Starting PostgreSQL container")
	hostAndPort := psqlContainer.GetHostPort("5432/tcp")
	dbURL := fmt.Sprintf("postgres://user:password@%s/postgres?sslmode=disable", hostAndPort)

	// Retry connection a few times
	for i := range 3 {
		time.Sleep(2 * time.Second)
		if h.psqlDB, err = pgxpool.New(ctx, dbURL); err == nil {
			if err = h.psqlDB.Ping(ctx); err == nil {
				break // Connected successfully
			}
		}
		logger.Error("Failed to connect to PostgreSQL", "retry", i, "error", err)
		if i == 2 {
			return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
		}
	}
	h.registerStop(func() error { h.psqlDB.Close(); return nil })
	logger.Info("Connected to PostgreSQL")

	// Run migrations
	logger.Info("Running migrations")
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

	// Setup service and server
	svc := &service.Service{
		Repo:   postgres.NewRepository(h.psqlDB),
		Logger: logger,
	}
	handler := server.NewHandler(logger, svc, string(jwtSecret), jwtExpDays)
	h.server = httptest.NewServer(handler)
	h.client = client.New(h.server.URL, "")

	return h, nil
}
