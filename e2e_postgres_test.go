// Copyright 2020 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_postgres
// +build !skip_postgres

package cloudsqlconn_test

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/instance"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"cloud.google.com/go/cloudsqlconn/postgres/pgxv4"
	"cloud.google.com/go/cloudsqlconn/postgres/pgxv5"
)

var (
	postgresConnName             = os.Getenv("POSTGRES_CONNECTION_NAME")              // "Cloud SQL Postgres instance connection name, in the form of 'project:region:instance'.
	postgresCASConnName          = os.Getenv("POSTGRES_CAS_CONNECTION_NAME")          // "Cloud SQL Postgres CAS instance connection name, in the form of 'project:region:instance'.
	postgresCustomerCASConnName  = os.Getenv("POSTGRES_CUSTOMER_CAS_CONNECTION_NAME") // "Cloud SQL Postgres Customer CAS instance connection name, in the form of 'project:region:instance'.
	postgresSANConnName          = os.Getenv("POSTGRES_SAN_CONNECTION_NAME")          // "Cloud SQL Postgres CAS instance connection name, in the form of 'project:region:instance'.
	postgresSANDomainName        = os.Getenv("POSTGRES_SAN_DOMAIN_NAME")              // Cloud SQL Postgres CAS domain name that is an instance Custom SAN of the postgresSANConnName instance.
	postgresSANInvalidDomainName = os.Getenv("POSTGRES_SAN_INVALID_DOMAIN_NAME")      // Cloud SQL Postgres CAS domain name that IS NOT an instance Custom SAN of the postgresSANConnName instance.
	postgresUser                 = os.Getenv("POSTGRES_USER")                         // Name of database user.
	postgresSANUser              = os.Getenv("POSTGRES_SAN_USER")                     // Name of database user.
	postgresPass                 = os.Getenv("POSTGRES_PASS")                         // Password for the database user; be careful when entering a password on the command line (it may go into your terminal's history).
	postgresCASPass              = os.Getenv("POSTGRES_CAS_PASS")                     // Password for the database user for CAS instances; be careful when entering a password on the command line (it may go into your terminal's history).
	postgresCustomerCASPass      = os.Getenv("POSTGRES_CUSTOMER_CAS_PASS")            // Password for the database user for customer CAS instances; be careful when entering a password on the command line (it may go into your terminal's history).
	postgresSANPass              = os.Getenv("POSTGRES_SAN_PASS")                     // Password for the database user for SAN domain name instances; be careful when entering a password on the command line (it may go into your terminal's history).
	postgresDB                   = os.Getenv("POSTGRES_DB")                           // Name of the database to connect to.
	postgresUserIAM              = os.Getenv("POSTGRES_USER_IAM")                     // Name of database IAM user.
)

func requirePostgresVars(t *testing.T) {
	switch "" {
	case postgresConnName:
		t.Fatal("'POSTGRES_CONNECTION_NAME' env var not set")
	case postgresCASConnName:
		t.Fatal("'POSTGRES_CAS_CONNECTION_NAME' env var not set")
	case postgresCustomerCASConnName:
		t.Fatal("'POSTGRES_CUSTOMER_CAS_CONNECTION_NAME' env var not set")
	case postgresSANConnName:
		t.Fatal("'POSTGRES_SAN_CONNECTION_NAME' env var not set")
	case postgresSANDomainName:
		t.Fatal("'POSTGRES_SAN_DOMAIN_NAME' env var not set")
	case postgresSANInvalidDomainName:
		t.Fatal("'POSTGRES_SAN_INVALID_DOMAIN_NAME' env var not set")
	case postgresUser:
		t.Fatal("'POSTGRES_USER' env var not set")
	case postgresPass:
		t.Fatal("'POSTGRES_PASS' env var not set")
	case postgresCASPass:
		t.Fatal("'POSTGRES_CAS_PASS' env var not set")
	case postgresCustomerCASPass:
		t.Fatal("'POSTGRES_CUSTOMER_CAS_PASS' env var not set")
	case postgresSANUser:
		t.Fatal("'POSTGRES_SAN_USER' env var not set")
	case postgresSANPass:
		t.Fatal("'POSTGRES_SAN_PASS' env var not set")
	case postgresDB:
		t.Fatal("'POSTGRES_DB' env var not set")
	case postgresUserIAM:
		t.Fatal("'POSTGRES_USER_IAM' env var not set")
	}
}

func TestPostgresPgxPoolConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// Configure the driver to connect to the database
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresPass, postgresDB)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}

	// Create a new dialer with any options
	d, err := cloudsqlconn.NewDialer(ctx)
	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}

	// call cleanup when you're done with the database connection to close dialer
	cleanup := func() error { return d.Close() }

	// Tell the driver to use the Cloud SQL Go Connector to create connections
	// postgresConnName takes the form of 'project:region:instance'.
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresConnName)
	}

	// Interact with the driver directly as you normally would
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	// ... etc

	defer cleanup()
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestPostgresSANDomainConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// Configure the driver to connect to the database
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresSANUser, postgresSANPass, "postgres")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}

	// Create a new dialer with any options
	d, err := cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithDNSResolver(),
		// TODO: Remove Additional options.
		cloudsqlconn.WithQuotaProject("hessjc-playground-01"),
		cloudsqlconn.WithAdminAPIEndpoint("https://int-108-sqladmin.sandbox.googleapis.com"))

	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}

	// call cleanup when you're done with the database connection to close dialer
	cleanup := func() error { return d.Close() }

	// Tell the driver to use the Cloud SQL Go Connector to create connections
	// postgresConnName takes the form of 'project:region:instance'.
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresSANDomainName)
	}

	// Interact with the driver directly as you normally would
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	// ... etc

	defer cleanup()
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestPostgresSANBadDomainCausesConnectError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// Configure the driver to connect to the database
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresSANUser, postgresSANPass, "postgres")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}

	// Create a new dialer with any options
	d, err := cloudsqlconn.NewDialer(ctx,
		cloudsqlconn.WithDNSResolver(),
		// TODO: Remove Additional options.
		cloudsqlconn.WithQuotaProject("hessjc-playground-01"),
		cloudsqlconn.WithAdminAPIEndpoint("https://int-108-sqladmin.sandbox.googleapis.com"))

	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}

	// call cleanup when you're done with the database connection to close dialer
	cleanup := func() error { return d.Close() }

	// Tell the driver to use the Cloud SQL Go Connector to create connections
	// postgresConnName takes the form of 'project:region:instance'.
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresSANInvalidDomainName)
	}

	// Interact with the driver directly as you normally would
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	// ... etc

	defer cleanup()
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err == nil {
		t.Fatal("Want error, got invalid error")
	}
	if !strings.Contains(fmt.Sprint(err), "Dial error: handshake failed") {
		t.Fatal("Want error 'Dial error: handshake failed'.  got: ", err)
	}
	t.Log(now)
}

func TestPostgresCASConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// Configure the driver to connect to the database
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresCASPass, postgresDB)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}

	// Create a new dialer with any options
	d, err := cloudsqlconn.NewDialer(ctx)
	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}

	// call cleanup when you're done with the database connection to close dialer
	cleanup := func() error { return d.Close() }

	// Tell the driver to use the Cloud SQL Go Connector to create connections
	// postgresConnName takes the form of 'project:region:instance'.
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresCASConnName)
	}

	// Interact with the driver directly as you normally would
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	// ... etc

	defer cleanup()
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestPostgresCustomerCASConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// Configure the driver to connect to the database
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresCustomerCASPass, postgresDB)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}

	// Create a new dialer with any options
	d, err := cloudsqlconn.NewDialer(ctx)
	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}

	// call cleanup when you're done with the database connection to close dialer
	cleanup := func() error { return d.Close() }

	// Tell the driver to use the Cloud SQL Go Connector to create connections
	// postgresConnName takes the form of 'project:region:instance'.
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresCustomerCASConnName)
	}

	// Interact with the driver directly as you normally would
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	// ... etc

	defer cleanup()
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

type pgMockResolver struct {
}

func (r *pgMockResolver) Resolve(_ context.Context, name string) (instanceName instance.ConnName, err error) {
	if name == "pg.example.com" {
		return instance.ParseConnNameWithDomainName(postgresConnName, "pg.example.com")
	}
	return instance.ConnName{}, fmt.Errorf("no resolution for %v", name)
}

func TestPostgresPgxPoolConnectDomainName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)
	pgxv5.RegisterDriver("pgxpool-connect")

	ctx := context.Background()

	// Configure the driver to connect to the database
	dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresPass, postgresDB)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}

	// Create a new dialer with any options
	d, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithResolver(&pgMockResolver{}))
	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}

	// call cleanup when you're done with the database connection to close dialer
	cleanup := func() { d.Close() }
	t.Cleanup(cleanup)

	// Tell the driver to use the Cloud SQL Go Connector to create connections
	// postgresConnName takes the form of 'project:region:instance'.
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, "pg.example.com")
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestPostgresConnectWithIAMUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// password is intentionally blank
	dsn := fmt.Sprintf("user=%s password=\"\" dbname=%s sslmode=disable", postgresUserIAM, postgresDB)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}
	d, err := cloudsqlconn.NewDialer(ctx, cloudsqlconn.WithIAMAuthN())
	if err != nil {
		t.Fatalf("failed to initiate Dialer: %v", err)
	}
	defer d.Close()

	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresConnName)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestPostgresConnectWithLazyRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	ctx := context.Background()

	// password is intentionally blank
	dsn := fmt.Sprintf("user=%s password=\"\" dbname=%s sslmode=disable", postgresUserIAM, postgresDB)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("failed to parse pgx config: %v", err)
	}
	d, err := cloudsqlconn.NewDialer(
		ctx,
		cloudsqlconn.WithLazyRefresh(),
		cloudsqlconn.WithIAMAuthN(), // use IAM AuthN to exercise all paths
	)
	if err != nil {
		t.Fatalf("failed to initiate Dialer: %v", err)
	}
	defer d.Close()
	config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return d.Dial(ctx, postgresConnName)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("failed to create pool: %s", err)
	}
	defer pool.Close()

	var now time.Time
	err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
	if err != nil {
		t.Fatalf("QueryRow failed: %s", err)
	}
	t.Log(now)
}

func TestPostgresEngineVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := cloudsqlconn.NewDialer(context.Background())
	if err != nil {
		t.Fatalf("failed to init Dialer: %v", err)
	}
	gotEV, err := d.EngineVersion(ctx, postgresConnName)
	if err != nil {
		t.Fatalf("failed to retrieve engine version: %v", err)
	}
	if !strings.Contains(gotEV, "POSTGRES") {
		t.Errorf("InstanceEngineVersion(%s) failed: want 'POSTGRES', got %v", gotEV, err)
	}
}

func TestPostgresV5Hook(t *testing.T) {
	tests := []struct {
		driver   string
		source   string
		IAMAuthN bool
		resolver bool
	}{
		{
			driver: "cloudsql-postgres-v5",
			source: fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
				postgresConnName, postgresUser, postgresPass, postgresDB),
			IAMAuthN: false,
		},
		{
			driver: "cloudsql-postgres-iam-v5",
			source: fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable",
				postgresConnName, postgresUserIAM, postgresDB),
			IAMAuthN: true,
		},
		{
			driver: "cloudsql-postgres-v5-dns",
			source: fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
				"pg.example.com", postgresUser, postgresPass, postgresDB),
			IAMAuthN: false,
			resolver: true,
		},
	}

	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	testConn := func(db *sql.DB) {
		var now time.Time
		if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
			t.Fatalf("QueryRow failed: %v", err)
		}
		t.Log(now)
	}

	for _, tc := range tests {
		if tc.IAMAuthN {
			pgxv5.RegisterDriver(tc.driver, cloudsqlconn.WithIAMAuthN())
		} else if tc.resolver {
			pgxv5.RegisterDriver(tc.driver, cloudsqlconn.WithResolver(&pgMockResolver{}))
		} else {
			pgxv5.RegisterDriver(tc.driver)
		}
		db, err := sql.Open(tc.driver, tc.source)

		if err != nil {
			t.Fatalf("sql.Open want err = nil, got = %v", err)
		}
		defer db.Close()
		testConn(db)
	}
}

func TestPostgresV4Hook(t *testing.T) {
	tests := []struct {
		driver   string
		source   string
		IAMAuthN bool
	}{
		{
			driver: "cloudsql-postgres-v4",
			source: fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
				postgresConnName, postgresUser, postgresPass, postgresDB),
			IAMAuthN: false,
		},
		{
			driver: "cloudsql-postgres-iam-v4",
			source: fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable",
				postgresConnName, postgresUserIAM, postgresDB),
			IAMAuthN: true,
		},
	}
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	testConn := func(db *sql.DB) {
		var now time.Time
		if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
			t.Fatalf("QueryRow failed: %v", err)
		}
		t.Log(now)
	}

	for _, tc := range tests {
		if tc.IAMAuthN {
			pgxv4.RegisterDriver(tc.driver, cloudsqlconn.WithIAMAuthN())
		} else {
			pgxv4.RegisterDriver(tc.driver)
		}
		db, err := sql.Open(tc.driver, tc.source)
		if err != nil {
			t.Fatalf("sql.Open want err = nil, got = %v", err)
		}
		defer db.Close()
		testConn(db)
	}
}

// removeAuthEnvVar retrieves an OAuth2 token and a path to a service account key
// and then unsets GOOGLE_APPLICATION_CREDENTIALS. It returns a cleanup function
// that restores the original setup.
func removeAuthEnvVar(t *testing.T) (*oauth2.Token, string, func()) {
	ts, err := google.DefaultTokenSource(context.Background(),
		"https://www.googleapis.com/auth/cloud-platform",
	)
	if err != nil {
		t.Errorf("failed to resolve token source: %v", err)
	}
	tok, err := ts.Token()
	if err != nil {
		t.Errorf("failed to get token: %v", err)
	}
	path, ok := os.LookupEnv("GOOGLE_APPLICATION_CREDENTIALS")
	if !ok {
		t.Fatalf("GOOGLE_APPLICATION_CREDENTIALS was not set in the environment")
	}
	if err := os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS"); err != nil {
		t.Fatalf("failed to unset GOOGLE_APPLICATION_CREDENTIALS")
	}
	return tok, path, func() {
		os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	}
}

func keyfile(t *testing.T) string {
	path := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if path == "" {
		t.Fatal("GOOGLE_APPLICATION_CREDENTIALS not set")
	}
	creds, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("io.ReadAll(): %v", err)
	}
	return string(creds)
}

func TestPostgresAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Postgres integration tests")
	}
	requirePostgresVars(t)

	creds := keyfile(t)
	tok, path, cleanup := removeAuthEnvVar(t)
	defer cleanup()

	tcs := []struct {
		desc string
		opts []cloudsqlconn.Option
	}{
		{
			desc: "with token",
			opts: []cloudsqlconn.Option{cloudsqlconn.WithTokenSource(
				oauth2.StaticTokenSource(tok),
			)},
		},
		{
			desc: "with credentials file",
			opts: []cloudsqlconn.Option{cloudsqlconn.WithCredentialsFile(path)},
		},
		{
			desc: "with credentials JSON",
			opts: []cloudsqlconn.Option{cloudsqlconn.WithCredentialsJSON([]byte(creds))},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()

			d, err := cloudsqlconn.NewDialer(ctx, tc.opts...)
			if err != nil {
				t.Fatalf("failed to init Dialer: %v", err)
			}
			defer d.Close()

			dsn := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", postgresUser, postgresPass, postgresDB)
			config, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("failed to parse pgx config: %v", err)
			}

			config.ConnConfig.DialFunc = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return d.Dial(ctx, postgresConnName)
			}

			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatalf("failed to create pool: %s", err)
			}
			defer pool.Close()

			var now time.Time
			err = pool.QueryRow(context.Background(), "SELECT NOW()").Scan(&now)
			if err != nil {
				t.Fatalf("QueryRow failed: %s", err)
			}
			t.Log(now)
		})
	}
}
