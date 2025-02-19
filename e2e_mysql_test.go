// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsqlconn_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn"
	"cloud.google.com/go/cloudsqlconn/instance"
	"cloud.google.com/go/cloudsqlconn/mysql/mysql"
	gomysql "github.com/go-sql-driver/mysql"
)

var (
	// "Cloud SQL MySQL instance connection name, in the form of 'project:region:instance'.
	mysqlConnName = os.Getenv("MYSQL_CONNECTION_NAME")
	// "Cloud SQL MySQL instance connection name, in the form of 'project:region:instance'.
	mysqlIAMConnName = os.Getenv("MYSQL_CONNECTION_NAME")
	// Name of database user.
	mysqlUser = os.Getenv("MYSQL_USER")
	// Name of database IAM user.
	mysqlIAMUser = os.Getenv("MYSQL_USER_IAM")
	// Password for the database user; be careful when entering a password on
	// the command line (it may go into your terminal's history).
	mysqlPass = os.Getenv("MYSQL_PASS")
	// Name of the database to connect to.
	mysqlDB = os.Getenv("MYSQL_DB")
)

func requireMySQLVars(t *testing.T) {
	switch "" {
	case mysqlConnName:
		t.Fatal("'MYSQL_CONNECTION_NAME' env var not set")
	case mysqlUser:
		t.Fatal("'MYSQL_USER' env var not set")
	case mysqlPass:
		t.Fatal("'MYSQL_PASS' env var not set")
	case mysqlDB:
		t.Fatal("'MYSQL_DB' env var not set")
	}
}

type mockResolver struct {
}

func (r *mockResolver) Resolve(_ context.Context, name string) (instanceName instance.ConnName, err error) {
	if name == "mysql.example.com" {
		return instance.ParseConnNameWithDomainName(mysqlConnName, "mysql.example.com")
	}
	return instance.ConnName{}, fmt.Errorf("no resolution for %v", name)
}

func TestMySQLDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MySQL integration tests")
	}

	tcs := []struct {
		desc         string
		driverName   string
		instanceName string
		user         string
		password     string
		opts         []cloudsqlconn.Option
	}{
		{
			desc:         "default options",
			driverName:   "cloudsql-mysql",
			opts:         nil,
			instanceName: mysqlConnName,
			user:         mysqlUser,
			password:     mysqlPass,
		},
		{
			desc:         "auto IAM authn",
			driverName:   "cloudsql-mysql-iam",
			opts:         []cloudsqlconn.Option{cloudsqlconn.WithIAMAuthN()},
			instanceName: mysqlIAMConnName,
			user:         mysqlIAMUser,
			password:     "password",
		},
		{
			desc:         "with dns",
			driverName:   "cloudsql-mysql-dns",
			opts:         []cloudsqlconn.Option{cloudsqlconn.WithResolver(&mockResolver{})},
			instanceName: "mysql.example.com",
			user:         mysqlUser,
			password:     mysqlPass,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			testConn := func(db *sql.DB) {
				var now time.Time
				if err := db.QueryRow("SELECT NOW()").Scan(&now); err != nil {
					t.Fatalf("QueryRow failed: %v", err)
				}
				t.Log(now)
			}
			cleanup, err := mysql.RegisterDriver(tc.driverName, tc.opts...)
			if err != nil {
				t.Fatalf("failed to register driver: %v", err)
			}
			defer cleanup()
			cfg := gomysql.NewConfig()
			cfg.CheckConnLiveness = true
			cfg.User = tc.user
			cfg.Passwd = tc.password
			cfg.DBName = mysqlDB
			cfg.Net = tc.driverName
			cfg.Addr = tc.instanceName
			cfg.Params = map[string]string{"parseTime": "true"}

			db, err := sql.Open("mysql", cfg.FormatDSN())
			if err != nil {
				t.Fatalf("sql.Open want err = nil, got = %v", err)
			}
			defer db.Close()
			testConn(db)
		})
	}
}
