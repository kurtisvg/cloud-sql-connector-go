// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudsqlconn

import (
	"context"
	"errors"
	"io/ioutil"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtypes"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

func TestDialerCanConnectToInstance(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	svc, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	stop := mock.StartServerProxy(t, inst)
	defer func() {
		stop()
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	d, err := NewDialer(context.Background(),
		WithDefaultDialOptions(WithPublicIP()),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	d.sqladmin = svc

	conn, err := d.Dial(context.Background(), "my-project:my-region:my-instance", WithPublicIP())
	if err != nil {
		t.Fatalf("expected Dial to succeed, but got error: %v", err)
	}
	defer conn.Close()

	data, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Fatalf("expected ReadAll to succeed, got error %v", err)
	}
	if string(data) != "my-instance" {
		t.Fatalf("expected known response from the server, but got %v", string(data))
	}
}

func TestDialerInstantiationErrors(t *testing.T) {
	_, err := NewDialer(context.Background(), WithCredentialsFile("bogus-file.json"))
	if err == nil {
		t.Fatalf("expected NewDialer to return error, but got none.")
	}
	_, err = NewDialer(context.Background(),
		WithCredentialsJSON([]byte("not the JSON you're looking for")))
	if err == nil {
		t.Fatalf("expected NewDialer to return error, but got none.")
	}
	_, err = NewDialer(context.Background(), WithCredentialsFile("not-a-file.json"))
	if err == nil {
		t.Fatalf("expected NewDialer to return error, but got none.")
	}
}

func TestDialWithAdminAPIErrors(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance")
	svc, cleanup, err := mock.NewSQLAdminService(context.Background())
	stop := mock.StartServerProxy(t, inst)
	defer func() {
		stop()
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	d, err := NewDialer(context.Background(),
		WithDefaultDialOptions(WithPublicIP()),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	d.sqladmin = svc

	_, err = d.Dial(context.Background(), "bad-instance-name")
	var wantErr1 *errtypes.ConfigError
	if !errors.As(err, &wantErr1) {
		t.Fatalf("when instance name is invalid, want = %T, got = %v", wantErr1, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = d.Dial(ctx, "my-project:my-region:my-instance")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("when context is canceled, want = %T, got = %v", context.Canceled, err)
	}

	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance")
	var wantErr2 *errtypes.RefreshError
	if !errors.As(err, &wantErr2) {
		t.Fatalf("when API call fails, want = %T, got = %v", wantErr2, err)
	}
}

func TestDialWithConfigurationErrors(t *testing.T) {
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance",
		mock.WithCertExpiry(time.Now().Add(-time.Hour)))
	svc, cleanup, err := mock.NewSQLAdminService(
		context.Background(),
		mock.InstanceGetSuccess(inst, 2),
		mock.CreateEphemeralSuccess(inst, 2),
	)
	d, err := NewDialer(context.Background(),
		WithDefaultDialOptions(WithPublicIP()),
		WithTokenSource(mock.EmptyTokenSource{}),
	)
	if err != nil {
		t.Fatalf("expected NewDialer to succeed, but got error: %v", err)
	}
	d.sqladmin = svc
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance", WithPrivateIP())
	var wantErr1 *errtypes.ConfigError
	if !errors.As(err, &wantErr1) {
		t.Fatalf("when IP type is invalid, want = %T, got = %v", wantErr1, err)
	}

	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance")
	var wantErr2 *errtypes.DialError
	if !errors.As(err, &wantErr2) {
		t.Fatalf("when server proxy socket is unavailable, want = %T, got = %v", wantErr2, err)
	}

	stop := mock.StartServerProxy(t, inst)
	defer stop()

	_, err = d.Dial(context.Background(), "my-project:my-region:my-instance")
	if !errors.As(err, &wantErr2) {
		t.Fatalf("when TLS handshake fails, want = %T, got = %v", wantErr2, err)
	}
}
