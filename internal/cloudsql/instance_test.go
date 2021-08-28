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

package cloudsql

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtypes"
	"cloud.google.com/go/cloudsqlconn/internal/mock"
)

// genRSAKey generates an RSA key used for test.
func genRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // unexpected, so just panic if it happens
	}
	return key
}

// RSAKey is used for test only.
var RSAKey = genRSAKey()

func TestParseConnName(t *testing.T) {
	tests := []struct {
		name string
		want connName
	}{
		{
			"project:region:instance",
			connName{"project", "region", "instance"},
		},
		{
			"google.com:project:region:instance",
			connName{"google.com:project", "region", "instance"},
		},
		{
			"project:instance", // missing region
			connName{},
		},
	}

	for _, tc := range tests {
		c, err := parseConnName(tc.name)
		if err != nil && tc.want != (connName{}) {
			t.Errorf("unexpected error: %e", err)
		}
		if c != tc.want {
			t.Errorf("ParseConnName(%s) failed: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

func TestConnectInfo(t *testing.T) {
	ctx := context.Background()
	wantAddr := "0.0.0.0"
	inst := mock.NewFakeCSQLInstance("my-project", "my-region", "my-instance", mock.WithPublicIP(wantAddr))
	client, cleanup, err := mock.NewSQLAdminService(
		ctx,
		mock.InstanceGetSuccess(inst, 1),
		mock.CreateEphemeralSuccess(inst, 1),
	)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Fatalf("%v", err)
		}
	}()

	i, err := NewInstance("my-project:my-region:my-instance", client, RSAKey, 30*time.Second, nil)
	if err != nil {
		t.Fatalf("failed to create mock instance: %v", err)
	}

	gotAddr, gotTLSCfg, err := i.ConnectInfo(ctx, PublicIP)
	if err != nil {
		t.Fatalf("failed to retrieve connect info: %v", err)
	}

	if gotAddr != wantAddr {
		t.Fatalf(
			"ConnectInfo returned unexpected IP address, want = %v, got = %v",
			wantAddr, gotAddr,
		)
	}

	wantServerName := "my-project:my-region:my-instance"
	if gotTLSCfg.ServerName != wantServerName {
		t.Fatalf(
			"ConnectInfo return unexpected server name in TLS Config, want = %v, got = %v",
			wantServerName, gotTLSCfg.ServerName,
		)
	}
}

func TestConnectInfoErrors(t *testing.T) {
	ctx := context.Background()

	client, cleanup, err := mock.NewSQLAdminService(ctx)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	// Use a timeout that should fail instantly
	im, err := NewInstance("my-project:my-region:my-instance", client, RSAKey, 0, nil)
	if err != nil {
		t.Fatalf("failed to initialize Instance: %v", err)
	}

	_, _, err = im.ConnectInfo(ctx, PublicIP)
	var wantErr *errtypes.DialError
	if !errors.As(err, &wantErr) {
		t.Fatalf("when connect info fails, want = %T, got = %v", wantErr, err)
	}

	// when client asks for wrong IP address type
	gotAddr, _, err := im.ConnectInfo(ctx, PrivateIP)
	if err == nil {
		t.Fatalf("expected ConnectInfo to fail but returned IP address = %v", gotAddr)
	}
}

func TestClose(t *testing.T) {
	ctx := context.Background()

	client, cleanup, err := mock.NewSQLAdminService(ctx)
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer cleanup()

	// Set up an instance and then close it immediately
	im, err := NewInstance("my-proj:my-region:my-inst", client, RSAKey, 30, nil)
	if err != nil {
		t.Fatalf("failed to initialize Instance: %v", err)
	}
	im.Close()

	_, _, err = im.ConnectInfo(ctx, PublicIP)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("failed to retrieve connect info: %v", err)
	}
}
