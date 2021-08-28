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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtypes"
	"cloud.google.com/go/cloudsqlconn/internal/trace"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	PublicIP  = "PUBLIC"
	PrivateIP = "PRIVATE"
)

// metadata contains information about a Cloud SQL instance needed to create connections.
type metadata struct {
	ipAddrs      map[string]string
	serverCaCert *x509.Certificate
	version      string
}

// fetchMetadata uses the Cloud SQL Admin APIs get method to retreive the information about a Cloud SQL instance
// that is used to create secure connections.
func fetchMetadata(ctx context.Context, client *sqladmin.Service, inst connName) (m metadata, err error) {
	var end trace.EndSpanFunc
	ctx, end = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.FetchMetadata")
	defer func() { end(err) }()
	db, err := client.Instances.Get(inst.project, inst.name).Context(ctx).Do()
	if err != nil {
		return metadata{}, errtypes.NewRefreshError("failed to get instance metadata", inst.String(), err)
	}
	// validate the instance is supported for authenticated connections
	if db.Region != inst.region {
		msg := fmt.Sprintf("provided region was mismatched - got %s, want %s", inst.region, db.Region)
		return metadata{}, errtypes.NewRefreshError(msg, inst.String(), nil)
	}
	if db.BackendType != "SECOND_GEN" {
		return metadata{}, errtypes.NewConfigError(
			"unsupported instance - only Second Generation instances are supported",
			inst.String(),
		)
	}

	// parse any ip addresses that might be used to connect
	ipAddrs := make(map[string]string)
	for _, ip := range db.IpAddresses {
		switch ip.Type {
		case "PRIMARY":
			ipAddrs[PublicIP] = ip.IpAddress
		case "PRIVATE":
			ipAddrs[PrivateIP] = ip.IpAddress
		}
	}
	if len(ipAddrs) == 0 {
		return metadata{}, errtypes.NewConfigError(
			"cannot connect to instance - it has no supported IP addresses",
			inst.String(),
		)
	}

	// parse the server-side CA certificate
	b, _ := pem.Decode([]byte(db.ServerCaCert.Cert))
	if b == nil {
		return metadata{}, errtypes.NewRefreshError("failed to decode valid PEM cert", inst.String(), nil)
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return metadata{}, errtypes.NewRefreshError(
			fmt.Sprintf("failed to parse as X.509 certificate: %v", err),
			inst.String(),
			nil,
		)
	}

	m = metadata{
		ipAddrs:      ipAddrs,
		serverCaCert: cert,
		version:      db.DatabaseVersion,
	}

	return m, nil
}

func refreshToken(ts oauth2.TokenSource, tok *oauth2.Token) (*oauth2.Token, error) {
	expiredToken := &oauth2.Token{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
		Expiry:       time.Time{}.Add(1), // Expired
	}
	return oauth2.ReuseTokenSource(expiredToken, ts).Token()
}

// fetchEphemeralCert uses the Cloud SQL Admin API's createEphemeral method to
// create a signed TLS certificate that authorized to connect via the Cloud SQL
// instance's serverside proxy. The cert if valid for approximately one hour.
func fetchEphemeralCert(
	ctx context.Context,
	client *sqladmin.Service,
	inst connName,
	key *rsa.PrivateKey,
	ts oauth2.TokenSource,
) (c tls.Certificate, err error) {
	var end trace.EndSpanFunc
	ctx, end = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.FetchEphemeralCert")
	defer func() { end(err) }()
	clientPubKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	req := sqladmin.SslCertsCreateEphemeralRequest{
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Bytes: clientPubKey, Type: "RSA PUBLIC KEY"})),
	}
	var tok *oauth2.Token
	if ts != nil {
		var tokErr error
		tok, tokErr = ts.Token()
		if tokErr != nil {
			return tls.Certificate{}, errtypes.NewRefreshError(
				"failed to retrieve Oauth2 token",
				inst.String(),
				tokErr,
			)
		}
		// Always refresh the token to ensure its expiration is far enough in
		// the future.
		tok, tokErr = refreshToken(ts, tok)
		if tokErr != nil {
			return tls.Certificate{}, errtypes.NewRefreshError(
				"failed to refresh Oauth2 token",
				inst.String(),
				tokErr,
			)
		}
		// TODO: remove this once issue with OAuth2 Tokens is resolved.
		// See https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/852.
		req.AccessToken = strings.TrimRight(tok.AccessToken, ".")
	}
	resp, err := client.SslCerts.CreateEphemeral(inst.project, inst.name, &req).Context(ctx).Do()
	if err != nil {
		return tls.Certificate{}, errtypes.NewRefreshError(
			"create ephemeral cert failed",
			inst.String(),
			err,
		)
	}

	// parse the client cert
	b, _ := pem.Decode([]byte(resp.Cert))
	if b == nil {
		return tls.Certificate{}, errtypes.NewRefreshError(
			"failed to decode valid PEM cert",
			inst.String(),
			nil,
		)
	}
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return tls.Certificate{}, errtypes.NewRefreshError(
			fmt.Sprintf("failed to parse as X.509 certificate: %v", err),
			inst.String(),
			nil,
		)
	}
	if ts != nil {
		// Adjust the certificate's expiration to be the earlier of the token's
		// expiration or the certificate's expiration.
		if tok.Expiry.Before(clientCert.NotAfter) {
			clientCert.NotAfter = tok.Expiry
		}
	}

	c = tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  key,
		Leaf:        clientCert,
	}
	return c, nil
}

// createTLSConfig returns a *tls.Config for connecting securely to the Cloud SQL instance.
func createTLSConfig(inst connName, m metadata, cert tls.Certificate) *tls.Config {
	certs := x509.NewCertPool()
	certs.AddCert(m.serverCaCert)

	cfg := &tls.Config{
		ServerName:   inst.String(),
		Certificates: []tls.Certificate{cert},
		RootCAs:      certs,
		// We need to set InsecureSkipVerify to true due to
		// https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/194
		// https://tip.golang.org/doc/go1.11#crypto/x509
		//
		// Since we have a secure channel to the Cloud SQL API which we use to retrieve the
		// certificates, we instead need to implement our own VerifyPeerCertificate function
		// that will verify that the certificate is OK.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: genVerifyPeerCertificateFunc(inst, certs),
		MinVersion:            tls.VersionTLS13,
	}
	return cfg
}

// genVerifyPeerCertificateFunc creates a VerifyPeerCertificate func that verifies that the peer
// certificate is in the cert pool. We need to define our own because CloudSQL
// instances use the instance name (e.g., my-project:my-instance) instead of a
// valid domain name for the certificate's Common Name.
func genVerifyPeerCertificateFunc(cn connName, pool *x509.CertPool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errtypes.NewDialError("no certificate to verify", cn.String(), nil)
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return errtypes.NewDialError("failed to parse X.509 certificate", cn.String(), err)
		}

		opts := x509.VerifyOptions{Roots: pool}
		if _, err = cert.Verify(opts); err != nil {
			return errtypes.NewDialError("failed to verify certificate", cn.String(), err)
		}

		certInstanceName := fmt.Sprintf("%s:%s", cn.project, cn.name)
		if cert.Subject.CommonName != certInstanceName {
			return errtypes.NewDialError(
				fmt.Sprintf("certificate had CN %q, expected %q",
					cert.Subject.CommonName, certInstanceName),
				cn.String(),
				nil,
			)
		}
		return nil
	}
}

// newRefresher creates a Refresher.
func newRefresher(
	timeout time.Duration,
	interval time.Duration,
	burst int,
	svc *sqladmin.Service,
	ts oauth2.TokenSource,
) refresher {
	return refresher{
		timeout:       timeout,
		clientLimiter: rate.NewLimiter(rate.Every(interval), burst),
		client:        svc,
		tokenSource:   ts,
	}
}

// refresher manages the SQL Admin API access to instance metadata and to
// ephemeral certificates.
type refresher struct {
	// timeout is the maximum amount of time a refresh operation should be allowed to take.
	timeout time.Duration

	clientLimiter *rate.Limiter
	client        *sqladmin.Service
	tokenSource   oauth2.TokenSource
}

// performRefresh immediately performs a full refresh operation using the Cloud SQL Admin API.
func (r refresher) performRefresh(ctx context.Context, cn connName, k *rsa.PrivateKey) (md metadata, c *tls.Config, expiry time.Time, err error) {
	var refreshEnd trace.EndSpanFunc
	ctx, refreshEnd = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.RefreshConnection",
		trace.AddInstanceName(cn.String()),
	)
	defer func() { refreshEnd(err) }()
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if ctx.Err() == context.Canceled {
		return metadata{}, nil, time.Time{}, ctx.Err()
	}

	// avoid refreshing too often to try not to tax the SQL Admin API quotas
	err = r.clientLimiter.Wait(ctx)
	if err != nil {
		return metadata{}, nil, time.Time{}, errtypes.NewDialError(
			"refresh was throttled until context expired",
			cn.String(),
			nil,
		)
	}

	// start async fetching the instance's metadata
	type mdRes struct {
		md  metadata
		err error
	}
	mdC := make(chan mdRes, 1)
	go func() {
		defer close(mdC)
		md, err := fetchMetadata(ctx, r.client, cn)
		mdC <- mdRes{md, err}
	}()

	// start async fetching the certs
	type ecRes struct {
		ec  tls.Certificate
		err error
	}
	ecC := make(chan ecRes, 1)
	go func() {
		defer close(ecC)
		ec, err := fetchEphemeralCert(ctx, r.client, cn, k, r.tokenSource)
		ecC <- ecRes{ec, err}
	}()

	// wait for the results of each operations
	select {
	case r := <-mdC:
		if r.err != nil {
			return md, nil, time.Time{}, fmt.Errorf("failed to get instance: %w", r.err)
		}
		md = r.md
	case <-ctx.Done():
		return md, nil, time.Time{}, fmt.Errorf("refresh failed: %w", ctx.Err())
	}
	var ec tls.Certificate
	select {
	case r := <-ecC:
		if r.err != nil {
			return md, nil, time.Time{}, fmt.Errorf("fetch ephemeral cert failed: %w", r.err)
		}
		ec = r.ec
	case <-ctx.Done():
		return md, nil, time.Time{}, fmt.Errorf("refresh failed: %w", ctx.Err())
	}

	c = createTLSConfig(cn, md, ec)
	// This should never not be the case, but we check to avoid a potential nil-pointer
	if len(c.Certificates) > 0 {
		expiry = c.Certificates[0].Leaf.NotAfter
	}
	return md, c, expiry, nil
}
