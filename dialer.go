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

package cloudsqlconn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"cloud.google.com/go/cloudsqlconn/errtypes"
	"cloud.google.com/go/cloudsqlconn/internal/cloudsql"
	"cloud.google.com/go/cloudsqlconn/internal/trace"
	"github.com/google/uuid"
	"golang.org/x/net/proxy"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

const (
	// versionString indicates the version of this library.
	versionString = "0.1.0-dev"
	userAgent     = "cloud-sql-go-connector/" + versionString

	// defaultTCPKeepAlive is the default keep alive value used on connections to a Cloud SQL instance.
	defaultTCPKeepAlive = 30 * time.Second
	// serverProxyPort is the port the server-side proxy receives connections on.
	serverProxyPort = "3307"
)

var (
	// defaultKey is the default RSA public/private keypair used by the clients.
	defaultKey    *rsa.PrivateKey
	defaultKeyErr error
	keyOnce       sync.Once
)

func getDefaultKeys() (*rsa.PrivateKey, error) {
	keyOnce.Do(func() {
		defaultKey, defaultKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return defaultKey, defaultKeyErr
}

// A Dialer is used to create connections to Cloud SQL instances.
//
// Use NewDialer to initialize a Dialer.
type Dialer struct {
	lock sync.RWMutex
	// instances map connection names (e.g., my-project:us-central1:my-instance)
	// to *cloudsql.Instance types.
	instances      map[string]*cloudsql.Instance
	key            *rsa.PrivateKey
	refreshTimeout time.Duration

	sqladmin *sqladmin.Service

	// defaultDialCfg holds the constructor level DialOptions, so that it can
	// be copied and mutated by the Dial function.
	defaultDialCfg dialCfg

	// dialerID uniquely identifies a Dialer. Used for monitoring purposes,
	// *only* when a client has configured OpenCensus exporters.
	dialerID string

	// dialFunc is the function used to connect to the address on the named
	// network. By default it is golang.org/x/net/proxy#Dial.
	dialFunc func(cxt context.Context, network, addr string) (net.Conn, error)

	// iamTokenSource supplies the OAuth2 token used for IAM DB Authn. If IAM DB
	// Authn is not enabled, iamTokenSource will be nil.
	iamTokenSource oauth2.TokenSource

	// mu sychronizes access to openConns
	mu sync.RWMutex
	// openConns tracks the number of connections across instances
	openConns map[string]int64

	metrics *trace.MetricsCollector
	done    chan struct{}
}

// NewDialer creates a new Dialer.
//
// Initial calls to NewDialer make take longer than normal because generation of an
// RSA keypair is performed. Calls with a WithRSAKeyPair DialOption or after a default
// RSA keypair is generated will be faster.
func NewDialer(ctx context.Context, opts ...DialerOption) (*Dialer, error) {
	cfg := &dialerConfig{
		refreshTimeout: 30 * time.Second,
		sqladminOpts:   []option.ClientOption{option.WithUserAgent(userAgent)},
		dialFunc:       proxy.Dial,
	}
	for _, opt := range opts {
		opt(cfg)
		if cfg.err != nil {
			return nil, cfg.err
		}
	}
	// If callers have not provided a token source, either explicitly with
	// WithTokenSource or implicitly with WithCredentialsJSON etc, then use the
	// default token source.
	if cfg.useIAMAuthN && cfg.tokenSource == nil {
		ts, err := google.DefaultTokenSource(ctx, sqladmin.SqlserviceAdminScope)
		if err != nil {
			return nil, fmt.Errorf("failed to create token source: %v", err)
		}
		cfg.tokenSource = ts
	}
	// If IAM Authn is not explicitly enabled, remove the token source.
	if !cfg.useIAMAuthN {
		cfg.tokenSource = nil
	}

	if cfg.rsaKey == nil {
		key, err := getDefaultKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA keys: %v", err)
		}
		cfg.rsaKey = key
	}

	client, err := sqladmin.NewService(ctx, cfg.sqladminOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create sqladmin client: %v", err)
	}

	dialCfg := dialCfg{
		ipType:       cloudsql.PublicIP,
		tcpKeepAlive: defaultTCPKeepAlive,
	}
	for _, opt := range cfg.dialOpts {
		opt(&dialCfg)
	}

	// The error returned indicates a configuration error inside the library and
	// will be caught be tests. So we safely ignore it here.
	mc, _ := trace.NewMetricsCollector()
	d := &Dialer{
		instances:      make(map[string]*cloudsql.Instance),
		key:            cfg.rsaKey,
		refreshTimeout: cfg.refreshTimeout,
		sqladmin:       client,
		defaultDialCfg: dialCfg,
		dialerID:       uuid.New().String(),
		iamTokenSource: cfg.tokenSource,
		dialFunc:       cfg.dialFunc,
		metrics:        mc,
		openConns:      make(map[string]int64),
		done:           make(chan struct{}),
	}
	// TODO: don't start the goroutine unless a user has enabled metrics.
	go d.reportOpenConns(ctx)
	return d, nil
}

// Dial returns a net.Conn connected to the specified Cloud SQL instance. The instance argument must be the
// instance's connection name, which is in the format "project-name:region:instance-name".
func (d *Dialer) Dial(ctx context.Context, instance string, opts ...DialOption) (conn net.Conn, err error) {
	startTime := time.Now()
	var endDial trace.EndSpanFunc
	ctx, endDial = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn.Dial",
		trace.AddInstanceName(instance),
		trace.AddDialerID(d.dialerID),
	)
	defer func() { endDial(err) }()
	cfg := d.defaultDialCfg
	for _, opt := range opts {
		opt(&cfg)
	}

	var endInfo trace.EndSpanFunc
	ctx, endInfo = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.InstanceInfo")
	i, err := d.instance(instance)
	if err != nil {
		endInfo(err)
		return nil, err
	}
	addr, tlsCfg, err := i.ConnectInfo(ctx, cfg.ipType)
	if err != nil {
		endInfo(err)
		return nil, err
	}
	endInfo(err)

	var connectEnd trace.EndSpanFunc
	ctx, connectEnd = trace.StartSpan(ctx, "cloud.google.com/go/cloudsqlconn/internal.Connect")
	defer func() { connectEnd(err) }()
	addr = net.JoinHostPort(addr, serverProxyPort)
	conn, err = d.dialFunc(ctx, "tcp", addr)
	if err != nil {
		// refresh the instance info in case it caused the connection failure
		i.ForceRefresh()
		return nil, errtypes.NewDialError("failed to dial", i.String(), err)
	}
	if c, ok := conn.(*net.TCPConn); ok {
		if err := c.SetKeepAlive(true); err != nil {
			return nil, errtypes.NewDialError("failed to set keep-alive", i.String(), err)
		}
		if err := c.SetKeepAlivePeriod(cfg.tcpKeepAlive); err != nil {
			return nil, errtypes.NewDialError("failed to set keep-alive period", i.String(), err)
		}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		// refresh the instance info in case it caused the handshake failure
		i.ForceRefresh()
		_ = tlsConn.Close() // best effort close attempt
		return nil, errtypes.NewDialError("handshake failed", i.String(), err)
	}
	latency := time.Since(startTime).Milliseconds()
	go func() {
		d.mu.Lock()
		d.openConns[instance]++
		d.mu.Unlock()
		d.metrics.RecordDialLatency(ctx, instance, d.dialerID, latency)
	}()

	return newInstrumentedConn(tlsConn, func() {
		d.mu.Lock()
		d.openConns[instance]--
		d.mu.Unlock()
	}), nil
}

// newInstrumentedConn initializes an instrumentedConn that on closing will
// decrement the number of open connects and record the result.
func newInstrumentedConn(conn net.Conn, closeFunc func()) *instrumentedConn {
	return &instrumentedConn{
		Conn:      conn,
		closeFunc: closeFunc,
	}
}

// instrumentedConn wraps a net.Conn and invokes closeFunc when the connection
// is closed.
type instrumentedConn struct {
	net.Conn
	closeFunc func()
}

// Close delegates to the underylying net.Conn interface and reports the close
// to the provided closeFunc only when Close returns no error.
func (i *instrumentedConn) Close() error {
	err := i.Conn.Close()
	if err != nil {
		return err
	}
	go i.closeFunc()
	return nil
}

func (d *Dialer) reportOpenConns(ctx context.Context) {
	// TODO: make this metrics reporting interval configurable.
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		select {
		case <-d.done:
			return
		case <-ctx.Done():
			return
		default:
			type instConn struct {
				inst  string
				conns int64
			}
			var ics []instConn
			d.mu.RLock()
			for inst, conns := range d.openConns {
				ics = append(ics, instConn{inst: inst, conns: conns})
			}
			d.mu.RUnlock()
			for _, ic := range ics {
				d.metrics.RecordOpenConnections(ctx, ic.conns, ic.inst, d.dialerID)
			}
		}
	}
}

// Close closes the Dialer; it prevents the Dialer from refreshing the information
// needed to connect. Additional dial operations may succeed until the information
// expires.
func (d *Dialer) Close() {
	d.lock.Lock()
	defer d.lock.Unlock()
	for _, i := range d.instances {
		i.Close()
	}
	close(d.done)
}

func (d *Dialer) instance(connName string) (*cloudsql.Instance, error) {
	// Check instance cache
	d.lock.RLock()
	i, ok := d.instances[connName]
	d.lock.RUnlock()
	if !ok {
		d.lock.Lock()
		// Recheck to ensure instance wasn't created between locks
		i, ok = d.instances[connName]
		if !ok {
			// Create a new instance
			var err error
			i, err = cloudsql.NewInstance(connName, d.sqladmin, d.key, d.refreshTimeout, d.iamTokenSource)
			if err != nil {
				d.lock.Unlock()
				return nil, err
			}
			d.instances[connName] = i
		}
		d.lock.Unlock()
	}
	return i, nil
}
