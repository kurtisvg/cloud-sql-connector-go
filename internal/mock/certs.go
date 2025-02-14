// Copyright 2025 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"
)

func name(cn string) pkix.Name {
	return pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Google\\, Inc"},
		CommonName:   cn,
	}
}

// "C=US,O=Google\\, Inc,CN=Google Cloud SQL Root CA"
var serverCaSubject = name("Google Cloud SQL Root CA")
var intermediateCaSubject = name("Google Cloud SQL Intermediate CA")
var signingCaSubject = name("Google Cloud SQL Signing CA foo:baz")
var instanceWithCnSubject = name("myProject:myInstance")

// TLSCertificates generates an accurate reproduction of the TLS certificates
// used by Cloud SQL. This was translated to Go from the Java connector.
//
// From the cloud-sql-jdbc-socket-factory project:
// core/src/test/java/com/google/cloud/sql/core/TestCertificateGenerator.java
type TLSCertificates struct {
	clientCertExpires time.Time
	projectName       string
	instanceName      string
	sans              []string

	serverCaKey             *rsa.PrivateKey
	serverIntermediateCaKey *rsa.PrivateKey
	clientSigningCaKey      *rsa.PrivateKey

	serverCaCert               *x509.Certificate
	serverIntermediateCaCert   *x509.Certificate
	clientSigningCACertificate *x509.Certificate

	serverKey            *rsa.PrivateKey
	serverCert           *x509.Certificate
	casServerCertificate *x509.Certificate
}

func mustGenerateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// newTLSCertificates creates a new instance of the TLSCertificates.
func newTLSCertificates(projectName, instanceName string, sans []string, clientCertExpires time.Time) *TLSCertificates {
	c := &TLSCertificates{
		clientCertExpires: clientCertExpires,
		projectName:       projectName,
		instanceName:      instanceName,
		sans:              sans,
	}
	c.rotateCA()
	return c
}

// generateSKI Generate public key id. Certificates need to include
// the key id to make the certificate chain work.
func generateSKI(pub *rsa.PublicKey) []byte {
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, uint64(pub.E))

	hasher := sha1.New()
	hasher.Write(bs)
	if pub.N != nil {
		hasher.Write(pub.N.Bytes())
	}
	ski := hasher.Sum(nil)

	return ski
}

// mustBuildRootCertificate produces a self-signed certificate.
// or panics - use only for testing.
func mustBuildRootCertificate(subject pkix.Name, k *rsa.PrivateKey) *x509.Certificate {

	sn, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		panic(err)
	}

	cert := &x509.Certificate{
		SerialNumber:          sn,
		SubjectKeyId:          generateSKI(&k.PublicKey),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDerBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(certDerBytes)
	if err != nil {
		panic(err)
	}
	return c
}

// mustBuildSignedCertificate produces a certificate for Subject that is signed
// by the issuer.
func mustBuildSignedCertificate(
	isCa bool,
	subject pkix.Name,
	subjectPublicKey *rsa.PrivateKey,
	certificateIssuer pkix.Name,
	issuerPrivateKey *rsa.PrivateKey,
	notAfter time.Time,
	subjectAlternativeNames []string) *x509.Certificate {

	sn, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		panic(err)
	}

	cert := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               subject,
		SubjectKeyId:          generateSKI(&subjectPublicKey.PublicKey),
		AuthorityKeyId:        generateSKI(&issuerPrivateKey.PublicKey),
		Issuer:                certificateIssuer,
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		IsCA:                  isCa,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              subjectAlternativeNames,
	}

	certDerBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &subjectPublicKey.PublicKey, issuerPrivateKey)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(certDerBytes)
	if err != nil {
		panic(err)
	}
	return c

}

// toPEMFormat Converts an array of certificates to PEM format.
func toPEMFormat(certs ...*x509.Certificate) ([]byte, error) {
	certPEM := new(bytes.Buffer)

	for _, cert := range certs {
		err := pem.Encode(certPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return nil, err
		}
	}

	return certPEM.Bytes(), nil
}

// signWithClientKey produces a PEM encoded certificate client certificate
// containing the clientKey public key, signed by the client CA certificate.
func (ct *TLSCertificates) signWithClientKey(clientKey *rsa.PublicKey) ([]byte, error) {
	notAfter := ct.clientCertExpires
	if ct.clientCertExpires.IsZero() {
		notAfter = time.Now().Add(1 * time.Hour)
	}

	// Create a signed cert from the client's public key.
	cert := &x509.Certificate{ // TODO: Validate this format vs API
		SerialNumber: &big.Int{},
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Google, Inc"},
			CommonName:   "Google Cloud SQL Client",
		},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ct.clientSigningCACertificate, clientKey, ct.clientSigningCaKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	return certPEM.Bytes(), nil
}

// generateServerCertWithCn generates a server certificate for legacy
// GOOGLE_MANAGED_INTERNAL_CA mode where the instance name is in the CN.
func (ct *TLSCertificates) generateServerCertWithCn(cn string) *x509.Certificate {
	return mustBuildSignedCertificate(
		false,
		name(cn),
		ct.serverKey,
		serverCaSubject,
		ct.serverCaKey,
		time.Now().Add(1*time.Hour), nil)
}

// serverChain creates a []tls.Certificate for use with a TLS server socket.
// serverCAMode controls whether this returns a legacy or CAS server
// certificate.
func (ct *TLSCertificates) serverChain(serverCAMode string) []tls.Certificate {
	// if this server is running in legacy mode
	if serverCAMode == "" || serverCAMode == "GOOGLE_MANAGED_INTERNAL_CA" {
		return []tls.Certificate{{
			Certificate: [][]byte{ct.serverCert.Raw, ct.serverCaCert.Raw},
			PrivateKey:  ct.serverKey,
			Leaf:        ct.serverCert,
		}}
	}

	return []tls.Certificate{{
		Certificate: [][]byte{ct.casServerCertificate.Raw, ct.serverIntermediateCaCert.Raw, ct.serverCaCert.Raw},
		PrivateKey:  ct.serverKey,
		Leaf:        ct.casServerCertificate,
	}}

}
func (ct *TLSCertificates) clientCAPool() *x509.CertPool {
	clientCa := x509.NewCertPool()
	clientCa.AddCert(ct.clientSigningCACertificate)
	return clientCa
}

func (ct *TLSCertificates) rotateClientCA() {
	ct.clientSigningCaKey = mustGenerateKey()
	ct.clientSigningCACertificate = mustBuildRootCertificate(signingCaSubject, ct.clientSigningCaKey)
}

func (ct *TLSCertificates) rotateCA() {
	oneYear := time.Now().AddDate(1, 0, 0)
	ct.serverCaKey = mustGenerateKey()
	ct.clientSigningCaKey = mustGenerateKey()
	ct.serverKey = mustGenerateKey()
	ct.serverIntermediateCaKey = mustGenerateKey()

	ct.serverCaCert = mustBuildRootCertificate(serverCaSubject, ct.serverCaKey)

	ct.serverIntermediateCaCert =
		mustBuildSignedCertificate(
			true,
			intermediateCaSubject,
			ct.serverIntermediateCaKey,
			serverCaSubject,
			ct.serverCaKey,
			oneYear,
			nil)

	ct.casServerCertificate =
		mustBuildSignedCertificate(
			false,
			name(""),
			ct.serverKey,
			intermediateCaSubject,
			ct.serverIntermediateCaKey,
			oneYear,
			ct.sans)

	ct.serverCert = mustBuildSignedCertificate(
		false,
		name(ct.projectName+":"+ct.instanceName),
		ct.serverKey,
		serverCaSubject,
		ct.serverCaKey,
		oneYear,
		nil)

	ct.rotateClientCA()
}
