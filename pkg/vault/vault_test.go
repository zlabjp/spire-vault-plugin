/**
 * Copyright 2019, Z Lab Corporation. All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"testing"

	vapi "github.com/hashicorp/vault/api"

	"github.com/zlabjp/spire-vault-plugin/pkg/fake"
)

const (
	caCert     = "../fake/fixtures/ca.pem"
	serverCert = "../fake/fixtures/server.pem"
	serverKey  = "../fake/fixtures/server-key.pem"
	clientCert = "../fake/fixtures/client.pem"
	clientKey  = "../fake/fixtures/client-key.pem"
	testReqCSR = "../fake/fixtures/test-req.csr"
	testReqCN  = "test request"
	testTTL    = ""
)

func getTestLogger() *log.Logger {
	logger := &log.Logger{}
	logger.SetOutput(new(bytes.Buffer))
	return logger
}

func getTestCertPool(certPemPath string) (*x509.CertPool, error) {
	wantPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile(certPemPath)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare cert pool: %v", err)
	}
	ok := wantPool.AppendCertsFromPEM(pem)
	if !ok {
		return nil, errors.New("failed to append cert")
	}
	return wantPool, nil
}

func getCertAndKeyPemBlock(certPath, keyPath string) (certPemBlock []byte, keyPemBlock []byte, err error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil

}

func TestNewAuthenticatedClientWithCertAuth(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	tlsAuthResp, err := ioutil.ReadFile("../fake/fixtures/tls-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = serverCert
	vc.ServerKeyPemPath = serverKey
	vc.TLSAuthResponseCode = 200
	vc.TLSAuthResponse = tlsAuthResp

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	c := New(CERT)
	c.Logger = getTestLogger()
	cp := &ClientParams{
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     caCert,
		ClientCertPath: clientCert,
		ClientKeyPath:  clientKey,
	}
	if err := c.SetClientParams(cp); err != nil {
		t.Errorf("failed to prepare test client: %v", err)
	}

	_, err = c.NewAuthenticatedClient()
	if err != nil {
		t.Errorf("unexpected error from NewAuthenticatedClient(): %v", err)
	}
}

func TestNewAuthenticatedClientWithCertAuthError(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	vc.ServerCertificatePemPath = serverCert
	vc.ServerKeyPemPath = serverKey
	vc.TLSAuthResponseCode = 500

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	c := New(CERT)
	c.Logger = getTestLogger()
	cp := &ClientParams{
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     caCert,
		ClientCertPath: clientCert,
		ClientKeyPath:  clientKey,
	}
	if err := c.SetClientParams(cp); err != nil {
		t.Errorf("failed to prepare test client: %v", err)
	}

	_, err = c.NewAuthenticatedClient()
	if err == nil {
		t.Error("expect an error but got nil")
	}
}

func TestNewAuthenticatedClientWithTokenAuth(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	vc.ServerCertificatePemPath = serverCert
	vc.ServerKeyPemPath = serverKey

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	c := New(TOKEN)
	c.Logger = getTestLogger()
	cp := &ClientParams{
		VaultAddr:      fmt.Sprintf("https://%v/", addr),
		CACertPath:     caCert,
		ClientCertPath: clientCert,
		ClientKeyPath:  clientKey,
	}
	if err := c.SetClientParams(cp); err != nil {
		t.Errorf("failed to prepare test client: %v", err)
	}

	_, err = c.NewAuthenticatedClient()
	if err != nil {
		t.Errorf("unexpected error from NewAuthenticatedClient(): %v", err)
	}
}

func TestSetClientParams(t *testing.T) {
	c := New(CERT)
	c.Logger = getTestLogger()
	c.clientParams.VaultAddr = "https://example.org/vault"
	c.clientParams.CACertPath = "path/to/test-ca.pem"
	c.clientParams.ClientCertPath = "path/to/client-cert.pem"
	c.clientParams.ClientKeyPath = "path/to/client-key.pem"

	cp := &ClientParams{
		VaultAddr:      "test-addr",
		CACertPath:     "test-ca.pem",
		ClientCertPath: "test-client.pem",
		ClientKeyPath:  "test-client-key.pem",
	}

	if err := c.SetClientParams(cp); err != nil {
		t.Errorf("error from SetClientParams(): %v", err)
	}
	if c.clientParams.VaultAddr != "test-addr" {
		t.Errorf("got %v, want %v", c.clientParams.VaultAddr, "test-addr")
	}
	if c.clientParams.CACertPath != "test-ca.pem" {
		t.Errorf("got %v, want %v", c.clientParams.VaultAddr, "test-ca.pem")
	}
	if c.clientParams.ClientCertPath != "test-client.pem" {
		t.Errorf("got %v, want %v", c.clientParams.VaultAddr, "test-client.pem")
	}
	if c.clientParams.ClientKeyPath != "test-client-key.pem" {
		t.Errorf("got %v, want %v", c.clientParams.VaultAddr, "test-client-key.pem")
	}
}

func TestConfigureTLSWithCertAuth(t *testing.T) {
	c := New(CERT)
	c.Logger = getTestLogger()
	c.clientParams.CACertPath = caCert
	c.clientParams.ClientCertPath = clientCert
	c.clientParams.ClientKeyPath = clientKey
	vConfig := vapi.DefaultConfig()

	if err := c.ConfigureTLS(vConfig); err != nil {
		t.Errorf("error from ConfigureTLS() %v", err)
	}

	wantPool, err := getTestCertPool(caCert)
	if err != nil {
		t.Errorf("failed to prepare cert pool: %v", err)
	}
	certPemBlock, keyPemBlock, err := getCertAndKeyPemBlock(clientCert, clientKey)
	if err != nil {
		t.Errorf("failed to load client cert/key: %v", err)
	}
	wantCert, err := tls.X509KeyPair(certPemBlock, keyPemBlock)
	if err != nil {
		t.Errorf("failed to prepare certificate: %v", err)
	}

	if err := c.ConfigureTLS(vConfig); err != nil {
		t.Errorf("error from ConfigureTLS(): %v", err)
	}
	tp := vConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig
	cert, err := tp.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Errorf("failed to get client cert: %v", err)
	}

	if !reflect.DeepEqual(tp.RootCAs, wantPool) {
		t.Errorf("got %v,\n want %v", tp.RootCAs, wantPool)
	}
	if !reflect.DeepEqual(cert.Certificate, wantCert.Certificate) {
		t.Errorf("got %v,\n want %v", cert.Certificate, wantCert.Certificate)
	}
}

func TestConfigureTLSWithTokenAuth(t *testing.T) {
	c := New(TOKEN)
	c.Logger = getTestLogger()
	c.clientParams.CACertPath = caCert
	vConfig := vapi.DefaultConfig()

	if err := c.ConfigureTLS(vConfig); err != nil {
		t.Errorf("error from ConfigureTLS() %v", err)
	}

	wantPool, err := getTestCertPool(caCert)
	if err != nil {
		t.Errorf("failed to prepare cert pool: %v", err)
	}

	if err := c.ConfigureTLS(vConfig); err != nil {
		t.Errorf("error from ConfigureTLS(): %v", err)
	}
	tp := vConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig

	if !reflect.DeepEqual(tp.RootCAs, wantPool) {
		t.Errorf("got %v,\n want %v", tp.RootCAs, wantPool)
	}
}

func TestSignIntermediate(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	tlsAuthResp, err := ioutil.ReadFile("../fake/fixtures/tls-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	signResp, err := ioutil.ReadFile("../fake/fixtures/sign-intermediate-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = serverCert
	vc.ServerKeyPemPath = serverKey
	vc.TLSAuthResponseCode = 200
	vc.TLSAuthResponse = tlsAuthResp
	vc.SignIntermediateResponseCode = 200
	vc.SignIntermediateResponse = signResp

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	c := New(CERT)
	c.Logger = getTestLogger()
	c.clientParams.VaultAddr = fmt.Sprintf("https://%v/", addr)
	c.clientParams.CACertPath = caCert
	c.clientParams.ClientCertPath = clientCert
	c.clientParams.ClientKeyPath = clientKey

	vClient, err := c.NewAuthenticatedClient()
	if err != nil {
		t.Errorf("failed to prepare vault client: %v", err)
	}

	resp, err := vClient.SignIntermediate(testReqCN, testTTL, []byte(testReqCSR))
	if err != nil {
		t.Errorf("error from SignIntermediate(): %v", err)
	} else if resp == nil {
		t.Error("response is empty")
	} else {
		if resp.CertPEM == "" {
			t.Error("CertPEM is empty")
		}
		if resp.CACertPEM == "" {
			t.Errorf("CACertPEM is empty")
		}
		if resp.CACertChainPEM == nil {
			t.Errorf("CACertChainPEM is empty")
		}
	}
}

func TestSignIntermediateError(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	tlsAuthResp, err := ioutil.ReadFile("../fake/fixtures/tls-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = serverCert
	vc.ServerKeyPemPath = serverKey
	vc.TLSAuthResponseCode = 200
	vc.TLSAuthResponse = tlsAuthResp
	vc.SignIntermediateResponseCode = 404

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	c := New(CERT)
	c.Logger = getTestLogger()
	c.clientParams.VaultAddr = fmt.Sprintf("https://%v/", addr)
	c.clientParams.CACertPath = caCert
	c.clientParams.ClientCertPath = clientCert
	c.clientParams.ClientKeyPath = clientKey

	vClient, err := c.NewAuthenticatedClient()
	if err != nil {
		t.Errorf("failed to prepare vault client: %v", err)
	}

	_, err = vClient.SignIntermediate(testReqCN, testTTL, []byte(testReqCSR))
	if err == nil {
		t.Error("error is empty")
	}
}
