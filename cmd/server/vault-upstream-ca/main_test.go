/**
 * Copyright 2019, Z Lab Corporation. All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"text/template"

	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"

	"github.com/zlabjp/spire-vault-plugin/pkg/fake"
	"github.com/zlabjp/spire-vault-plugin/pkg/vault"
)

const (
	fakeServerCert = "../../../pkg/fake/fixtures/server.pem"
	fakeServerKey  = "../../../pkg/fake/fixtures/server-key.pem"
	fakeCaCert     = "../../../pkg/fake/fixtures/ca.pem"
	fakeClientCert = "../../../pkg/fake/fixtures/client.pem"
	fakeClientKey  = "../../../pkg/fake/fixtures/client-key.pem"
)

type configParam struct {
	Addr  string
	Token string
}

func getTestLogger() *log.Logger {
	logger := &log.Logger{}
	logger.SetOutput(new(bytes.Buffer))
	return logger
}

func getFakeConfigureRequestCertAuth(addr string) (*plugin.ConfigureRequest, error) {
	file, err := ioutil.ReadFile("./fixtures/cert-auth-config.tpl")
	if err != nil {
		return nil, err
	}
	t, err := template.New("plugin config").Parse(string(file))
	if err != nil {
		return nil, err
	}
	cp := &configParam{
		Addr: addr,
	}

	var c bytes.Buffer
	if err := t.Execute(&c, cp); err != nil {
		return nil, err
	}

	return &plugin.ConfigureRequest{
		Configuration: c.String(),
	}, nil
}

func getFakeConfigureRequestTokenAuth(addr, token string) (*plugin.ConfigureRequest, error) {
	file, err := ioutil.ReadFile("./fixtures/token-auth-config.tpl")
	if err != nil {
		return nil, err
	}
	t, err := template.New("plugin config").Parse(string(file))
	if err != nil {
		return nil, err
	}
	cp := &configParam{
		Addr:  addr,
		Token: token,
	}

	var c bytes.Buffer
	if err := t.Execute(&c, cp); err != nil {
		return nil, err
	}

	return &plugin.ConfigureRequest{
		Configuration: c.String(),
	}, nil
}

func getFakeVaultClientWithCertAuth(addr, authMountP, pkiMountP string) (*vault.Client, error) {
	vaultConfig := vault.New(vault.CERT)
	cp := &vault.ClientParams{
		VaultAddr:         fmt.Sprintf("https://%v/", addr),
		CACertPath:        fakeCaCert,
		TLSAuthMountPoint: authMountP,
		PKIMountPoint:     pkiMountP,
		ClientKeyPath:     fakeClientKey,
		ClientCertPath:    fakeClientCert,
	}
	if err := vaultConfig.SetClientParams(cp); err != nil {
		return nil, fmt.Errorf("failetd to prepare vault client")
	}
	return vaultConfig.NewAuthenticatedClient()
}

func getFakeSubmitCSRRequest(csr []byte) *upstreamca.SubmitCSRRequest {
	return &upstreamca.SubmitCSRRequest{
		Csr: csr,
	}
}

func TestConfigureCertConfig(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	tlsAuthResp, err := ioutil.ReadFile("../../../pkg/fake/fixtures/tls-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.TLSAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.TLSAuthResponseCode = 200
	vc.TLSAuthResponse = tlsAuthResp

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	p := New()
	p.logger = getTestLogger()

	ctx := context.Background()
	req, err := getFakeConfigureRequestCertAuth(fmt.Sprintf("https://%v/", addr))
	if err != nil {
		t.Errorf("failed to prepare request: %v", err)
	}

	_, err = p.Configure(ctx, req)
	if err != nil {
		t.Errorf("error from Configure(): %v", err)
	}
}

func TestConfigureTokenConfig(t *testing.T) {
	vc := fake.NewVaultServerConfig()
	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	p := New()
	p.logger = getTestLogger()

	ctx := context.Background()
	req, err := getFakeConfigureRequestTokenAuth(fmt.Sprintf("https://%v/", addr), "test-token")
	if err != nil {
		t.Errorf("failed to prepare request: %v", err)
	}

	_, err = p.Configure(ctx, req)
	if err != nil {
		t.Errorf("error from Configure(): %v", err)
	}
}

func TestConfigureError(t *testing.T) {
	ctx := context.Background()
	req := &plugin.ConfigureRequest{
		Configuration: "invalid-config",
	}

	wantErrPrefix := "failed to decode configuration file"

	p := New()
	_, err := p.Configure(ctx, req)
	if err == nil {
		t.Error("error is empty")
	} else if !strings.HasPrefix(err.Error(), wantErrPrefix) {
		t.Errorf("got %v, want prefix %v", err.Error(), wantErrPrefix)
	}
}

func TestSubmitCSR(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	tlsAuthResp, err := ioutil.ReadFile("../../../pkg/fake/fixtures/tls-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	signResp, err := ioutil.ReadFile("../../../pkg/fake/fixtures/sign-intermediate-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.TLSAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.TLSAuthResponseCode = 200
	vc.TLSAuthResponse = tlsAuthResp
	vc.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vc.SignIntermediateResponseCode = 200
	vc.SignIntermediateResponse = signResp

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	p := New()
	p.logger = getTestLogger()
	client, err := getFakeVaultClientWithCertAuth(addr, "test-auth", "test-pki")
	if err != nil {
		t.Error(err)
	}
	p.vc = client
	p.config = &VaultPluginConfig{}

	testCSR, err := ioutil.ReadFile("../../../pkg/fake/fixtures/test-req.csr")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}

	testCSRReq := getFakeSubmitCSRRequest([]byte(testCSR))

	ctx := context.Background()
	resp, err := p.SubmitCSR(ctx, testCSRReq)
	if err != nil {
		t.Errorf("error from SubmitCSR(): %v", err)
	} else if resp == nil {
		t.Error("SubmitCSR response is empty")
	} else {
		if resp.Cert == nil {
			t.Error("Cert is empty")
		}
		if resp.UpstreamTrustBundle == nil {
			t.Error("UpstreamTrustBundle is empty")
		}
	}
}

func TestSubmitCSRError(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	tlsAuthResp, err := ioutil.ReadFile("../../../pkg/fake/fixtures/tls-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.TLSAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.TLSAuthResponseCode = 200
	vc.TLSAuthResponse = tlsAuthResp
	vc.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vc.SignIntermediateResponseCode = 500

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	p := New()
	p.logger = getTestLogger()
	client, err := getFakeVaultClientWithCertAuth(addr, "test-auth", "test-pki")
	if err != nil {
		t.Error(err)
	}
	p.vc = client
	p.config = &VaultPluginConfig{}

	testCSR, err := ioutil.ReadFile("../../../pkg/fake/fixtures/test-req.csr")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}

	testCSRReq := getFakeSubmitCSRRequest([]byte(testCSR))

	ctx := context.Background()
	_, err = p.SubmitCSR(ctx, testCSRReq)
	if err == nil {
		t.Error("error is empty, want to get error")
	}
}
