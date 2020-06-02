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
	"strings"
	"testing"
	"text/template"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"

	"github.com/zlabjp/spire-vault-plugin/pkg/common"
	"github.com/zlabjp/spire-vault-plugin/pkg/fake"
	"github.com/zlabjp/spire-vault-plugin/pkg/vault"
)

const (
	fakeServerCert = "../../../pkg/fake/_test_data/server.pem"
	fakeServerKey  = "../../../pkg/fake/_test_data/server-key.pem"
	fakeCaCert     = "../../../pkg/fake/_test_data/ca.pem"
	fakeClientCert = "../../../pkg/fake/_test_data/client.pem"
	fakeClientKey  = "../../../pkg/fake/_test_data/client-key.pem"
)

type configParam struct {
	Addr  string
	Token string
}

func getTestLogger() hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Output: new(bytes.Buffer),
		Name:   common.PluginName,
		Level:  hclog.Debug,
	})
}

func getFakeConfigureRequest(addr string, fixturePath string) (*plugin.ConfigureRequest, error) {
	file, err := ioutil.ReadFile(fixturePath)
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

func getFakeVaultClientWithCertAuth(addr, authMountP, pkiMountP string) (*vault.Client, error) {
	vaultConfig := vault.New(vault.CERT)
	retry := 0
	cp := &vault.ClientParams{
		MaxRetries:         &retry,
		VaultAddr:          fmt.Sprintf("https://%v/", addr),
		CACertPath:         fakeCaCert,
		CertAuthMountPoint: authMountP,
		PKIMountPoint:      pkiMountP,
		ClientKeyPath:      fakeClientKey,
		ClientCertPath:     fakeClientCert,
	}
	if err := vaultConfig.SetClientParams(cp); err != nil {
		return nil, fmt.Errorf("failetd to prepare vault client")
	}
	return vaultConfig.NewAuthenticatedClient()
}

func getFakeSubmitCSRRequest(csr []byte) (*upstreamca.SubmitCSRRequest, error) {
	csrDER, err := pemutil.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRRequest{
		Csr: csrDER.Raw,
	}, nil
}

func TestConfigureCertConfig(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	certAuthResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/cert-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.CertAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.CertAuthResponseCode = 200
	vc.CertAuthResponse = certAuthResp

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	p := New()
	p.logger = getTestLogger()

	ctx := context.Background()
	req, err := getFakeConfigureRequest(fmt.Sprintf("https://%v/", addr), "./_test_data/cert-auth-config.tpl")
	if err != nil {
		t.Errorf("failed to prepare request: %v", err)
	}

	_, err = p.Configure(ctx, req)
	if err != nil {
		t.Errorf("error from Configure(): %v", err)
	}
}

func TestConfigureAppRoleConfig(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	appRoleResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/approle-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.AppRoleAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.AppRoleAuthResponseCode = 200
	vc.AppRoleAuthResponse = appRoleResp

	s, addr, err := vc.NewTLSServer()
	if err != nil {
		t.Errorf("failed to prepare test server: %v", err)
	}
	s.Start()
	defer s.Close()

	p := New()
	p.logger = getTestLogger()

	ctx := context.Background()
	req, err := getFakeConfigureRequest(fmt.Sprintf("https://%v/", addr), "./_test_data/approle-auth-config.tpl")
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
	req, err := getFakeConfigureRequest(fmt.Sprintf("https://%v/", addr), "./_test_data/token-auth-config.tpl")
	if err != nil {
		t.Errorf("failed to prepare request: %v", err)
	}

	_, err = p.Configure(ctx, req)
	if err != nil {
		t.Errorf("error from Configure(): %v", err)
	}
}

func TestConfigureErrorInvalidTTL(t *testing.T) {
	file, err := ioutil.ReadFile("./_test_data/invalid-ttl.hcl")
	if err != nil {
		t.Errorf("failed to read fixture file: %v", err)
	}

	req := &plugin.ConfigureRequest{
		Configuration: string(file),
	}

	p := New()
	p.logger = getTestLogger()
	ctx := context.Background()
	_, err = p.Configure(ctx, req)

	wantErrPrefix := "failed to parse TTL value: time: missing unit in duration"
	if err == nil {
		t.Errorf("expected got an error")
	} else if !strings.HasPrefix(err.Error(), wantErrPrefix) {
		t.Errorf("got %v, want prefix %v", err, wantErrPrefix)
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

	certAuthResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/cert-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	signResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/sign-intermediate-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	renewResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/renew-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}

	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.CertAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.CertAuthResponseCode = 200
	vc.CertAuthResponse = certAuthResp
	vc.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vc.SignIntermediateResponseCode = 200
	vc.SignIntermediateResponse = signResp
	vc.RenewResponseCode = 200
	vc.RenewResponse = renewResp

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
	p.certTTL = time.Duration(60 * time.Minute)
	p.config = &VaultPluginConfig{}

	testCSR, err := ioutil.ReadFile("../../../pkg/fake/_test_data/test-req.csr")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}

	testCSRReq, err := getFakeSubmitCSRRequest(testCSR)
	if err != nil {
		t.Errorf("failed to get fake CSR: %v", err)
	}

	ctx := context.Background()
	resp, err := p.SubmitCSR(ctx, testCSRReq)
	if err != nil {
		t.Errorf("error from SubmitCSR(): %v", err)
	} else if resp == nil {
		t.Error("SubmitCSR response is empty")
	} else {
		if resp.SignedCertificate == nil {
			t.Error("SignedCertificate is empty")
		} else {
			if resp.SignedCertificate.CertChain == nil {
				t.Errorf("CertChain is empty")
			}
			if resp.SignedCertificate.Bundle == nil {
				t.Errorf("Bundle is empty")
			}
		}
	}
}

func TestSubmitCSRError(t *testing.T) {
	vc := fake.NewVaultServerConfig()

	certAuthResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/cert-auth-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}
	renewResp, err := ioutil.ReadFile("../../../pkg/fake/_test_data/renew-response.json")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}

	vc.ServerCertificatePemPath = fakeServerCert
	vc.ServerKeyPemPath = fakeServerKey
	vc.CertAuthReqEndpoint = "/v1/auth/test-auth/login"
	vc.CertAuthResponseCode = 200
	vc.CertAuthResponse = certAuthResp
	vc.SignIntermediateReqEndpoint = "/v1/test-pki/root/sign-intermediate"
	vc.SignIntermediateResponseCode = 500
	vc.RenewResponseCode = 200
	vc.RenewResponse = renewResp

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

	testCSR, err := ioutil.ReadFile("../../../pkg/fake/_test_data/test-req.csr")
	if err != nil {
		t.Errorf("failed to load fixture: %v", err)
	}

	testCSRReq, err := getFakeSubmitCSRRequest(testCSR)
	if err != nil {
		t.Errorf("failed to get fake CSR: %v", err)
	}

	ctx := context.Background()
	_, err = p.SubmitCSR(ctx, testCSRReq)
	if err == nil {
		t.Error("error is empty, want to get error")
	}
}
