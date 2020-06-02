/**
 * Copyright 2019, Z Lab Corporation. All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package fake

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
)

const (
	defaultCertAuthEndpoint         = "/v1/auth/cert/login"
	defaultAppRoleAuthEndpoint      = "/v1/auth/approle/login"
	defaultSignIntermediateEndpoint = "/v1/pki/root/sign-intermediate"
	defaultRenewEndpoint            = "/v1/auth/token/renew-self"

	listenAddr = "127.0.0.1:0"
)

type VaultServerConfig struct {
	ListenAddr                   string
	ServerCertificatePemPath     string
	ServerKeyPemPath             string
	CertAuthReqEndpoint          string
	CertAuthReqHandler           func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	CertAuthResponseCode         int
	CertAuthResponse             []byte
	AppRoleAuthReqEndpoint       string
	AppRoleAuthReqHandler        func(code int, resp []byte) func(w http.ResponseWriter, r *http.Request)
	AppRoleAuthResponseCode      int
	AppRoleAuthResponse          []byte
	SignIntermediateReqEndpoint  string
	SignIntermediateReqHandler   func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	SignIntermediateResponseCode int
	SignIntermediateResponse     []byte
	RenewReqEndpoint             string
	RenewReqHandler              func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	RenewResponseCode            int
	RenewResponse                []byte
}

// NewVaultServerConfig returns VaultServerConfig with default values
func NewVaultServerConfig() *VaultServerConfig {
	return &VaultServerConfig{
		ListenAddr:                  listenAddr,
		CertAuthReqEndpoint:         defaultCertAuthEndpoint,
		CertAuthReqHandler:          defaultReqHandler,
		AppRoleAuthReqEndpoint:      defaultAppRoleAuthEndpoint,
		AppRoleAuthReqHandler:       defaultReqHandler,
		SignIntermediateReqEndpoint: defaultSignIntermediateEndpoint,
		SignIntermediateReqHandler:  defaultReqHandler,
		RenewReqEndpoint:            defaultRenewEndpoint,
		RenewReqHandler:             defaultReqHandler,
	}
}

func defaultReqHandler(code int, resp []byte) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		fmt.Fprintf(w, string(resp))
	}
}

func (v *VaultServerConfig) NewTLSServer() (srv *httptest.Server, addr string, err error) {
	cert, err := tls.LoadX509KeyPair(v.ServerCertificatePemPath, v.ServerKeyPemPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load key-pair: %v", err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	l, err := tls.Listen("tcp", v.ListenAddr, config)
	if err != nil {
		return nil, "", fmt.Errorf("failed to listen test server: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(v.CertAuthReqEndpoint, v.CertAuthReqHandler(v.CertAuthResponseCode, v.CertAuthResponse))
	mux.HandleFunc(v.AppRoleAuthReqEndpoint, v.AppRoleAuthReqHandler(v.AppRoleAuthResponseCode, v.AppRoleAuthResponse))
	mux.HandleFunc(v.SignIntermediateReqEndpoint, v.SignIntermediateReqHandler(v.SignIntermediateResponseCode, v.SignIntermediateResponse))
	mux.HandleFunc(v.RenewReqEndpoint, v.RenewReqHandler(v.RenewResponseCode, v.RenewResponse))

	srv = httptest.NewUnstartedServer(mux)
	srv.Listener = l
	return srv, l.Addr().String(), nil
}
