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
	defaultTLSAuthEndpoint          = "/v1/auth/cert/login"
	defaultSignIntermediateEndpoint = "/v1/pki/root/sign-intermediate"

	listenAddr = "127.0.0.1:0"
)

type VaultServerConfig struct {
	ListenAddr                   string
	ServerCertificatePemPath     string
	ServerKeyPemPath             string
	TLSAuthReqEndpoint           string
	TLSAuthReqHandler            func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	TLSAuthResponseCode          int
	TLSAuthResponse              []byte
	SignIntermediateReqEndpoint  string
	SignIntermediateReqHandler   func(code int, resp []byte) func(http.ResponseWriter, *http.Request)
	SignIntermediateResponseCode int
	SignIntermediateResponse     []byte
}

// NewVaultServerConfig returns VaultServerConfig with default values
func NewVaultServerConfig() *VaultServerConfig {
	return &VaultServerConfig{
		ListenAddr:                  listenAddr,
		TLSAuthReqEndpoint:          defaultTLSAuthEndpoint,
		TLSAuthReqHandler:           defaultReqHandler,
		SignIntermediateReqEndpoint: defaultSignIntermediateEndpoint,
		SignIntermediateReqHandler:  defaultReqHandler,
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
	mux.HandleFunc(v.TLSAuthReqEndpoint, v.TLSAuthReqHandler(v.TLSAuthResponseCode, v.TLSAuthResponse))
	mux.HandleFunc(v.SignIntermediateReqEndpoint, v.SignIntermediateReqHandler(v.SignIntermediateResponseCode, v.SignIntermediateResponse))

	srv = httptest.NewUnstartedServer(mux)
	srv.Listener = l
	return srv, l.Addr().String(), nil
}
