/**
 * Copyright 2020, Z Lab Corporation. All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	upi "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamauthority"

	"github.com/zlabjp/spire-vault-plugin/pkg/common"
	"github.com/zlabjp/spire-vault-plugin/pkg/vault"
)

type VaultPluginConfig struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string `hcl:"vault_addr"`
	// Name of mount point where PKI secret engine is mounted. (e.g., /<mount_point>/ca/pem)
	PKIMountPoint string `hcl:"pki_mount_point"`
	// Configuration parameters to use token auth method
	TokenAuthConfig VaultTokenAuthConfig `hcl:"token_auth_config"`
	// Configuration parameters to use TLS certificate auth method
	CertAuthConfig VaultCertAuthConfig `hcl:"cert_auth_config"`
	// Configuration parameters to use AppRole auth method
	AppRoleAuthConfig VaultAppRoleAuthConfig `hcl:"approle_auth_config"`
	// Path to a CA certificate file that the client verifies the server certificate.
	// Only PEM format is supported.
	CACertPath string `hcl:"ca_cert_path"`
	// (Deprecated) Request to issue a certificate with the specified TTL (Go-style time duration)
	TTL string `hcl:"ttl"`
	// If true, vault client accepts any server certificates.
	// It should be used only test environment so on.
	TLSSkipVerify bool `hcl:"tls_skip_verify"`
}

// VaultTokenAuthConfig represents parameters for token auth method
type VaultTokenAuthConfig struct {
	// Token string to set into "X-Vault-Token" header
	Token string `hcl:"token"`
}

// VaultCertAuthConfig represents parameters for cert auth method
type VaultCertAuthConfig struct {
	// (Deprecated) Name of mount point where TLS auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/cert)
	TLSAuthMountPoint string `hcl:"tls_auth_mount_point"`
	// Name of mount point where TLS Cert auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/cert)
	CertAuthMountPoint string `hcl:"cert_auth_mount_point"`
	// Path to a client certificate file.
	// Only PEM format is supported.
	ClientCertPath string `hcl:"client_cert_path"`
	// Path to a client private key file.
	// Only PEM format is supported.
	ClientKeyPath string `hcl:"client_key_path"`
}

// VaultAppRoleAuthConfig represents parameters for AppRole auth method.
type VaultAppRoleAuthConfig struct {
	// Name of mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login)
	// If the value is empty, use default mount point (/auth/approle)
	AppRoleMountPoint string `hcl:"approle_auth_mount_point"`
	// An identifier that selects the AppRole
	RoleID string `hcl:"approle_id"`
	// A credential that is required for login.
	SecretID string `hcl:"approle_secret_id"`
}

type VaultPlugin struct {
	mtx     *sync.RWMutex
	logger  hclog.Logger
	vc      *vault.Client
	certTTL time.Duration
}

// BuiltIn constructs a catalog Plugin using a new instance of this plugin.
func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *VaultPlugin) catalog.Plugin {
	return catalog.MakePlugin(common.PluginName, upi.PluginServer(p))
}

func New() *VaultPlugin {
	return &VaultPlugin{
		mtx: &sync.RWMutex{},
	}
}

func (p *VaultPlugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *VaultPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := new(VaultPluginConfig)
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration file: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	var (
		ttl time.Duration
		err error
	)

	if config.TTL != "" {
		p.logger.Warn("the configuration value 'ttl' is deprecated. " +
			"When unset, the plugin will use the preferred TTL from SPIRE server, " +
			"corresponding to the SPIRE server ca_ttl configurable")
		ttl, err = time.ParseDuration(config.TTL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TTL value: %v", err)
		}
	}

	certAuthMountPoint := config.CertAuthConfig.CertAuthMountPoint
	if config.CertAuthConfig.TLSAuthMountPoint != "" {
		p.logger.Warn("'tls_auth_mount_point' is deprecated, so use 'cert_auth_mount_point' instead.")
		certAuthMountPoint = config.CertAuthConfig.TLSAuthMountPoint
	}

	am, err := parseAuthMethod(config)
	if err != nil {
		return nil, err
	}

	vaultConfig := vault.New(am).WithEnvVar()
	vaultConfig.Logger = p.logger
	cp := &vault.ClientParams{
		VaultAddr:             config.VaultAddr,
		CACertPath:            config.CACertPath,
		Token:                 config.TokenAuthConfig.Token,
		PKIMountPoint:         config.PKIMountPoint,
		CertAuthMountPoint:    certAuthMountPoint,
		ClientKeyPath:         config.CertAuthConfig.ClientKeyPath,
		ClientCertPath:        config.CertAuthConfig.ClientCertPath,
		AppRoleAuthMountPoint: config.AppRoleAuthConfig.AppRoleMountPoint,
		AppRoleID:             config.AppRoleAuthConfig.RoleID,
		AppRoleSecretID:       config.AppRoleAuthConfig.SecretID,
		TLSSKipVerify:         config.TLSSkipVerify,
	}
	if err := vaultConfig.SetClientParams(cp); err != nil {
		return nil, fmt.Errorf("failetd to prepare vault client")
	}

	vc, err := vaultConfig.NewAuthenticatedClient()
	if err != nil {
		return nil, fmt.Errorf("failed to prepare vault authentication: %v", err)
	}

	p.vc = vc
	p.certTTL = ttl

	return &spi.ConfigureResponse{}, nil
}

func (p *VaultPlugin) MintX509CA(req *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	certReq := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.Csr}
	pemData := pem.EncodeToMemory(certReq)

	var ttl string
	if p.certTTL != time.Duration(0) {
		ttl = fmt.Sprintf("%d", int64(p.certTTL/time.Second))
	} else {
		ttl = strconv.Itoa(int(req.PreferredTtl))
	}

	signResp, err := p.vc.SignIntermediate(ttl, pemData)
	if err != nil {
		return fmt.Errorf("MintX509CA request is failed: %v", err)
	}
	if signResp == nil {
		return errors.New("MintX509CA response is empty")
	}

	// Parse PEM format data to get DER format data
	certificate, err := pemutil.ParseCertificate([]byte(signResp.CertPEM))
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}
	certChain := [][]byte{certificate.Raw}

	caCert, err := pemutil.ParseCertificate([]byte(signResp.CACertPEM))
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}
	bundles := [][]byte{caCert.Raw}

	for i := range signResp.CACertChainPEM {
		c := signResp.CACertChainPEM[i]
		if c == signResp.CACertPEM {
			continue
		}

		b, err := pemutil.ParseCertificate([]byte(c))
		if err != nil {
			return fmt.Errorf("failed to parse upstream bundle certificates: %v", err)
		}
		bundles = append(bundles, b.Raw)
	}

	return stream.Send(&upstreamauthority.MintX509CAResponse{
		X509CaChain:       certChain,
		UpstreamX509Roots: bundles,
	})
}

func (*VaultPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (*VaultPlugin) PublishJWTKey(*upstreamauthority.PublishJWTKeyRequest, upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	return makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "vault: "+format, args...)
}

func parseAuthMethod(config *VaultPluginConfig) (vault.AuthMethod, error) {
	if config.TokenAuthConfig.Token != "" {
		return vault.TOKEN, nil
	}
	if config.CertAuthConfig.ClientCertPath != "" {
		return vault.CERT, nil
	}
	if config.AppRoleAuthConfig.RoleID != "" {
		return vault.APPROLE, nil
	}

	return 0, errors.New("must be configured one of these authentication method 'Token or Cert or AppRole'")
}

func main() {
	catalog.PluginMain(BuiltIn())
}
