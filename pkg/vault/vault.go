/**
 * Copyright 2019, Z Lab Corporation. All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

package vault

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"

	"github.com/hashicorp/go-hclog"
	vapi "github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
	"github.com/spiffe/spire/pkg/common/pemutil"
)

const (
	envVaultAddr            = "VAULT_ADDR"
	envVaultToken           = "VAULT_TOKEN"
	envVaultClientCert      = "VAULT_CLIENT_CERT"
	envVaultClientKey       = "VAULT_CLIENT_KEY"
	envVaultCACert          = "VAULT_CACERT"
	envVaultAppRoleID       = "VAULT_APPROLE_ID"
	envVaultAppRoleSecretID = "VAULT_APPROLE_SECRET_ID"

	DefaultCertMountPoint    = "cert"
	DefaultPKIMountPoint     = "pki"
	DefaultAppRoleMountPoint = "approle"
)

type AuthMethod int

const (
	_ AuthMethod = iota
	CERT
	TOKEN
	APPROLE
)

// Config represents configuration parameters for vault client
type Config struct {
	Logger hclog.Logger
	// Name of method to use authenticate to vault. value must be upper case.
	method AuthMethod
	// vault client parameters
	clientParams *ClientParams
}

type ClientParams struct {
	// A URL of Vault server. (e.g., https://vault.example.com:8443/)
	VaultAddr string
	// Name of mount point where PKI secret engine is mounted. (e.e., /<mount_point>/ca/pem )
	PKIMountPoint string
	// token string to use when auth method is 'token'
	Token string
	// Name of mount point where TLS auth method is mounted. (e.g., /auth/<mount_point>/login )
	TLSAuthMountPoint string
	// Path to a client certificate file to be used when auth method is 'cert'
	ClientCertPath string
	// Path to a client private key file to be used when auth method is 'cert'
	ClientKeyPath string
	// Path to a CA certificate file to be used when client verifies a server certificate
	CACertPath string
	// Name of mount point where AppRole auth method is mounted. (e.g., /auth/<mount_point>/login )
	AppRoleAuthMountPoint string
	// An identifier of AppRole
	AppRoleID string
	// A credential set of AppRole
	AppRoleSecretID string
	// If true, client accepts any certificates.
	// It should be used only test environment so on.
	TLSSKipVerify bool
	// MaxRetries controls the number of times to retry to connect
	// Set to 0 to disable retrying.
	// If the value is nil, to use the default in hashicorp/vault/api.
	MaxRetries *int
}

type Client struct {
	vaultClient  *vapi.Client
	clientParams *ClientParams
}

// SignCSRResponse includes certificates which are generates by Vault
type SignCSRResponse struct {
	// A certificate requested to sign
	CertPEM string
	// A certificate of CA(Vault)
	CACertPEM string
	// Set of Upstream CA certificates
	CACertChainPEM []string
}

// New returns a new *Config with default parameters.
func New(authMethod AuthMethod) *Config {
	return &Config{
		Logger: hclog.New(hclog.DefaultOptions),
		method: authMethod,
		clientParams: &ClientParams{
			TLSAuthMountPoint:     DefaultCertMountPoint,
			AppRoleAuthMountPoint: DefaultAppRoleMountPoint,
			PKIMountPoint:         DefaultPKIMountPoint,
		},
	}
}

// WithEnvVar set parameters with environment variables
func (c *Config) WithEnvVar() *Config {
	if c.clientParams == nil {
		c.clientParams = &ClientParams{}
	}
	c.clientParams.VaultAddr = os.Getenv(envVaultAddr)
	c.clientParams.CACertPath = os.Getenv(envVaultCACert)
	c.clientParams.Token = os.Getenv(envVaultToken)
	c.clientParams.ClientCertPath = os.Getenv(envVaultClientCert)
	c.clientParams.ClientKeyPath = os.Getenv(envVaultClientKey)
	c.clientParams.AppRoleID = os.Getenv(envVaultAppRoleID)
	c.clientParams.AppRoleSecretID = os.Getenv(envVaultAppRoleSecretID)
	return c
}

// SetClientParams merges given p into c.clientParam
func (c *Config) SetClientParams(p *ClientParams) error {
	if c.clientParams == nil {
		c.clientParams = &ClientParams{}
	}
	if err := mergo.Merge(p, c.clientParams); err != nil {
		return err
	}
	c.clientParams = p
	return nil
}

// NewAuthenticatedClient returns a new authenticated vault client
func (c *Config) NewAuthenticatedClient() (*Client, error) {
	config := vapi.DefaultConfig()
	config.Address = c.clientParams.VaultAddr

	if c.clientParams.MaxRetries != nil {
		config.MaxRetries = *c.clientParams.MaxRetries
	}

	if err := c.ConfigureTLS(config); err != nil {
		return nil, err
	}
	vc, err := vapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	client := &Client{
		vaultClient:  vc,
		clientParams: c.clientParams,
	}

	switch c.method {
	case TOKEN:
		client.SetToken(c.clientParams.Token)
	case CERT:
		path := fmt.Sprintf("auth/%v/login", c.clientParams.TLSAuthMountPoint)
		sec, err := client.Auth(path, map[string]interface{}{})
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, errors.New("tls cert authentication response is nil")
		}
		if sec.Auth.Renewable {
			c.Logger.Debug("token will be renewed")
			if err := renewToken(vc, sec, c.Logger); err != nil {
				return nil, err
			}
		} else {
			c.Logger.Debug("token never renew")
		}
	case APPROLE:
		path := fmt.Sprintf("auth/%v/login", c.clientParams.AppRoleAuthMountPoint)
		body := map[string]interface{}{
			"role_id":   c.clientParams.AppRoleID,
			"secret_id": c.clientParams.AppRoleSecretID,
		}
		sec, err := client.Auth(path, body)
		if err != nil {
			return nil, err
		}
		if sec == nil {
			return nil, errors.New("approle authentication response is nil")
		}
		if sec.Auth.Renewable {
			c.Logger.Debug("token will be renewed")
			if err := renewToken(vc, sec, c.Logger); err != nil {
				return nil, err
			}
		} else {
			c.Logger.Debug("token never renew")
		}
	}

	return client, nil
}

func renewToken(vc *vapi.Client, sec *vapi.Secret, logger hclog.Logger) error {
	renew, err := NewRenew(vc, sec)
	if err != nil {
		return err
	}
	renew.Logger = logger
	go renew.Run()
	return nil
}

// ConfigureTLS Configures TLS for Vault Client
func (c *Config) ConfigureTLS(vc *vapi.Config) error {
	if vc.HttpClient == nil {
		vc.HttpClient = vapi.DefaultConfig().HttpClient
	}
	clientTLSConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig

	var clientCert tls.Certificate
	foundClientCert := false

	switch {
	case c.method == TOKEN:
	case c.clientParams.ClientCertPath != "" && c.clientParams.ClientKeyPath != "":
		keyObj, err := pemutil.LoadPrivateKey(c.clientParams.ClientKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load client private-key: %v", err)
		}
		Key, err := pemutil.EncodePKCS8PrivateKey(keyObj)
		if err != nil {
			return fmt.Errorf("failed to encode client private-key: %v", err)
		}

		certObj, err := pemutil.LoadCertificate(c.clientParams.ClientCertPath)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %v", err)
		}
		cert := pemutil.EncodeCertificate(certObj)

		c, err := tls.X509KeyPair(cert, Key)
		if err != nil {
			return fmt.Errorf("failed to parse client cert and private-key: %v", err)
		}
		clientCert = c
		foundClientCert = true
	case c.clientParams.ClientCertPath != "" || c.clientParams.ClientKeyPath != "":
		return fmt.Errorf("client cert and client key is required")
	}

	if c.clientParams.CACertPath != "" {
		certs, err := pemutil.LoadCertificates(c.clientParams.CACertPath)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate: %v", err)
		}
		pool := x509.NewCertPool()
		for i := range certs {
			cert := certs[i]
			pool.AddCert(cert)
		}
		clientTLSConfig.RootCAs = pool
	}

	if c.clientParams.TLSSKipVerify {
		clientTLSConfig.InsecureSkipVerify = true
	}

	if foundClientCert {
		clientTLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	return nil
}

// SetToken wraps vapi.Client.SetToken()
func (c *Client) SetToken(v string) {
	c.vaultClient.SetToken(v)
}

// TLSAuth authenticates to vault server with TLS certificate method
func (c *Client) Auth(path string, body map[string]interface{}) (*vapi.Secret, error) {
	c.vaultClient.ClearToken()
	secret, err := c.vaultClient.Logical().Write(path, body)
	if err != nil {
		return nil, fmt.Errorf("authentication failed %v: %v", path, err)
	}

	tokenId, err := secret.TokenID()
	if err != nil {
		return nil, fmt.Errorf("authentication is successful, but could not get token: %v", err)
	}
	c.vaultClient.SetToken(tokenId)
	return secret, nil
}

// SignIntermediate requests sign-intermediate endpoint to generate certificate.
// ttl = Issue Intermediate CA Certificate by given TTL
// csr = PEM format CSR
// see: https://www.vaultproject.io/api/secret/pki/index.html#sign-intermediate
func (c *Client) SignIntermediate(ttl string, csr []byte) (*SignCSRResponse, error) {
	csrObj, err := pemutil.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR PEM data: %v", err)
	}

	reqData := map[string]interface{}{
		"common_name":  csrObj.Subject.CommonName,
		"organization": strings.Join(csrObj.Subject.Organization, ","),
		"country":      strings.Join(csrObj.Subject.Country, ","),
		"csr":          string(csr),
		"ttl":          ttl,
	}

	path := fmt.Sprintf("/%s/root/sign-intermediate", c.clientParams.PKIMountPoint)
	s, err := c.vaultClient.Logical().Write(path, reqData)
	if err != nil {
		return nil, err
	}

	resp := &SignCSRResponse{}

	if certData, ok := s.Data["certificate"]; !ok {
		return nil, errors.New("request is successful, but certificate data is empty")
	} else {
		if cert, ok := certData.(string); !ok {
			return nil, errors.New("failed to type conversion for certificate")
		} else {
			resp.CertPEM = cert
		}
	}

	if caCertData, ok := s.Data["issuing_ca"]; !ok {
		return nil, errors.New("request is successful, but issuing_ca data is empty")
	} else {
		if caCert, ok := caCertData.(string); !ok {
			return nil, errors.New("failed to type conversion for issuing_ca")
		} else {
			resp.CACertPEM = caCert
		}
	}

	if caChainData, ok := s.Data["ca_chain"]; !ok {
		// empty is general use case when Vault is Root CA.
	} else {
		if caChainCertObj, ok := caChainData.([]interface{}); !ok {
			return nil, fmt.Errorf("failed to type conversion for ca_chain, %v", reflect.TypeOf(caChainData))
		} else {
			var caChainCert []string
			for i := range caChainCertObj {
				caChainCert = append(caChainCert, caChainCertObj[i].(string))
			}
			resp.CACertChainPEM = caChainCert
		}
	}

	return resp, nil
}
