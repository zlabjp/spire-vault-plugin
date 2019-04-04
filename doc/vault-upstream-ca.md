#  Upstream CA "vault" Plugin
The vault plugin requests to sign intermediate certificate to Vault PKI Engine as the Upstream CA. The Spire Server generates SVID as intermediate CA.

## Configuration

The plugin accepts the following configuration options:

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| auth_method | string | ✓ | The method used for authentication to Vault. ("token", "cert") | |
| vault_addr  | string |   | A URL of Vault server. (e.g., https://vault.example.com:8443/) | `${VAULT_ADDR}` |
| auth_mount_point | string |  | Name of mount point where TLS auth method is mounted | cert |
| pki_mount_point  | string |  | Name of mount point where PKI secret engine is mounted | pki |
| ca_cert_path     | string |  | Path to a CA certificate file that the client verifies the server certificate. PEM and DER is supported. | `${VAULT_CACERT}` |
| ttl              | string |  | Request to issue a certificate with the specified TTL (Go-Style time duration value e.g., 1h)  | |
| tls_skip_verify  | string |  | If true, vault client accepts any server certificates | false |
| cert_auth_config | struct |  | Configuration parameters to use when auth method is "cert" | |
| token_auth_config | struct | | Configuration parameters to use when auth method is "token" | |

The Plugin now supports only **cert** and **token** auth method.
**cert** method authenticates to Vault using the TLS client certificate, **token** method authenticates to Vault using the token in the HTTP Request header.

**cert_auth_config**

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| client_cert_path | string | | Path to a client certificate file. PEM and DER is supported. | `${VAULT_CLIENT_CERT}` |
| client_key_path  | string | | Path to a client private key file PEM and DER is supported. | `${VAULT_CLIENT_KEY}` |

**token_auth_config**

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| token | string | | Token string to set into "X-Vault-Token" header | `${VAULT_TOKEN}` |

```hcl
    UpstreamCA "vault" {
        plugin_cmd = "vault-upstream-ca binary"
        plugin_checksum = "(SHOULD) sha256 of the plugin binary"
        plugin_data {
            vault_addr = "https://vault.example.org/"
            auth_method = "cert"
            tls_auth_mount_point = "test-tls-auth"
            pki_mount_point = "test-pki"
            ca_cert_path = "/path/to/ca-cert.pem"
            cert_auth_config {
                client_cert_path = "/path/to/client-cert.pem"
                client_key_path  = "/path/to/client-key.pem"
            }
        }
    }
```

```hcl
    UpstreamCA "vault" {
        plugin_cmd = "vault-upstream-ca binary"
        plugin_checksum = "(SHOULD) sha256 of the plugin binary"
        plugin_data {
            vault_addr = "https://vault.example.org/"
            auth_method = "token"
            pki_mount_point = "test-pki"
            ca_cert_path = "/path/to/ca-cert.pem"
            token_auth_config {
               token = "<token>" // or specified by environment variables
            }
        }
    }
```