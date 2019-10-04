vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/fixtures/ca.pem"
ttl = "1h"
cert_auth_config {
   tls_auth_mount_point = "test-auth"
   client_cert_path = "../../../pkg/fake/fixtures/client.pem"
   client_key_path  = "../../../pkg/fake/fixtures/client-key.pem"
}
