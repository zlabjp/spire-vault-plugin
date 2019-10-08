vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/fixtures/ca.pem"
ttl = "1h"
token_auth_config {
   token  = "{{ .Token }}"
}
