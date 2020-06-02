vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/_test_data/ca.pem"
ttl = "1h"
approle_auth_config {
   approle_auth_mount_point = "test-auth"
   approle_id = "test-approle-id"
   approle_secret_id  = "test-approle-secret-id"
}
