vault_addr  = "{{ .Addr }}"
auth_method = "cert"
tls_auth_mount_point = "test-auth"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/fixtures/ca.pem"
cert_auth_config {
   client_cert_path = "../../../pkg/fake/fixtures/client.pem"
   client_key_path  = "../../../pkg/fake/fixtures/client-key.pem"
}
