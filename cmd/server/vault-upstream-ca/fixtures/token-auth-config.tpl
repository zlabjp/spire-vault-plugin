vault_addr  = "{{ .Addr }}"
auth_method = "token"
tls_auth_mount_point = "test-auth"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/fixtures/ca.pem"
token_auth_config {
   token  = "{{ .Token }}"
}
