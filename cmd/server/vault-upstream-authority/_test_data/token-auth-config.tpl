vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/_test_data/ca.pem"
token_auth_config {
   token  = "test-token"
}
