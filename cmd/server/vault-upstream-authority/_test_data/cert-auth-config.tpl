vault_addr  = "{{ .Addr }}"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/_test_data/ca.pem"
cert_auth_config {
   tls_auth_mount_point = "test-auth"
   client_cert_path = "../../../pkg/fake/_test_data/client.pem"
   client_key_path  = "../../../pkg/fake/_test_data/client-key.pem"
}
