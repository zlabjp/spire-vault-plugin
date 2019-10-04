vault_addr  = "https://localhost"
pki_mount_point = "test-pki"
ca_cert_path = "../../../pkg/fake/fixtures/ca.pem"
ttl = "600"
cert_auth_config {
   client_cert_path = "../../../pkg/fake/fixtures/client.pem"
   client_key_path  = "../../../pkg/fake/fixtures/client-key.pem"
}
