# maintenance test certificates

## CA Certificate

```
$ openssl genrsa -out ca.key 2048

$ openssl req -new -key ca-key.pem  -out ca.csr

$ openssl x509 -days 3650 -in ca.csr -req -signkey ca-key.pem -out ca.pem
```

## Server Certificate

```
$ openssl genrsa -out server-key.pem 2048

$ cfssl gencert -config config.json -profile server -ca ca.pem -ca-key ca-key.pem server-csr.json | cfssljson -bare server
```

## Client Certificate

```
$ openssl genrsa -out client-key.pem 2048

$ cfssl gencert -config config.json -profile client -ca ca.pem -ca-key ca-key.pem client-csr.json | cfssljson -bare client
```

## CSR/Certificate for TestRequest

```
$ openssl genrsa -out test-req.pem 2048

$ cfssl gencert -config config.json -profile client -ca ca.pem -ca-key ca-key.pem test-req-csr.json | cfssljson -bare test-req
```