ui = false
api_addr = "https://openbao:8200"
cluster_addr = "https://openbao:8201"

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/openbao/tls/server.crt"
  tls_key_file    = "/openbao/tls/server.key"
  tls_client_ca_file = "/openbao/tls/ca.crt"
  tls_min_version = "tls13"
}

storage "file" {
  path = "/openbao/data"
}

telemetry {
  disable_hostname = true
}
