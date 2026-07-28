ui = false
disable_mlock = true
api_addr = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/openbao/tls/server.crt"
  tls_key_file    = "/openbao/tls/server.key"
  tls_min_version = "tls13"
}

storage "file" {
  path = "/openbao/data"
}

telemetry {
  disable_hostname = true
}
