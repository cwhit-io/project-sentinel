# Bind this policy only to narrowly scoped application identities.
path "secret/data/monitoring/*" {
  capabilities = ["read"]
}

path "secret/metadata/monitoring/*" {
  capabilities = ["read", "list"]
}
