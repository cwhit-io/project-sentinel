# Bind this policy only to narrowly scoped application identities. Do not use
# this policy for operators or bootstrap/recovery actions.
path "secret/data/monitoring/*" {
  capabilities = ["read"]
}

path "secret/metadata/monitoring/*" {
  capabilities = ["read", "list"]
}
