#!/bin/bash
[[ $DEBUG ]] || exec >/vault.log
set -xe
set -o pipefail
echo "VAULT SERVER STARTUP"
touch /vault/config/config.hcl
chmod 777 /vault/config/config.hcl

cat <<"EOF" > /vault/config/config.hcl
ui = false
seal "gcpckms" {
  project    = "${KMS_PROJECT}"
  region     = "${KMS_LOCATION}"
  key_ring   = "${KMS_KEYRING}"
  crypto_key = "${KMS_CRYPTO_KEY}"
}
storage "gcs" {
  bucket     = "${STORAGE_BUCKET}"
  ha_enabled = false
}
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}
"plugin_directory"  = "/vault/plugins"

#"default_lease_ttl" = "168h",
#"max_lease_ttl"     = "720h",

"disable_mlock"=true
"api_addr"          = "127.0.0.1:8200"
EOF

vault server -config=/vault/config/config.hcl
