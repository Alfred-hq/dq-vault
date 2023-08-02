#!/bin/bash
[ $DEBUG ] || exec >/vault.log
set -xe
#set -o pipefail
echo "VAULT SERVER STARTUP"
mkdir -p /vault/config_
touch /vault/config_/config.hcl
chmod 777 /vault/config_/config.hcl

cat <<EOF > /vault/config_/config.hcl
ui = true
seal "gcpckms" {
  project    = "__KMS_PROJECT"
  region     = "__KMS_LOCATION"
  key_ring   = "__KMS_KEYRING"
  crypto_key = "__KMS_CRYPTO_KEY"
}
storage "gcs" {
  bucket     = "__STORAGE_BUCKET"
  ha_enabled = false
}



listener "tcp" {
  address     = "0.0.0.0:8080"
  tls_disable = 1
}
plugin_directory  = "/vault/plugins"

#default_lease_ttl = "168h",
#max_lease_ttl     = "720h",

disable_mlock=true
api_addr          = "http://127.0.0.1:8080"
EOF
sed -i 's/__KMS_PROJECT/'"${KMS_PROJECT}"'/g' /vault/config_/config.hcl
sed -i 's/__KMS_LOCATION/'"${KMS_LOCATION}"'/g' /vault/config_/config.hcl
sed -i 's/__KMS_KEYRING/'"${KMS_KEYRING}"'/g' /vault/config_/config.hcl
sed -i 's/__KMS_CRYPTO_KEY/'"${KMS_CRYPTO_KEY}"'/g' /vault/config_/config.hcl
sed -i 's/__STORAGE_BUCKET/'"${STORAGE_BUCKET}"'/g' /vault/config_/config.hcl
vault server -config=/vault/config_/config.hcl
