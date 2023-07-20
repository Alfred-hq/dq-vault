#!/bin/bash
[ $DEBUG ] || exec >/vault.log
set -xe
#set -o pipefail
echo "VAULT SERVER STARTUP"
mkdir -p /vault/config
touch /vault/config/config.hcl
chmod 777 /vault/config/config.hcl
echo "${KMS_PROJECT}"
echo "${KMS_LOCATION}"
echo "${KMS_KEYRING}"

cat <<EOF > /vault/config/config.hcl
ui = false
seal "gcpckms" {
  project    = __KMS_PROJECT
  region     = __KMS_LOCATION
  key_ring   = __KMS_KEYRING
  crypto_key = __KMS_CRYPTO_KEY
}
storage "gcs" {
  bucket     = __STORAGE_BUCKET
  ha_enabled = false
}


listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}
plugin_directory  = "/vault/plugins"

default_lease_ttl = "168h",
max_lease_ttl     = "720h",

disable_mlock=true
api_addr          = "http://127.0.0.1:8200"
EOF
sed -i 's/__KMS_PROJECT/'"${KMS_PROJECT}"'/g' /vault/config/config.hcl
sed -i 's/__KMS_LOCATION/'"${KMS_LOCATION}"'/g' /vault/config/config.hcl
sed -i 's/__KMS_KEYRING/'"${KMS_KEYRING}"'/g' /vault/config/config.hcl
sed -i 's/__KMS_CRYPTO_KEY/'"${KMS_CRYPTO_KEY}"'/g' /vault/config/config.hcl
sed -i 's/__STORAGE_BUCKET/'"${STORAGE_BUCKET}"'/g' /vault/config/config.hcl
echo $(cat /vault/config/config.hcl)
vault server -config=/vault/config/config.hcl
