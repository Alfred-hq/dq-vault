#!/bin/bash
[ $DEBUG ] || exec >/vault.log
set -xe
#set -o pipefail
echo "STARTUP SCRIPT STARTED"
echo ${ROOT_TOKEN_KEY}
export VAULT_ADDR="http://127.0.0.1:8080"
export SHA256=$(shasum -a 256 "/vault/plugins/vault_plugin" | cut -d' ' -f1)
root_token="THIS_IS_DUMMY"
export VAULT_CLIENT_TIMEOUT=300s
if [ $(vault status | grep 'Initialized'| awk '{print $NF}') = "false" ]
then
#        root_token=$(vault operator init | grep 'Initial Root Token:' | awk '{print $NF}')
        output=$(vault operator init)
        echo "Vault operator init output:"
        root_token=$(echo "$output" | grep 'Initial Root Token:' | awk '{print $NF}')
        touch /vault/token.txt
        touch chmod 777 /vault/token.txt
        echo $root_token >> /vault/token.txt
        gcloud secrets versions add ${ROOT_TOKEN_KEY} --data-file=/vault/token.txt --project=${PROJECT_ID}
        sleep 30
fi
if [ $(vault status | grep 'Initialized'| awk '{print $NF}') = "true" ]
then
        vault login ${ROOT_TOKEN}
        vault secrets disable /api
        vault write sys/plugins/catalog/secrets-api sha_256=$SHA256 command="vault_plugin"
        vault secrets enable -path="api" -plugin-name="secrets-api" plugin
        vault policy write application /vault/policy/policy.hcl
        vault plugin register -sha256=$SHA256 -command="vault_plugin" -version=1 secret secrets-api
        vault plugin reload -plugin secrets-api
        vault secrets tune -plugin-version=1 api
else
        error "Vault is not initalized"
fi



## get root token from secret in root token

socat TCP-LISTEN:8200,fork TCP:localhost:8080
# now vault will listen on port 8200

