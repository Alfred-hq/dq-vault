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
root_token=$(gcloud secrets versions access latest --secret=${ROOT_TOKEN_KEY} --project=${PROJECT_ID})
if [ $(vault status | grep 'Initialized'| awk '{print $NF}') = "true" ]
then
        vault login $root_token
        vault secrets disable /api
        vault write sys/plugins/catalog/secrets-api sha_256=$SHA256 command="vault_plugin"
        vault secrets enable -path="api" -plugin-name="secrets-api" plugin
else
        error "Vault is not initalized"
fi



## get root token from secret in root token
vault login $root_token
vault plugin register -sha256=$SHA256 -command="vault_plugin" -version=1 secret secrets-api
vault secrets tune -plugin-version=1 api
vault plugin reload -plugin secrets-api

