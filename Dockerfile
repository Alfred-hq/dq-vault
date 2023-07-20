# Stage 1 (to create a "build" image)
FROM golang:1.20 AS source

RUN curl https://glide.sh/get | sh

COPY . /go/src/github.com/deqode/dq-vault/
WORKDIR /go/src/github.com/deqode/dq-vault/

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build

# Stage 2 (to create a vault conatiner with executable)
FROM vault:1.13.3
RUN apk add perl-utils
RUN apk add nano
RUN apk add --update supervisor
RUN mkdir -p /etc/supervisor/conf.d
# Make new directory for plugins
RUN mkdir /vault/plugins
COPY vault_config.sh /vault/vault_config.sh
COPY vault_startup.sh /vault/vault_startup.sh
RUN chmod +x /vault/vault_config.sh
RUN chmod +x /vault/vault_startup.sh
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ENV ROOT_TOKEN_KEY "dummy"
ENV KMS_PROJECT "dummy"
ENV KMS_LOCATION "dummy"
ENV KMS_KEYRING "dummy"
ENV KMS_CRYPTO_KEY "dummy"
ENV VAULT_BUCKET "dummy"




#RUN apk --no-cache add ca-certificates wget make
#RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
#RUN wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.28-r0/glibc-2.28-r0.apk
#RUN apk add glibc-2.28-r0.apk


# Copy executable from source to vault
COPY --from=source /go/src/github.com/deqode/dq-vault/dq-vault /vault/plugins/vault_plugin
#COPY ./Makefile .
#
#
## TODO: add make run
#CMD ["make", "run"]

CMD /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf