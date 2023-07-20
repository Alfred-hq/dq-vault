# Stage 1 (to create a "build" image)
FROM golang:1.20 AS source

RUN curl https://glide.sh/get | sh

COPY . /go/src/github.com/deqode/dq-vault/
WORKDIR /go/src/github.com/deqode/dq-vault/

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build

# Stage 2 (to create a vault conatiner with executable)
FROM debian:10
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    lsb-release \
    unzip \
    perl

# Download and install Vault 1.13.1
RUN curl -fsSL https://releases.hashicorp.com/vault/1.13.1/vault_1.13.1_linux_amd64.zip -o vault.zip \
    && unzip vault.zip \
    && mv vault /usr/local/bin/ \
    && rm vault.zip


# Set up the Google Cloud SDK package repository
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
    tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | \
    apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

# Install the Google Cloud SDK
RUN apt-get update && apt-get install -y google-cloud-sdk

# Set up the Docker client to connect to the Docker daemon on the host system
# Mount the Docker socket from the host system into the container (Be cautious with this step!)

RUN apt-get update && apt-get install -y supervisor
RUN mkdir -p /etc/supervisor/conf.d
# Make new directory for plugins
RUN mkdir -p /vault/plugins
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