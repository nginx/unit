FROM rust:slim-bullseye

ADD https://unit.nginx.org/keys/nginx-keyring.gpg \
    /usr/share/keyrings/nginx-keyring.gpg

RUN set -eux \
    export DEBIAN_FRONTEND=noninteractive; \
    echo 'fc27fd284cceb4bf6c8ac2118dbb5e834590836f8d6ba3944da0e0451cbadeca  /usr/share/keyrings/nginx-keyring.gpg' |\
    sha256sum --check -; \
    chmod 0644 /usr/share/keyrings/nginx-keyring.gpg; \
    echo "deb [signed-by=/usr/share/keyrings/nginx-keyring.gpg] https://packages.nginx.org/unit/debian/ bullseye unit" > /etc/apt/sources.list.d/unit.list; \
    apt-get -qq update; \
    apt-get -qq upgrade --yes; \
    apt-get -qq install --yes --no-install-recommends --no-install-suggests \
        bsdmainutils \
        ca-certificates \
        git \
        gzip \
        grep \
        gawk \
        sed \
        make \
        rpm \
        pkg-config \
        libssl-dev \
        dpkg-dev \
        musl-dev \
        musl-tools \
        unit \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        gcc-x86-64-linux-gnu \
        libc6-dev-amd64-cross; \
    rustup target install x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl; \
    cargo install --quiet cargo-deb cargo-generate-rpm; \
    rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*; \
    git config --global --add safe.directory /project
