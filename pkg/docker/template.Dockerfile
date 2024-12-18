FROM @@CONTAINER@@

LABEL org.opencontainers.image.title="Unit (@@MODULE@@)"
LABEL org.opencontainers.image.description="Official build of Unit for Docker."
LABEL org.opencontainers.image.url="https://unit.nginx.org"
LABEL org.opencontainers.image.source="https://github.com/nginx/unit"
LABEL org.opencontainers.image.documentation="https://unit.nginx.org/installation/#docker-images"
LABEL org.opencontainers.image.vendor="NGINX Docker Maintainers <docker-maint@nginx.com>"
LABEL org.opencontainers.image.version="@@VERSION@@"

RUN set -ex \
    && savedAptMark="$(apt-mark showmanual)" \
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
         ca-certificates git build-essential libssl-dev libpcre2-dev curl pkg-config libclang-dev cmake \
    && export RUST_VERSION=1.80.1 \
    && export RUSTUP_HOME=/usr/src/unit/rustup \
    && export CARGO_HOME=/usr/src/unit/cargo \
    && export PATH=/usr/src/unit/cargo/bin:$PATH \
    && dpkgArch="$(dpkg --print-architecture)" \
    && case "${dpkgArch##*-}" in \
         amd64) rustArch="x86_64-unknown-linux-gnu"; rustupSha256="6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d" ;; \
         arm64) rustArch="aarch64-unknown-linux-gnu"; rustupSha256="1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2" ;; \
         *) echo >&2 "unsupported architecture: ${dpkgArch}"; exit 1 ;; \
       esac \
    && url="https://static.rust-lang.org/rustup/archive/1.27.1/${rustArch}/rustup-init" \
    && curl -L -O "$url" \
    && echo "${rustupSha256} *rustup-init" | sha256sum -c - \
    && chmod +x rustup-init \
    && ./rustup-init -y --no-modify-path --profile minimal --default-toolchain $RUST_VERSION --default-host ${rustArch} \
    && rm rustup-init \
    && rustup --version \
    && cargo --version \
    && rustc --version \
    && mkdir -p /usr/lib/unit/modules /usr/lib/unit/debug-modules \
    && mkdir -p /usr/src/unit \
    && cd /usr/src/unit \
    && git clone --depth 1 -b @@VERSION@@-@@PATCHLEVEL@@ https://github.com/nginx/unit \
    && cd unit \
    && NCPU="$(getconf _NPROCESSORS_ONLN)" \
    && DEB_HOST_MULTIARCH="$(dpkg-architecture -q DEB_HOST_MULTIARCH)" \
    && CC_OPT="$(DEB_BUILD_MAINT_OPTIONS="hardening=+all,-pie" DEB_CFLAGS_MAINT_APPEND="-Wp,-D_FORTIFY_SOURCE=2 -fPIC" dpkg-buildflags --get CFLAGS)" \
    && LD_OPT="$(DEB_BUILD_MAINT_OPTIONS="hardening=+all,-pie" DEB_LDFLAGS_MAINT_APPEND="-Wl,--as-needed -pie" dpkg-buildflags --get LDFLAGS)" \
    && CONFIGURE_ARGS_MODULES="--prefix=/usr \
                --statedir=/var/lib/unit \
                --control=unix:/var/run/control.unit.sock \
                --runstatedir=/var/run \
                --pid=/var/run/unit.pid \
                --logdir=/var/log \
                --log=/var/log/unit.log \
                --tmpdir=/var/tmp \
                --user=unit \
                --group=unit \
                --openssl \
                --libdir=/usr/lib/$DEB_HOST_MULTIARCH" \
    && CONFIGURE_ARGS="$CONFIGURE_ARGS_MODULES \
                --njs \
                --otel" \
    && make -j $NCPU -C pkg/contrib .njs \
    && export PKG_CONFIG_PATH=$(pwd)/pkg/contrib/njs/build \
    && ./configure $CONFIGURE_ARGS --cc-opt="$CC_OPT" --ld-opt="$LD_OPT" --modulesdir=/usr/lib/unit/debug-modules --debug \
    && make -j $NCPU unitd \
    && install -pm755 build/sbin/unitd /usr/sbin/unitd-debug \
    && make clean \
    && ./configure $CONFIGURE_ARGS --cc-opt="$CC_OPT" --ld-opt="$LD_OPT" --modulesdir=/usr/lib/unit/modules \
    && make -j $NCPU unitd \
    && install -pm755 build/sbin/unitd /usr/sbin/unitd \
    && make clean \
    && @@MODULE_PREBUILD@@ \
    && ./configure $CONFIGURE_ARGS_MODULES --cc-opt="$CC_OPT" --modulesdir=/usr/lib/unit/debug-modules --debug \
    && ./configure @@CONFIGURE@@ \
    && make -j $NCPU @@INSTALL@@ \
    && make clean \
    && ./configure $CONFIGURE_ARGS_MODULES --cc-opt="$CC_OPT" --modulesdir=/usr/lib/unit/modules \
    && ./configure @@CONFIGURE@@ \
    && make -j $NCPU @@INSTALL@@ \
    && cd \
    && rm -rf /usr/src/unit \
    && for f in /usr/sbin/unitd /usr/lib/unit/modules/*.unit.so; do \
        ldd $f | awk '/=>/{print $(NF-1)}' | while read n; do dpkg-query -S $n; done | sed 's/^\([^:]\+\):.*$/\1/' | sort | uniq >> /requirements.apt; \
       done \
    && apt-mark showmanual | xargs apt-mark auto > /dev/null \
    && { [ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; } \
    && @@RUN@@ \
    && mkdir -p /var/lib/unit/ \
    && mkdir -p /docker-entrypoint.d/ \
    && groupadd --gid 999 unit \
    && useradd \
         --uid 999 \
         --gid unit \
         --no-create-home \
         --home /nonexistent \
         --comment "unit user" \
         --shell /bin/false \
         unit \
    && apt-get update \
    && apt-get --no-install-recommends --no-install-suggests -y install curl $(cat /requirements.apt) \
    && apt-get purge -y --auto-remove build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /requirements.apt \
    && ln -sf /dev/stderr /var/log/unit.log

COPY docker-entrypoint.sh /usr/local/bin/
COPY welcome.* /usr/share/unit/welcome/

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
EXPOSE 80
CMD ["unitd", "--no-daemon", "--control", "unix:/var/run/control.unit.sock"]
