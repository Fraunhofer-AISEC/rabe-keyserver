#########################################################################################
#
# Builds minimal runtime environment for the RABE Attribute Based Enryption Keyserver
#
# Copyright 2018 Fraunhofer AISEC
#
#########################################################################################

FROM debian:stretch-slim

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Copy our project into the image (see .dockerignore for exclusions)
COPY ./ /server
# Switch the current directory to /server
WORKDIR /server

EXPOSE 8000/tcp

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libc6-dev \
        wget \
        libmariadbclient-dev-compat \
        libmariadbclient18 \
        ; \
    \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly-2018-06-10; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version; \

    # Finally, we build our project
    cargo build --release; \
    # After that we copy our binary to the project root (you need to adjust this to your project)
    cp target/release/abe-keyserver . ; \
    # Remove as much stuff as possible to reduce image size
    rm -rf target/ ~/.cargo/ rust-abe/ ; \
    apt-get purge -y --allow-remove-essential --auto-remove wget gcc libc6-dev wget libmariadbclient-dev-compat bash sed apt; \
    rm -rf /var/lib/apt/lists/*; \
    rm -rf /var/log/*; \
    rm -rf /var/cache/apt/*; \
    rm -rf $CARGO_HOME ; \
    rm -rf $RUSTUP_HOME
# Finally, we configure RABE keyserver as entrypoint
ENTRYPOINT ["./abe-keyserver"]