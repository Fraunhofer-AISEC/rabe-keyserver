# Builds minimal runtime environment for the Attribute Based Enryption Keyserver

# Start with alpine as base image
FROM alpine:latest
# Copy our project into the image (see .dockerignore for exclusions)
COPY ./ /server
# Switch the current directory to /server
WORKDIR /server
# This does multiple things in one go to keep the image size and layer number extremly low:
# llvm-libunwind is required to run the final rust binary, so we install it first
RUN apk add --no-cache llvm-libunwind 
    # Next, we install rust and cargo and tag them in a virtual package called `.build-rust`
     RUN apk add --no-cache --virtual .build-rust rust cargo \
    # Finally, we build our project
    RUN cargo build --release 
    # After that we copy our binary to the project root (you need to adjust this to your project)
    RUN cp target/release/abe-keyserver . 
    # Discard the target/ and ~/.cargo/ directory so it won't bloat our image
    RUN  rm -rf target/ ~/.cargo/ 
    # As the final cleanup step we uninstall our virtual package
    # This uninstalls cargo, rust and all dependencies that aren't needed anymore so they won't end up in the final image
    RUN apk del --purge .build-rust
# Finally, we configure our binary as entrypoint (you need to adjust this too)
ENTRYPOINT ["./abe-keyserver"]