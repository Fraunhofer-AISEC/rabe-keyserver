# REST API for rust-abe attribute based encryption library

This is a standalone web server that makes the [rabe](https://github.com/Fraunhofer-AISEC/rabe) library for Attribute Based Encryption (ABE) usable via a REST API.

Currently, rabe-keyserver only supports the BSW scheme, but further schemes implemented by rabe might be added in the future.

Head over to the [Github page](https://fraunhofer-aisec.github.io/rabe-keyserver/) for documentation.

## Checkout

Clone this project with subprojects:

```
git clone --recurse-submodules git@github.com:Fraunhofer-AISEC/rabe-keyserver.git
```

## Building

Rust is a rapidly evolving ecosystem and future versions might break the build. We thus provide a stable docker environment for building and running `rabe-keyserver` based on rust _nightly-2018-06-10_.

Simply run 

```bash
docker build . -t rabe-keyserver
```

and you will end up with an ~70 MB docker images that hosts the rabe-keyserver. Start it with

```bash
docker run -ti -P --env ROOT_ADDRESS=0.0.0.0 \
		--env ROCKET_PORT=8000 \
		--env ROCKET_ENV=production \
		--env DATABASE_URL=mysql://username:password@localhost/rabe \
		--restart always \
		--name rabe \
		rabe-keyserver:latest
```
