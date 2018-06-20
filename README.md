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

This project is based on rocket, which requires rustc nightly:

```
$ rustup component add rls --toolchain nightly-x86_64-unknown-linux-gnu
$ rustup default nightly
```

You may also want to run ssh-agent before building, so cargo can pull from internal git repos.

```
eval `ssh-agent -s`
```

Install diesel:

```
cargo install diesel_cli
```

Run with mysql (make sure you have a mysql server running on localhost):

```
DATABASE_URL=mysql://username:password@localhost/rabe cargo test -- --nocapture
```