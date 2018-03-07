[![pipeline status](https://git-int.aisec.fraunhofer.de/sas/rust-abe-rest/badges/develop/pipeline.svg)](https://git-int.aisec.fraunhofer.de/sas/rust-abe-rest/commits/master)

# REST API for rust-abe attribute based encryption library

At present, this is a toy project and only supports the BSW ABE scheme. Feel free to extend as desired.


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

Alternatively, you can checkout rust-abe in a folder next to abe-keyserver and uncomment the respective line in `Cargo.toml`.