# Packaging (for release)

Normally, Debian packages containing the Ubiq client libraries and development
headers can be built by building the `package` target. This will build the
software and packages on the host system using the libraries available on that
system. For release, we want to target something a bit more stable. The files
in this directory can be used to build the libraries and packages in the
current Debian stable release environment via Docker.

To build, at the top level of this repository, run:
```sh
make -f package/Makefile
```

Upon completion of a successful build, the created packages are left in the
`package/` directory. The build does its best to remove any created Docker
images and containers but makes no attempt to remove the `debian:stable`
image upon which it is based.
