# go-fips-test
Test that Go binary is using a FIPS validated cryptographic module

Two implementation available in portable C and Go.

This utilitiy is able to identify binaries that use:
- [Geomys](https://go.dev/doc/security/fips140] cryptographic module
- [microsoft/go](https://github.com/microsoft/go)'s systemcryptography experiment and thus access FIPS crypgraphic module via OpenSSL.
- no cryptrography, if build preserves symbols tables (compiled without `-ldflags`, or with `-ldflags -w`, specifically without using `-s`)

Example outputs are below

## Geomys binaries

Example output for a go binary that is compiled using [Geomys](https://go.dev/doc/security/fips140] cryptographic module

```
go-fips-test: go1.26.3
	path	github.com/chainguard-sandbox/go-fips-test
	mod	github.com/chainguard-sandbox/go-fips-test	v0.0.0-20260518100633-ff1998689a15+dirty
	build	-buildmode=exe
	build	-compiler=gc
	build	-ldflags=-w
	build	-tags=fips140v1.0
	build	DefaultGODEBUG=fips140=on
	build	CGO_ENABLED=1
	build	CGO_CFLAGS=
	build	CGO_CPPFLAGS=
	build	CGO_CXXFLAGS=
	build	CGO_LDFLAGS=
	build	GOARCH=amd64
	build	GOFIPS140=v1.0.0-c2097c7c
	build	GOOS=linux
	build	GOAMD64=v1
	build	vcs=git
	build	vcs.revision=ff1998689a15cc90b36eedd18bcae9fe361ddadb
	build	vcs.time=2026-05-18T10:06:33Z
	build	vcs.modified=true

Binary is using CMVP #5247
```

## Systemcrypto binaries

Example output for a go binary that is compiled using [microsoft/go](https://github.com/microsoft/go) toolchain

```
go-fips-test: go1.26.3
	path	github.com/chainguard-sandbox/go-fips-test
	mod	github.com/chainguard-sandbox/go-fips-test	(devel)
	build	microsoft_systemcrypto=1
	build	microsoft_toolset_version=go1.26.3-microsoft
	build	-buildmode=exe
	build	-compiler=gc
	build	DefaultGODEBUG=fips140=on
	build	CGO_ENABLED=1
	build	CGO_CFLAGS=
	build	CGO_CPPFLAGS=
	build	CGO_CXXFLAGS=
	build	CGO_LDFLAGS=
	build	GOARCH=amd64
	build	GOFIPS140=latest
	build	GOOS=linux
	build	GOAMD64=v1

Binary is using OpenSSL, check status with openssl-fips-test
```

## No cryptography used

Example output for a go binary that is compiled with a symbols table and does not use any cryptography

```
go-fips-test: go1.26.3
	path	github.com/chainguard-sandbox/go-fips-test
	mod	github.com/chainguard-sandbox/go-fips-test	v0.0.0-20260518100633-ff1998689a15+dirty	
	build	-buildmode=exe
	build	-compiler=gc
	build	-trimpath=true
	build	CGO_ENABLED=0
	build	GOARCH=amd64
	build	GOOS=linux
	build	GOAMD64=v2
	build	vcs=git
	build	vcs.revision=ff1998689a15cc90b36eedd18bcae9fe361ddadb
	build	vcs.time=2026-05-18T10:06:33Z
	build	vcs.modified=true

Binary is not using any cryptography, which is FIPS compliant. (verified symbols table)
```

## No cryptographic module in use

Binary that does not use a cryptographic module. Note that this binary is built without symbols table (`-ldflags="-w -s"`), hence symbols table inspection cannot be performed.

```
./go-fips-test: go1.26.3
	path	github.com/chainguard-sandbox/go-fips-test
	mod	github.com/chainguard-sandbox/go-fips-test	v0.0.0-20260518100633-ff1998689a15+dirty
	build	-buildmode=exe
	build	-compiler=gc
	build	-ldflags="-w -s"
	build	CGO_ENABLED=1
	build	CGO_CFLAGS=
	build	CGO_CPPFLAGS=
	build	CGO_CXXFLAGS=
	build	CGO_LDFLAGS=
	build	GOARCH=amd64
	build	GOOS=linux
	build	GOAMD64=v1
	build	vcs=git
	build	vcs.revision=ff1998689a15cc90b36eedd18bcae9fe361ddadb
	build	vcs.time=2026-05-18T10:06:33Z
	build	vcs.modified=true

Binary does not use a validated cryptographic module. Unknown if cryptography is in use. (no symbols table)
```
