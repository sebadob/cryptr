set shell := ["bash", "-uc"]

export TAG := `cat Cargo.toml | grep '^version =' | cut -d " " -f3 | xargs`

# prints out the currently set version
version:
    #!/usr/bin/env bash
    echo "v$TAG"


# clippy lint + check with minimal versions from nightly
check:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear
    cargo update

    echo 'Clippy with default'
    cargo +nightly clippy -- -D warnings
    echo 'Clippy with s3'
    cargo +nightly clippy --features s3 -- -D warnings
    echo 'Clippy with streaming'
    cargo +nightly clippy --features streaming -- -D warnings
    echo 'Clippy with cli'
    cargo +nightly clippy --features cli -- -D warnings

    echo 'Checking minimal versions'
    cargo minimal-versions check


# runs tests without s3
test:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear
    cargo test


# runs the full set of tests
test-full:
    #!/usr/bin/env bash
    set -euxo pipefail
    clear
    cargo test
    cargo test -- --ignored


# builds the code
build:
    #!/usr/bin/env bash
    set -euxo pipefail
    # build as musl to make sure this works
    cargo build --features cli --release --target x86_64-unknown-linux-musl

    # this needs mingw32 to be installed:
    # sudo dnf install mingw32-gcc mingw64-gcc  -y
    cargo build --features cli --release --target x86_64-pc-windows-gnu

    #git add out/*


# builds binaries
build-binaries: build
    #!/usr/bin/env bash
    set -euxo pipefail
    mkdir out

    cp target/x86_64-unknown-linux-musl/release/cryptr out/cryptr_{{TAG}}
    cp target/x86_64-pc-windows-gnu/release/cryptr.exe out/cryptr_{{TAG}}.exe

    git add out/*


# verifies the MSRV
msrv-verify:
    cargo msrv verify


# find's the new MSRV, if it needs a bump
msrv-find:
    cargo msrv --min 1.70.0


# verify thats everything is good
verify: check test-full build msrv-verify


# makes sure everything is fine
verfiy-is-clean: verify
    #!/usr/bin/env bash
    set -euxo pipefail

    # make sure everything has been committed
    git diff --exit-code

    echo all good


# sets a new git tag and pushes it
release: verfiy-is-clean build-binaries
    #!/usr/bin/env bash
    set -euxo pipefail

    # make sure git is clean
    git diff --quiet || exit 1

    git tag "v$TAG"
    git push origin "v$TAG"


# publishes the current version to cargo.io
publish: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    # We must delete the pre-built binaries to not push them to crates.io
    rm -rf out/*

    cargo publish


# dry run for publishing to crates.io
publish-dry: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    # We must delete the pre-built binaries to not push them to crates.io
    rm -rf out/*

    cargo publish --dry-run
