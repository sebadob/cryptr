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

    # The full feature matrix. `aws_lc_rs` and `ring` are mutually exclusive, so
    # `--all-features` is not a valid combination. The no-backend build (`s3` and
    # `streaming` off) is not checkable here: the dev-dependency on cryptr with `cli`
    # unifies `s3` and `streaming` into every build, so the backend guard in lib.rs
    # fires for the tests as well as for `--lib`.
    echo 'Clippy with aws_lc_rs (default)'
    cargo +nightly clippy --all-targets -- -D warnings
    echo 'Clippy with ring'
    cargo +nightly clippy --no-default-features --features ring --all-targets -- -D warnings
    echo 'Clippy with s3 + aws_lc_rs'
    cargo +nightly clippy --all-targets --features s3 -- -D warnings
    echo 'Clippy with s3 + ring'
    cargo +nightly clippy --no-default-features --features ring,s3 --all-targets -- -D warnings
    echo 'Clippy with streaming + aws_lc_rs'
    cargo +nightly clippy --all-targets --features streaming -- -D warnings
    echo 'Clippy with streaming + ring'
    cargo +nightly clippy --no-default-features --features ring,streaming --all-targets -- -D warnings
    echo 'Clippy with cli + aws_lc_rs'
    cargo +nightly clippy --all-targets --features cli -- -D warnings
    echo 'Clippy with cli + ring'
    cargo +nightly clippy --no-default-features --features ring,cli --all-targets -- -D warnings

    echo 'Checking minimal versions'
    cargo minimal-versions check
    cargo update

    echo 'Checking examples'
    cd examples/simple-in-memory
    cargo clippy --all-targets -- -D warnings
    cd ../in-memory-dynamic-keys
    cargo clippy --all-targets -- -D warnings
    cd ../streaming-file-to-file
    cargo clippy --all-targets -- -D warnings
    cd ../..

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
    cargo test test_file_to_s3_to_file -- --ignored

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
    cp target/x86_64-unknown-linux-musl/release/cryptr out/cryptr_{{ TAG }}
    cp target/x86_64-pc-windows-gnu/release/cryptr.exe out/cryptr_{{ TAG }}.exe

    git add -f out/*

# verifies the MSRV
msrv-verify:
    cargo msrv verify

# find's the new MSRV, if it needs a bump
msrv-find:
    cargo msrv find --min $(cat Cargo.toml | grep '^rust-version =' | cut -d " " -f3 | xargs)

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
release: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    git tag "v$TAG"
    git push origin "v$TAG"

# publishes the current version to cargo.io
publish: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    cargo publish

# dry run for publishing to crates.io
publish-dry: verfiy-is-clean
    #!/usr/bin/env bash
    set -euxo pipefail

    # We must delete the pre-built binaries to not push them to crates.io
    rm -rf out/*

    cargo publish --dry-run
