# Changelog

## v0.2.2

Make it compile on Windows systems with `cli` or `streaming` features.
The before implementation for reading the filesize in `FileReader` was unix specific.

## v0.2.1

Add pre-built binaries to `.gitignore` again to not push them to crates.io

## v0.2.0

- pre-built binaries will be added to the repo with each version
- `anyhow` has been dropped in favor of the new `CryptrError` with `std::error` support
- Some new functions for in-memory zero copy decryptions have been added

## v0.1.1

Some internal code cleanup and `all-features = true` for docs.rs for complete docs.

## v0.1.0

Open Source Release
