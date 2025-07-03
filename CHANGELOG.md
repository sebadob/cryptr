# Changelog

## UNRELEASED

This version brings a new `ChannelReader` and `ChannelWriter`. These can be used for working with streaming values
in-memory, for instance when you want to download a `cryptr` file from S3, receive the data in-memory, apply conversions
and then maybe return it as an async HTTP response.

The `ChannelReader` does NOT implement a decryption logic, because it does not make much sense. If you want to decrypt
in-memory values, just stick to the already existing `MemoryReader`.

## v0.6.2

Fixes a bug in `KdfValue::new_with_params()`, which ignored `m_cost`, `t_cost`, `p_cost` from the params and used the
defaults all the time.

## v0.6.1

2 new helper functions for `EncKeys` have been added, which provide more flexibility when they are handled manually or
converted between formats:

- `EncKeys::try_parse()`
- `EncKeys::keys_as_v64_vec()`

## v0.6.0

All dependencies have been bumped to the latest versions to fix some security advisories for `ring` and `tokio`.
The MSRV has been bumped to `1.85.1`.

## v0.5.1

Adds pub re-exports of the `s3-simple` API with `s3` feature enabled.
This is now reachable via `cryptr::stream::s3::*` to be able to create
`s3` readers and writers again.

## v0.5.0

A migration from `rusty_s3` to `s3-simple` for S3 requests has been done.
This brings additional compatibility with for instance [Garage](https://garagehq.deuxfleurs.fr/)
and gets rid of pre-signed URLs in favor of signed headers, which is a more secure approach.

## v0.4.0

- fix a misleading error message if a given encryption key is not exactly 32 bytes long
- MSRV has been bumped to `1.72.1`

## v0.3.0

- fix an offset bug in the `S3Reader` which would cause an in-flight decryption to
  fail on the last chunk
- optimized the performance of the `S3Reader`
- cleaner error logging when using the CLI
- bump external dependencies

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
