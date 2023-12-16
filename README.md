# cryptr - simple encrypted (streaming) values

The idea of cryptr is to provide a simple and robust way of encryption all different kinds of values.

### Early Version

cryptr is in a very early phase. I did have the base layer set up properly before releasing the first open
source version, but it may be possible, that things change with the first early versions, even though I don't
expect any big changes.  
I do have a quite a few ideas for future features like being able to spawn a server from the CLI, which then
would mean you could host your own small storage anywhere, without the fear of exposing values, because
everything would be encrypted locally beforehand.

I do have quite a few test cases set up and everything looks very good and stable so far.  
Pre-packaged versions will come in the future.

## Why

There are a lot of encryption tools out there already and cryptr's main purpose is not file encryption, even
though it handles this perfectly fine and really fast.  
The main idea why cryptr was born is that I needed to encrypt small values in different projects, because
I just did not want to save them in clear text inside the database or somewhere else. With passwords, you
have hashing, but that is not an option when you need to be able to read that value inside the application
at some point, like for instance Webauthn user data.

I had two very simple, small functions for exactly that use case which I copy & pasted all over the place.
This became really tedious at some point and even more, when I did an improvement on them.  
Another problem was, that these did not care about future-proof ways of doing it at all.
When I did a change on the functions, I needed to handle the migration of all encrypted values manually
each time, which was really annoying.

## What it can do

### Direct encryption of small values

I created cryptr to handle all of that stuff in a really fast, efficient and robust way.
It can handle small values that you want to encrypt for a special database column for instance without 
much overhead or setup needed. You don't need to track the encryption key that was used with the value,
because you should always be able to do key rotations and stuff.  
A **tiny header with usually below 40 bytes** (depending on if you choose a custom, long key id) will be added
to the value, which then contains all the necessary information. In all my projects, I had this information
in different columns and needed to handle all of this manually each time. This is not the case no more.

### Streaming

What cryptr can do as well is streaming encryption on-the-fly with very minimal memory usage.
I use it for instance to do a streaming replication of database backups to an external storage.
It can basically handle **files of any size**, read them piece by piece, do an on-the-fly streaming
encryption using **ChaCha20Poly1305** and then stream the chunks to the external **S3 object storage**
directly.  
Performance does not suffer from this at all. The load and tasks are spread over multiple cores internally
and 4 small buffers are used in between the tasks. In my first tests, the memory overhead was very minimal,
and I was able to stream files of any size with just a few MB of memory during the whole operation.

Since the encryption happens locally, you can use it easily in environments, where you may not trust
the storage admin or whoever has access to it.

### Tamper Resistant

cryptr uses AEAD streaming encryption algorithms (only ChaCha20Poly1305 at the moment).
This means, that the whole encrypted payload and each streamed chunk have appended MACs. This means, that
even if someone would tamper with your data, the worst thing that can happen, is that the encryption does
not work or actually complain, that the payload is corrupted. The data is not only encrypted, but validated
at the same time, that it is still the original value.

### CLI and library

cryptr comes as a CLI tool, or it can be used in any project as a normal crate.  
The CLI can handle most cases already and even provides a nice UX with importing and setting values via
CLI instead of manually updating the config file. You can do in-memory as well as streaming operations
via CLI, even to S3 storage already.

#### Install CLI

You can install the CLI via `cargo` for now:

```
cargo install cryptr --features cli
```

## Examples

You can find usage examples for both the library and the CLI in the `examples/` folder.
