# CLI usage example

This should give a short intro to the CLI usage.  
Since the project is in an early phase, there are no pre-packaged binaries yet.  
We will use an ALIAS in this example, but as soon as it has been published to crates.io, you can do a `cargo install`,
which I will update then.

Set ourselves an alias, until the point, where we can just install cryptr. You should be in this project's 
root directory for this to work properly:

```
alias cryptr="cargo run -q --features cli -- "
```

Check that it is working. The very first execution might take a while. It will compile the project and we
have set the output to quiet `-q` in the alias.

```
cryptr -h
```

You should see right away from the help, what you can do.  
Hopefully, most of the stuff is clear just from the documentation already.

The CLI usually expects its config in `~/.cryptr/config`, so let's generate an encryption key for testing

```
cryptr keys new-random
```

And then show our new key

```
cryptr keys list
```

We can generate as many keys as we like, also with a specific name / id.  
The IDs must match `^[a-zA-Z0-9_-]{2,20}$` though.

```
cryptr keys new-random --with-id my_secure_key
```

Now we have 2 keys and as you can see with 

```
cryptr keys list
```

it shows an `Active Key ID`. When we generate a new key, the new one will always be assumed to be the new default.  
If no ID is specified for an encryption, it will always take the current active key as default.  
This makes key rotations and all operations more straightforward, since you don't need to specify
the ID manually each time.

We can change the active key with

```
cryptr keys set-active
```

And then paste for instance the other ID here to do the switch.

Now let's encrypt the `test.txt` file in this example folder. Let's find out our options

```
cryptr encrypt -h
```

If you don't set any options, it will take the default active key and use the terminal for direct values.  
We want to encrypt our text file though

```
cryptr encrypt -f file:examples/cli/test.txt -t file:examples/cli/test.txt.enc
```

And we have our newly encrypted file

```
ls -l examples/cli/
```

This file is in binary format of course, and you cannot read it. You could compare the hashes, but as you can see
from the file size already, they are different anyway. The encryption has a small overhead. This is more prominent
the smaller the files are.

Let's decrypt it back to a readable format and make sure it's the same content

```
cryptr decrypt -f file:examples/cli/test.txt.enc -t file:examples/cli/test.txt.dec
```

And by comparing the sha256sum, you can see, that we got our original file back in 100% the same format

```
sha256sum examples/cli/test.txt
```
```
sha256sum examples/cli/test.txt.dec
```

The CLI can do quite a bit more stuff, but I think you got the idea now and can handle the rest yourself.  
For instance, you could add some credentials for an S3 storage you have access to and do these operations in the
same way, just sent to a remote storage over the network

```
cryptr s3 -h
```

The descriptions and error messages should be self-explanatory, hopefully.
