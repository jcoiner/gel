# gel
Git Encryption Layer (gel)

## What is it?

Gel provides a near-transparent encryption layer over git.

Plaintext appears in the workspace, ciphered text appears in the repo. The repo is outside the security perimeter. This lets you control read access to parts of the repo by controlling key distribution. You can configure different keys, or no key at all, on a per-subtree basis.

## How does it work?

It uses git's existing hooks:
 * Git provides hooks for _smudge_ and _clean_ filters, which apply transforms to data as it moves from the repo to the workspace or vice versa. Gel uses those hooks to encrypt data moving into the repo, and decrypt data moving into the workspace.
 * Git provides a hook for a custom merge driver, so we implement a merge driver that understands ciphered files. This allows automatic merge to work transparently.
 * Git provides a hook for a custom diff driver (aka _textconv_), so we implement a _textconv_ driver that understands ciphered files so that 'git diff' works transparently.

The encryption algorithm has the property that local changes in the plaintext file cause local changes in the ciphered file, so git can use deltification to store changes in the ciphered files efficiently. This algorithm was inspired by [rsyncrypto](https://rsyncrypto.lingnu.com/index.php/Home_Page) though the implementation here differs a bit from the rsyncrypto cipher.

## Why do this?

The primary use case is to support a large corporate environment, where we'd like to deploy a monorepo at scale, with thousands of users and millions of files. (Monorepos are awesome, for reasons that are beyond the scope of this document.)

Git can scale to this size, with the help of Microsoft's open source [VFSForGit](https://github.com/Microsoft/VFSForGit) filesystem.

For this particular use case, we must restrict read access in certain subtrees of the repo to certain user groups. By itself, git lacks a concept of read-access control.

## Status

As of Jan 2019, gel is prototype quality -- a proof of concept. It is not deployed in any large installation.

Any aspect of this might change in a future version, though I'll try to keep the in-repo ciphered format stable, especially if actual users make themselves known to me.

## How to build and run self-test

When you first pull this tree, you should be able to:

```
cd filter
make filter
make selftest
```

On Ubuntu, you might need to first install packages `libgit2-dev`, `libcrypto++-dev`, and `protobuf-compiler`.

If those commands work, you have built the filter package and run its self-tests.

## How to see the live demo!

This repo provides some ciphered files in the `secret/` directory. On your first checkout, they will look like binary garbage. You can modify your workspace to transparently decrypt them, as follows:

```
cd filter
mkdir -p ~/git-bin
make install        # this installs the 'filter' program to ~/git-bin/filter
```

Then, open `filter/sample.git.config`. Copy its contents, paste them into your `.git/config` file, and replace the FILTER and CHECKOUT keywords with your appropriate local values: FILTER should be the path to the `filter` program you just installed, and CHECKOUT should be the path to the root of your workspace.

Then, create `.git/access_map` with the following text:

```
map: {
  key: "secret"
  value: {
    keylist_id: "CHECKOUT/filter/test/secret.key"
  }
}
```

... and again, replace CHECKOUT with the full path to your checkout.

Now you should be in business; just do this to force the smudge filter to rerun, and the contents of `secret/` should come into focus:

```
cd CHECKOUT
rm .git/index
git checkout HEAD -- "$(git rev-parse --show-toplevel)"
```

### Cool! How did THAT happen?

The `.gitattributes` file in the checkout root names `gel-filter` as the filter to use for smudge, clean, diff, and merge operations on all files.

The text you created in `.git/config` defines what `gel-filter` means, in the context of smudge, clean, diff, and merge. In each case, it means calling the filter binary with some arguments.

One of those arguments is `-access_map`. This file maps in-workspace paths (like `secret/`) to a key (really a set of keys, because key rotation...) Any directory for which a key mapping exists shall be encrypted; other directories will go as plaintext. The sample access_map only has a single mapping for the `secret/` directory, but you could have any number of protected directories and a unique key for each one. (Note that the root dir cannot be ciphered, as that's where the `.gitattributes` file is, and ciphering that would lead to a bootstrapping problem.)

The file formats used by gel are all [protobufs](https://developers.google.com/protocol-buffers/) which, if you don't know about them, are well worth learning. Protobufs are _the best_ data-serialization system, and also the best system for creating custom text file formats. You just document the schema, and the protobuf compiler writes all the code to translate between data structures in your favorite language, to and from human-readable text files, to and from compact binaries.

The schemas used by the gel filter are defined in `filter/filter.proto`. The `-access_map` file is a text proto of type AccessMap, the key file is a text proto of type KeyList. Ciphered repo entries are binary protos of type CipheredFile.

## Cipher Details

How do we ensure that local edits to the plaintext file result in local diffs in the ciphered file?

The cipher works as follows:
 * Split the plaintext into variable sized "blobs", each of which must be at least 64 bytes. A trigger function in `findBlobs()` decides where to split the plaintext. At each position in the file, the trigger function looks backward at a span of the previous 64 bytes, and hashes those bytes. (It also hashes in the path for the file.) The hash has a 1/128 chance of selecting a new blob start on any given byte.
   The trigger function will tend to identify a stable set of blobs, even after small edits in a large file, so the ciphered file can deltify nicely.
 * Each blob is independently run through an AES CBC cipher. The cipher is seeded with an IV derived from a hash of the path to the file; the hash of the blob contents; and the count of blobs seen so far with the same hash. (The last term ensures that repeated, identical plaintext blobs will use different IVs, so no relationship will be observable to someone without the key.)
 * Ciphered blobs are packed into the CipheredFile proto.

An attacker should be unable to recognize sections that repeat in the same file, or sections which are common to two different files, since the file path is part of each IV and also part of the hash function used to split blobs. Two identical files with different paths should produce entirely different ciphertexts, even the signature of blob sizes should show no relationship.

## TO DO

*Security Review* - I'm not a security expert. Are there any weaknesses in the ciphered format used here? TBD. Your comments would be welcome.

*VFSForGit Integration* - I have not tested gel with VFSForGit yet, only with plain old git. Will we need changes in either gel or VFSForGit for them to work together nicely?

*Streamlined Setup* - My goal isn't to make it super easy to do encryption on a tiny repo; my goal is to make it possible for a very large repo.

*Optimizations* - Implement the long-running filter process API; for now git invokes the filter once per file which could be slow. Reduce extra copies made in the filter, it could be faster.

## Risks and Limitations

The git hooks allow us to cipher file contents only. Everything else is cleartext in the repo, including filenames, branch names, the identity of committers, and comment history. All this is visible to any observer with repo access; they don't need any decryption key to see it.

The encrypted format is not tamper-proof. Without the key, an attacker could remove, rearrange, or duplicate sections of the ciphered file, and produce a new valid ciphered file that will still decrypt without error. I don't think tampering is likely to be a concern, since git itself will record the identities of anyone modifying file contents.

I haven't thought about what would be involved to "chain" the gel filters with some other smudge/clean filters. I haven't thought about whether the gel filter is compatible with every other git feature and user-configurable extension possible. I tested with a vanilla setup.

## Committing Secrets as Plaintext :(

A particular area of risk is the possibility of secrets being committed as plaintext.

For the scenarios below, I'm thinking particularly of a corporate environment, where thousands of users all share a central monorepo. The large number of users opens us up to mistakes at scale!

Committed plaintext could happen in a few ways:
 * An accidental (or socially engineered?) change to `.git/config` or `.gitattributes` removes the filters.
 * An accidental change to the AccessMap removes encryption for a part of the repo.
 * The `required` line in the `.git/config` file _should_ cause git to fail a commit operation if the clean filter fails. (Without that line, git will happily and silently commit plaintext to the repo if the filter exits with bad status.) Git's not strongly designed around this use case, so is that an ironclad guarantee?

Most likely, in a corporate environment, it would be important to defend against a committed-plaintext failure by rejecting such pushes at the central repo. TBD: can an update hook do that? TODO: develop something in this space.

A related risk: the encrypting filter is maybe a little _too_ transparent! It's not obvious which directories are protected and which are not. Some users may not be aware of the security boundary at all. You could imagine a well-intentioned user copying secrets from a protected directory to an unprotected one and committing it. (That seems more likely than the user knowing about the AccessMap file and being able to read it...)

And while we can't prevent people with legitimate read access from taking secrets out and sharing them illegitimately, it would be nice to make the security boundaries more visible (how?) so this is less likely to happen by accident. Alternatively, we could protect against this with an update hook: we could embed a particular constant string in comments of most secret files, and then reject any push containing this string as plaintext. Such a comment may also educate users, too, if it's worded well.
