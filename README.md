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

The primary use case is to support a large corporate environment, where we'd like to deploy a monorepo at at scale, with thousands of users and millions of files. (Monorepos are awesome, for reasons that are beyond the scope of this document.)

Git can scale to this size, with the help of Microsoft's open source [VFSForGit](https://github.com/Microsoft/VFSForGit) filesystem.

For this particular use case, we must restrict read access in certain subtrees of the repo to certain user groups. By itself, git lacks a concept of read-access control.

## Status

As of Jan 2019, gel is prototype quality -- a proof of concept. It is not deployed in any large installation.

Any aspect of this might change in a future version, though I'll try to keep the in-repo ciphered format stable, especially if actual users make themselves known to me.

## How to build and run self-test

When you first pull this tree, you should be able to:

```cd filter
make filter
make selftest
```

On Ubuntu, you might need to first install packages `libgit2-dev`, `libcrypto++-dev`, and `protobuf-compiler`.

If those commands work, you have built the filter package and run its self-tests.

## How to see the live demo!

This repo provides some ciphered files in the `secret/` directory. On your first checkout, they will look like binary garbage. You can modify your workspace to transparently decrypt them, as follows:

```cd filter
mkdir -p ~/git-bin
make install        # this installs the 'filter' program to ~/git-bin/filter
```

Then, open `filter/sample.git.config`. Copy its contents, paste them into your `.git/config` file, and replace the FILTER and CHECKOUT keywords with your appropriate local values.




## TO DO

*Security Review* - I'm not a security expert. Are there any weaknesses in the ciphered format used here? TBD. Your comments would be welcome.

*VFSForGit Integration* - I have not tested gel with VFSForGit yet, only with plain old git. Will we need changes in either gel or VFSForGit for them to work together nicely?

*Streamlined Setup* - My goal isn't to make it super easy to do encryption on a tiny repo; my goal is to make it possible for a very large repo.

*Optimizations* - Implement the long-running filter process API; for now git invokes the filter once per file which could be slow. Reduce extra copies made in the filter, it could be faster.

## Bugs / Limitations

The git hooks allow us to cipher file contents only. Everything else is cleartext in the repo, including filenames, branch names, the identity of committers, and comment history. All this is visible to any observer with repo access; they don't need any decryption key to see it.
