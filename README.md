![Strongbox](strongbox-logo.png)

Encryption for Git users.

Strongbox makes it easy to encrypt and decrypt files stored in Git, with
minimal divergence from a typical Git workflow. Once installed, Strongbox
enables normal use of commands such as `git diff` etc. and all of the files
that should be encrypted in the repository remain decrypted on your working
copy.

It supports use of different keys per directory if wanted. It can cover as many
or as few files as you wish based on
[.gitattributes](https://www.git-scm.com/docs/gitattributes)

## Installation

You can obtain a binary from https://github.com/uw-labs/strongbox/releases

Alternatively, assuming you have a working [Go](https://golang.org) installation, you can
install via the following command:

```console
$ go install github.com/uw-labs/strongbox@v1.1.0
```

### Homebrew

If you're on macOS or Linux and have [Homebrew](https://brew.sh/) installed,
getting Strongbox is as simple as running:

```console
$ brew install uw-labs/tap/strongbox
```

## Usage

Strongbox supports [age](https://github.com/FiloSottile/age) and
[siv](https://pkg.go.dev/github.com/jacobsa/crypto/siv?utm_source=godoc)
encryption. Age is the recommended option.

| encryption | identity / keyring file | recipient / key file |
| ---------- | ----------------------- | -------------------- |
| age        | .strongbox_identity     | .strongbox_recipient |
| siv        | .strongbox-keyring      | .strongbox-keyid     |

1. As a one time action, install the plugin by running `strongbox -git-config`.
   This will edit global Git config to enable Strongbox filter and diff
   configuration.

2. In each repository you want to use Strongbox, create `.gitattributes` file
   containing the patterns to be managed by Strongbox.

   For example:

   ```
   secrets/* filter=strongbox diff=strongbox
   ```

3. Generate a key to use for the encryption, for example:
   ```console
   strongbox -gen-identity my-key
   ```
   This will generate a new [age](https://github.com/FiloSottile/age) keypair
   and place it in `~/.strongbox_identity`. You can specify alternative
   location using `-identity-file` flag or setting `$HOME` envvar.

4. Include `.strongbox_recipient` file in your repository
   (https://github.com/FiloSottile/age?tab=readme-ov-file#recipient-files).
   This can be in the same directory as the protected resource(s) or any parent
   directory. When searching for `.strongbox_recipient` for a given resource,
   Strongbox will recurse up the directory structure until it finds the file.
   This allows using different keys for different subdirectories within a
   repository.

5. If Strongbox identity file is stored in different location `-identity-file`
   can be used. ie `strongbox [-identity-file <identity_file_path>]
   -gen-identity key-name`

## Existing project

Strongbox uses [clean and smudge
filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes#filters_a)
to encrypt and decrypt files.

If you are cloning a project that uses Strongbox, you will need to have
identity in your Strongbox identity file prior to cloning (checkout). Otherwise
that filter will fail and not decrypt files on checkout.

If you already have the project locally and added identity, you can remove and
checkout the files to force the filter:
```
rm <files> && git checkout -- <files>
```

## Verification

Following a `git add`, you can verify the file is encrypted in the index:

```console
$ git show :/path/to/file
```

Verify a file is encrypted in the commit:

```console
$ git show HEAD:/path/to/file
```

What you should see is a Strongbox encrypted resource, and this is what would
be pushed to the remote.

Compare an entire branch (as it would appear on the remote) to master:

```console
$ git diff-index -p master
```

## Key rotation

To rotate keys, update the `.strongbox_recipient` with the new value, then
`touch` all files/directories covered by `.gitattributes`. All affected files
should now show up as "modified".

## Security

Strongbox uses [age](https://github.com/FiloSottile/age) and SIV-AES as defined
in rfc5297.

## Testing

Run integration tests:

```console
$ make test
```

## SIV manual decryption
Following commands can be used to decrypt files outside of the Git flow:

```console
# decrypt using default keyring file `$HOME/.strongbox_keyring`
strongbox -decrypt -recursive <path>

# decrypt using `keyring_file_path`
strongbox -keyring <keyring_file_path> -decrypt -recursive <path>

# decrypt using private key `<key>`
strongbox -key <key> -decrypt -recursive <path>

# decrypt single file with given key
strongbox -decrypt -key <key>
```

## Known issues

### Clone file ordering (SIV only)

Given a `.strongbox-keyid` in the root of the repository and an encrypted file
in the same directory,*and* alphabetically it comes before the key-id file.

Git checks out files alphanumerically, so if the strongboxed file is being
checked out before the `.strongbox-keyid` is present on disk, strongbox will
fail to find the decryption key.

Order of files being cloned is dictated by the index.

#### Workarounds

1. Clone repository, let the descryption fail. Delete encrypted files and do
   `git checkout` on the deleted files.
2. Move affected files down to a subdirectory from `.strongbox-keyid` file
