# Strongbox

Encryption for git users.

Strongbox makes it easy to encrypt and decrypt files stored in git, with minimal divergence from a typical git workflow.  Once installed, strongbox enables normal use of commands such as `git diff` etc. and all of the files that should be encrypted in the repository remain decrypted on your working copy.

It supports use of different keys per directory if wanted.  It can cover as many or as few files as you wish based on [.gitattributes](https://www.git-scm.com/docs/gitattributes)

## Installation

Assuming you have a working [Go](https://golang.org) installation, you can install via `go get github.com/uw-labs/strongbox`

Or you can obtain a binary from https://github.com/uw-labs/strongbox/releases

## Usage

 1. As a one time action, install the plugin by running `strongbox install`. This will edit global git config to enable strongbox filter and diff configuration.

 1. In each repository you want to use strongbox, create one or more `.gitattributes` files containing the file patterns you want to be managed by strongbox.
    For example:
    ```
    secrets-strongbox/* filter=strongbox diff=strongbox
    ```

 1. Generate a key to use for the encryption, for example:
    ```
    strongbox gen-key "my key"
    ```
    This will add a new key to `$HOME/.strongbox_keyring`

 1. Include a `.strongbox-keyid` file in your repository containing public key you want to use (typically by copying a public key from `$HOME/.strongbox_keyring` )  This can be in the same directory as the protected resource(s) or any parent directory.   When searching for `.strongbox-keyid` for a given resource, strongbox will recurse up the directory structure until it finds the file.  This allows using different keys for different subdirectories within a repository.

## Verification

You can verify the files have been encrypted in the commit before pushing by running `git show HEAD:/path/to/file`

What you should see is a Strongbox encrypted resource, and this is what would be pushed to the remote.

## Security

Strongbox uses SIV-AES as defined in rfc5297 in order to achieve authenticated deterministic encryption.
