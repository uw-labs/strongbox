# Vendored Go 1.26.0 gzip writer

`flate/` and `gzip/` are the writer side of `compress/flate` and
`compress/gzip` from Go 1.26.0 (`src/compress/{flate,gzip}`), under the Go
license in `LICENSE`.

Files are unmodified apart from one import path in `gzip/gzip.go`
(`compress/flate` became `github.com/uw-labs/strongbox/v2/internal/flate`).
`flate/consts.go` and `gzip/header.go` hold the few declarations that live in
the reader files upstream.

Do not update these from a newer Go. Go 1.27 changed the compressed bytes, and
those bytes are inside every file already encrypted, so a different compressor
makes the same plaintext encrypt to a different file. `compress_golden_test.go`
fails if the output moves.
