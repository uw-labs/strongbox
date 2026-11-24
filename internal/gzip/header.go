// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gzip

import (
	"encoding/binary"
	"time"
)

// Constants and types that live in gunzip.go upstream; only the writer is
// vendored here.
const (
	gzipID1     = 0x1f
	gzipID2     = 0x8b
	gzipDeflate = 8
)

var le = binary.LittleEndian

// A Header is the header of a gzip member.
type Header struct {
	Comment string
	Extra   []byte
	ModTime time.Time
	Name    string
	OS      byte
}
