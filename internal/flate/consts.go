// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package flate

// maxNumLit and InternalError live in inflate.go upstream; only the writer is
// vendored here.
const maxNumLit = 286

// An InternalError reports an error in the flate code itself.
type InternalError string

func (e InternalError) Error() string { return "flate: internal error: " + string(e) }
