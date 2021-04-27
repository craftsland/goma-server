// Copyright 2017 The Goma Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package hash provides a hash function used in goma.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"

	"google.golang.org/protobuf/proto"
)

// SHA256HMAC returns a hexdecimal representation of the SHA256 hmac of the given two content.
func SHA256HMAC(key []byte, data []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// SHA256Content returns a hexdecimal representation of the SHA256 hash of the given content.
func SHA256Content(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SHA256Proto returns a hexdecimal representation of the SHA256 hash of the given protocol buffer.
func SHA256Proto(m proto.Message) (string, error) {
	// github.com/golang/protobuf/proto's Marshal returned error for nil
	// message, but google.golang.org/protobuf/proto returns nil err.
	// To preserve behavior of SHA256Proto, check m is nil-pointer or not.
	if !reflect.ValueOf(m).IsValid() {
		return "", fmt.Errorf("nil %T", m)
	}
	b, err := proto.Marshal(m)
	if err != nil {
		return "", err
	}
	return SHA256Content(b), nil
}

// SHA256File returns a hexadecimal representation of the SHA256 hash of the file contents.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
