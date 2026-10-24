// Package creds checks user names and passwords against a fixed account
// list for the servers of this module. It depends on the standard library
// alone.
package creds

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Accounts holds the SHA-256 digests of the passwords of a fixed account
// list.
type Accounts struct {
	digests map[string][sha256.Size]byte
}

// New returns the accounts of the user names and passwords in accounts,
// which is read once.
func New(accounts map[string]string) Accounts {
	digests := make(map[string][sha256.Size]byte, len(accounts))
	for user, password := range accounts {
		digests[user] = sha256.Sum256([]byte(password))
	}
	return Accounts{digests: digests}
}

// Check reports whether password is the password of user. It compares
// SHA-256 digests in constant time, and for unknown users compares against
// a digest of no account, so that the time taken tells neither the length
// of a password nor whether a user exists.
func (a Accounts) Check(user, password string) bool {
	want, known := a.digests[user]
	var unknown [sha256.Size]byte // no password has this digest
	if !known {
		want = unknown
	}
	got := sha256.Sum256([]byte(password))
	match := subtle.ConstantTimeCompare(want[:], got[:]) == 1
	return known && match
}
