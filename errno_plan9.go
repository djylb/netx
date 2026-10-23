//go:build plan9

package netx

import "syscall"

// platformErrnos are the errnos of each errnoID; see errors.go. Plan 9
// reports network failures as error strings and package syscall has no
// errno for most of them, so those classifiers rely on their text fallback.
// errnoValue is the type of the errors in platformErrnos.
type errnoValue = error

var platformErrnos = [numErrnoIDs][]errnoValue{
	eAccess:   {syscall.EACCES},
	ePerm:     {syscall.EPERM},
	eTimedOut: {syscall.ETIMEDOUT},
}

// errnoOf returns no errno: plan9 errors carry none, and the Go versions netx
// supports may not define syscall.Errno on plan9.
func errnoOf(error) (int, string) { return 0, "" }

// errnoValueSet returns the errnos of the table that err is, if it is one
// of package syscall's error strings; see errno_name.go.
//
//goland:noinspection GoTypeAssertionOnErrors
func errnoValueSet(err error) (errnoSet, bool) {
	if _, ok := err.(syscall.ErrorString); !ok {
		return 0, false
	}
	var set errnoSet
	for id, targets := range platformErrnos {
		for _, target := range targets {
			if target == err {
				set |= 1 << id
				break
			}
		}
	}
	return set, true
}
