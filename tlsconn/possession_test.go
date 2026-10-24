package tlsconn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestChallenger(t testing.TB, opts ChallengerOptions) *Challenger {
	t.Helper()
	c, err := NewChallenger(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPossessionKeys(t *testing.T) {
	keys := []struct {
		name string
		key  crypto.Signer
	}{
		{"RSA", testRSAKey(t)},
		{"P-256", testECKey(t, elliptic.P256())},
		{"P-384", testECKey(t, elliptic.P384())},
		{"P-521", testECKey(t, elliptic.P521())},
		{"Ed25519", testEd25519Key(t)},
	}
	c := newTestChallenger(t, ChallengerOptions{})
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			const purpose = "claim domain example.com for user 42"
			leaf := newTestCert(t, leafTmpl("example.com"), nil, k.key, nil)
			challenge, err := c.Challenge(purpose)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := SignPossession(k.key, purpose, challenge)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Verify(leaf.PublicKey, purpose, challenge+"x", sig); !errors.Is(err, ErrBadChallenge) {
				t.Fatalf("Verify(longer challenge) = %v", err)
			}
			if err := c.Verify(leaf.PublicKey, purpose+" ", challenge, sig); !errors.Is(err, ErrBadChallenge) {
				t.Fatalf("Verify(other purpose) = %v", err)
			}
			wrong := sig[:len(sig)-1]
			if err := c.Verify(leaf.PublicKey, purpose, challenge, wrong); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("Verify(truncated signature) = %v", err)
			}
			if err := c.Verify(leaf.PublicKey, purpose, challenge, sig); err != nil {
				t.Fatalf("Verify() = %v", err)
			}
			if err := c.Verify(leaf.PublicKey, purpose, challenge, sig); !errors.Is(err, ErrChallengeUsed) {
				t.Fatalf("Verify() again = %v, want ErrChallengeUsed", err)
			}
		})
	}
}

func TestPossessionWrongKey(t *testing.T) {
	c := newTestChallenger(t, ChallengerOptions{})
	key, other := testECKey(t, elliptic.P256()), testECKey(t, elliptic.P256())
	challenge, err := c.Challenge("p")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignPossession(other, "p", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(key.Public(), "p", challenge, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify(other key's signature) = %v", err)
	}
	if err := c.Verify(testEd25519Key(t).Public(), "p", challenge, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify(ECDSA signature, Ed25519 key) = %v", err)
	}
	// The failed attempts did not use the challenge up.
	sig, err = SignPossession(key, "p", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(key.Public(), "p", challenge, sig); err != nil {
		t.Fatalf("Verify() after failed attempts = %v", err)
	}
}

func TestPossessionChallengeForms(t *testing.T) {
	c := newTestChallenger(t, ChallengerOptions{TTL: time.Minute})
	key := testEd25519Key(t)
	challenge, err := c.Challenge("p")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Fatalf("Challenge() = %q, not URL-safe", challenge)
	}
	// Expiry is the Challenger's monotonic clock read as a wall time, which
	// some platforms (such as js/wasm) let drift a little from the wall clock.
	if exp, err := c.Expiry("p", challenge); err != nil || exp.Before(time.Now().Add(50*time.Second)) || exp.After(time.Now().Add(70*time.Second)) {
		t.Fatalf("Expiry() = %v, %v", exp, err)
	}
	if _, err := c.Expiry("q", challenge); !errors.Is(err, ErrBadChallenge) {
		t.Fatalf("Expiry(other purpose) = %v", err)
	}
	other := newTestChallenger(t, ChallengerOptions{})
	sig, err := SignPossession(key, "p", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Verify(key.Public(), "p", challenge, sig); !errors.Is(err, ErrBadChallenge) {
		t.Fatalf("Verify() on another Challenger = %v", err)
	}
	flipped := []byte(challenge)
	flipped[len(flipped)/2] ^= 1
	bad := []string{"", "x", string(flipped), challenge[:len(challenge)-1], strings.Repeat("!", len(challenge))}
	for _, b := range bad {
		if err := c.Verify(key.Public(), "p", b, sig); !errors.Is(err, ErrBadChallenge) {
			t.Errorf("Verify(%q) = %v", b, err)
		}
	}
}

func TestPossessionExpiry(t *testing.T) {
	c := newTestChallenger(t, ChallengerOptions{TTL: time.Minute, MaxUsed: 2})
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	c.now = func() time.Time { return time.Unix(0, now.Load()) }
	key := testECKey(t, elliptic.P256())
	prove := func() error {
		challenge, err := c.Challenge("p")
		if err != nil {
			t.Fatal(err)
		}
		sig, err := SignPossession(key, "p", challenge)
		if err != nil {
			t.Fatal(err)
		}
		return c.Verify(key.Public(), "p", challenge, sig)
	}
	old, err := c.Challenge("p")
	if err != nil {
		t.Fatal(err)
	}
	oldSig, err := SignPossession(key, "p", old)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := prove(); err != nil {
			t.Fatal(err)
		}
	}
	if err := prove(); !errors.Is(err, ErrTooManyChallenges) {
		t.Fatalf("Verify() past MaxUsed = %v", err)
	}
	now.Add(int64(time.Minute))
	if err := c.Verify(key.Public(), "p", old, oldSig); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("Verify(expired) = %v", err)
	}
	// The used ones expired, making room.
	for range 2 {
		if err := prove(); err != nil {
			t.Fatalf("Verify() after expiry = %v", err)
		}
	}
	if len(c.used) != 2 || len(c.seen) != 2 {
		t.Fatalf("Challenger holds %d, %d used challenges, want 2", len(c.used), len(c.seen))
	}
}

// Of concurrent proofs with one challenge, exactly one is accepted.
func TestPossessionConcurrentReplay(t *testing.T) {
	c := newTestChallenger(t, ChallengerOptions{})
	key := testEd25519Key(t)
	challenge, err := c.Challenge("p")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignPossession(key, "p", challenge)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var accepted, replayed atomic.Int32
	for range 16 {
		wg.Go(func() {
			switch err := c.Verify(key.Public(), "p", challenge, sig); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrChallengeUsed):
				replayed.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 || replayed.Load() != 15 {
		t.Fatalf("accepted %d, refused %d as used, want 1 and 15", accepted.Load(), replayed.Load())
	}
}

func TestPossessionUnsupported(t *testing.T) {
	p224 := testECKey(t, elliptic.P224())
	if _, err := SignPossession(p224, "p", "c"); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("SignPossession(P-224) = %v", err)
	}
	if _, err := SignPossession(nil, "p", "c"); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("SignPossession(nil) = %v", err)
	}
	for _, pub := range []crypto.PublicKey{p224.Public(), nil, "key", (*rsa.PublicKey)(nil), (*ecdsa.PublicKey)(nil), &ecdsa.PublicKey{}} {
		if err := VerifyPossession(pub, "p", "c", []byte{1}); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("VerifyPossession(%T) = %v", pub, err)
		}
	}
	if err := VerifyPossession(ed25519.PublicKey{1, 2}, "p", "c", make([]byte, ed25519.SignatureSize)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("VerifyPossession(short Ed25519 key) = %v", err)
	}
}

// The purpose and the challenge are framed, so moving bytes between them
// changes the message.
func TestPossessionFraming(t *testing.T) {
	key := testEd25519Key(t)
	sig, err := SignPossession(key, "ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPossession(key.Public(), "ab", "c", sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPossession(key.Public(), "a", "bc", sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("VerifyPossession(moved byte) = %v", err)
	}
	// The signed message is not the bare challenge, so a signature that a
	// key made over the challenge for another protocol does not verify.
	bare := ed25519.Sign(key, []byte("c"))
	if err := VerifyPossession(key.Public(), "", "c", bare); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("VerifyPossession(bare signature) = %v", err)
	}
	rsaKey := testRSAKey(t)
	d := sha256.Sum256(possessionMessage("p", "c"))
	pkcs1, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPossession(rsaKey.Public(), "p", "c", pkcs1); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("VerifyPossession(PKCS #1 v1.5 signature) = %v", err)
	}
}

// The zero Challenger has no key: it issues nothing and accepts nothing,
// not even a challenge made with the all-zero key it would otherwise have.
func TestPossessionZeroChallenger(t *testing.T) {
	var zero Challenger
	var nilChallenger *Challenger
	if _, err := zero.Challenge("p"); !errors.Is(err, ErrNoChallenger) {
		t.Fatalf("zero Challenge() = %v", err)
	}
	if _, err := nilChallenger.Challenge("p"); !errors.Is(err, ErrNoChallenger) {
		t.Fatalf("nil Challenge() = %v", err)
	}
	var raw [challengeSize]byte
	raw[0] = challengeVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(time.Now().Add(100*365*24*time.Hour).UnixNano()))
	m := hmac.New(sha256.New, make([]byte, sha256.Size))
	m.Write(raw[:9+nonceSize])
	m.Write([]byte("p"))
	m.Sum(raw[9+nonceSize : 9+nonceSize])
	forged := base64.RawURLEncoding.EncodeToString(raw[:])
	if _, err := zero.Expiry("p", forged); !errors.Is(err, ErrNoChallenger) {
		t.Fatalf("zero Expiry(forged) = %v", err)
	}
	key := testEd25519Key(t)
	sig, err := SignPossession(key, "p", forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := zero.Verify(key.Public(), "p", forged, sig); !errors.Is(err, ErrNoChallenger) {
		t.Fatalf("zero Verify(forged) = %v", err)
	}
	if err := nilChallenger.Verify(key.Public(), "p", forged, sig); !errors.Is(err, ErrNoChallenger) {
		t.Fatalf("nil Verify(forged) = %v", err)
	}
}

// A challenge's expiry counts from the Challenger's creation on its own
// monotonic clock, not the wall clock, and a used one is kept until then.
func TestPossessionOwnClock(t *testing.T) {
	c := newTestChallenger(t, ChallengerOptions{TTL: time.Minute})
	challenge, err := c.Challenge("p")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.open("p", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if offset := time.Duration(binary.BigEndian.Uint64(raw[1:9])); offset < time.Minute || offset > time.Minute+time.Hour {
		t.Fatalf("challenge expiry = %v after the Challenger's creation, want about the TTL", offset)
	}
	key := testEd25519Key(t)
	sig, err := SignPossession(key, "p", challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(key.Public(), "p", challenge, sig); err != nil {
		t.Fatal(err)
	}
	// A used challenge stays used for as long as it has not expired on the
	// Challenger's clock, whatever the wall clock does meanwhile.
	if err := c.Verify(key.Public(), "p", challenge, sig); !errors.Is(err, ErrChallengeUsed) {
		t.Fatalf("Verify() again = %v", err)
	}
	if c.used[0].expiry != int64(binary.BigEndian.Uint64(raw[1:9])) {
		t.Fatal("used challenge is kept until another time than its expiry")
	}
}
