package tlsconn

import (
	"container/heap"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"
)

// Errors of a possession proof.
var (
	// ErrBadChallenge is the error of a challenge that the Challenger did
	// not issue, or issued for another purpose.
	ErrBadChallenge = errors.New("tlsconn: invalid challenge")
	// ErrChallengeExpired is the error of a challenge past its expiry.
	ErrChallengeExpired = errors.New("tlsconn: challenge has expired")
	// ErrChallengeUsed is the error of a challenge that already proved
	// possession once.
	ErrChallengeUsed = errors.New("tlsconn: challenge was already used")
	// ErrTooManyChallenges is the error of a Challenger that holds
	// MaxUsed unexpired used challenges, which it keeps to refuse their
	// reuse, so it cannot accept another until one expires.
	ErrTooManyChallenges = errors.New("tlsconn: too many challenges in use")
	// ErrNoChallenger is the error of a Challenger that NewChallenger did
	// not make, such as the zero value, which has no key.
	ErrNoChallenger = errors.New("tlsconn: Challenger not made by NewChallenger")
	// ErrBadSignature is the error of a signature that does not verify
	// against the public key.
	ErrBadSignature = errors.New("tlsconn: possession proof signature is invalid")
)

const (
	// DefaultChallengeTTL is how long a challenge of a Challenger with no
	// TTL is valid.
	DefaultChallengeTTL = 5 * time.Minute
	// DefaultMaxUsed is how many unexpired used challenges a Challenger with
	// no MaxUsed keeps.
	DefaultMaxUsed = 1 << 16
)

// proofContext starts every signed possession message, so that a signature
// made for a proof is not one for any other protocol, nor the reverse.
const proofContext = "tlsconn key possession proof v1\x00"

// SignPossession signs challenge for purpose with key, proving to a holder
// of its public key that the signer holds key. The signature is RSA-PSS with
// SHA-256 and a salt the length of the hash for an RSA key, ECDSA (ASN.1)
// with SHA-256, SHA-384 or SHA-512 for a P-256, P-384 or P-521 key, and
// Ed25519 for an Ed25519 key, over a message that holds a fixed context,
// purpose and challenge. Other keys are ErrUnsupportedKey. A hardware key
// works through its crypto.Signer if it supports that scheme.
func SignPossession(key crypto.Signer, purpose, challenge string) ([]byte, error) {
	if key == nil {
		return nil, ErrUnsupportedKey
	}
	msg := possessionMessage(purpose, challenge)
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		if pub == nil {
			return nil, ErrUnsupportedKey
		}
		d := sha256.Sum256(msg)
		return key.Sign(rand.Reader, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case *ecdsa.PublicKey:
		h, ok := curveHash(pub)
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA %s", ErrUnsupportedKey, curveName(pub))
		}
		return key.Sign(rand.Reader, digest(h, msg), h)
	case ed25519.PublicKey:
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}

// VerifyPossession verifies a signature that SignPossession made for purpose
// and challenge with the private key of pub, such as a leaf certificate's
// PublicKey, and fails with ErrBadSignature if it does not verify or
// ErrUnsupportedKey for a key SignPossession does not sign with.
//
// It checks the signature only. The challenge must be one the verifier
// issued, unpredictable (128 random bits or more), for this purpose, not yet
// used and not expired, which the caller checks and records; a Challenger
// does all of that.
func VerifyPossession(pub crypto.PublicKey, purpose, challenge string, sig []byte) error {
	msg := possessionMessage(purpose, challenge)
	var ok bool
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if pub == nil {
			return ErrUnsupportedKey
		}
		d := sha256.Sum256(msg)
		ok = rsa.VerifyPSS(pub, crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case *ecdsa.PublicKey:
		h, supported := curveHash(pub)
		if !supported {
			return fmt.Errorf("%w: ECDSA %s", ErrUnsupportedKey, curveName(pub))
		}
		ok = ecdsa.VerifyASN1(pub, digest(h, msg), sig)
	case ed25519.PublicKey:
		ok = len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig)
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
}

// possessionMessage returns the signed message: the context, then purpose
// and challenge, each after its 4-byte big-endian length.
func possessionMessage(purpose, challenge string) []byte {
	msg := make([]byte, 0, len(proofContext)+8+len(purpose)+len(challenge))
	msg = append(msg, proofContext...)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(purpose)))
	msg = append(msg, purpose...)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(challenge)))
	return append(msg, challenge...)
}

// curveHash returns the hash used with pub, by its curve.
func curveHash(pub *ecdsa.PublicKey) (crypto.Hash, bool) {
	if pub == nil {
		return 0, false
	}
	switch pub.Curve {
	case elliptic.P256():
		return crypto.SHA256, true
	case elliptic.P384():
		return crypto.SHA384, true
	case elliptic.P521():
		return crypto.SHA512, true
	}
	return 0, false
}

// curveName returns the name of pub's curve, such as P-256.
func curveName(pub *ecdsa.PublicKey) string {
	if pub == nil || pub.Curve == nil || pub.Params() == nil {
		return "without a curve"
	}
	return pub.Params().Name
}

func digest(h crypto.Hash, msg []byte) []byte {
	var d hash.Hash
	switch h {
	case crypto.SHA384:
		d = sha512.New384()
	case crypto.SHA512:
		d = sha512.New()
	default:
		d = sha256.New()
	}
	d.Write(msg)
	return d.Sum(nil)
}

// Challenger issues challenges for possession proofs and verifies the
// answers: a server asks a client to prove that it holds the private key of
// a certificate by sending it Challenge(purpose), which the client signs with
// SignPossession, and checks the signature against the certificate's public
// key with Verify.
//
// Challenges are stateless: each holds its expiry and 128 random bits,
// authenticated with HMAC-SHA-256 under a key the Challenger makes and never
// reveals, together with the purpose, so issuing one stores nothing and a
// challenge for one purpose does not verify for another. A challenge proves
// possession once: Verify remembers the ones it accepted until they expire
// and refuses them again, keeping at most MaxUsed, and fails closed with
// ErrTooManyChallenges rather than forget one that has not expired.
//
// The key and the memory are the Challenger's own, so a challenge verifies
// only on the Challenger that issued it, and not after a restart, when the
// client asks for a new one; this is what makes reuse impossible without
// shared state. Servers behind a load balancer route the answer back to the
// issuing instance, or use VerifyPossession with challenges kept in their
// shared store. Verified proofs need a key, but any self-signed one does, so
// rate-limit Verify per user to keep one from filling MaxUsed.
//
// Expiry is kept on the Challenger's own monotonic clock, counted from its
// creation, not on the wall clock: a challenge expires a TTL of elapsed time
// after it was issued, and a used one is remembered until then, so a wall
// clock that steps back cannot make a used challenge acceptable again, and
// one that steps forward does not expire challenges early. Where the
// monotonic clock stops while the system sleeps, challenges live longer by
// that time.
//
// Its methods are safe for concurrent use. Create it with NewChallenger;
// the zero value has no key, and its methods fail with ErrNoChallenger.
type Challenger struct {
	mu    sync.Mutex
	now   func() time.Time // for tests
	used  usedHeap
	seen  map[[nonceSize]byte]struct{}
	epoch time.Time // with a monotonic reading
	key   [sha256.Size]byte
	ttl   time.Duration
	max   int
}

// ChallengerOptions configures NewChallenger.
type ChallengerOptions struct {
	// TTL is how long a challenge is valid; DefaultChallengeTTL (5 minutes)
	// if not positive.
	TTL time.Duration
	// MaxUsed bounds how many accepted challenges, each kept until it
	// expires, the Challenger holds; DefaultMaxUsed (65536, a few MB) if not
	// positive.
	MaxUsed int
}

// NewChallenger returns a Challenger with a new random key.
func NewChallenger(opts ChallengerOptions) (*Challenger, error) {
	c := &Challenger{
		ttl:   positive(opts.TTL, DefaultChallengeTTL),
		max:   opts.MaxUsed,
		seen:  make(map[[nonceSize]byte]struct{}),
		epoch: time.Now(),
	}
	if c.max <= 0 {
		c.max = DefaultMaxUsed
	}
	if _, err := rand.Read(c.key[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// A challenge is its version, its expiry in nanoseconds of the Challenger's
// monotonic clock since its creation, a random nonce
// and the HMAC of those and the purpose, in unpadded URL-safe base64.
const (
	challengeVersion = 1
	nonceSize        = 16
	challengeSize    = 1 + 8 + nonceSize + sha256.Size
)

// Challenge returns a new challenge for purpose, such as a string naming
// the action, the user and the domain being claimed, valid for the TTL. It
// is ASCII, safe in URLs and JSON.
func (c *Challenger) Challenge(purpose string) (string, error) {
	if c == nil || c.seen == nil {
		return "", ErrNoChallenger
	}
	var raw [challengeSize]byte
	raw[0] = challengeVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(c.elapsed()+int64(c.ttl)))
	if _, err := rand.Read(raw[9 : 9+nonceSize]); err != nil {
		return "", err
	}
	c.mac(raw[9+nonceSize:9+nonceSize], raw[:9+nonceSize], purpose)
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// Expiry returns when challenge, as Challenge returned it for purpose,
// expires, by the wall clock as it would read had it not been set since the
// Challenger was made, or ErrBadChallenge or ErrNoChallenger.
func (c *Challenger) Expiry(purpose, challenge string) (time.Time, error) {
	raw, err := c.open(purpose, challenge)
	if err != nil {
		return time.Time{}, err
	}
	return c.epoch.Add(time.Duration(binary.BigEndian.Uint64(raw[1:9]))).Round(0), nil
}

// Verify checks that sig, made by SignPossession for purpose and challenge,
// verifies against pub, such as a leaf certificate's PublicKey, that this
// Challenger issued challenge for purpose, that it has not expired and that
// it has not proved possession before; it then records it as used. It fails
// with ErrNoChallenger, ErrBadChallenge, ErrChallengeExpired, ErrBadSignature,
// ErrUnsupportedKey, ErrChallengeUsed or ErrTooManyChallenges. Only an
// accepted proof uses up a challenge, so a wrong signature does not keep
// the right one from verifying.
func (c *Challenger) Verify(pub crypto.PublicKey, purpose, challenge string, sig []byte) error {
	raw, err := c.open(purpose, challenge)
	if err != nil {
		return err
	}
	expiry := int64(binary.BigEndian.Uint64(raw[1:9]))
	if c.elapsed() >= expiry {
		return ErrChallengeExpired
	}
	if err := VerifyPossession(pub, purpose, challenge, sig); err != nil {
		return err
	}
	var nonce [nonceSize]byte
	copy(nonce[:], raw[9:9+nonceSize])
	return c.use(nonce, expiry)
}

// open decodes challenge and checks its MAC for purpose.
func (c *Challenger) open(purpose, challenge string) (*[challengeSize]byte, error) {
	if c == nil || c.seen == nil {
		return nil, ErrNoChallenger
	}
	var raw [challengeSize]byte
	if base64.RawURLEncoding.EncodedLen(challengeSize) != len(challenge) {
		return nil, ErrBadChallenge
	}
	if n, err := base64.RawURLEncoding.Decode(raw[:], []byte(challenge)); err != nil || n != challengeSize || raw[0] != challengeVersion {
		return nil, ErrBadChallenge
	}
	var want [sha256.Size]byte
	c.mac(want[:0], raw[:9+nonceSize], purpose)
	if !hmac.Equal(want[:], raw[9+nonceSize:]) {
		return nil, ErrBadChallenge
	}
	return &raw, nil
}

// mac appends to dst the HMAC of body and purpose.
func (c *Challenger) mac(dst, body []byte, purpose string) {
	m := hmac.New(sha256.New, c.key[:])
	m.Write(body)
	m.Write([]byte(purpose))
	m.Sum(dst)
}

// use records nonce as used until expiry, or fails if it is in use or no
// room is left.
func (c *Challenger) use(nonce [nonceSize]byte, expiry int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.elapsed()
	for len(c.used) > 0 && c.used[0].expiry <= now {
		delete(c.seen, heap.Pop(&c.used).(usedChallenge).nonce)
	}
	if _, ok := c.seen[nonce]; ok {
		return ErrChallengeUsed
	}
	if len(c.used) >= c.max {
		return ErrTooManyChallenges
	}
	c.seen[nonce] = struct{}{}
	heap.Push(&c.used, usedChallenge{expiry: expiry, nonce: nonce})
	return nil
}

// elapsed returns the nanoseconds since c was made, by the monotonic clock.
func (c *Challenger) elapsed() int64 {
	now := time.Now()
	if c.now != nil {
		now = c.now()
	}
	return int64(now.Sub(c.epoch))
}

// usedChallenge is a used challenge's nonce, kept until its expiry.
type usedChallenge struct {
	expiry int64
	nonce  [nonceSize]byte
}

// usedHeap orders used challenges by expiry, the soonest first.
type usedHeap []usedChallenge

func (h *usedHeap) Len() int           { return len(*h) }
func (h *usedHeap) Less(i, j int) bool { return (*h)[i].expiry < (*h)[j].expiry }
func (h *usedHeap) Swap(i, j int)      { (*h)[i], (*h)[j] = (*h)[j], (*h)[i] }
func (h *usedHeap) Push(x any)         { *h = append(*h, x.(usedChallenge)) }
func (h *usedHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
