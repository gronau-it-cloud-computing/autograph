package contentsignature // import "go.mozilla.org/autograph/signer/contentsignature"

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"

	"go.mozilla.org/autograph/signer"

	"github.com/pkg/errors"
)

const (
	Type = "contentsignature"
)

type ContentSigner struct {
	signer.Configuration
	privKey *ecdsa.PrivateKey
}

func New(conf signer.Configuration) (s *ContentSigner, err error) {
	s = new(ContentSigner)
	s.ID = conf.ID
	s.Type = conf.Type
	s.PrivateKey = conf.PrivateKey
	s.X5U = conf.X5U
	if conf.Type != Type {
		return nil, errors.Errorf("contentsignature: invalid usage %q, must be %q", conf.Type, Type)
	}
	if conf.ID == "" {
		return nil, errors.New("contentsignature: missing signer ID in signer configuration")
	}
	if conf.PrivateKey == "" {
		return nil, errors.New("contentsignature: missing private key in signer configuration")
	}
	privKey, err := signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature: failed to parse private key")
	}
	switch privKey.(type) {
	case *ecdsa.PrivateKey:
		s.privKey = privKey.(*ecdsa.PrivateKey)
	default:
		return nil, errors.Errorf("contentsignature: invalid private key algorithm, must be ecdsa, not %T", s.privKey)
	}
	pubkeybytes, err := x509.MarshalPKIXPublicKey(s.privKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature: failed to unmarshal public key")
	}
	s.PublicKey = base64.StdEncoding.EncodeToString(pubkeybytes)
	return
}

func (s *ContentSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
		X5U:        s.X5U,
	}
}

// Hash returns the templated sha256 of the input data. The template adds
// the string "Content-Signature:\x00" before the input data prior to
// calculating the sha256.
//
// The name of the hash function "sha256" is returned, followed by the hash bytes
func (s *ContentSigner) Hash(data []byte) (string, []byte) {
	templated := make([]byte, len("Content-Signature:\x00")+len(data))
	copy(templated[:len("Content-Signature:\x00")], []byte("Content-Signature:\x00"))
	copy(templated[len("Content-Signature:\x00"):], data)
	var md hash.Hash
	md = sha512.New384()
	md.Write(data)
	return "sha384", md.Sum(nil)
}

// Sign takes an input hash and returns a signature. It assumes Hash() has already
// been called on the data and doesn't attempt
func (s *ContentSigner) Sign(hash []byte) (interface{}, error) {
	var err error
	csig := new(ContentSignature)
	csig.len = s.SignatureLen()
	csig.curveName = s.CurveName()
	csig.x5u = s.X5U
	csig.id = s.ID
	csig.R, csig.S, err = ecdsa.Sign(rand.Reader, s.privKey, hash)
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	csig.finished = true
	return csig, nil
}

// SignatureLen returns the size of an ECDSA signature issued by the signer.
// The signature length is double the size size of the curve field, in bytes
// (each R and S value is equal to the size of the curve field).
// If the curve field it not a multiple of 8, round to the upper multiple of 8.
func (s *ContentSigner) SignatureLen() int {
	siglen := 0
	if s.privKey.Params().BitSize%8 != 0 {
		siglen = 8 - (s.privKey.Params().BitSize % 8)
	}
	siglen += s.privKey.Params().BitSize
	siglen /= 8
	siglen *= 2
	return siglen
}

// CurveName returns an elliptic curve string identifier, or an empty string
// if the curve is unknown
func (s *ContentSigner) CurveName() string {
	switch s.privKey.Curve.Params().Name {
	case "P-256":
		return "p256ecdsa"
	case "P-384":
		return "p384ecdsa"
	case "P-521":
		return "p521ecdsa"
	default:
		return ""
	}
}
