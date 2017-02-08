package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
	"go.mozilla.org/pkcs7"
)

const (
	Usage = "xpi"
)

type Signer struct {
	signer.Configuration
	privKey rsa.PrivateKey
}

func New(conf signer.Configuration) (s *Signer, err error) {
	s = new(Signer)
	if conf.Usage != Usage {
		return nil, errors.Errorf("xpi: invalid usage %q, must be 'xpi'", conf.Usage)
	}
	if conf.ID == "" {
		return nil, errors.New("xpi: missing signer ID in signer configuration")
	}
	if conf.PrivateKey == "" {
		return nil, errors.New("xpi: missing private key in signer configuration")
	}
	s.privKey, err = signer.ParsePrivateKey([]byte(s.PrivateKey))
	if err != nil {
		return nil, errors.Wrap("xpi: failed to parse private key", err)
	}
	switch s.privKey.(type) {
	case *rsa.PrivateKey:
		pubkeybytes, err := x509.MarshalPKIXPublicKey(s.privKey.(*rsa.PrivateKey).Public())
		if err != nil {
			return err
		}
		s.PublicKey = base64.StdEncoding.EncodeToString(pubkeybytes)
	default:
		return nil, errors.Errorf("xpi: invalid private key algorithm, must be rsa, not %T", s.privKey)
	}
	return
}

// sign takes input data and returns a signature
func (s *Signer) Sign(data []byte) (sig *Signature, err error) {
	toBeSigned, err := pkcs7.NewSignedData(data)
	if err != nil {
		return nil, errors.Wrap("xpi.Sign: cannot initialize signed data", err)
	}
	if err = toBeSigned.AddSigner(cert, privkey, SignerInfoConfig{}); err != nil {
		return nil, errors.Wrap("xpi.Sign: cannota add signer", err)
	}
	toBeSigned.Detach()
	sig.data, err = toBeSigned.Finish()
	if err != nil {
		return nil, errors.Wrap("xpi.Sign: cannot finish signing data", err)
	}
	return
}

// Hash returns the hash of input data calculated over a given algorithm.
// If no algorithm is provided (empty string), then sha256 is used.
func (s *Signer) Hash(data []byte) (string, []byte, error) {
	return "sha256", digest(hashinput, "sha256")
}

type Signature struct {
	data []byte
	sd   pkcs7.SignedData
}

// String returns a content-signature header string
func (s *Signature) String() (string, err error) {
	return
}

func (s *Signature) Write(w io.Writer) (err error) {
	return err
}
