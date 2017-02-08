package contentsignature // import "go.mozilla.org/autograph/signer/contentsignature"
import (
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

type ContentSignature struct {
	R, S      *big.Int // fields must be exported for ASN.1 marshalling
	curveName string
	x5u       string
	id        string
	len       int
	finished  bool
}

// Marshal returns the R||S signature is encoded in base64 URL safe,
// following DL/ECSSA format spec from IEEE Std 1363-2000.
func (sig *ContentSignature) Marshal() (str string, err error) {
	if !sig.finished {
		return "", fmt.Errorf("contentsignature.Marshal: unfinished cannot be encoded")
	}
	// write R and S into a slice of len
	// both R and S are zero-padded to the left to be exactly
	// len/2 in length
	Rstart := (sig.len / 2) - len(sig.R.Bytes())
	Rend := (sig.len / 2)
	Sstart := sig.len - len(sig.S.Bytes())
	Send := sig.len
	rs := make([]byte, sig.len)
	copy(rs[Rstart:Rend], sig.R.Bytes())
	copy(rs[Sstart:Send], sig.S.Bytes())
	encodedsig := base64.RawURLEncoding.EncodeToString(rs)
	if sig.x5u != "" {
		return fmt.Sprintf("x5u=\"%s\";%s=%s", sig.x5u, sig.curveName, encodedsig), nil
	}
	return fmt.Sprintf("keyid=%s;%s=%s", sig.id, sig.curveName, encodedsig), nil
}

// Unmarshal parses the string representation of a content signature
// and return a ContentSignature value
func Unmarshal(signature string) (sig *ContentSignature, err error) {
	sig = new(ContentSignature)
	data, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature.Unmarshal")
	}
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(data[:len(data)/2])
	sig.S.SetBytes(data[len(data)/2:])
	return sig, nil
}
