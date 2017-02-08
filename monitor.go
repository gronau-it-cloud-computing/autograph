package main

import (
	"encoding/json"
	"log"
	"net/http"

	"go.mozilla.org/autograph/signer"
)

func (a *autographer) addMonitoring(monitoring authorization) {
	if monitoring.Key == "" {
		return
	}
	if _, ok := a.auths["monitor"]; ok {
		panic("user 'monitor' is reserved for monitoring, duplication is not permitted")
	}
	a.auths["monitor"] = monitoring
}

func (a *autographer) handleMonitor(w http.ResponseWriter, r *http.Request) {
	userid, authorized, err := a.authorize(r, []byte(""))
	if err != nil || !authorized {
		httpError(w, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	if userid != "monitor" {
		httpError(w, http.StatusUnauthorized, "user is not permitted to call this endpoint")
		return
	}
	sigresps := make([]signatureresponse, len(a.signers)*2)
	for i, s := range a.signers {
		// base64 of the string 'AUTOGRAPH MONITORING'
		_, hash := s.Hash([]byte("AUTOGRAPH MONITORING"))
		sig, err := s.Sign(hash)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
			return
		}
		csig := sig.(signer.Signature)
		encodedsig, err := csig.Marshal()
		if err != nil {
			httpError(w, http.StatusInternalServerError, "encoding failed with error: %v", err)
			return
		}
		sigresps[i] = signatureresponse{
			Ref:       id(),
			SignerID:  s.Config().ID,
			X5U:       s.Config().X5U,
			PublicKey: s.Config().PublicKey,
			Signature: encodedsig,
		}
	}
	respdata, err := json.Marshal(sigresps)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
		return
	}
	if a.debug {
		log.Printf("signature response: %s", respdata)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(respdata)
	log.Printf("monitoring operation succeeded")
}
