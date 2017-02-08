// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	log "github.com/Sirupsen/logrus"
	"go.mozilla.org/autograph/signer"
)

// a signaturerequest is sent by an autograph client to request
// a signature on input data
type signaturerequest struct {
	Input string `json:"input"`
	KeyID string `json:"keyid,omitempty"`
}

// a signatureresponse is returned by autograph to a client with
// a signature computed on input data
type signatureresponse struct {
	Ref              string `json:"ref"`
	Type             string `json:"type,omitempty"`
	SignerID         string `json:"signer_id,omitempty"`
	X5U              string `json:"x5u,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
	Hash             string `json:"hash_algorithm,omitempty"`
	Signature        string `json:"signature"`
	ContentSignature string `json:"content-signature,omitempty"`
}

// handleSignature endpoint accepts a list of signature requests in a HAWK authenticated POST request
// and calls the signers to generate signature responses.
func (a *autographer) handleSignature(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}
	userid, authorized, err := a.authorize(r, body)
	if err != nil || !authorized {
		httpError(w, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	var sigreqs []signaturerequest
	err = json.Unmarshal(body, &sigreqs)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to parse request body: %v", err)
		return
	}
	if a.debug {
		log.Printf("signature request: %s", body)
	}
	sigresps := make([]signatureresponse, len(sigreqs))
	// Each signature requested in the http request body is processed individually.
	// For each, a signer is looked up, and used to compute a raw signature
	// the signature is then encoded appropriately, and added to the response slice
	for i, sigreq := range sigreqs {
		var (
			hash            []byte
			alg, encodedsig string
		)
		signerID, err := a.getSignerID(userid, sigreq.KeyID)
		if err != nil || signerID < 0 {
			httpError(w, http.StatusUnauthorized, "%v", err)
			return
		}
		hash, err = base64.StdEncoding.DecodeString(sigreq.Input)
		if err != nil {
			httpError(w, http.StatusBadRequest, "%v", err)
			return
		}
		if r.URL.RequestURI() == "/sign/data" {
			alg, hash = a.signers[signerID].Hash(hash)
		}
		sig, err := a.signers[signerID].Sign(hash)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
			return
		}
		csig := sig.(signer.Signature)
		encodedsig, err = csig.Marshal()
		if err != nil {
			httpError(w, http.StatusInternalServerError, "encoding failed with error: %v", err)
			return
		}
		sigresps[i] = signatureresponse{
			Ref:              id(),
			Type:             a.signers[signerID].Config().Type,
			SignerID:         a.signers[signerID].Config().ID,
			X5U:              a.signers[signerID].Config().X5U,
			PublicKey:        a.signers[signerID].Config().PublicKey,
			Hash:             alg,
			Signature:        encodedsig,
			ContentSignature: encodedsig,
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
	log.Printf("signing operation from %q succeeded", userid)
}

// handleHeartbeat returns a simple message indicating that the API is alive and well
func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	w.Write([]byte("ohai"))
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	dir, err := os.Getwd()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "Could not get CWD")
		return
	}
	filename := path.Clean(dir + string(os.PathSeparator) + "version.json")
	f, err := os.Open(filename)
	if err != nil {
		httpError(w, http.StatusNotFound, "version.json file not found")
		return
	}
	stat, err := f.Stat()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "stat failed on version.json")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "version.json", stat.ModTime(), f)
}
