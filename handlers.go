// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hashicorp/golang-lru"
)

// a signaturerequest is sent by an autograph client to request
// a signature on input data
type signaturerequest struct {
	Template string `json:"template"`
	HashWith string `json:"hashwith"`
	Input    string `json:"input"`
	KeyID    string `json:"keyid"`
	Encoding string `json:"signature_encoding"`
}

// a signatureresponse is returned by autograph to a client with
// a signature computed on input data
type signatureresponse struct {
	Ref              string `json:"ref"`
	X5u              string `json:"x5u,omitempty"`
	PublicKey        string `json:"publickey,omitempty"`
	Hash             string `json:"hashalgorithm,omitempty"`
	Encoding         string `json:"signature_encoding,omitempty"`
	Signature        string `json:"signature"`
	ContentSignature string `json:"content-signature,omitempty"`
}

// A autographer signs input data with a private key
type autographer struct {
	signers     []signer
	auths       map[string]authorization
	signerIndex map[string]int
	nonces      *lru.Cache
}

func newAutographer(cachesize int) (a *autographer, err error) {
	a = new(autographer)
	a.nonces, err = lru.New(cachesize)
	return
}

// addSigners initializes each signer specified in the configuration by parsing
// and loading their private keys. The signers are then copied over to the
// autographer handler.
func (a *autographer) addSigners(signers []signer) {
	for _, signer := range signers {
		err := signer.init()
		if err != nil {
			panic(err)
		}
		a.signers = append(a.signers, signer)
	}
}

// addAuthorizations reads a list of authorizations from the configuration and
// stores them into the autographer handler as a map indexed by user id, for fast lookup.
func (a *autographer) addAuthorizations(auths []authorization) {
	a.auths = make(map[string]authorization)
	for _, auth := range auths {
		if _, ok := a.auths[auth.ID]; ok {
			panic("authorization id '" + auth.ID + "' already defined, duplicates are not permitted")
		}
		a.auths[auth.ID] = auth
	}
}

// makeSignerIndex creates a map of authorization IDs and signer IDs to
// quickly locate a signer based on the user requesting the signature.
func (a *autographer) makeSignerIndex() {
	a.signerIndex = make(map[string]int)
	// add an entry for each authid+signerid pair
	for _, auth := range a.auths {
		for _, sid := range auth.Signers {
			for pos, s := range a.signers {
				if sid == s.ID {
					log.Printf("Mapping auth id %q and signer id %q to signer %d", auth.ID, s.ID, pos)
					tag := auth.ID + "+" + s.ID
					a.signerIndex[tag] = pos
				}
			}
		}
	}
	// add a fallback entry with just the authid, to use when no signerid
	// is specified in the signing request. This entry maps to the first
	// authorized signer
	for _, auth := range a.auths {
		// if the authorization has no signer configured, skip it
		if len(auth.Signers) < 1 {
			continue
		}
		for pos, signer := range a.signers {
			if auth.Signers[0] == signer.ID {
				log.Printf("Mapping auth id %q to default signer %d", auth.ID, pos)
				tag := auth.ID + "+"
				a.signerIndex[tag] = pos
				break
			}
		}
	}
}

// handleSignature endpoint accepts a list of signature requests in a HAWK authenticated POST request
// and calls the signers to generate signature responses.
func (a *autographer) handleSignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts POST only", r.Method)
		return
	}
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
	sigresps := make([]signatureresponse, len(sigreqs))
	// Each signature requested in the http request body is processed individually.
	// For each, a signer is looked up, and used to compute a raw signature
	// the signature is then encoded appropriately, and added to the response slice
	for i, sigreq := range sigreqs {
		hash, err := getInputHash(sigreq)
		if err != nil {
			httpError(w, http.StatusBadRequest, "%v", err)
			return
		}
		signerID, err := a.getSignerID(userid, sigreq.KeyID)
		if err != nil || signerID < 0 {
			httpError(w, http.StatusUnauthorized, "%v", err)
			return
		}
		ecdsaSig, err := a.signers[signerID].sign(hash)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
			return
		}
		encodedsig, err := encode(ecdsaSig, sigreq.Encoding)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "encoding failed with error: %v", err)
			return
		}
		encodedcs, err := a.signers[signerID].ContentSignature(ecdsaSig)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "failed to retrieve content-signature: %v", err)
			return
		}
		sigresps[i] = signatureresponse{
			Ref:              id(),
			PublicKey:        a.signers[signerID].PublicKey,
			Hash:             sigreq.HashWith,
			Encoding:         sigreq.Encoding,
			Signature:        encodedsig,
			ContentSignature: encodedcs,
		}
	}
	respdata, err := json.Marshal(sigresps)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
		return
	}
	log.Printf("signing operation succeeded. userid=%q; request=%s; response=%s",
		userid, body, respdata)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(respdata)
}

// handleHeartbeat returns a simple message indicating that the API is alive and well
func (a *autographer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	w.Write([]byte("ohai"))
}

// handleVersion returns the current version of the API
func (a *autographer) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	w.Write([]byte(fmt.Sprintf(`{
"source": "https://github.com/mozilla-services/autograph",
"version": "%s",
"commit": "%s"
}`, version, commit)))
}
