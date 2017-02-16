// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

//go:generate ./version.sh

import (
	"flag"
	"io/ioutil"
	"net/http"

	log "github.com/Sirupsen/logrus"

	"github.com/gorilla/mux"
	lru "github.com/hashicorp/golang-lru"

	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/mozlogrus"
	"gopkg.in/yaml.v2"
)

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph")
}

// configuration loads a yaml file that contains the configuration of Autograph
type configuration struct {
	Server struct {
		Listen         string
		NonceCacheSize int
	}
	Signers        []signer.Configuration
	Authorizations []authorization
	Monitoring     authorization
}

// An autographer is a running instance of an autograph service,
// with all signers and permissions configured
type autographer struct {
	signers     []signer.Signer
	auths       map[string]authorization
	signerIndex map[string]int
	nonces      *lru.Cache
	debug       bool
}

func main() {
	var (
		ag      *autographer
		conf    configuration
		cfgFile string
		debug   bool
		err     error
	)
	flag.StringVar(&cfgFile, "c", "autograph.yaml", "Path to configuration file")
	flag.BoolVar(&debug, "D", false, "Print debug logs")
	flag.Parse()

	err = conf.loadFromFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	// initialize signers from the configuration
	// and store them into the autographer handler
	ag = newAutographer(conf.Server.NonceCacheSize)
	ag.addSigners(conf.Signers)
	ag.addAuthorizations(conf.Authorizations)
	ag.addMonitoring(conf.Monitoring)
	ag.makeSignerIndex()
	if debug {
		ag.enableDebug()
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/__heartbeat__", handleHeartbeat).Methods("GET")
	router.HandleFunc("/__lbheartbeat__", handleHeartbeat).Methods("GET")
	router.HandleFunc("/__version__", handleVersion).Methods("GET")
	router.HandleFunc("/__monitor__", ag.handleMonitor).Methods("GET")
	router.HandleFunc("/sign/data", ag.handleSignature).Methods("POST")
	router.HandleFunc("/sign/hash", ag.handleSignature).Methods("POST")

	server := &http.Server{
		Addr: conf.Server.Listen,
		Handler: handleMiddlewares(
			router,
			addRequestID(),
			logRequest(),
			setResponseHeaders(),
		),
	}
	log.Println("starting autograph on", conf.Server.Listen)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// loadFromFile reads a configuration from a local file
func (c *configuration) loadFromFile(path string) error {
	fd, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(fd, &c)
	if err != nil {
		return err
	}
	return nil
}

// newAutographer creates an instance of an autographer
func newAutographer(cachesize int) (a *autographer) {
	var err error
	a = new(autographer)
	a.auths = make(map[string]authorization)
	a.signerIndex = make(map[string]int)
	a.nonces, err = lru.New(cachesize)
	if err != nil {
		log.Fatal(err)
	}
	return a
}

// enableDebug enables debug logging
func (a *autographer) enableDebug() {
	a.debug = true
	return
}

// disableDebug disables debug logging
func (a *autographer) disableDebug() {
	a.debug = false
	return
}

// addSigners initializes each signer specified in the configuration by parsing
// and loading their private keys. The signers are then copied over to the
// autographer handler.
func (a *autographer) addSigners(signerConfs []signer.Configuration) {
	for _, signerConf := range signerConfs {
		var (
			s   signer.Signer
			err error
		)
		switch signerConf.Type {
		case contentsignature.Type:
			s, err = contentsignature.New(signerConf)
			if err != nil {
				log.Fatal(err)
			}
		default:
			log.Fatalf("unknown signer type %q", signerConf.Type)
		}
		a.signers = append(a.signers, s)
	}
}

// addAuthorizations reads a list of authorizations from the configuration and
// stores them into the autographer handler as a map indexed by user id, for fast lookup.
func (a *autographer) addAuthorizations(auths []authorization) {
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
	// add an entry for each authid+signerid pair
	for _, auth := range a.auths {
		for _, sid := range auth.Signers {
			for pos, s := range a.signers {
				if sid == s.Config().ID {
					log.Printf("Mapping auth id %q and signer id %q to signer %d", auth.ID, s.Config().ID, pos)
					tag := auth.ID + "+" + s.Config().ID
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
			if auth.Signers[0] == signer.Config().ID {
				log.Printf("Mapping auth id %q to default signer %d", auth.ID, pos)
				tag := auth.ID + "+"
				a.signerIndex[tag] = pos
				break
			}
		}
	}
}
