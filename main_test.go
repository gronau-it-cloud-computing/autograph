// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	ag     *autographer
	pubkey *ecdsa.PublicKey
	conf   configuration
)

func TestMain(m *testing.M) {
	// load the signers
	err := conf.loadFromFile(os.Getenv("GOPATH") + "/src/go.mozilla.org/autograph/autograph.yaml")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("configuration: %+v\n", conf)
	ag, err = newAutographer(1)
	if err != nil {
		log.Fatal(err)
	}
	ag.addSigners(conf.Signers)
	ag.addAuthorizations(conf.Authorizations)
	ag.addMonitoring(conf.Monitoring)
	ag.makeSignerIndex()
	log.Printf("autographer: %+v\n", ag)
	// run the tests and exit
	r := m.Run()
	os.Exit(r)
}

func TestConfigLoad(t *testing.T) {
	testcases := []struct {
		pass bool
		data []byte
	}{
		{true, []byte(`
server:
    listen: "localhost:8000"

signers:
    - id: testsigner1
      privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDBe7dXZ/epqVkrRWbStmwe2WyTcpWJ5cCbrqcM4tCG4vdX9b0Ri+VYo
        LiHkmxenK0mgBwYFK4EEACKhZANiAASvggNRMynXOObY9QW4gJXCwgsNa/8vcjHK
        wgzyqfXUzv3PbiZbDVYtYT7FMzd84CmX9BEtsE8bQS2Ci7q0Izp9aRUjCiTlUuAZ
        XMhBcGTy1e65CRjbCNM4A8w0/K30x4k=
        -----END EC PRIVATE KEY-----

monitoring:
    key: qowidhqowidhqoihdqodwh
`)},
		{true, []byte(`
server:
    listen: "localhost:8000"

signers:
    - id: testsigner1
      privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDBe7dXZ/epqVkrRWbStmwe2WyTcpWJ5cCbrqcM4tCG4vdX9b0Ri+VYo
        LiHkmxenK0mgBwYFK4EEACKhZANiAASvggNRMynXOObY9QW4gJXCwgsNa/8vcjHK
        wgzyqfXUzv3PbiZbDVYtYT7FMzd84CmX9BEtsE8bQS2Ci7q0Izp9aRUjCiTlUuAZ
        XMhBcGTy1e65CRjbCNM4A8w0/K30x4k=
        -----END EC PRIVATE KEY-----

    - id: testsigner2
      privatekey: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIBOgIBAAJBALhlXvMK5hIgGGRgdUycR8FWAmZC5bOeUrLr9SWep2NnR9nmBDgS
        AYYFTraBw2se+oagYyWjccDnbJR9GPHarWkCAwEAAQJAey1kbxCxvhvoj20MDoA7
        QsB02+EGVqWFcvZCjb3c7X4XZS0Oe1y1TJSmyL7oEepuL3NTgXYib+RSLT8vph8u
        zQIhANzuVRWzm7sSgTsPgg/P+q/5O2BXzoY/QpWdDb8DWEVjAiEA1apqeW9u38o3
        xpjJBa7tTNzgmuZtupFvB7baO8So0cMCICjTxld3VI0Sk10ltYRUi+AfL7DTKTA3
        2ocpedPVu2c/AiEAuCx0KQa3sKmTWFmcdYyqOeXuqTbVAMuZxDGGfZxv1JcCIA2v
        84l6Qav0l4A3NDdT+cotbnDqQ5wjF+UZ8uwsBwSl
        -----END RSA PRIVATE KEY-----

authorizations:
    - id: tester
      key: oiqwhfoqihfoiqeheouqqouhfdq
      signers:
          - testsigner1
`)},
		// bogus yaml
		{false, []byte(`{{{{{{{`)},
		// yaml with tabs
		{false, []byte(`
server:
	listen: "localhost:8000"

signers:
      - privatekey: |
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
        AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
        3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
        -----END EC PRIVATE KEY-----
authorizations:
	- tester
`)},
	}
	for i, testcase := range testcases {
		var conf configuration
		// write conf file to /tmp and read it back
		fd, err := ioutil.TempFile("", "autographtestconf")
		if err != nil {
			t.Fatal(err)
		}
		fi, err := fd.Stat()
		if err != nil {
			t.Fatal(err)
		}
		filename := fmt.Sprintf("%s/%s", os.TempDir(), fi.Name())
		_, err = fd.Write(testcase.data)
		if err != nil {
			t.Fatal(err)
		}
		fd.Close()
		err = conf.loadFromFile(filename)
		if err != nil && testcase.pass {
			t.Fatalf("testcase %d failed and should have passed: %v",
				i, err)
		}
		if err == nil && !testcase.pass {
			t.Fatalf("testcase %d passed and should have failed", i)
		}
		os.Remove(filename)
	}
}

func TestConfigLoadFileNotExist(t *testing.T) {
	var conf configuration
	err := conf.loadFromFile("/tmp/a/b/c/d/e/f/e/d/c/b/a/oned97fy2qoelfahd018oehfa9we8ohf219")
	if err == nil {
		t.Fatalf("should have file with file not found, but passed")
	}
}

func TestStartMain(t *testing.T) {
	go main()
	time.Sleep(200 * time.Millisecond)
	resp, err := http.Get("http://localhost:8000/__heartbeat__")
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if fmt.Sprintf("%s", body) != "ohai" {
		t.Errorf("expected heartbeat message 'ohai', got %q", body)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected response code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}
