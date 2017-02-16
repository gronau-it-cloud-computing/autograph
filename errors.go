// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
)

func httpError(w http.ResponseWriter, errorCode int, errorMessage string, args ...interface{}) {
	log.WithFields(log.Fields{
		"code": errorCode,
	}).Errorf(errorMessage, args...)
	http.Error(w, fmt.Sprintf(errorMessage, args...), errorCode)
	return
}
