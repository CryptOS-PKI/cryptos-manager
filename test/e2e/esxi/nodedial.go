package main

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/CryptOS-PKI/cryptos-manager/internal/nodeclient"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// dialNode connects directly to n's own mTLS admin endpoint with the admin
// credentials the lab gate already issued it, the same way the manager
// itself would. This is how a step checks a write path's result on the node
// itself rather than trusting the manager's view of it.
func dialNode(n nodeUnderTest) (*nodeclient.Client, error) {
	var opts []nodeclient.Option
	if n.InsecureSkipNodeVerify {
		opts = append(opts, nodeclient.InsecureSkipNodeVerify())
	}
	c, err := nodeclient.Dial(store.Node{
		Name:      n.Name,
		Endpoint:  n.Endpoint,
		Role:      n.Role,
		AdminCert: n.AdminCertPath,
		AdminKey:  n.AdminKeyPath,
		CACert:    n.CACertPath,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("dialing node %s directly: %w", n.Name, err)
	}
	return c, nil
}

// serialMatches compares a node's hex-encoded serial (colons optional, any
// case) against a parsed certificate's serial number by value, sidestepping
// any formatting difference between how this script and the node render the
// same number as hex.
func serialMatches(nodeHex string, serial *big.Int) bool {
	clean := strings.ReplaceAll(nodeHex, ":", "")
	n, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		return false
	}
	return n.Cmp(serial) == 0
}
