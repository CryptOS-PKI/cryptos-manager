package mcpserver

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
	"reflect"
	"testing"

	fleetv1connect "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1/fleetv1connect"
)

// The catalog is the complete policy table, so every FleetService method has
// a row and no row names a method the contract doesn't have. A new RPC can't
// reach agents, or silently fail to, without a decision here.
func TestCatalog_MatchesTheFleetServiceContract(t *testing.T) {
	handler := reflect.TypeFor[fleetv1connect.FleetServiceHandler]()
	rows := map[string]bool{}
	for _, s := range Catalog {
		if s.RPC != "" {
			rows[s.RPC] = true
		}
	}
	for i := range handler.NumMethod() {
		if name := handler.Method(i).Name; !rows[name] {
			t.Errorf("FleetService.%s has no catalog row", name)
		}
	}
	for rpc := range rows {
		if _, ok := handler.MethodByName(rpc); !ok {
			t.Errorf("catalog row names %s, which FleetService doesn't have", rpc)
		}
	}
}
