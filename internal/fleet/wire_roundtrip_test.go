package fleet

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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1/fleetv1connect"
	"github.com/CryptOS-PKI/cryptos-manager/internal/authz"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/memory"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

// These tests drive the FleetService over the same wire the web UI uses:
// Connect with protojson bodies. connect-go decodes JSON with DiscardUnknown,
// and protojson never re-emits unknown fields, so a field the manager's api
// types don't know is silently dropped on every hop through the manager. A
// config or profile that survives these round trips byte-for-byte proves the
// manager's types carry every field the web and the node exchange.

// wireConfigJSON is a node config in the web's JSON form, covering every
// MachineConfig field added to the api since the manager's previous pin: DNS
// nameservers and search domains, the ST and L subject RDNs, Kerberos and UPN
// otherName SANs, and allow_request_sans.
const wireConfigJSON = `{
  "apiVersion": "cryptos.dev/v1alpha1",
  "kind": "MachineConfig",
  "metadata": {"name": "A"},
  "role": {"kind": "root"},
  "network": {
    "interface": "eth0",
    "address": "203.0.113.40/24",
    "gateway": "203.0.113.1",
    "nameservers": ["203.0.113.53", "198.51.100.53"],
    "search": ["lab.example.org", "example.org"]
  },
  "pki": {
    "rootKeyAlg": "ECDSA-P384",
    "rootSubject": {
      "commonName": "Lab Root CA",
      "organization": "Acme",
      "country": "CA",
      "province": "Ontario",
      "locality": "Toronto"
    },
    "profiles": [{
      "name": "kdc",
      "sans": {
        "dns": ["kdc.ad.example.org"],
        "krb5Principal": ["krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG"],
        "upn": ["kdc@ad.example.org"]
      },
      "allowRequestSans": true
    }]
  }
}`

// wireAdoptConfigJSON is an adopt wizard config in the web's JSON form. It
// stays inside the node's first-boot schema so the ceremony YAML can be decoded
// strictly, the way the node parses it.
const wireAdoptConfigJSON = `{
  "apiVersion": "cryptos.dev/v1alpha1",
  "kind": "MachineConfig",
  "metadata": {"name": "A"},
  "role": {"kind": "root"},
  "network": {
    "interface": "eth0",
    "address": "203.0.113.40/24",
    "gateway": "203.0.113.1",
    "nameservers": ["203.0.113.53", "198.51.100.53"],
    "search": ["lab.example.org", "example.org"]
  },
  "pki": {
    "rootKeyAlg": "ECDSA-P384",
    "rootSubject": {"commonName": "Lab Root CA", "province": "Ontario", "locality": "Toronto"},
    "rootValidityYears": 10
  },
  "install": {"disk": "/dev/nvme0n1"},
  "stateKey": {"mode": "nodeid"}
}`

// wireProfileJSON is a certificate profile in the web's JSON form, carrying the
// profile fields added since the previous pin.
const wireProfileJSON = `{
  "name": "kdc",
  "keyAlg": "ECDSA-P256",
  "subject": {"commonName": "kdc", "province": "Ontario", "locality": "Toronto"},
  "extKeyUsage": ["server_auth", "1.3.6.1.5.2.3.5"],
  "sans": {
    "dns": ["kdc.ad.example.org"],
    "krb5Principal": ["krbtgt/AD.EXAMPLE.ORG@AD.EXAMPLE.ORG"],
    "upn": ["kdc@ad.example.org"]
  },
  "allowRequestSans": true
}`

// wireClient serves svc over httptest as the web sees it and returns a JSON
// Connect client for it. Every request runs as the given caller; the real
// server derives that identity from the mTLS peer.
func wireClient(t *testing.T, svc *Service, id authz.Identity) fleetv1connect.FleetServiceClient {
	t.Helper()
	_, handler := fleetv1connect.NewFleetServiceHandler(svc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(authz.NewContext(r.Context(), id)))
	}))
	t.Cleanup(srv.Close)
	return fleetv1connect.NewFleetServiceClient(srv.Client(), srv.URL, connect.WithProtoJSON())
}

// mustUnmarshal decodes a web JSON fixture into msg. It is strict on purpose:
// a field the manager's api types don't know fails here rather than vanishing.
func mustUnmarshal(t *testing.T, fixture string, msg proto.Message) {
	t.Helper()
	if err := protojson.Unmarshal([]byte(fixture), msg); err != nil {
		t.Fatalf("the manager's api types reject the web's JSON: %v", err)
	}
}

// jsonTree parses JSON into a generic tree so two documents compare by content,
// not by key order or whitespace.
func jsonTree(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse json: %v\n%s", err, raw)
	}
	return v
}

// requireSameJSON fails unless msg renders to the same JSON content as want.
// drop names top-level keys the manager is expected to add on the way through.
func requireSameJSON(t *testing.T, leg string, msg proto.Message, want string, drop ...string) {
	t.Helper()
	raw, err := protojson.Marshal(msg)
	if err != nil {
		t.Fatalf("%s: marshal: %v", leg, err)
	}
	got := jsonTree(t, raw)
	if m, ok := got.(map[string]any); ok {
		for _, k := range drop {
			delete(m, k)
		}
	}
	if w := jsonTree(t, []byte(want)); !reflect.DeepEqual(got, w) {
		t.Errorf("%s changed the config:\n got  %s\n want %s", leg, raw, want)
	}
}

func TestWireRoundTrip_GetNodeConfig_KeepsEveryField(t *testing.T) {
	nodeCfg := &nodev1.MachineConfig{}
	mustUnmarshal(t, wireConfigJSON, nodeCfg)
	connA := &fakeConn{getConfigResp: &nodev1.GetConfigResponse{Config: nodeCfg}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))
	client := wireClient(t, svc, authz.Identity{CN: "op@acme.example", Level: authz.LevelOperator})

	resp, err := client.GetNodeConfig(context.Background(), connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("GetNodeConfig over JSON: %v", err)
	}
	requireSameJSON(t, "read (node -> manager -> web)", resp.Msg.GetConfig(), wireConfigJSON)
}

func TestWireRoundTrip_ApplyNodeConfig_KeepsEveryField(t *testing.T) {
	connA := &fakeConn{applyConfigResp: &nodev1.ApplyConfigResponse{Generation: 2}}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))
	client := wireClient(t, svc, authz.Identity{CN: "admin@acme.example", Level: authz.LevelAdmin})

	sent := &nodev1.MachineConfig{}
	mustUnmarshal(t, wireConfigJSON, sent)
	if _, err := client.ApplyNodeConfig(context.Background(), connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "A", Config: sent,
	})); err != nil {
		t.Fatalf("ApplyNodeConfig over JSON: %v", err)
	}
	if connA.gotApplyConfig == nil {
		t.Fatal("node ApplyConfig was not called")
	}
	requireSameJSON(t, "apply (web -> manager -> node)", connA.gotApplyConfig, wireConfigJSON)
}

func TestWireRoundTrip_AdoptNode_KeepsDNSThroughApplyAndCeremony(t *testing.T) {
	adoptCredsBaseDir = t.TempDir()
	mconn := &fakeConn{applyConfigResp: &nodev1.ApplyConfigResponse{RequiresReboot: true, Generation: 1}}
	running := &fakeConn{
		identity: rootIdentity(t),
		status:   &nodev1.GetStatusResponse{},
		ceremonyStream: &scriptedCeremony{kinds: []nodev1.CeremonyEventKind{
			nodev1.CeremonyEventKind_CEREMONY_EVENT_KIND_COMPLETE,
		}},
	}
	svc := New(memory.New(nil), dialFor(map[string]*fakeConn{"A": running})).WithAdoption(nil,
		func(string, string, string, string) (NodeConn, error) { return mconn, nil })
	restore := setRebootTiming(5*time.Millisecond, 1*time.Millisecond, 1*time.Millisecond)
	defer restore()
	client := wireClient(t, svc, authz.Identity{CN: "admin@acme.example", Level: authz.LevelAdmin})

	cfg := &nodev1.MachineConfig{}
	mustUnmarshal(t, wireAdoptConfigJSON, cfg)
	stream, err := client.AdoptNode(context.Background(), connect.NewRequest(&fleetv1.AdoptNodeRequest{
		Endpoint: "node:4443", PinnedCertSha256: "abc", Config: cfg,
	}))
	if err != nil {
		t.Fatalf("AdoptNode over JSON: %v", err)
	}
	for stream.Receive() {
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("AdoptNode stream: %v", err)
	}

	if mconn.gotApplyConfig == nil {
		t.Fatal("maintenance ApplyConfig was not called")
	}
	// The manager adds only the bootstrap admin it minted for the node.
	requireSameJSON(t, "adopt apply (web -> manager -> node)", mconn.gotApplyConfig, wireAdoptConfigJSON, "bootstrap")

	var got nodeConfigMirror
	dec := yaml.NewDecoder(bytes.NewReader(running.gotCeremonyYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("node-strict decode rejected the ceremony config: %v\n---\n%s", err, running.gotCeremonyYAML)
	}
	if want := []string{"203.0.113.53", "198.51.100.53"}; !reflect.DeepEqual(got.Network.Nameservers, want) {
		t.Errorf("ceremony network.nameservers = %v, want %v", got.Network.Nameservers, want)
	}
	if want := []string{"lab.example.org", "example.org"}; !reflect.DeepEqual(got.Network.Search, want) {
		t.Errorf("ceremony network.search = %v, want %v", got.Network.Search, want)
	}
	if s := got.PKI.RootSubject; s.Province != "Ontario" || s.Locality != "Toronto" {
		t.Errorf("ceremony root_subject = %+v, want province Ontario, locality Toronto", s)
	}
}

func TestWireRoundTrip_Profile_KeepsEveryField(t *testing.T) {
	svc := New(memory.New(nil), nil)
	client := wireClient(t, svc, authz.Identity{CN: "admin@acme.example", Level: authz.LevelAdmin})

	p := &nodev1.CertificateProfile{}
	mustUnmarshal(t, wireProfileJSON, p)
	if _, err := client.CreateProfile(context.Background(), connect.NewRequest(&fleetv1.CreateProfileRequest{Profile: p})); err != nil {
		t.Fatalf("CreateProfile over JSON: %v", err)
	}
	resp, err := client.ListProfiles(context.Background(), connect.NewRequest(&fleetv1.ListProfilesRequest{}))
	if err != nil {
		t.Fatalf("ListProfiles over JSON: %v", err)
	}
	for _, item := range resp.Msg.GetItems() {
		if item.GetName() == "kdc" {
			requireSameJSON(t, "profile (web -> manager store -> web)", item, wireProfileJSON)
			return
		}
	}
	t.Fatal("created profile kdc is missing from ListProfiles")
}

// wireProtocolConfigJSON is an issuing node's config in the web's JSON form
// with both enrolment protocol blocks, write-only secrets blank as GetConfig
// returns them.
const wireProtocolConfigJSON = `{
  "apiVersion": "cryptos.dev/v1alpha1",
  "kind": "MachineConfig",
  "metadata": {"name": "A"},
  "role": {"kind": "issuing"},
  "pki": {
    "acme": {
      "enabled": true,
      "baseUrl": "https://ca.example.org/acme",
      "httpPort": 8080,
      "profile": "tls-server",
      "termsOfService": "https://ca.example.org/tos",
      "website": "https://ca.example.org",
      "externalAccountKeys": [{"keyId": "k1"}],
      "allowedIdentifierSuffixes": ["example.org"],
      "orderTtlHours": 24
    },
    "est": {
      "hostnames": ["est.example.org"],
      "httpPort": 8443,
      "profile": "device",
      "label": "routers",
      "realm": "cryptos",
      "allowedIdentifierSuffixes": ["net.example.org"],
      "enrollCredentials": [{"username": "router"}]
    }
  }
}`

func TestWireRoundTrip_ProtocolBlocks_KeepEveryField(t *testing.T) {
	nodeCfg := &nodev1.MachineConfig{}
	mustUnmarshal(t, wireProtocolConfigJSON, nodeCfg)
	connA := &fakeConn{
		getConfigResp:   &nodev1.GetConfigResponse{Config: nodeCfg},
		applyConfigResp: &nodev1.ApplyConfigResponse{Generation: 2, RequiresReboot: true},
	}
	svc := New(certsTestStore(), dialFor(map[string]*fakeConn{"A": connA}))
	client := wireClient(t, svc, authz.Identity{CN: "admin@acme.example", Level: authz.LevelAdmin})

	got, err := client.GetNodeConfig(context.Background(), connect.NewRequest(&fleetv1.GetNodeConfigRequest{NodeName: "A"}))
	if err != nil {
		t.Fatalf("GetNodeConfig over JSON: %v", err)
	}
	requireSameJSON(t, "read (node -> manager -> web)", got.Msg.GetConfig(), wireProtocolConfigJSON)

	if _, err := client.ApplyNodeConfig(context.Background(), connect.NewRequest(&fleetv1.ApplyNodeConfigRequest{
		NodeName: "A", Config: got.Msg.GetConfig(),
	})); err != nil {
		t.Fatalf("ApplyNodeConfig over JSON: %v", err)
	}
	requireSameJSON(t, "apply (web -> manager -> node)", connA.gotApplyConfig, wireProtocolConfigJSON)
}
