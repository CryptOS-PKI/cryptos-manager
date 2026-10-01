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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unicode"

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	"github.com/CryptOS-PKI/cryptos-manager/internal/auditlog"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// phaseAwaitingFingerprint is streamed, with the presented SHA-256, while an
// adoption waits for the operator to confirm the installed node's certificate.
const phaseAwaitingFingerprint = "awaiting-fingerprint-confirmation"

// confirmWait bounds how long an adoption waits for the operator to confirm
// the installed node's fingerprint. It is a var so tests can shrink it.
var confirmWait = 15 * time.Minute

// errFingerprintMismatch is what a waiting adoption receives when the
// operator confirms a fingerprint the node does not present.
var errFingerprintMismatch = errors.New("fleet: the confirmed fingerprint does not match the certificate the installed node presents; nothing was trusted or recorded. Find out what answered on the node's address before adopting again")

// pendingConfirm is one adoption waiting for its fingerprint confirmation.
type pendingConfirm struct {
	node      string
	endpoint  string
	presented string
	result    chan error
}

// adoptionWaits holds the adoptions waiting for a confirmation, keyed by
// adoption ID. It lives in the replica that runs the adoption stream.
type adoptionWaits struct {
	mu sync.Mutex
	m  map[string]*pendingConfirm
}

func (w *adoptionWaits) add(id string, p *pendingConfirm) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.m == nil {
		w.m = map[string]*pendingConfirm{}
	}
	w.m[id] = p
}

// take removes and returns the adoption waiting under id.
func (w *adoptionWaits) take(id string) (*pendingConfirm, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	p, ok := w.m[id]
	delete(w.m, id)
	return p, ok
}

// presented returns the fingerprint the adoption under id waits on, or "".
func (w *adoptionWaits) presented(id string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if p, ok := w.m[id]; ok {
		return p.presented
	}
	return ""
}

func newAdoptionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("fleet: newAdoptionID: %v", err))
	}
	return "adp-" + hex.EncodeToString(b)
}

// normalizeFingerprint drops colons and whitespace and lowercases, so a
// fingerprint copied from the console or openssl compares equal to hex.
func normalizeFingerprint(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ':' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// adoptSink builds the phase sink the AdoptNode handler streams through:
// every message carries the adoption ID, and the awaiting phase carries the
// presented fingerprint.
func (s *Service) adoptSink(id string, msg *fleetv1.AdoptNodeRequest, send func(*fleetv1.AdoptNodeResponse) error) phaseSink {
	return func(phase, detail string, done bool) error {
		resp := s.adoptResponse(msg, phase, detail, done)
		resp.AdoptionId = id
		if phase == phaseAwaitingFingerprint {
			resp.PresentedCertSha256 = s.adoptions.presented(id)
		}
		return send(resp)
	}
}

// awaitFingerprintConfirm streams the awaiting phase with presented and
// blocks until the operator confirms it through ConfirmAdoptionFingerprint,
// the wait expires, or the client goes away. Only a matching confirmation
// returns nil.
func (s *Service) awaitFingerprintConfirm(ctx context.Context, id, nodeName, endpoint, presented string, send phaseSink) error {
	p := &pendingConfirm{node: nodeName, endpoint: endpoint, presented: presented, result: make(chan error, 1)}
	s.adoptions.add(id, p)
	defer s.adoptions.take(id)
	log.Printf("fleet: adopt %s (%s): waiting up to %s for the operator to confirm the installed node's certificate sha256 %s", nodeName, id, confirmWait, presented)

	if err := send(phaseAwaitingFingerprint, fmt.Sprintf(
		"the node is back in running mode and presents certificate sha256 %s. Compare it with the Mgmt SHA-256 line on the node's console and confirm it to continue", presented), false); err != nil {
		return err
	}

	timer := time.NewTimer(confirmWait)
	defer timer.Stop()
	select {
	case err := <-p.result:
		if err != nil {
			log.Printf("fleet: adopt %s (%s): fingerprint refused: %v", nodeName, id, err)
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
		log.Printf("fleet: adopt %s (%s): fingerprint confirmed", nodeName, id)
		return nil
	case <-timer.C:
		log.Printf("fleet: adopt %s (%s): no fingerprint confirmation within %s", nodeName, id, confirmWait)
		return connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf(
			"fleet: the installed node's fingerprint was not confirmed within %s; nothing was trusted or recorded. Adopt the node again to resume", confirmWait))
	case <-ctx.Done():
		log.Printf("fleet: adopt %s (%s): the client went away while waiting for the fingerprint confirmation", nodeName, id)
		return connect.NewError(connect.CodeCanceled, fmt.Errorf("fleet: adoption stopped before the fingerprint was confirmed: %w", ctx.Err()))
	}
}

// ConfirmAdoptionFingerprint confirms the certificate an installed node
// presents, so the adoption waiting under adoption_id continues. The
// fingerprint must equal the presented one (case, colons and whitespace
// ignored); a mismatch fails the adoption and nothing is trusted or recorded.
// Admin-gated; both outcomes are audited.
func (s *Service) ConfirmAdoptionFingerprint(ctx context.Context, req *connect.Request[fleetv1.ConfirmAdoptionFingerprintRequest]) (*connect.Response[fleetv1.ConfirmAdoptionFingerprintResponse], error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	id := req.Msg.GetAdoptionId()
	confirmed := normalizeFingerprint(req.Msg.GetCertSha256())
	if id == "" || confirmed == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("fleet: adoption_id and cert_sha256 are required"))
	}
	p, ok := s.adoptions.take(id)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("fleet: no adoption %s is waiting for a fingerprint confirmation", id))
	}

	if confirmed != p.presented {
		p.result <- errFingerprintMismatch
		auditlog.Record(ctx, s.store, store.AuditEvent{
			ID:         newAuditID(),
			Kind:       "node-adoption-fingerprint-rejected",
			Outcome:    auditlog.OutcomeDenied,
			Summary:    fmt.Sprintf("Refused adoption of node %s at %s: confirmed sha256 %s, but the node presents %s", p.node, p.endpoint, confirmed, p.presented),
			TargetKind: "adoption",
			TargetPath: "/adoptions/" + id,
		})
		return nil, connect.NewError(connect.CodeInvalidArgument, errFingerprintMismatch)
	}

	p.result <- nil
	auditlog.Record(ctx, s.store, store.AuditEvent{
		ID:         newAuditID(),
		Kind:       "node-adoption-fingerprint-confirmed",
		Summary:    fmt.Sprintf("Confirmed certificate sha256 %s for the adoption of node %s at %s", p.presented, p.node, p.endpoint),
		TargetKind: "adoption",
		TargetPath: "/adoptions/" + id,
	})
	return connect.NewResponse(&fleetv1.ConfirmAdoptionFingerprintResponse{}), nil
}
