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
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	"github.com/smallstep/scep"

	fleetv1 "github.com/CryptOS-PKI/cryptos-manager/gen/go/cryptos/fleet/v1"
	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// scepStep exercises MintNodeScepChallenge, ListNodeScepChallenges and
// RevokeNodeScepChallenge. A node only accepts a mint when its own stored
// config already names at least one Pki.scep.profiles entry: this script
// does not configure one for the primary node itself, since doing so needs a
// reboot before the listener (and so the mint) would actually work, and the
// config-push step already proves a config round trip. So this step runs
// for real only against a node the lab gate (or an earlier manual
// config-push) already enabled SCEP on; otherwise it skips with that reason.
//
// A device enrolment through a challenge, and its approval or rejection, is
// scepEnrolStep.
func (s *scenario) scepStep() step {
	return step{name: "scep/mint-list-revoke-challenge", run: func(ctx context.Context) (string, error) {
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		id, name := s.nodeRef(primary)

		c, err := dialNode(primary)
		if err != nil {
			return "", err
		}
		cfg, err := c.GetConfig(ctx)
		_ = c.Close()
		if err != nil {
			return "", fmt.Errorf("GetConfig on %s: %w", primary.Name, err)
		}
		profiles := cfg.GetConfig().GetPki().GetScep().GetProfiles()
		if len(profiles) == 0 {
			return "", skip(fmt.Sprintf("%s has no pki.scep.profiles configured; nothing to mint a challenge under", primary.Name))
		}
		scepProfile := profiles[0].GetProfile()

		minted, err := s.fleet.MintNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.MintNodeScepChallengeRequest{
			NodeId: id, NodeName: name, Profile: scepProfile,
		}))
		if err != nil {
			return "", fmt.Errorf("MintNodeScepChallenge: %w", err)
		}
		challengeID := minted.Msg.GetChallenge().GetId()

		listed, err := s.fleet.ListNodeScepChallenges(ctx, connect.NewRequest(&fleetv1.ListNodeScepChallengesRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("ListNodeScepChallenges: %w", err)
		}
		if !scepChallengeListed(listed.Msg.GetChallenges(), challengeID) {
			return "", fmt.Errorf("%s's ListNodeScepChallenges does not carry the challenge MintNodeScepChallenge just minted", primary.Name)
		}

		if _, err := s.fleet.RevokeNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.RevokeNodeScepChallengeRequest{
			NodeId: id, NodeName: name, Id: challengeID,
		})); err != nil {
			return "", fmt.Errorf("RevokeNodeScepChallenge: %w", err)
		}

		after, err := s.fleet.ListNodeScepChallenges(ctx, connect.NewRequest(&fleetv1.ListNodeScepChallengesRequest{NodeId: id, NodeName: name}))
		if err != nil {
			return "", fmt.Errorf("ListNodeScepChallenges (after revoke): %w", err)
		}
		if scepChallengeListed(after.Msg.GetChallenges(), challengeID) {
			return "", fmt.Errorf("%s's ListNodeScepChallenges still carries the challenge after RevokeNodeScepChallenge", primary.Name)
		}
		return fmt.Sprintf("minted and revoked a scep challenge on %s under profile %s", primary.Name, scepProfile), nil
	}}
}

func scepChallengeListed(items []*fleetv1.NodeScepChallenge, id string) bool {
	for _, c := range items {
		if c.GetId() == id {
			return true
		}
	}
	return false
}

// scepEnrolStep drives two real RFC 8894 device enrolments (scepdevice.go)
// against the primary node's SCEP listener, each authorized by a challenge
// minted through the manager, and decides them through the manager: one
// approved, one rejected. Both decisions are checked on the node itself and
// from the device's side: the approved device collects its certificate with
// CertPoll and the node's ListIssued carries it; the rejected device's
// CertPoll is answered FAILURE and the node's queue no longer holds it.
//
// It needs E2E_SCEP_URL, the listener's address as this script reaches it,
// and a pki.scep.profiles entry with require_approval on the node, since an
// enrolment under a profile without it is issued on arrival and leaves
// nothing to approve or reject. Without either it skips with the reason.
func (s *scenario) scepEnrolStep(cfg config) step {
	return step{name: "scep/enrol-approve-reject", run: func(ctx context.Context) (string, error) {
		if cfg.ScepURL == "" {
			return "", skip("no E2E_SCEP_URL configured; a device enrolment needs the node's SCEP listener address")
		}
		primary, err := s.primary()
		if err != nil {
			return "", err
		}
		c, err := dialNode(primary)
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()
		got, err := c.GetConfig(ctx)
		if err != nil {
			return "", fmt.Errorf("GetConfig on %s: %w", primary.Name, err)
		}
		profile, suffix, ok := scepApprovalProfile(got.GetConfig().GetPki().GetScep())
		if !ok {
			return "", skip(fmt.Sprintf("%s has no pki.scep.profiles entry with require_approval and an allowed identifier suffix; nothing would wait for a decision", primary.Name))
		}

		approved, err := s.scepEnrolAndDecide(ctx, c, primary, cfg.ScepURL, profile, suffix, true)
		if err != nil {
			return "", fmt.Errorf("approve path: %w", err)
		}
		if _, err := s.scepEnrolAndDecide(ctx, c, primary, cfg.ScepURL, profile, suffix, false); err != nil {
			return "", fmt.Errorf("reject path: %w", err)
		}
		return fmt.Sprintf("a SCEP device enrolled on %s under %s, approved and issued serial %s; a second was rejected and refused", primary.Name, profile, approved), nil
	}}
}

// scepApprovalProfile picks the first SCEP profile that holds enrolments
// for approval, with the first allowed identifier suffix to name the device
// under.
func scepApprovalProfile(sc *nodev1.Scep) (profile, suffix string, ok bool) {
	if len(sc.GetAllowedIdentifierSuffixes()) == 0 {
		return "", "", false
	}
	for _, p := range sc.GetProfiles() {
		if p.GetRequireApproval() {
			return p.GetProfile(), strings.TrimPrefix(sc.GetAllowedIdentifierSuffixes()[0], "."), true
		}
	}
	return "", "", false
}

// scepEnrolAndDecide mints a challenge through the manager, enrols a fresh
// device with it, finds the queued enrolment through the manager, approves
// or rejects it, and checks the outcome from the device and on the node. It
// returns the issued serial on approval.
func (s *scenario) scepEnrolAndDecide(ctx context.Context, c nodeChecker, n nodeUnderTest, scepURL, profile, suffix string, approve bool) (string, error) {
	id, name := s.nodeRef(n)
	minted, err := s.fleet.MintNodeScepChallenge(ctx, connect.NewRequest(&fleetv1.MintNodeScepChallengeRequest{
		NodeId: id, NodeName: name, Profile: profile,
	}))
	if err != nil {
		return "", fmt.Errorf("MintNodeScepChallenge: %w", err)
	}

	tag := make([]byte, 4)
	if _, err := rand.Read(tag); err != nil {
		return "", err
	}
	verb := map[bool]string{true: "approve", false: "reject"}[approve]
	cn := fmt.Sprintf("scep-%s-%s.%s", verb, hex.EncodeToString(tag), suffix)

	dev := newSCEPDevice(scepURL, &http.Client{Timeout: 30 * time.Second})
	if err := dev.GetCACert(ctx); err != nil {
		return "", err
	}
	status, _, failInfo, err := dev.Enroll(ctx, pkix.Name{CommonName: cn}, minted.Msg.GetChallengePassword())
	if err != nil {
		return "", err
	}
	if status != scep.PENDING {
		return "", fmt.Errorf("PKCSReq for %s answered status %s (failInfo %q), want PENDING under a require_approval profile", cn, status, failInfo)
	}

	listed, err := s.fleet.ListNodeScepEnrollments(ctx, connect.NewRequest(&fleetv1.ListNodeScepEnrollmentsRequest{
		NodeId: id, NodeName: name, Profile: profile,
	}))
	if err != nil {
		return "", fmt.Errorf("ListNodeScepEnrollments: %w", err)
	}
	enrollmentID := findScepEnrollment(listed.Msg.GetEnrollments(), dev.TransactionID(), cn)
	if enrollmentID == "" {
		return "", fmt.Errorf("ListNodeScepEnrollments does not carry the enrolment for %s (transaction %s)", cn, dev.TransactionID())
	}

	if !approve {
		if _, err := s.fleet.RejectNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.RejectNodeScepEnrollmentRequest{
			NodeId: id, NodeName: name, Id: enrollmentID, Reason: "e2e reject-path exercise",
		})); err != nil {
			return "", fmt.Errorf("RejectNodeScepEnrollment: %w", err)
		}
		status, cert, _, err := dev.PollCert(ctx)
		if err != nil {
			return "", err
		}
		if status != scep.FAILURE || cert != nil {
			return "", fmt.Errorf("CertPoll after the rejection answered status %s, want FAILURE with no certificate", status)
		}
		queue, err := c.ListScepEnrollments(ctx, profile)
		if err != nil {
			return "", fmt.Errorf("ListScepEnrollments on %s: %w", n.Name, err)
		}
		for _, e := range queue.GetEnrollments() {
			if e.GetId() == enrollmentID {
				return "", fmt.Errorf("%s still queues enrolment %s after RejectNodeScepEnrollment", n.Name, enrollmentID)
			}
		}
		return "", nil
	}

	decided, err := s.fleet.ApproveNodeScepEnrollment(ctx, connect.NewRequest(&fleetv1.ApproveNodeScepEnrollmentRequest{
		NodeId: id, NodeName: name, Id: enrollmentID,
	}))
	if err != nil {
		return "", fmt.Errorf("ApproveNodeScepEnrollment: %w", err)
	}
	serialHex := decided.Msg.GetSerialHex()
	status, cert, failInfo, err := dev.PollCert(ctx)
	if err != nil {
		return "", err
	}
	if status != scep.SUCCESS || cert == nil {
		return "", fmt.Errorf("CertPoll after the approval answered status %s (failInfo %q), want SUCCESS with a certificate", status, failInfo)
	}
	if !serialMatches(serialHex, cert.SerialNumber) {
		return "", fmt.Errorf("the device collected serial %x, but ApproveNodeScepEnrollment reported %s", cert.SerialNumber, serialHex)
	}
	if cert.Subject.CommonName != cn {
		return "", fmt.Errorf("the device collected a certificate for %q, want %q", cert.Subject.CommonName, cn)
	}
	if err := cert.CheckSignatureFrom(dev.ca); err != nil {
		return "", fmt.Errorf("the collected certificate is not signed by the node's CA: %w", err)
	}
	issued, err := c.ListIssued(ctx)
	if err != nil {
		return "", fmt.Errorf("ListIssued on %s: %w", n.Name, err)
	}
	if !issuedContains(issued.GetIssued(), cert.SerialNumber) {
		return "", fmt.Errorf("%s's own ListIssued does not carry the SCEP certificate %s", n.Name, serialHex)
	}
	return serialHex, nil
}

// nodeChecker is the part of the direct node client the SCEP step checks
// outcomes with.
type nodeChecker interface {
	ListIssued(ctx context.Context) (*nodev1.ListIssuedResponse, error)
	ListScepEnrollments(ctx context.Context, profile string) (*nodev1.ListScepEnrollmentsResponse, error)
}

// findScepEnrollment returns the id of the queued enrolment with the
// device's transactionID, or failing that the one whose subject names cn.
func findScepEnrollment(items []*fleetv1.NodeScepEnrollment, transactionID, cn string) string {
	for _, e := range items {
		if transactionID != "" && e.GetTransactionId() == transactionID {
			return e.GetId()
		}
	}
	for _, e := range items {
		if strings.Contains(e.GetSubjectDn(), "CN="+cn) {
			return e.GetId()
		}
	}
	return ""
}
