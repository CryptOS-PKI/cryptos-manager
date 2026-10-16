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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunStepsClassifiesOkSkipAndFail(t *testing.T) {
	steps := []step{
		{name: "a", run: func(ctx context.Context) (string, error) { return "did a", nil }},
		{name: "b", run: func(ctx context.Context) (string, error) { return "", skip("no spare node configured") }},
		{name: "c", run: func(ctx context.Context) (string, error) { return "", errors.New("boom") }},
	}
	results := runSteps(context.Background(), steps, time.Second, nil)
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	if results[0].status != stepOK || results[0].detail != "did a" {
		t.Errorf("results[0] = %+v", results[0])
	}
	if results[1].status != stepSkipped || results[1].detail != "no spare node configured" {
		t.Errorf("results[1] = %+v", results[1])
	}
	if results[2].status != stepFailed || results[2].detail != "boom" {
		t.Errorf("results[2] = %+v", results[2])
	}
}

func TestRunStepsContinuesPastAFailure(t *testing.T) {
	var ran []string
	steps := []step{
		{name: "a", run: func(ctx context.Context) (string, error) { ran = append(ran, "a"); return "", errors.New("boom") }},
		{name: "b", run: func(ctx context.Context) (string, error) { ran = append(ran, "b"); return "ok", nil }},
	}
	runSteps(context.Background(), steps, time.Second, nil)
	if len(ran) != 2 || ran[0] != "a" || ran[1] != "b" {
		t.Errorf("ran = %v, want both steps to run in order", ran)
	}
}

func TestRunStepsWrappedSkipIsStillASkip(t *testing.T) {
	steps := []step{
		{name: "a", run: func(ctx context.Context) (string, error) {
			return "", fmt.Errorf("checking prerequisite: %w", skip("no E2E_IMAGE_URL configured"))
		}},
	}
	results := runSteps(context.Background(), steps, time.Second, nil)
	if results[0].status != stepSkipped {
		t.Errorf("status = %v, want skipped for a wrapped skip error", results[0].status)
	}
	if results[0].detail != "no E2E_IMAGE_URL configured" {
		t.Errorf("detail = %q, want the skip reason unwrapped", results[0].detail)
	}
}

func TestRunStepsEnforcesPerStepTimeout(t *testing.T) {
	steps := []step{
		{name: "slow", run: func(ctx context.Context) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		}},
	}
	start := time.Now()
	results := runSteps(context.Background(), steps, 20*time.Millisecond, nil)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("runSteps took %v, want it bounded by the per-step timeout", elapsed)
	}
	if results[0].status != stepFailed {
		t.Errorf("status = %v, want failed on a timed-out step", results[0].status)
	}
}

func TestRunStepsReportsEachResultAsItFinishes(t *testing.T) {
	var seen []string
	steps := []step{
		{name: "a", run: func(ctx context.Context) (string, error) { return "", nil }},
		{name: "b", run: func(ctx context.Context) (string, error) { return "", skip("x") }},
	}
	runSteps(context.Background(), steps, time.Second, func(r stepResult) { seen = append(seen, r.name) })
	if len(seen) != 2 || seen[0] != "a" || seen[1] != "b" {
		t.Errorf("seen = %v, want both names reported in order", seen)
	}
}

func TestAnyFailed(t *testing.T) {
	ok := []stepResult{{status: stepOK}, {status: stepSkipped}}
	if anyFailed(ok) {
		t.Error("anyFailed(ok/skip only) = true, want false")
	}
	withFail := []stepResult{{status: stepOK}, {status: stepFailed}}
	if !anyFailed(withFail) {
		t.Error("anyFailed(with a failure) = false, want true")
	}
}

func TestWriteResultsRecordsEveryStepRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	results := []stepResult{
		{name: "a", status: stepOK, detail: "did a on 10.1.2.3"},
		{name: "b", status: stepSkipped, detail: "no spare node configured"},
		{name: "c", status: stepFailed, detail: "dial node.example.org:4443: refused"},
	}
	if err := writeResults(path, results, newRedactor("node.example.org:4443")); err != nil {
		t.Fatalf("writeResults: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	var got []resultRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("results are not JSON: %v\n%s", err, data)
	}
	want := []resultRecord{
		{Name: "a", Status: "ok", Detail: "did a on [ipv4]"},
		{Name: "b", Status: "skip", Detail: "no spare node configured"},
		{Name: "c", Status: "FAIL", Detail: "dial [redacted]: refused"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestEscrowSourceDefaultsToThePrimary(t *testing.T) {
	cfg := config{Nodes: []nodeUnderTest{{Name: "int"}, {Name: "root"}}}
	s := newScenario(nil, cfg, nil, nil)
	got, err := s.escrowSource(cfg)
	if err != nil || got.Name != "int" {
		t.Errorf("escrowSource = %q, %v; want the primary int", got.Name, err)
	}
	cfg.EscrowNode = "root"
	if got, err := s.escrowSource(cfg); err != nil || got.Name != "root" {
		t.Errorf("escrowSource with E2E_ESCROW_NODE = %q, %v; want root", got.Name, err)
	}
	cfg.EscrowNode = "missing"
	if _, err := s.escrowSource(cfg); err == nil {
		t.Error("escrowSource with an unknown E2E_ESCROW_NODE: want an error")
	}
}
