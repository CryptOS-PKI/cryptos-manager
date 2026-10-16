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
	"time"
)

// skipError is how a step says a write path was not exercised on purpose (a
// prerequisite the lab run didn't supply), as distinct from a real failure.
// errors.As finds it regardless of wrapping, so a step can return
// fmt.Errorf("%w: ...", skip) and still be classified as skipped.
type skipError struct{ reason string }

func (e *skipError) Error() string { return e.reason }

// skip builds a skipError with reason.
func skip(reason string) error { return &skipError{reason: reason} }

// step is one write path this run exercises. run does the API call(s) and
// the on-the-node check, and returns a short human-readable summary of what
// it proved on success. Returning a *skipError (directly or wrapped) marks
// the step skipped rather than failed.
type step struct {
	name string
	run  func(ctx context.Context) (detail string, err error)
}

type stepStatus int

const (
	stepOK stepStatus = iota
	stepSkipped
	stepFailed
)

func (s stepStatus) String() string {
	switch s {
	case stepOK:
		return "ok"
	case stepSkipped:
		return "skip"
	case stepFailed:
		return "FAIL"
	default:
		return "?"
	}
}

type stepResult struct {
	name   string
	status stepStatus
	detail string
}

// runSteps runs every step in order under its own timeout, so one hung call
// can't stall the rest of the matrix. It never stops early: a step that
// depends on an earlier one's state (certificate issuance needs the profile
// the profile step created) simply fails or skips on its own terms, and a
// later, independent step still gets its chance to run and be reported.
// report is called once per step as it finishes, for live progress.
func runSteps(ctx context.Context, steps []step, timeout time.Duration, report func(stepResult)) []stepResult {
	results := make([]stepResult, 0, len(steps))
	for _, s := range steps {
		stepCtx, cancel := context.WithTimeout(ctx, timeout)
		detail, err := s.run(stepCtx)
		cancel()

		res := stepResult{name: s.name}
		var se *skipError
		switch {
		case errors.As(err, &se):
			res.status = stepSkipped
			res.detail = se.reason
		case err != nil:
			res.status = stepFailed
			res.detail = err.Error()
		default:
			res.status = stepOK
			res.detail = detail
		}
		results = append(results, res)
		if report != nil {
			report(res)
		}
	}
	return results
}

// anyFailed reports whether any result is a real failure (not a skip).
func anyFailed(results []stepResult) bool {
	for _, r := range results {
		if r.status == stepFailed {
			return true
		}
	}
	return false
}

// summary renders a one-line-per-step report, in run order.
func summary(results []stepResult) string {
	out := ""
	for _, r := range results {
		out += fmt.Sprintf("%-5s %-28s %s\n", r.status, r.name, r.detail)
	}
	return out
}

// resultRecord is one step result as writeResults records it.
type resultRecord struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// writeResults writes results to path as a JSON array, in run order, with
// each detail redacted the same way this script's own output is, so a
// harness can report every step on its own without parsing the log.
func writeResults(path string, results []stepResult, red *redactor) error {
	records := make([]resultRecord, 0, len(results))
	for _, r := range results {
		records = append(records, resultRecord{Name: r.name, Status: r.status.String(), Detail: red.line(r.detail)})
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
