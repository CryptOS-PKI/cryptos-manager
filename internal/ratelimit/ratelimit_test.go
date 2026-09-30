package ratelimit

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
	"net/http/httptest"
	"testing"
	"time"
)

func TestFailures_BlocksAfterTheBurstPerClient(t *testing.T) {
	f := NewFailures(5, time.Minute)
	for i := 0; i < 5; i++ {
		if f.Blocked("192.0.2.1") {
			t.Fatalf("blocked after %d failures, want a burst of 5", i)
		}
		f.Fail("192.0.2.1")
	}
	if !f.Blocked("192.0.2.1") {
		t.Fatal("not blocked after 5 failures")
	}
	if f.Blocked("192.0.2.2") {
		t.Fatal("another client is blocked by the first client's failures")
	}
}

func TestFailures_SuccessesSpendNothing(t *testing.T) {
	f := NewFailures(1, time.Hour)
	for i := 0; i < 100; i++ {
		if f.Blocked("192.0.2.1") {
			t.Fatal("a client that never failed is blocked")
		}
	}
}

func TestFailures_RefillsOverTime(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f := NewFailures(2, time.Minute)
	f.now = func() time.Time { return now }
	f.Fail("192.0.2.1")
	f.Fail("192.0.2.1")
	if !f.Blocked("192.0.2.1") {
		t.Fatal("not blocked after the burst")
	}
	now = now.Add(61 * time.Second)
	if f.Blocked("192.0.2.1") {
		t.Fatal("still blocked after one refill interval")
	}
}

func TestWindow_TripsAtTheLimitWithinTheWindowAndResets(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	w := NewWindow(3, time.Hour)
	w.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		if w.Fail() {
			t.Fatalf("tripped at failure %d, before the limit of 3", i+1)
		}
	}
	if !w.Fail() {
		t.Fatal("the third failure within the hour didn't trip")
	}
	if w.Fail() {
		t.Fatal("tripped again straight after a trip; the count should start over")
	}
}

func TestWindow_ForgetsFailuresOlderThanTheWindow(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	w := NewWindow(3, time.Hour)
	w.now = func() time.Time { return now }
	w.Fail()
	w.Fail()
	now = now.Add(61 * time.Minute)
	if w.Fail() {
		t.Fatal("failures older than the window still counted")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.7:4431"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := ClientIP(r); got != "192.0.2.7" {
		t.Fatalf("ClientIP = %q, want the peer address, never X-Forwarded-For", got)
	}
	r.RemoteAddr = "not-an-addr"
	if got := ClientIP(r); got != "not-an-addr" {
		t.Fatalf("ClientIP = %q, want the raw RemoteAddr when it has no port", got)
	}
}
