package operatorca

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

import "testing"

func TestLRU_EvictsTheLeastRecentlyUsed(t *testing.T) {
	c := newLRU[string, int](2)
	c.put("a", 1)
	c.put("b", 2)
	if _, ok := c.get("a"); !ok {
		t.Fatal("a missing")
	}
	c.put("c", 3)
	if _, ok := c.get("b"); ok {
		t.Fatal("b survived although it was the least recently used")
	}
	if v, ok := c.get("a"); !ok || v != 1 {
		t.Fatalf("a = %d, %v", v, ok)
	}
	c.put("a", 4)
	if v, _ := c.get("a"); v != 4 || c.len() != 2 {
		t.Fatalf("a = %d, len %d", v, c.len())
	}
	c.remove(func(k string) bool { return k == "a" })
	if _, ok := c.get("a"); ok || c.len() != 1 {
		t.Fatal("remove didn't remove")
	}
}
