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

import (
	"container/list"
	"sync"
)

// lru is a small, concurrency-safe least-recently-used cache.
type lru[K comparable, V any] struct {
	mu    sync.Mutex
	max   int
	order *list.List
	items map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](max int) *lru[K, V] {
	return &lru[K, V]{max: max, order: list.New(), items: map[K]*list.Element{}}
}

func (c *lru[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.order.MoveToFront(e)
		return e.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

func (c *lru[K, V]) put(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.Value.(*lruEntry[K, V]).val = v
		c.order.MoveToFront(e)
		return
	}
	c.items[k] = c.order.PushFront(&lruEntry[K, V]{key: k, val: v})
	if c.order.Len() > c.max {
		oldest := c.order.Back()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruEntry[K, V]).key)
	}
}

func (c *lru[K, V]) remove(match func(K) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.items {
		if match(k) {
			c.order.Remove(e)
			delete(c.items, k)
		}
	}
}

func (c *lru[K, V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
