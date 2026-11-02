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
	"errors"
	"fmt"
	"time"

	redis "github.com/Bugs5382/go-redis"
	"github.com/CryptOS-PKI/cryptos-manager/internal/config"
	"github.com/CryptOS-PKI/cryptos-manager/internal/store/kv"
)

// What the health body says about the audit stream.
const (
	auditChainOK     = "ok"
	auditChainBroken = "broken"
)

// kvChecks is what the manager asks of a KV server before it serves.
type kvChecks interface {
	CheckPersistence(context.Context) (kv.Persistence, error)
	CheckAuditACL(context.Context) error
	VerifyAudit(context.Context) error
}

// checkKV refuses a server the manager can't keep its promises on: one with
// no persistence, or an account that could rewrite the audit stream. A chain
// that fails to verify doesn't stop the start: the manager still runs the
// fleet, what's left of the log is evidence, and health keeps saying so.
func checkKV(ctx context.Context, c kvChecks, logf func(string, ...any)) error {
	if _, err := c.CheckPersistence(ctx); err != nil {
		return err
	}
	if err := c.CheckAuditACL(ctx); err != nil {
		return err
	}
	if err := c.VerifyAudit(ctx); err != nil {
		if errors.Is(err, kv.ErrAuditChainBroken) {
			logf("manager: ERROR %v", err)
			return nil
		}
		return fmt.Errorf("verify the audit chain: %w", err)
	}
	return nil
}

// openKV connects, waiting for a server that isn't up yet the way the
// Postgres path does (see dbConnectWindow), and checks it.
func openKV(ctx context.Context, cfg config.Config, logf func(string, ...any)) (*kv.Store, error) {
	waitCtx, cancel := context.WithTimeout(ctx, dbConnectWindow)
	defer cancel()

	var st *kv.Store
	err := redis.WaitFor(waitCtx, func(ctx context.Context) error {
		s, err := kv.New(ctx, kv.Options{URL: cfg.Storage.KV.URL, CAFile: cfg.Storage.KV.CAFile})
		st = s
		return err
	}, redis.WithRetryHook(func(attempt int, err error, delay time.Duration) {
		logf("manager: the kv server isn't answering yet, attempt %d, retrying in %s: %v", attempt, delay, err)
	}))
	if err != nil {
		return nil, err
	}
	if err := checkKV(ctx, st, logf); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// kvDetail is the health report for a server in the given state: anything
// short of AOF and a chain that verifies works, but isn't the supported setup.
func kvDetail(p kv.Persistence, chainErr error) storageDetail {
	d := storageDetail{Persistence: string(p), AuditChain: auditChainOK, Degraded: p != kv.PersistenceAOF}
	if chainErr != nil {
		d.AuditChain, d.Degraded = auditChainBroken, true
	}
	return d
}

func kvHealth(st *kv.Store) storeHealth {
	return storeHealth{
		Mode:    config.StorageModeKV,
		Check:   st.Ping,
		Version: st.Version,
		Detail: func(ctx context.Context) storageDetail {
			return kvDetail(st.Persistence(ctx), st.AuditChainError())
		},
	}
}
