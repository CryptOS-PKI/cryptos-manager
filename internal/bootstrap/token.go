package bootstrap

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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/CryptOS-PKI/cryptos-manager/internal/store"
)

// Bootstrap token and session formats and lifetimes.
const (
	// TokenPrefix starts every bootstrap token, so secret scanners can spot
	// a pasted one.
	TokenPrefix = "fos_boot_"
	// SessionPrefix starts every bootstrap session secret.
	SessionPrefix = "fos_bsess_"
	// SessionHeader carries the session secret. It is never a cookie and
	// never in a URL.
	SessionHeader = "Fleetos-Bootstrap-Session"

	// TokenTTL is how long a token can start a session.
	TokenTTL = time.Hour
	// SessionIdle ends a session that goes this long without a call.
	SessionIdle = 15 * time.Minute
	// SessionMax ends a session this long after it started.
	SessionMax = time.Hour

	secretBytes     = 32
	tokenBodyLength = 52 // 256 bits in base32
	tokenGroup      = 4
)

// TokenLockName is the advisory lock a replica holds while it keeps the
// bootstrap token live. The break-glass reset takes it too, so it can't run
// beside a manager that has first run open.
const TokenLockName = "fleetos.bootstrap_token"

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// crockford encodes b in Crockford base32, most significant bit first, with
// no padding.
func crockford(b []byte) string {
	var (
		out  strings.Builder
		acc  uint
		bits uint
	)
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(crockfordAlphabet[(acc>>bits)&0x1f])
		}
	}
	if bits > 0 {
		out.WriteByte(crockfordAlphabet[(acc<<(5-bits))&0x1f])
	}
	return out.String()
}

// NewToken returns a new bootstrap token: the prefix and 256 random bits in
// Crockford base32, grouped in fours for reading aloud.
func NewToken(r io.Reader) (string, error) {
	b := make([]byte, secretBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("bootstrap: token randomness: %w", err)
	}
	body := crockford(b)
	groups := make([]string, 0, len(body)/tokenGroup)
	for i := 0; i < len(body); i += tokenGroup {
		groups = append(groups, body[i:i+tokenGroup])
	}
	return TokenPrefix + strings.Join(groups, "-"), nil
}

// CanonicalToken brings a token as an operator typed or pasted it to the one
// form that is hashed: surrounding space, case and the group dashes don't
// matter, and the letters Crockford base32 reads as digits (O, I, L) are
// taken as those digits. It reports false for anything that can't be a
// token.
func CanonicalToken(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < len(TokenPrefix) || !strings.EqualFold(s[:len(TokenPrefix)], TokenPrefix) {
		return "", false
	}
	var body strings.Builder
	for _, c := range strings.ToUpper(s[len(TokenPrefix):]) {
		switch {
		case c == '-':
			continue
		case c == 'O':
			c = '0'
		case c == 'I' || c == 'L':
			c = '1'
		case !strings.ContainsRune(crockfordAlphabet, c):
			return "", false
		}
		body.WriteRune(c)
	}
	if body.Len() != tokenBodyLength {
		return "", false
	}
	return TokenPrefix + body.String(), true
}

// HashSecret is the lowercase hex SHA-256 of a token or session secret: the
// only form either is stored in.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newSessionSecret(r io.Reader) (string, error) {
	b := make([]byte, secretBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("bootstrap: session randomness: %w", err)
	}
	return SessionPrefix + crockford(b), nil
}

// tokens issues bootstrap tokens and prints each once, in a banner. The
// replica that holds the token lock issues one at start and whenever the
// live one expires; any replica issues one when a session starts or the
// failure cap trips, so a used token is replaced at once.
type tokens struct {
	st     store.Bootstrap
	lock   func(ctx context.Context, name string) (func(), bool, error)
	now    func() time.Time
	rand   io.Reader
	print  func([]string)
	server ServerInfo
	logf   func(string, ...any)

	mu      sync.Mutex
	release func()
}

// issue stores a new token, retiring the earlier one, and prints it. why,
// when set, says in the banner why a new token was needed.
func (t *tokens) issue(ctx context.Context, why string) error {
	tok, err := NewToken(t.rand)
	if err != nil {
		return err
	}
	canon, _ := CanonicalToken(tok)
	now := t.now().UTC()
	expires := now.Add(TokenTTL)
	if err := t.st.IssueBootstrapToken(ctx, store.BootstrapToken{Hash: HashSecret(canon), CreatedAt: now, ExpiresAt: expires}); err != nil {
		return err
	}
	lines := []string{"manager: ================= FLEETOS FIRST RUN ================="}
	if why != "" {
		lines = append(lines, "manager: new bootstrap token: "+why)
	}
	lines = append(lines,
		fmt.Sprintf("manager: bootstrap token: %s  (single use, expires %s)", tok, expires.Format(time.RFC3339)),
		fmt.Sprintf("manager: server certificate SHA-256: %s  (check this in the browser first)", t.server.SHA256),
		"manager: open https://<this-host>/ and enter this token to register your operator CA certificate",
		"manager: ======================================================",
	)
	t.print(lines)
	return nil
}

// holdLock takes the token lock if this replica doesn't hold it yet, and
// reports whether it holds it.
func (t *tokens) holdLock(ctx context.Context) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.release != nil {
		return true
	}
	release, ok, err := t.lock(ctx, TokenLockName)
	if err != nil {
		t.logf("bootstrap: can't take the token lock: %v", err)
		return false
	}
	if ok {
		t.release = release
	}
	return ok
}

// stop gives up the token lock.
func (t *tokens) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.release != nil {
		t.release()
		t.release = nil
	}
}

// ensure issues a token when this replica holds the lock and no token is
// live. force issues one even when a token is live (a fresh start, whose
// earlier token was printed by a process that is gone).
func (t *tokens) ensure(ctx context.Context, force bool) {
	if !t.holdLock(ctx) {
		return
	}
	if !force {
		_, live, err := t.st.LiveBootstrapToken(ctx, t.now())
		if err != nil {
			t.logf("bootstrap: can't read the bootstrap token: %v", err)
			return
		}
		if live {
			return
		}
	}
	why := ""
	if !force {
		why = "the previous token expired"
	}
	if err := t.issue(ctx, why); err != nil {
		if errors.Is(err, store.ErrBootstrapClosed) {
			t.stop()
			return
		}
		t.logf("bootstrap: can't issue a bootstrap token: %v", err)
	}
}
