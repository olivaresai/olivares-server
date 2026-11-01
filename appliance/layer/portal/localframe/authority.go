// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package localframe

import (
	"encoding/hex"
	"strings"
	"time"
)

// AuthorityRequest carries an exact act, never an identity claim. Its one FD
// is the original accepted human socket, verified independently by the engine.
type AuthorityRequest struct {
	Task         string `json:"task"`
	Target       string `json:"target"`
	IntentDigest string `json:"intent_digest"`
}

// AuthorityReply names the current actor for this exact act and finite window.
// It is neither a credential nor a cached permission.
type AuthorityReply struct {
	Task         string    `json:"task"`
	Target       string    `json:"target"`
	IntentDigest string    `json:"intent_digest"`
	Actor        string    `json:"actor"`
	Mode         string    `json:"mode"`
	ValidUntil   time.Time `json:"valid_until"`
}

func validAuthorityText(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && !strings.ContainsAny(s, "\x00\r\n")
}

func validAuthorityRequest(r AuthorityRequest) bool {
	digest, err := hex.DecodeString(r.IntentDigest)
	return validAuthorityText(r.Task, 128) && validAuthorityText(r.Target, 4096) &&
		err == nil && len(digest) == 32 && strings.ToLower(r.IntentDigest) == r.IntentDigest
}

func validAuthorityReply(r AuthorityReply) bool {
	return validAuthorityRequest(AuthorityRequest{r.Task, r.Target, r.IntentDigest}) &&
		validAuthorityText(r.Actor, 256) && r.Mode == "product-up" && !r.ValidUntil.IsZero()
}

func parseAuthorityRecord(data []byte) (Record, error) {
	return parseOperationRecord(data, true)
}
