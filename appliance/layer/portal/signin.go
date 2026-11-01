// SPDX-FileCopyrightText: 2026 Olivares.AI
// SPDX-License-Identifier: AGPL-3.0-only
// Additional terms under AGPL-3.0-only section 7(a) disclaim warranty and limit liability: see DISCLAIMER.md at the repository root.

package portal

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/olivaresai/olivares/appliance/layer/portal/auth"
)

var signInPage = template.Must(template.New("sign-in").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in — Appliance Console</title></head>
<body><main><h1>Sign in</h1><p>{{.Statement}}</p>
{{if .Offer}}<h2>OS sign-in verified</h2><p>{{.Offer.Login}} authenticated for this request. Each repair needs fresh authentication.</p>
<ul>{{range .Offer.Verbs}}<li>{{.}}</li>{{end}}</ul>
{{else if .Repair}}<form method="post" action="/sign-in">
<p><label for="login">OS account</label> <input id="login" name="login" autocomplete="username" required></p>
<p><label for="password">Password</label> <input id="password" name="password" type="password" autocomplete="current-password" required></p>
<button type="submit">Sign in</button></form>
{{else}}<p>Use the product console on port 8443 when it answers. Local recovery remains on tty1.</p>{{end}}
</main></body></html>`))

type signInView struct {
	Statement string
	Repair    bool
	Offer     *auth.Offer
}

func (h *protectedNetwork) signIn(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.URL.RawQuery != "" {
		h.refuse(w, http.StatusBadRequest, "repair.sign-in")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.refuse(w, http.StatusMethodNotAllowed, "repair.sign-in")
		return
	}
	if h.access.records == nil || h.measurePAM == nil {
		h.refuse(w, http.StatusServiceUnavailable, "repair.sign-in")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	state := auth.NewSelector(h.access.product, auth.NewPAM(h.measurePAM(ctx))).Select()
	view := signInView{Statement: state.Statement(), Repair: state.Mode == auth.ProductDownRepair}
	if r.Method == http.MethodPost {
		if state.Mode != auth.ProductDownRepair || ctx.Err() != nil || h.requestPAM == nil {
			code := http.StatusServiceUnavailable
			if state.Mode == auth.ProductUp {
				code = http.StatusConflict
			}
			if !h.record("anonymous", "repair.sign-in", "refused", state.Mode) {
				code = http.StatusServiceUnavailable
			}
			http.Error(w, state.Statement(), code)
			return
		}
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" || (params["charset"] != "" && params["charset"] != "utf-8") {
			h.refuse(w, http.StatusUnsupportedMediaType, "repair.sign-in")
			return
		}
		if !h.record("anonymous", "repair.sign-in", "unknown", state.Mode) {
			http.Error(w, "Sign-in audit unavailable. Local recovery remains on tty1.", http.StatusServiceUnavailable)
			return
		}
		login, password, err := signInCredentials(r.Body)
		defer clear(password) // Includes paths on which the selector never calls Start.
		var offer auth.Offer
		if err == nil && ctx.Err() == nil {
			var stack auth.Stack
			stack, err = h.requestPAM(ctx, login, password)
			if err == nil && ctx.Err() == nil {
				offer, err = auth.NewSelector(h.access.product, auth.NewPAM(stack)).SignIn(login)
			}
		}
		actor, outcome := "anonymous", "refused"
		if err == nil && ctx.Err() == nil {
			actor, outcome = "os-account:"+offer.Login, "performed"
		} else if errors.Is(err, auth.ErrProductIsTheRoute) {
			state.Mode = auth.ProductUp
		} else if errors.Is(err, auth.ErrConsoleRemains) {
			state.Mode = auth.Unavailable
		}
		if !h.record(actor, "repair.sign-in", outcome, state.Mode) {
			http.Error(w, "Sign-in audit unavailable. Local recovery remains on tty1.", http.StatusServiceUnavailable)
			return
		}
		if ctx.Err() != nil {
			http.Error(w, "Sign-in refused.", http.StatusServiceUnavailable)
			return
		}
		if outcome != "performed" {
			code := http.StatusForbidden
			if state.Mode == auth.ProductUp {
				code = http.StatusConflict
			}
			if state.Mode == auth.Unavailable || ctx.Err() != nil {
				code = http.StatusServiceUnavailable
			}
			http.Error(w, "Sign-in refused.", code)
			return
		}
		view.Offer = &offer
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	_ = signInPage.Execute(w, view)
}

// Decode the closed browser form in owned bytes: net/url.ParseQuery would keep
// the password in immutable strings. Clear the entire encoded body before PAM
// receives the sole decoded copy, which Start clears before it returns.
func signInCredentials(body io.Reader) (string, []byte, error) {
	var buffer [(8 << 10) + 1]byte
	defer clear(buffer[:])
	n, err := io.ReadFull(body, buffer[:])
	if n > 8<<10 || (err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
		return "", nil, auth.ErrNotAdmitted
	}
	data := buffer[:n]
	fields := bytes.Split(data, []byte{'&'})
	if len(fields) != 2 {
		return "", nil, auth.ErrNotAdmitted
	}
	var login, password []byte
	for _, field := range fields {
		key, value, ok := bytes.Cut(field, []byte{'='})
		if !ok {
			return "", nil, auth.ErrNotAdmitted
		}
		value, err = decodeSignInValue(value)
		if err != nil {
			return "", nil, err
		}
		switch {
		case bytes.Equal(key, []byte("login")):
			if login != nil {
				return "", nil, auth.ErrNotAdmitted
			}
			login = value
		case bytes.Equal(key, []byte("password")):
			if password != nil {
				return "", nil, auth.ErrNotAdmitted
			}
			password = value
		default:
			return "", nil, auth.ErrNotAdmitted
		}
	}
	if len(login) == 0 || len(password) == 0 {
		return "", nil, auth.ErrNotAdmitted
	}
	return string(login), bytes.Clone(password), nil
}

func decodeSignInValue(value []byte) ([]byte, error) {
	n := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '+':
			value[n] = ' '
		case '%':
			if i+2 >= len(value) {
				return nil, auth.ErrNotAdmitted
			}
			if _, err := hex.Decode(value[n:n+1], value[i+1:i+3]); err != nil {
				return nil, auth.ErrNotAdmitted
			}
			i += 2
		default:
			value[n] = value[i]
		}
		n++
	}
	return value[:n], nil
}
