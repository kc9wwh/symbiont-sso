package oidcrp

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Result is a verified login.
type Result struct {
	Subject string
	// Claims are the merged ID token + userinfo claims. Never log these.
	Claims map[string]any
}

// Upstream error categories (logged; users see generic text).
const (
	CategoryTokenExchange   = "token_exchange_failed"
	CategoryIDToken         = "id_token_invalid"
	CategoryNonce           = "nonce_mismatch"
	CategoryUserinfo        = "userinfo_failed"
	CategorySubjectMismatch = "userinfo_sub_mismatch"
)

// Error is an upstream login or identity failure. Err may include provider
// responses; log it at debug level only.
type Error struct {
	Category string
	Err      error
}

func (e *Error) Error() string { return e.Category + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Exchange redeems code with the PKCE verifier, verifies the ID token
// (signature, iss, aud, exp) and nonce, optionally merges userinfo, and
// returns the merged claims. ID token claims win on conflict, and the
// userinfo sub must equal the ID token sub.
func (c *Client) Exchange(ctx context.Context, code, verifier, nonce string) (*Result, error) {
	hctx := oidc.ClientContext(ctx, c.httpClient)
	tok, err := c.oauth.Exchange(hctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, &Error{Category: CategoryTokenExchange, Err: err}
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, &Error{Category: CategoryIDToken, Err: errors.New("token response has no id_token")}
	}
	idt, err := c.verifier.Verify(hctx, raw)
	if err != nil {
		return nil, &Error{Category: CategoryIDToken, Err: err}
	}
	if nonce == "" || idt.Nonce != nonce {
		return nil, &Error{Category: CategoryNonce, Err: errors.New("ID token nonce does not match the login request")}
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return nil, &Error{Category: CategoryIDToken, Err: err}
	}
	if !c.opts.FetchUserinfo {
		return &Result{Subject: idt.Subject, Claims: claims}, nil
	}

	ui, err := c.provider.UserInfo(hctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return nil, &Error{Category: CategoryUserinfo, Err: err}
	}
	// OIDC Core 5.3.2: userinfo MUST return sub, and it MUST match.
	switch {
	case ui.Subject == "":
		return nil, &Error{Category: CategorySubjectMismatch, Err: errors.New("userinfo response has no sub claim")}
	case ui.Subject != idt.Subject:
		return nil, &Error{Category: CategorySubjectMismatch, Err: errors.New("userinfo sub does not match ID token sub")}
	}
	extra := map[string]any{}
	if err := ui.Claims(&extra); err != nil {
		return nil, &Error{Category: CategoryUserinfo, Err: err}
	}
	for k, v := range extra {
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}
	return &Result{Subject: idt.Subject, Claims: claims}, nil
}
