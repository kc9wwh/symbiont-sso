package server

import "encoding/base64"

// LoginPathPrefix is the IdP-initiated login path prefix (/login/{sp_id}).
// The handler itself arrives in phase 4.
const LoginPathPrefix = "/login/"

func loginPath(spID string) string { return LoginPathPrefix + spID }

func encodeStd(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
