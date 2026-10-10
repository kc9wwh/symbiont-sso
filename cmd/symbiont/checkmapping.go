package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kc9wwh/symbiont-sso/internal/access"
	"github.com/kc9wwh/symbiont-sso/internal/config"
	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/mapping"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
)

const maxClaimsFileBytes = 1 << 20

// runCheckMapping implements `symbiont check-mapping`: it evaluates the
// access policy and attribute mapping of each service provider in a
// service provider file against a sample claims JSON file, using exactly
// the code path that decides real assertions (access.Decide).
//
// Exit codes: 0 every evaluated SP would issue an assertion; 1 at least one
// SP denies access or refuses the assertion; 3 invalid files.
func runCheckMapping(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-mapping", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "service provider file (as SYMBIONT_SP_CONFIG_FILE) (required)")
	claimsPath := fs.String("claims", "", "JSON file with sample OIDC claims (ID token + userinfo merged) (required)")
	spID := fs.String("sp", "", "evaluate only this service provider id")
	emailClaim := fs.String("email-claim", "email", "claim holding the email (as OIDC_EMAIL_CLAIM)")
	nameClaim := fs.String("name-claim", "name", "claim holding the display name (as OIDC_NAME_CLAIM)")
	groupsClaim := fs.String("groups-claim", "groups", "claim holding groups (as OIDC_GROUPS_CLAIM)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: symbiont check-mapping --file symbiont.yaml --claims claims.json [--sp fleet-admin]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *file == "" || *claimsPath == "" || fs.NArg() > 0 {
		fs.Usage()
		return exitUsage
	}

	sps, warnings, err := config.LoadServiceProviders(*file)
	if err != nil {
		printConfigError(stderr, *file, err)
		return exitConfig
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintf(stdout, "warning: %s\n", w)
	}
	claims, err := readClaims(*claimsPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", *claimsPath, err)
		return exitConfig
	}
	ident, err := oidcrp.ExtractIdentity(&oidcrp.Result{Claims: claims},
		oidcrp.ClaimNames{Email: *emailClaim, Name: *nameClaim, Groups: *groupsClaim}, oidcrp.Policy{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", *claimsPath, err)
		return exitConfig
	}
	_, _ = fmt.Fprintf(stdout, "identity: email=%s name=%q groups=%v\n", ident.Email, ident.Name, ident.Groups)
	_, _ = fmt.Fprintln(stdout, "note: global checks (email_verified, ALLOWED_EMAIL_DOMAINS) are not evaluated here")

	code, found := exitOK, false
	for i := range sps {
		sp := &sps[i]
		if *spID != "" && sp.ID != *spID {
			continue
		}
		found = true
		if !printDecision(stdout, sp, ident) {
			code = exitError
		}
	}
	if !found {
		_, _ = fmt.Fprintf(stderr, "no service provider with id %q in %s\n", *spID, *file)
		return exitUsage
	}
	return code
}

// printDecision prints one SP's outcome and reports whether an assertion
// would be issued.
func printDecision(w io.Writer, sp *config.ServiceProvider, ident *oidcrp.Identity) bool {
	_, _ = fmt.Fprintf(w, "\n[%s] %s (entity_id %s)\n", sp.ID, sp.DisplayName, sp.EntityID)
	dec, err := access.Decide(sp, access.Subject{Email: ident.Email, Groups: ident.Groups, Claims: ident.Claims})
	switch {
	case !dec.Allowed:
		_, _ = fmt.Fprintf(w, "  access: DENIED (%s)\n", dec.Reason)
		return false
	case err != nil:
		var me *mapping.Error
		if errors.As(err, &me) {
			_, _ = fmt.Fprintf(w, "  access: allowed\n  result: REJECTED (%s): %s\n", me.Category, me.Message)
		} else {
			_, _ = fmt.Fprintf(w, "  access: allowed\n  result: ERROR: %v\n", err)
		}
		return false
	}
	_, _ = fmt.Fprintf(w, "  access: allowed\n  attributes:\n")
	_, _ = fmt.Fprintf(w, "    %s = %s\n", idp.AttrEmail, ident.Email)
	if ident.Name != "" {
		_, _ = fmt.Fprintf(w, "    %s = %s\n", idp.AttrName, ident.Name)
	}
	for _, a := range dec.Mapping.Attributes {
		_, _ = fmt.Fprintf(w, "    %s = %s  (%s)\n", a.Name, a.Value, a.Source)
	}
	for _, n := range dec.Mapping.Notes {
		_, _ = fmt.Fprintf(w, "  note: %s\n", n)
	}
	return true
}

func readClaims(path string) (map[string]any, error) {
	f, err := os.Open(path) //nolint:gosec // G304: operator-supplied CLI path is the intended input
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, maxClaimsFileBytes))
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("invalid claims JSON (want an object): %w", err)
	}
	return claims, nil
}

func printConfigError(w io.Writer, file string, err error) {
	var cerr *config.Error
	if errors.As(err, &cerr) {
		_, _ = fmt.Fprintf(w, "%s: invalid configuration:\n  - %s\n", file, strings.Join(cerr.Problems, "\n  - "))
		return
	}
	_, _ = fmt.Fprintf(w, "%s: %v\n", file, err)
}
