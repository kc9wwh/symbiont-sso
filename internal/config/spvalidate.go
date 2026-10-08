package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/kc9wwh/symbiont-sso/internal/mapping"
)

var spIDPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

const (
	maxSPIDLen          = 64
	maxDisplayNameRunes = 100
	// fleetMDMACSSuffix identifies Fleet's MDM end-user authentication ACS,
	// which only accepts SP-initiated responses.
	fleetMDMACSSuffix = "/api/v1/fleet/mdm/sso/callback"
)

type spValidator struct {
	problems []string
	warnings []string
}

func (v *spValidator) problemf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func isSpaceOrControl(r rune) bool { return r <= ' ' || r == 0x7f }

func (v *spValidator) validate(f *spFile) []ServiceProvider {
	if len(f.ServiceProviders) == 0 {
		v.problemf("define at least one entry under service_providers")
		return nil
	}
	ids := map[string]int{}
	entityIDs := map[string]string{}
	acsOwners := map[string]string{}
	out := make([]ServiceProvider, 0, len(f.ServiceProviders))

	for i, e := range f.ServiceProviders {
		where := fmt.Sprintf("service_providers[%d]", i)
		if e.ID != "" {
			where = fmt.Sprintf("service provider %q", e.ID)
		}
		sp := ServiceProvider{ID: e.ID, DisplayName: strings.TrimSpace(e.DisplayName), EntityID: e.EntityID}

		switch {
		case e.ID == "":
			v.problemf("%s: id is required", where)
		case len(e.ID) > maxSPIDLen || !spIDPattern.MatchString(e.ID):
			v.problemf("%s: id must match ^[a-z0-9-]+$ (max %d characters)", where, maxSPIDLen)
		default:
			if prev, dup := ids[e.ID]; dup {
				v.problemf("%s: id is also used by service_providers[%d]; ids must be unique", where, prev)
			}
			ids[e.ID] = i
		}
		if sp.DisplayName == "" {
			sp.DisplayName = e.ID
		}
		if utf8.RuneCountInString(sp.DisplayName) > maxDisplayNameRunes {
			v.problemf("%s: display_name must be at most %d characters", where, maxDisplayNameRunes)
		}

		switch {
		case e.EntityID == "":
			v.problemf("%s: entity_id is required (it must equal the entity ID configured in the service provider)", where)
		case strings.ContainsFunc(e.EntityID, isSpaceOrControl):
			v.problemf("%s: entity_id must not contain whitespace or control characters", where)
		default:
			if prev, dup := entityIDs[e.EntityID]; dup {
				v.problemf("%s: entity_id %q is also used by %s; entity IDs must be unique", where, e.EntityID, prev)
			}
			entityIDs[e.EntityID] = where
		}

		sp.ACSURLs = v.acsURLs(where, e.ACSURLs, acsOwners)
		v.idpInitiated(where, e.IDPInitiated, &sp)
		sp.Access = v.access(where, e.Access)

		sp.FleetRoleValidation = e.FleetRoleValidation == nil || *e.FleetRoleValidation
		sp.PassthroughPrefixes = e.PassthroughPrefixes
		sp.Attributes = e.Attributes
		for _, p := range mapping.Validate(e.Attributes, e.PassthroughPrefixes, sp.FleetRoleValidation) {
			v.problemf("%s: %s", where, p)
		}
		// Unsolicited responses only ever go to idp_initiated.acs_url, so
		// that is the URL to check.
		if sp.IDPInitiatedEnabled && strings.HasSuffix(sp.IDPInitiatedACSURL, fleetMDMACSSuffix) {
			v.warnings = append(v.warnings, fmt.Sprintf(
				"%s: idp_initiated is enabled for %q: Fleet's MDM end-user authentication requires SP-initiated login; "+
					"IdP-initiated responses to this ACS will be rejected", where, sp.IDPInitiatedACSURL))
		}
		if sp.ID != "" && usesPlaceholderDomain(&sp) {
			v.warnings = append(v.warnings, placeholderWarning(sp.ID))
		}
		if sp.Access.AllowAll && mapping.HasFleetRoleAttributes(e.Attributes, e.PassthroughPrefixes) {
			v.warnings = append(v.warnings, fmt.Sprintf(
				"%s: access.allow_all is true and Fleet role attributes are configured; every user who can sign in "+
					"to the identity provider can be provisioned in Fleet with a mapped or default role", where))
		}
		out = append(out, sp)
	}
	return out
}

func (v *spValidator) acsURLs(where string, raw []string, owners map[string]string) []string {
	if len(raw) == 0 {
		v.problemf("%s: acs_urls must list at least one URL", where)
		return nil
	}
	var out []string
	for j, u := range raw {
		if _, err := ParsePublicURL(u); err != nil {
			v.problemf("%s: acs_urls[%d] %v", where, j, err)
			continue
		}
		if slices.Contains(out, u) {
			v.problemf("%s: acs_urls[%d] %q is listed twice", where, j, u)
			continue
		}
		if prev, dup := owners[u]; dup {
			v.problemf("%s: acs_urls[%d] %q is also listed under %s; an ACS URL may belong to only one service provider",
				where, j, u, prev)
		}
		owners[u] = where
		out = append(out, u)
	}
	return out
}

func (v *spValidator) idpInitiated(where string, raw *spIDPInitiated, sp *ServiceProvider) {
	if raw == nil {
		return // disabled unless explicitly enabled
	}
	sp.IDPInitiatedEnabled = raw.Enabled != nil && *raw.Enabled
	if !sp.IDPInitiatedEnabled {
		if raw.ACSURL != "" {
			v.problemf("%s: idp_initiated.acs_url is set but idp_initiated.enabled is not true", where)
		}
		return
	}
	if raw.ACSURL == "" {
		if len(sp.ACSURLs) > 0 {
			sp.IDPInitiatedACSURL = sp.ACSURLs[0]
		}
		return
	}
	if !slices.Contains(sp.ACSURLs, raw.ACSURL) {
		v.problemf("%s: idp_initiated.acs_url %q must be one of acs_urls", where, raw.ACSURL)
		return
	}
	sp.IDPInitiatedACSURL = raw.ACSURL
}
