package config

import (
	"slices"
	"strings"
)

// access validates an SP's access block. A missing block is a startup error:
// access is denied by default and must be granted explicitly.
func (v *spValidator) access(where string, raw *spAccess) AccessPolicy {
	if raw == nil {
		v.problemf("%s: access block is required (access is denied by default); "+
			"set allow_groups, allow_emails, or allow_all: true", where)
		return AccessPolicy{}
	}
	p := AccessPolicy{AllowAll: raw.AllowAll != nil && *raw.AllowAll}
	hasLists := len(raw.AllowGroups) > 0 || len(raw.AllowEmails) > 0
	if p.AllowAll && hasLists {
		v.problemf("%s: access.allow_all cannot be combined with allow_groups or allow_emails", where)
		return p
	}
	if !p.AllowAll && !hasLists {
		v.problemf("%s: access must set at least one of allow_groups, allow_emails, or allow_all: true", where)
		return p
	}
	for j, g := range raw.AllowGroups {
		if g == "" || g != strings.TrimSpace(g) {
			v.problemf("%s: access.allow_groups[%d] must be a non-empty group name without surrounding whitespace", where, j)
			continue
		}
		if !slices.Contains(p.AllowGroups, g) {
			p.AllowGroups = append(p.AllowGroups, g)
		}
	}
	for j, e := range raw.AllowEmails {
		e = strings.ToLower(strings.TrimSpace(e))
		at := strings.LastIndexByte(e, '@')
		if at <= 0 || at == len(e)-1 || strings.Count(e, "@") != 1 || strings.ContainsFunc(e, isSpaceOrControl) {
			v.problemf("%s: access.allow_emails[%d] is not a valid email address", where, j)
			continue
		}
		if !slices.Contains(p.AllowEmails, e) {
			p.AllowEmails = append(p.AllowEmails, e)
		}
	}
	return p
}
