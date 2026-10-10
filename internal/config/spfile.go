package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/kc9wwh/symbiont-sso/internal/mapping"
)

const maxSPFileBytes = 1 << 20

// ServiceProvider is a validated SAML service provider definition.
type ServiceProvider struct {
	// ID is a URL-safe slug used in /login/{id} and logs.
	ID string
	// DisplayName is shown on error pages.
	DisplayName string
	// EntityID is the SP's SAML entity ID (the AuthnRequest Issuer and the
	// assertion Audience).
	EntityID string
	// ACSURLs are the permitted Assertion Consumer Service URLs, in
	// configuration order.
	ACSURLs []string
	// IDPInitiatedEnabled enables GET /login/{id}.
	IDPInitiatedEnabled bool
	// IDPInitiatedACSURL receives unsolicited responses. Always one of ACSURLs.
	IDPInitiatedACSURL string
	// Access is the default-deny access policy, evaluated per assertion.
	Access AccessPolicy
	// FleetRoleValidation enables Fleet JIT role checks for this SP.
	FleetRoleValidation bool
	// PassthroughPrefixes copies matching OIDC claims verbatim.
	PassthroughPrefixes []string
	// Attributes are rule-based SAML attributes.
	Attributes []mapping.Attribute
}

// AccessPolicy decides who may receive an assertion for a service provider.
// Exactly one of AllowAll or (AllowGroups and/or AllowEmails) is set.
type AccessPolicy struct {
	AllowAll    bool
	AllowGroups []string
	// AllowEmails is lower-cased.
	AllowEmails []string
}

// Raw YAML schema. Pointers distinguish "absent" from zero values.
type spFile struct {
	ServiceProviders []spEntry `yaml:"service_providers"`
}

type spEntry struct {
	ID                  string              `yaml:"id"`
	DisplayName         string              `yaml:"display_name"`
	EntityID            string              `yaml:"entity_id"`
	ACSURLs             []string            `yaml:"acs_urls"`
	IDPInitiated        *spIDPInitiated     `yaml:"idp_initiated"`
	Access              *spAccess           `yaml:"access"`
	FleetRoleValidation *bool               `yaml:"fleet_role_validation"`
	PassthroughPrefixes []string            `yaml:"passthrough_prefixes"`
	Attributes          []mapping.Attribute `yaml:"attributes"`
}

type spIDPInitiated struct {
	Enabled *bool  `yaml:"enabled"`
	ACSURL  string `yaml:"acs_url"`
}

type spAccess struct {
	AllowGroups []string `yaml:"allow_groups"`
	AllowEmails []string `yaml:"allow_emails"`
	AllowAll    *bool    `yaml:"allow_all"`
}

// LoadServiceProviders reads and validates a service provider file. On
// failure it returns an *Error listing every problem. Warnings are
// non-fatal findings the caller should log.
func LoadServiceProviders(path string) (sps []ServiceProvider, warnings []string, err error) {
	data, err := readLimited(path, maxSPFileBytes)
	if err != nil {
		return nil, nil, &Error{Problems: []string{fmt.Sprintf("cannot read %q: %v", path, err)}}
	}
	return ParseServiceProviders(data)
}

// ParseServiceProviders validates service provider YAML.
func ParseServiceProviders(data []byte) ([]ServiceProvider, []string, error) {
	raw, err := decodeSPFile(data)
	if err != nil {
		return nil, nil, &Error{Problems: []string{err.Error()}}
	}
	v := &spValidator{}
	sps := v.validate(raw)
	if len(v.problems) > 0 {
		return nil, nil, &Error{Problems: v.problems}
	}
	return sps, v.warnings, nil
}

// decodeSPFile strictly decodes exactly one YAML document; unknown keys are
// errors so that typos (e.g. "acces:") cannot silently weaken policy.
func decodeSPFile(data []byte) (*spFile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f spFile
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("file is empty; define at least one entry under service_providers")
		}
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("file must contain a single YAML document")
	}
	return &f, nil
}
