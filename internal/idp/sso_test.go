package idp

import (
	"errors"
	"testing"

	"github.com/crewjam/saml"
)

func roundTrip(t *testing.T, p *IdP, sp *saml.ServiceProvider, binding string) (*saml.Assertion, *PostForm) {
	t.Helper()
	build := redirectRequest
	if binding == saml.HTTPPostBinding {
		build = postRequest
	}
	r, reqID := build(t, sp, "fleet-relay")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	form, err := p.Respond(req, testIdentity())
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	assertion, err := sp.ParseResponse(acsPost(form), []string{reqID})
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) {
			t.Fatalf("SP rejected response: %v", ire.PrivateErr)
		}
		t.Fatalf("SP rejected response: %v", err)
	}
	return assertion, form
}

// TestSSORoundTripBothBindings is the phase 2 acceptance test: a crewjam
// ServiceProvider (as used by Fleet) sends an AuthnRequest and validates the
// Response, including both signatures, audience and recipient.
func TestSSORoundTripBothBindings(t *testing.T) {
	p := newTestIdP(t, nil)
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			sp := testSP(t, p, adminEntityID, adminACS)
			a, form := roundTrip(t, p, sp, binding)

			if form.Action != adminACS {
				t.Errorf("form action = %q, want %q", form.Action, adminACS)
			}
			if form.RelayState != "fleet-relay" {
				t.Errorf("RelayState = %q", form.RelayState)
			}
			if a.Subject.NameID.Value != testUserEmail {
				t.Errorf("NameID = %q", a.Subject.NameID.Value)
			}
			if a.Subject.NameID.Format != string(saml.EmailAddressNameIDFormat) {
				t.Errorf("NameID format = %q", a.Subject.NameID.Format)
			}
			if got := a.Conditions.AudienceRestrictions; len(got) != 1 || got[0].Audience.Value != adminEntityID {
				t.Errorf("audience = %+v, want exactly %q", got, adminEntityID)
			}
			sc := a.Subject.SubjectConfirmations[0].SubjectConfirmationData
			if sc.Recipient != adminACS {
				t.Errorf("Recipient = %q", sc.Recipient)
			}
			if sc.Address != "" {
				t.Errorf("SubjectConfirmationData Address leaked client IP %q", sc.Address)
			}
			if a.Issuer.Value != testBase+MetadataPath {
				t.Errorf("Issuer = %q", a.Issuer.Value)
			}
			if a.AuthnStatements[0].SessionIndex != testSessionIdx {
				t.Errorf("SessionIndex = %q", a.AuthnStatements[0].SessionIndex)
			}
		})
	}
}

func TestSSORoundTripSecondSP(t *testing.T) {
	p := newTestIdP(t, nil)
	sp := testSP(t, p, mdmEntityID, mdmACS)
	a, form := roundTrip(t, p, sp, saml.HTTPRedirectBinding)
	if form.Action != mdmACS {
		t.Errorf("action = %q", form.Action)
	}
	if got := a.Conditions.AudienceRestrictions; len(got) != 1 || got[0].Audience.Value != mdmEntityID {
		t.Errorf("audience = %+v, want only %q", got, mdmEntityID)
	}
}

// TestAssertionForSPARejectedBySPB: an assertion minted for one SP must not
// validate at another SP, even one sharing the IdP and ACS host.
func TestAssertionForSPARejectedBySPB(t *testing.T) {
	p := newTestIdP(t, nil)
	spA := testSP(t, p, adminEntityID, adminACS)
	r, reqID := redirectRequest(t, spA, "")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	form, err := p.Respond(req, testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	// SP B configured with B's entity ID but (to isolate the audience check)
	// accepting A's ACS URL as its own.
	spB := testSP(t, p, mdmEntityID, adminACS)
	_, err = spB.ParseResponse(acsPost(form), []string{reqID})
	var ire *saml.InvalidResponseError
	if !errors.As(err, &ire) {
		t.Fatalf("SP B accepted SP A's assertion (err=%v)", err)
	}
	if got := ire.PrivateErr.Error(); !containsAll(got, "AudienceRestriction", mdmEntityID) {
		t.Errorf("rejection reason = %q, want audience failure", got)
	}
}
