// Package idp is symbiont's SAML identity provider, built on crewjam/saml.
//
// Behaviour of crewjam/saml v0.5.1 that shaped this package (verified by
// reading the source and pinned by tests in this package):
//
//   - DefaultAssertionMaker emits a transient NameID and sets
//     SubjectConfirmationData/SubjectLocality Address to the client
//     RemoteAddr. We replace it (AssertionMaker) to emit an emailAddress
//     NameID and no addresses.
//   - MakeAssertionEl signs the Assertion and MakeResponse signs the
//     Response, so both are always signed. The default algorithm is
//     RSA-SHA1; we set RSA-SHA256.
//   - IdentityProvider.ServeSSO has no request size limit, panics on an
//     AuthnRequest without <Issuer>, logs via Printf, and renders an HTML
//     form with inline scripts that cannot carry a CSP nonce. We therefore
//     orchestrate SSO ourselves from crewjam's building blocks
//     (IdpAuthnRequest.Validate, PostBinding) and render our own form.
//   - ServeIDPInitiated picks the FIRST HTTP-POST ACS in SP metadata order
//     (isDefault is ignored). We avoid relying on that by setting the ACS
//     endpoint explicitly, and additionally list the IdP-initiated ACS first.
//   - Fleet (itself a crewjam SP) sends AuthnRequests with the HTTP-Redirect
//     binding, setting AssertionConsumerServiceURL and an emailAddress
//     NameIDPolicy. Both Redirect and POST bindings are accepted here.
package idp
