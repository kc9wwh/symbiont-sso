package idp

import (
	"fmt"
	"net/http"
	"os"
	"slices"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

// ServiceProviders is an immutable registry of configured service providers,
// indexed by ID and entity ID. It implements saml.ServiceProviderProvider.
type ServiceProviders struct {
	byID       map[string]*config.ServiceProvider
	byEntityID map[string]*config.ServiceProvider
	metadata   map[string]*saml.EntityDescriptor // by entity ID
	ordered    []*config.ServiceProvider
}

var _ saml.ServiceProviderProvider = (*ServiceProviders)(nil)

// NewServiceProviders builds the registry. The input must already be
// validated (config.ParseServiceProviders); duplicates are still rejected
// defensively.
func NewServiceProviders(sps []config.ServiceProvider) (*ServiceProviders, error) {
	r := &ServiceProviders{
		byID:       make(map[string]*config.ServiceProvider, len(sps)),
		byEntityID: make(map[string]*config.ServiceProvider, len(sps)),
		metadata:   make(map[string]*saml.EntityDescriptor, len(sps)),
	}
	for i := range sps {
		sp := &sps[i]
		if _, dup := r.byID[sp.ID]; dup {
			return nil, fmt.Errorf("duplicate service provider id %q", sp.ID)
		}
		if _, dup := r.byEntityID[sp.EntityID]; dup {
			return nil, fmt.Errorf("duplicate service provider entity_id %q", sp.EntityID)
		}
		r.byID[sp.ID] = sp
		r.byEntityID[sp.EntityID] = sp
		r.metadata[sp.EntityID] = spMetadata(sp)
		r.ordered = append(r.ordered, sp)
	}
	return r, nil
}

// ByID returns the service provider with the given slug.
func (r *ServiceProviders) ByID(id string) (*config.ServiceProvider, bool) {
	sp, ok := r.byID[id]
	return sp, ok
}

// ByEntityID returns the service provider with the given entity ID.
func (r *ServiceProviders) ByEntityID(entityID string) (*config.ServiceProvider, bool) {
	sp, ok := r.byEntityID[entityID]
	return sp, ok
}

// All returns service providers in configuration order.
func (r *ServiceProviders) All() []*config.ServiceProvider { return slices.Clone(r.ordered) }

// GetServiceProvider implements saml.ServiceProviderProvider. Unknown entity
// IDs return os.ErrNotExist, as the interface requires.
func (r *ServiceProviders) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	md, ok := r.metadata[entityID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return md, nil
}

// spMetadata synthesises SP metadata from configuration. All ACS endpoints
// use the HTTP-POST binding (the only response binding crewjam's IdP
// supports). The IdP-initiated ACS, when enabled, is listed first and marked
// isDefault, so even crewjam code paths that pick "the first POST ACS" or
// "the default ACS" land on it.
func spMetadata(sp *config.ServiceProvider) *saml.EntityDescriptor {
	urls := slices.Clone(sp.ACSURLs)
	if sp.IDPInitiatedEnabled && sp.IDPInitiatedACSURL != "" {
		if i := slices.Index(urls, sp.IDPInitiatedACSURL); i > 0 {
			urls = slices.Delete(urls, i, i+1)
			urls = slices.Insert(urls, 0, sp.IDPInitiatedACSURL)
		}
	}
	acs := make([]saml.IndexedEndpoint, len(urls))
	for i, u := range urls {
		isDefault := i == 0
		acs[i] = saml.IndexedEndpoint{
			Binding:   saml.HTTPPostBinding,
			Location:  u,
			Index:     i,
			IsDefault: &isDefault,
		}
	}
	return &saml.EntityDescriptor{
		EntityID: sp.EntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				},
				NameIDFormats: []saml.NameIDFormat{saml.EmailAddressNameIDFormat},
			},
			AssertionConsumerServices: acs,
		}},
	}
}
