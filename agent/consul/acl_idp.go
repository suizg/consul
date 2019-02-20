package consul

import (
	"fmt"
	"strings"

	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/structs"
)

type IdentityProviderValidator interface {
	// ValidateToken takes raw user-provided IdP metadata and ensures it is
	// sane, provably correct, and currently valid. Relevant identifying data
	// is extracted and returned for immediate use by the role binding process.
	//
	// Depending upon the provider, it may make sense to use these calls to
	// continue to extend the life of the underlying token
	//
	// TODO(rb): cook up stock errors that the caller may care about
	ValidateLogin(*LoginValidationRequest) (*LoginValidationResponse, error)

	AvailableFields() []string
}

type LoginValidationRequest struct {
	// Token is a bearer token, such as a JWT that is identity provider specific.
	Token string
}

type LoginValidationResponse struct {
	// Fields stores IdP specific metadata suitable for the Role Binding process.
	Fields map[string]string
}

type idpValidatorEntry struct {
	Validator   IdentityProviderValidator
	ModifyIndex uint64 // the raft index when this last changed
}

func (s *Server) purgeIdentityProviderValidators() {
	s.aclIDPValidatorLock.Lock()
	s.aclIDPValidators = make(map[string]*idpValidatorEntry)
	s.aclIDPValidatorLock.Unlock()
}

func (s *Server) getIdentityProviderValidator(name string) (uint64, IdentityProviderValidator, bool) {
	s.aclIDPValidatorLock.RLock()
	defer s.aclIDPValidatorLock.RUnlock()

	if s.aclIDPValidators != nil {
		v, ok := s.aclIDPValidators[name]
		if ok {
			return v.ModifyIndex, v.Validator, true
		}
	}
	return 0, nil, false
}

func (s *Server) getOrReplaceIdentityProviderValidator(name string, idx uint64, v IdentityProviderValidator) IdentityProviderValidator {
	s.aclIDPValidatorLock.Lock()
	defer s.aclIDPValidatorLock.Unlock()

	if s.aclIDPValidators == nil {
		s.aclIDPValidators = make(map[string]*idpValidatorEntry)
	}

	prev, ok := s.aclIDPValidators[name]
	if ok {
		if prev.ModifyIndex >= idx {
			return prev.Validator
		}
	}

	s.logger.Printf("[INFO] acl: updating cached identity provider validator for %q", name)

	s.aclIDPValidators[name] = &idpValidatorEntry{
		Validator:   v,
		ModifyIndex: idx,
	}
	return v
}

func isValidIdentityProviderField(idpType, name string) bool {
	var allowed []string // this list will be VERY short

	switch idpType {
	case "kubernetes":
		allowed = k8sAvailableFields
	}

	for _, f := range allowed {
		if f == name {
			return true
		}
	}

	return false
}

func findUnknownIdentityProviderFields(idpType string, names []string) []string {
	if len(names) == 0 {
		return nil
	}

	var (
		allowed []string // this list will be VERY short
		unknown []string
	)

	switch idpType {
	case "kubernetes":
		allowed = k8sAvailableFields
	}

	for _, name := range names {
		found := false
		for _, f := range allowed {
			if f == name {
				found = true
				break
			}
		}
		if !found {
			unknown = append(unknown, name)
		}
	}

	return unknown
}

// TODO: rename
func (s *Server) validateIdentityProviderSpecificFields(idp *structs.ACLIdentityProvider) error {
	switch idp.Type {
	case "kubernetes":
		return k8sValidateIdentityProvider(idp)
	default:
		return nil
	}
}

func (s *Server) getIdentityProvider(idpType, name string) (IdentityProviderValidator, error) {
	idx, idp, err := s.fsm.State().ACLIdentityProviderGetByName(nil, name)
	if err != nil {
		return nil, err
	} else if idp == nil {
		return nil, acl.ErrNotFound
	}

	if idp.Type != idpType {
		return nil, fmt.Errorf("identity provider with name %q is of type %q not %q", name, idp.Type, idpType)
	}

	if prevIdx, v, ok := s.getIdentityProviderValidator(name); ok && idx <= prevIdx {
		return v, nil
	}

	var v IdentityProviderValidator

	switch idp.Type {
	case "kubernetes":
		v, err = newK8SIdentityProviderValidator(idp)
	default:
		return nil, fmt.Errorf("identity provider with name %q found with unknown type %q", name, idp.Type)
	}

	if err == nil && s.aclIDPValidatorCreateTestHook != nil {
		v, err = s.aclIDPValidatorCreateTestHook(v)
	}

	if err != nil {
		return nil, fmt.Errorf("identity provider validator for %q could not be initialized: %v", idp.Name, err)
	}

	v = s.getOrReplaceIdentityProviderValidator(name, idx, v)

	return v, nil
}

func (s *Server) evaluateRoleBindings(idpName string, validationResp *LoginValidationResponse) ([]structs.ACLTokenRoleLink, error) {
	if idpName == "" {
		return nil, nil
	}

	// Only fetch rules that are relevant for this idp.
	_, rules, err := s.fsm.State().ACLRoleBindingRuleList(nil, idpName)
	if err != nil {
		return nil, err
	} else if len(rules) == 0 {
		return nil, nil
	}

	var matchingRules []*structs.ACLRoleBindingRule
	for _, rule := range rules {
		if doesRoleBindingRuleMatch(rule, validationResp.Fields) {
			matchingRules = append(matchingRules, rule)
		}
	}
	if len(matchingRules) == 0 {
		return nil, nil
	}

	var roleLinks []structs.ACLTokenRoleLink

	for _, rule := range matchingRules {
		roleName, err := simpleInterpolateVars(rule.RoleName, validationResp.Fields)
		if err != nil {
			return nil, fmt.Errorf("cannot compute role name for bind target: %v", err)
		}

		var link structs.ACLTokenRoleLink
		if rule.MustExist {
			// We are opting out of synthetic roles, so set Name here. This
			// will let the normal machinery take care of resolving the Name to
			// ID during the token persistence operation.
			link.Name = roleName
		} else {
			// This is how you declare a synthetic role mapping. Note that
			// if a role with this name is present during a token resolve operation
			// that real role may still take effect, it's just not REQUIRED in the way
			// that MustExist=true implies.
			link.BoundName = roleName
		}
		roleLinks = append(roleLinks, link)
	}

	return roleLinks, nil
}

func doesRoleBindingRuleMatch(rule *structs.ACLRoleBindingRule, fields map[string]string) bool {
	if len(rule.Match) == 0 {
		return true // catch-all
	}

	if len(fields) == 0 {
		return false // cannot match
	}

	// Only one of these must match for it to apply.
	ruleMatches := false
	for _, match := range rule.Match {
		if len(match.Selector) == 0 {
			continue // makes no sense
		}

		// ALL of these must match for it to apply.
		selectorMatches := true
		for _, entry := range match.Selector {
			lhs, rhs, ok := parseExactMatchSelector(entry)
			if !ok {
				selectorMatches = false // Fails to match if invalid.
				break
			}
			val, ok := fields[lhs]
			if !ok || val != rhs {
				selectorMatches = false // missing field or wrong value
				break
			}
		}

		if selectorMatches {
			ruleMatches = true
			break
		}
	}

	return ruleMatches
}

func parseExactMatchSelector(s string) (lhs, rhs string, ok bool) {
	parts := strings.Split(s, "=")
	if len(parts) != 2 {
		return "", "", false
	}
	lhs, rhs = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if lhs == "" || rhs == "" {
		return "", "", false
	}
	return lhs, rhs, true
}
