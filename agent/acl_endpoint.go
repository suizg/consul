package agent

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/structs"
)

// aclCreateResponse is used to wrap the ACL ID
type aclBootstrapResponse struct {
	ID string
	structs.ACLToken
}

// checkACLDisabled will return a standard response if ACLs are disabled. This
// returns true if they are disabled and we should not continue.
func (s *HTTPServer) checkACLDisabled(resp http.ResponseWriter, req *http.Request) bool {
	if s.agent.delegate.ACLsEnabled() {
		return false
	}

	resp.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(resp, "ACL support disabled")
	return true
}

// ACLBootstrap is used to perform a one-time ACL bootstrap operation on
// a cluster to get the first management token.
func (s *HTTPServer) ACLBootstrap(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	args := structs.DCSpecificRequest{
		Datacenter: s.agent.config.Datacenter,
	}

	legacy := false
	legacyStr := req.URL.Query().Get("legacy")
	if legacyStr != "" {
		legacy, _ = strconv.ParseBool(legacyStr)
	}

	if legacy && s.agent.delegate.UseLegacyACLs() {
		var out structs.ACL
		err := s.agent.RPC("ACL.Bootstrap", &args, &out)
		if err != nil {
			if strings.Contains(err.Error(), structs.ACLBootstrapNotAllowedErr.Error()) {
				resp.WriteHeader(http.StatusForbidden)
				fmt.Fprint(resp, acl.PermissionDeniedError{Cause: err.Error()}.Error())
				return nil, nil
			} else {
				return nil, err
			}
		}
		return &aclBootstrapResponse{ID: out.ID}, nil
	} else {
		var out structs.ACLToken
		err := s.agent.RPC("ACL.BootstrapTokens", &args, &out)
		if err != nil {
			if strings.Contains(err.Error(), structs.ACLBootstrapNotAllowedErr.Error()) {
				resp.WriteHeader(http.StatusForbidden)
				fmt.Fprint(resp, acl.PermissionDeniedError{Cause: err.Error()}.Error())
				return nil, nil
			} else {
				return nil, err
			}
		}
		return &aclBootstrapResponse{ID: out.SecretID, ACLToken: out}, nil
	}
}

func (s *HTTPServer) ACLReplicationStatus(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	// Note that we do not forward to the ACL DC here. This is a query for
	// any DC that's doing replication.
	args := structs.DCSpecificRequest{}
	s.parseSource(req, &args.Source)
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	// Make the request.
	var out structs.ACLReplicationStatus
	if err := s.agent.RPC("ACL.ReplicationStatus", &args, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *HTTPServer) ACLRulesTranslate(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var token string
	s.parseToken(req, &token)
	rule, err := s.agent.resolveToken(token)
	if err != nil {
		return nil, err
	}
	// Should this require lesser permissions? Really the only reason to require authorization at all is
	// to prevent external entities from DoS Consul with repeated rule translation requests
	if rule != nil && !rule.ACLRead() {
		return nil, acl.ErrPermissionDenied
	}

	policyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("Failed to read body: %v", err)}
	}

	translated, err := acl.TranslateLegacyRules(policyBytes)
	if err != nil {
		return nil, BadRequestError{Reason: err.Error()}
	}

	resp.Write(translated)
	return nil, nil
}

func (s *HTTPServer) ACLRulesTranslateLegacyToken(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	tokenID := strings.TrimPrefix(req.URL.Path, "/v1/acl/rules/translate/")
	if tokenID == "" {
		return nil, BadRequestError{Reason: "Missing token ID"}
	}

	args := structs.ACLTokenGetRequest{
		Datacenter:  s.agent.config.Datacenter,
		TokenID:     tokenID,
		TokenIDType: structs.ACLTokenAccessor,
	}
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	// Do not allow blocking
	args.QueryOptions.MinQueryIndex = 0

	var out structs.ACLTokenResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.TokenRead", &args, &out); err != nil {
		return nil, err
	}

	if out.Token == nil {
		return nil, acl.ErrNotFound
	}

	if out.Token.Rules == "" {
		return nil, fmt.Errorf("The specified token does not have any rules set")
	}

	translated, err := acl.TranslateLegacyRules([]byte(out.Token.Rules))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse legacy rules: %v", err)
	}

	resp.Write(translated)
	return nil, nil
}

func (s *HTTPServer) ACLPolicyList(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var args structs.ACLPolicyListRequest
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLPolicyListResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.PolicyList", &args, &out); err != nil {
		return nil, err
	}

	// make sure we return an array and not nil
	if out.Policies == nil {
		out.Policies = make(structs.ACLPolicyListStubs, 0)
	}

	return out.Policies, nil
}

func (s *HTTPServer) ACLPolicyCRUD(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var fn func(resp http.ResponseWriter, req *http.Request, policyID string) (interface{}, error)

	switch req.Method {
	case "GET":
		fn = s.ACLPolicyRead

	case "PUT":
		fn = s.ACLPolicyWrite

	case "DELETE":
		fn = s.ACLPolicyDelete

	default:
		return nil, MethodNotAllowedError{req.Method, []string{"GET", "PUT", "DELETE"}}
	}

	policyID := strings.TrimPrefix(req.URL.Path, "/v1/acl/policy/")
	if policyID == "" && req.Method != "PUT" {
		return nil, BadRequestError{Reason: "Missing policy ID"}
	}

	return fn(resp, req, policyID)
}

func (s *HTTPServer) ACLPolicyRead(resp http.ResponseWriter, req *http.Request, policyID string) (interface{}, error) {
	args := structs.ACLPolicyGetRequest{
		Datacenter: s.agent.config.Datacenter,
		PolicyID:   policyID,
	}
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLPolicyResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.PolicyRead", &args, &out); err != nil {
		return nil, err
	}

	if out.Policy == nil {
		return nil, acl.ErrNotFound
	}

	return out.Policy, nil
}

func (s *HTTPServer) ACLPolicyCreate(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	return s.ACLPolicyWrite(resp, req, "")
}

// fixTimeAndHashFields is used to help in decoding the ExpirationTTL, ExpirationTime, CreateTime, and Hash
// attributes from the ACL Token/Policy create/update requests. It is needed
// to help mapstructure decode things properly when decodeBody is used.
func fixTimeAndHashFields(raw interface{}) error {
	rawMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}

	if val, ok := rawMap["ExpirationTTL"]; ok {
		if sval, ok := val.(string); ok {
			d, err := time.ParseDuration(sval)
			if err != nil {
				return err
			}
			rawMap["ExpirationTTL"] = d
		}
	}

	if val, ok := rawMap["ExpirationTime"]; ok {
		if sval, ok := val.(string); ok {
			t, err := time.Parse(time.RFC3339, sval)
			if err != nil {
				return err
			}
			rawMap["ExpirationTime"] = t
		}
	}

	if val, ok := rawMap["CreateTime"]; ok {
		if sval, ok := val.(string); ok {
			t, err := time.Parse(time.RFC3339, sval)
			if err != nil {
				return err
			}
			rawMap["CreateTime"] = t
		}
	}

	if val, ok := rawMap["Hash"]; ok {
		if sval, ok := val.(string); ok {
			rawMap["Hash"] = []byte(sval)
		}
	}
	return nil
}

func (s *HTTPServer) ACLPolicyWrite(resp http.ResponseWriter, req *http.Request, policyID string) (interface{}, error) {
	args := structs.ACLPolicySetRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseToken(req, &args.Token)

	if err := decodeBody(req, &args.Policy, fixTimeAndHashFields); err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("Policy decoding failed: %v", err)}
	}

	args.Policy.Syntax = acl.SyntaxCurrent

	if args.Policy.ID != "" && args.Policy.ID != policyID {
		return nil, BadRequestError{Reason: "Policy ID in URL and payload do not match"}
	} else if args.Policy.ID == "" {
		args.Policy.ID = policyID
	}

	var out structs.ACLPolicy
	if err := s.agent.RPC("ACL.PolicySet", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLPolicyDelete(resp http.ResponseWriter, req *http.Request, policyID string) (interface{}, error) {
	args := structs.ACLPolicyDeleteRequest{
		Datacenter: s.agent.config.Datacenter,
		PolicyID:   policyID,
	}
	s.parseToken(req, &args.Token)

	var ignored string
	if err := s.agent.RPC("ACL.PolicyDelete", args, &ignored); err != nil {
		return nil, err
	}

	return true, nil
}

func (s *HTTPServer) ACLTokenList(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	args := &structs.ACLTokenListRequest{
		IncludeLocal:  true,
		IncludeGlobal: true,
	}
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	args.Policy = req.URL.Query().Get("policy")
	args.Role = req.URL.Query().Get("role")
	args.IDPName = req.URL.Query().Get("idp")

	var out structs.ACLTokenListResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.TokenList", &args, &out); err != nil {
		return nil, err
	}

	return out.Tokens, nil
}

func (s *HTTPServer) ACLTokenCRUD(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var fn func(resp http.ResponseWriter, req *http.Request, tokenID string) (interface{}, error)

	switch req.Method {
	case "GET":
		fn = s.ACLTokenGet

	case "PUT":
		fn = s.ACLTokenSet

	case "DELETE":
		fn = s.ACLTokenDelete

	default:
		return nil, MethodNotAllowedError{req.Method, []string{"GET", "PUT", "DELETE"}}
	}

	tokenID := strings.TrimPrefix(req.URL.Path, "/v1/acl/token/")
	if strings.HasSuffix(tokenID, "/clone") && req.Method == "PUT" {
		tokenID = tokenID[:len(tokenID)-6]
		fn = s.ACLTokenClone
	}
	if tokenID == "" && req.Method != "PUT" {
		return nil, BadRequestError{Reason: "Missing token ID"}
	}

	return fn(resp, req, tokenID)
}

func (s *HTTPServer) ACLTokenSelf(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	args := structs.ACLTokenGetRequest{
		TokenIDType: structs.ACLTokenSecret,
	}

	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	// copy the token parameter to the ID
	args.TokenID = args.Token

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLTokenResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.TokenRead", &args, &out); err != nil {
		return nil, err
	}

	if out.Token == nil {
		return nil, acl.ErrNotFound
	}

	return out.Token, nil
}

func (s *HTTPServer) ACLTokenCreate(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	return s.ACLTokenSet(resp, req, "")
}

func (s *HTTPServer) ACLTokenGet(resp http.ResponseWriter, req *http.Request, tokenID string) (interface{}, error) {
	args := structs.ACLTokenGetRequest{
		Datacenter:  s.agent.config.Datacenter,
		TokenID:     tokenID,
		TokenIDType: structs.ACLTokenAccessor,
	}

	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLTokenResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.TokenRead", &args, &out); err != nil {
		return nil, err
	}

	if out.Token == nil {
		return nil, acl.ErrNotFound
	}

	return out.Token, nil
}

func (s *HTTPServer) ACLTokenSet(resp http.ResponseWriter, req *http.Request, tokenID string) (interface{}, error) {
	args := structs.ACLTokenSetRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseToken(req, &args.Token)

	if err := decodeBody(req, &args.ACLToken, fixTimeAndHashFields); err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("Token decoding failed: %v", err)}
	}

	if args.ACLToken.AccessorID != "" && args.ACLToken.AccessorID != tokenID {
		return nil, BadRequestError{Reason: "Token Accessor ID in URL and payload do not match"}
	} else if args.ACLToken.AccessorID == "" {
		args.ACLToken.AccessorID = tokenID
	}

	var out structs.ACLToken
	if err := s.agent.RPC("ACL.TokenSet", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLTokenDelete(resp http.ResponseWriter, req *http.Request, tokenID string) (interface{}, error) {
	args := structs.ACLTokenDeleteRequest{
		Datacenter: s.agent.config.Datacenter,
		TokenID:    tokenID,
	}
	s.parseToken(req, &args.Token)

	var ignored string
	if err := s.agent.RPC("ACL.TokenDelete", args, &ignored); err != nil {
		return nil, err
	}
	return true, nil
}

func (s *HTTPServer) ACLTokenClone(resp http.ResponseWriter, req *http.Request, tokenID string) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	args := structs.ACLTokenSetRequest{
		Datacenter: s.agent.config.Datacenter,
	}

	if err := decodeBody(req, &args.ACLToken, fixTimeAndHashFields); err != nil && err.Error() != "EOF" {
		return nil, BadRequestError{Reason: fmt.Sprintf("Token decoding failed: %v", err)}
	}
	s.parseToken(req, &args.Token)

	// Set this for the ID to clone
	args.ACLToken.AccessorID = tokenID

	var out structs.ACLToken
	if err := s.agent.RPC("ACL.TokenClone", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLRoleList(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var args structs.ACLRoleListRequest
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	args.Policy = req.URL.Query().Get("policy")

	var out structs.ACLRoleListResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.RoleList", &args, &out); err != nil {
		return nil, err
	}

	// make sure we return an array and not nil
	if out.Roles == nil {
		out.Roles = make(structs.ACLRoleListStubs, 0)
	}

	return out.Roles, nil
}

func (s *HTTPServer) ACLRoleCRUD(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var fn func(resp http.ResponseWriter, req *http.Request, roleID string) (interface{}, error)

	switch req.Method {
	case "GET":
		fn = s.ACLRoleReadByID

	case "PUT":
		fn = s.ACLRoleWrite

	case "DELETE":
		fn = s.ACLRoleDelete

	default:
		return nil, MethodNotAllowedError{req.Method, []string{"GET", "PUT", "DELETE"}}
	}

	roleID := strings.TrimPrefix(req.URL.Path, "/v1/acl/role/")
	if roleID == "" && req.Method != "PUT" {
		return nil, BadRequestError{Reason: "Missing role ID"}
	}

	return fn(resp, req, roleID)
}

func (s *HTTPServer) ACLRoleReadByName(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	roleName := strings.TrimPrefix(req.URL.Path, "/v1/acl/role/name/")
	if roleName == "" {
		return nil, BadRequestError{Reason: "Missing role Name"}
	}

	return s.ACLRoleRead(resp, req, "", roleName)
}

func (s *HTTPServer) ACLRoleReadByID(resp http.ResponseWriter, req *http.Request, roleID string) (interface{}, error) {
	return s.ACLRoleRead(resp, req, roleID, "")
}

func (s *HTTPServer) ACLRoleRead(resp http.ResponseWriter, req *http.Request, roleID, roleName string) (interface{}, error) {
	args := structs.ACLRoleGetRequest{
		Datacenter: s.agent.config.Datacenter,
		RoleID:     roleID,
		RoleName:   roleName,
	}
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLRoleResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.RoleRead", &args, &out); err != nil {
		return nil, err
	}

	if out.Role == nil {
		return nil, acl.ErrNotFound
	}

	return out.Role, nil
}

func (s *HTTPServer) ACLRoleCreate(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	return s.ACLRoleWrite(resp, req, "")
}

func (s *HTTPServer) ACLRoleWrite(resp http.ResponseWriter, req *http.Request, roleID string) (interface{}, error) {
	args := structs.ACLRoleSetRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseToken(req, &args.Token)

	if err := decodeBody(req, &args.Role, fixTimeAndHashFields); err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("Role decoding failed: %v", err)}
	}

	if args.Role.ID != "" && args.Role.ID != roleID {
		return nil, BadRequestError{Reason: "Role ID in URL and payload do not match"}
	} else if args.Role.ID == "" {
		args.Role.ID = roleID
	}

	var out structs.ACLRole
	if err := s.agent.RPC("ACL.RoleSet", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLRoleDelete(resp http.ResponseWriter, req *http.Request, roleID string) (interface{}, error) {
	args := structs.ACLRoleDeleteRequest{
		Datacenter: s.agent.config.Datacenter,
		RoleID:     roleID,
	}
	s.parseToken(req, &args.Token)

	var ignored string
	if err := s.agent.RPC("ACL.RoleDelete", args, &ignored); err != nil {
		return nil, err
	}

	return true, nil
}

func (s *HTTPServer) ACLRoleBindingRuleList(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var args structs.ACLRoleBindingRuleListRequest
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLRoleBindingRuleListResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.RoleBindingRuleList", &args, &out); err != nil {
		return nil, err
	}

	// make sure we return an array and not nil
	if out.RoleBindingRules == nil {
		out.RoleBindingRules = make(structs.ACLRoleBindingRules, 0)
	}

	return out.RoleBindingRules, nil
}

func (s *HTTPServer) ACLRoleBindingRuleCRUD(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var fn func(resp http.ResponseWriter, req *http.Request, roleBindingRuleID string) (interface{}, error)

	switch req.Method {
	case "GET":
		fn = s.ACLRoleBindingRuleRead

	case "PUT":
		fn = s.ACLRoleBindingRuleWrite

	case "DELETE":
		fn = s.ACLRoleBindingRuleDelete

	default:
		return nil, MethodNotAllowedError{req.Method, []string{"GET", "PUT", "DELETE"}}
	}

	roleBindingRuleID := strings.TrimPrefix(req.URL.Path, "/v1/acl/rolebindingrule/")
	if roleBindingRuleID == "" && req.Method != "PUT" {
		return nil, BadRequestError{Reason: "Missing role binding rule ID"}
	}

	return fn(resp, req, roleBindingRuleID)
}

func (s *HTTPServer) ACLRoleBindingRuleRead(resp http.ResponseWriter, req *http.Request, roleBindingRuleID string) (interface{}, error) {
	args := structs.ACLRoleBindingRuleGetRequest{
		Datacenter:        s.agent.config.Datacenter,
		RoleBindingRuleID: roleBindingRuleID,
	}
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLRoleBindingRuleResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.RoleBindingRuleRead", &args, &out); err != nil {
		return nil, err
	}

	if out.RoleBindingRule == nil {
		return nil, acl.ErrNotFound
	}

	return out.RoleBindingRule, nil
}

func (s *HTTPServer) ACLRoleBindingRuleCreate(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	return s.ACLRoleBindingRuleWrite(resp, req, "")
}

func (s *HTTPServer) ACLRoleBindingRuleWrite(resp http.ResponseWriter, req *http.Request, roleBindingRuleID string) (interface{}, error) {
	args := structs.ACLRoleBindingRuleSetRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseToken(req, &args.Token)

	if err := decodeBody(req, &args.RoleBindingRule, fixTimeAndHashFields); err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("RoleBindingRule decoding failed: %v", err)}
	}

	if args.RoleBindingRule.ID != "" && args.RoleBindingRule.ID != roleBindingRuleID {
		return nil, BadRequestError{Reason: "RoleBindingRule ID in URL and payload do not match"}
	} else if args.RoleBindingRule.ID == "" {
		args.RoleBindingRule.ID = roleBindingRuleID
	}

	var out structs.ACLRoleBindingRule
	if err := s.agent.RPC("ACL.RoleBindingRuleSet", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLRoleBindingRuleDelete(resp http.ResponseWriter, req *http.Request, roleBindingRuleID string) (interface{}, error) {
	args := structs.ACLRoleBindingRuleDeleteRequest{
		Datacenter:        s.agent.config.Datacenter,
		RoleBindingRuleID: roleBindingRuleID,
	}
	s.parseToken(req, &args.Token)

	var out string
	if err := s.agent.RPC("ACL.RoleBindingRuleDelete", args, &out); err != nil {
		return nil, err
	}

	return true, nil
}

func (s *HTTPServer) ACLIdentityProviderList(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var args structs.ACLIdentityProviderListRequest
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLIdentityProviderListResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.IdentityProviderList", &args, &out); err != nil {
		return nil, err
	}

	// make sure we return an array and not nil
	if out.IdentityProviders == nil {
		out.IdentityProviders = make(structs.ACLIdentityProviderListStubs, 0)
	}

	return out.IdentityProviders, nil
}

func (s *HTTPServer) ACLIdentityProviderCRUD(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	var fn func(resp http.ResponseWriter, req *http.Request, idpName string) (interface{}, error)

	switch req.Method {
	case "GET":
		fn = s.ACLIdentityProviderRead

	case "PUT":
		fn = s.ACLIdentityProviderWrite

	case "DELETE":
		fn = s.ACLIdentityProviderDelete

	default:
		return nil, MethodNotAllowedError{req.Method, []string{"GET", "PUT", "DELETE"}}
	}

	idpName := strings.TrimPrefix(req.URL.Path, "/v1/acl/idp/")
	if idpName == "" && req.Method != "PUT" {
		return nil, BadRequestError{Reason: "Missing identity provider name"}
	}

	return fn(resp, req, idpName)
}

func (s *HTTPServer) ACLIdentityProviderRead(resp http.ResponseWriter, req *http.Request, idpName string) (interface{}, error) {
	args := structs.ACLIdentityProviderGetRequest{
		Datacenter:           s.agent.config.Datacenter,
		IdentityProviderName: idpName,
	}
	if done := s.parse(resp, req, &args.Datacenter, &args.QueryOptions); done {
		return nil, nil
	}

	if args.Datacenter == "" {
		args.Datacenter = s.agent.config.Datacenter
	}

	var out structs.ACLIdentityProviderResponse
	defer setMeta(resp, &out.QueryMeta)
	if err := s.agent.RPC("ACL.IdentityProviderRead", &args, &out); err != nil {
		return nil, err
	}

	if out.IdentityProvider == nil {
		return nil, acl.ErrNotFound
	}

	return out.IdentityProvider, nil
}

func (s *HTTPServer) ACLIdentityProviderCreate(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	return s.ACLIdentityProviderWrite(resp, req, "")
}

func (s *HTTPServer) ACLIdentityProviderWrite(resp http.ResponseWriter, req *http.Request, idpName string) (interface{}, error) {
	args := structs.ACLIdentityProviderSetRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseToken(req, &args.Token)

	if err := decodeBody(req, &args.IdentityProvider, fixTimeAndHashFields); err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("IdentityProvider decoding failed: %v", err)}
	}

	// TODO: should we introduce ids again?
	if idpName != "" {
		if args.IdentityProvider.Name != "" && args.IdentityProvider.Name != idpName {
			return nil, BadRequestError{Reason: "IdentityProvider Name in URL and payload do not match"}
		} else if args.IdentityProvider.Name == "" {
			args.IdentityProvider.Name = idpName
		}
	}

	var out structs.ACLIdentityProvider
	if err := s.agent.RPC("ACL.IdentityProviderSet", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLIdentityProviderDelete(resp http.ResponseWriter, req *http.Request, idpName string) (interface{}, error) {
	args := structs.ACLIdentityProviderDeleteRequest{
		Datacenter:           s.agent.config.Datacenter,
		IdentityProviderName: idpName,
	}
	s.parseToken(req, &args.Token)

	var out string
	if err := s.agent.RPC("ACL.IdentityProviderDelete", args, &out); err != nil {
		return nil, err
	}

	return true, nil
}

func (s *HTTPServer) ACLLogin(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	args := &structs.ACLLoginRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseDC(req, &args.Datacenter)

	if err := decodeBody(req, &args.Auth, nil); err != nil {
		return nil, BadRequestError{Reason: fmt.Sprintf("Failed to decode request body:: %v", err)}
	}

	var out structs.ACLToken
	if err := s.agent.RPC("ACL.Login", args, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (s *HTTPServer) ACLLogout(resp http.ResponseWriter, req *http.Request) (interface{}, error) {
	if s.checkACLDisabled(resp, req) {
		return nil, nil
	}

	args := structs.ACLLogoutRequest{
		Datacenter: s.agent.config.Datacenter,
	}
	s.parseDC(req, &args.Datacenter)
	s.parseToken(req, &args.Token)

	if args.Token == "" {
		return nil, acl.ErrNotFound
	}

	var ignored bool
	if err := s.agent.RPC("ACL.Logout", &args, &ignored); err != nil {
		return nil, err
	}

	return true, nil
}
