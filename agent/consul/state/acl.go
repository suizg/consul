package state

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	memdb "github.com/hashicorp/go-memdb"
)

type TokenPoliciesIndex struct {
}

func (s *TokenPoliciesIndex) FromObject(obj interface{}) (bool, [][]byte, error) {
	token, ok := obj.(*structs.ACLToken)
	if !ok {
		return false, nil, fmt.Errorf("object is not an ACLToken")
	}

	links := token.Policies

	numLinks := len(links)
	if numLinks == 0 {
		return false, nil, nil
	}

	vals := make([][]byte, 0, numLinks)
	for _, link := range links {
		vals = append(vals, []byte(link.ID+"\x00"))
	}

	return true, vals, nil
}

func (s *TokenPoliciesIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	arg, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("argument must be a string: %#v", args[0])
	}
	// Add the null character as a terminator
	arg += "\x00"
	return []byte(arg), nil
}

func (s *TokenPoliciesIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	val, err := s.FromArgs(args...)
	if err != nil {
		return nil, err
	}

	// Strip the null terminator, the rest is a prefix
	n := len(val)
	if n > 0 {
		return val[:n-1], nil
	}
	return val, nil
}

type TokenRolesIndex struct {
	// boundNames=true means index the BoundName field, otherwise index the ID
	boundNames bool
}

func (s *TokenRolesIndex) FromObject(obj interface{}) (bool, [][]byte, error) {
	token, ok := obj.(*structs.ACLToken)
	if !ok {
		return false, nil, fmt.Errorf("object is not an ACLToken")
	}

	links := token.Roles

	numLinks := len(links)
	if numLinks == 0 {
		return false, nil, nil
	}

	vals := make([][]byte, 0, numLinks)
	for _, link := range links {
		if link.BoundName != "" && s.boundNames {
			vals = append(vals, []byte(link.BoundName+"\x00"))
		} else if link.ID != "" && !s.boundNames {
			vals = append(vals, []byte(link.ID+"\x00"))
		}
	}

	return true, vals, nil
}

func (s *TokenRolesIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	arg, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("argument must be a string: %#v", args[0])
	}
	// Add the null character as a terminator
	arg += "\x00"
	return []byte(arg), nil
}

func (s *TokenRolesIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	val, err := s.FromArgs(args...)
	if err != nil {
		return nil, err
	}

	// Strip the null terminator, the rest is a prefix
	n := len(val)
	if n > 0 {
		return val[:n-1], nil
	}
	return val, nil
}

type RolePoliciesIndex struct {
}

func (s *RolePoliciesIndex) FromObject(obj interface{}) (bool, [][]byte, error) {
	role, ok := obj.(*structs.ACLRole)
	if !ok {
		return false, nil, fmt.Errorf("object is not an ACLRole")
	}

	links := role.Policies

	numLinks := len(links)
	if numLinks == 0 {
		return false, nil, nil
	}

	vals := make([][]byte, 0, numLinks)
	for _, link := range links {
		vals = append(vals, []byte(link.ID+"\x00"))
	}

	return true, vals, nil
}

func (s *RolePoliciesIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	arg, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("argument must be a string: %#v", args[0])
	}
	// Add the null character as a terminator
	arg += "\x00"
	return []byte(arg), nil
}

func (s *RolePoliciesIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	val, err := s.FromArgs(args...)
	if err != nil {
		return nil, err
	}

	// Strip the null terminator, the rest is a prefix
	n := len(val)
	if n > 0 {
		return val[:n-1], nil
	}
	return val, nil
}

type TokenExpirationIndex struct {
	LocalFilter bool
}

func (s *TokenExpirationIndex) encodeTime(t time.Time) []byte {
	val := t.Unix()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(val))
	return buf
}

func (s *TokenExpirationIndex) FromObject(obj interface{}) (bool, []byte, error) {
	token, ok := obj.(*structs.ACLToken)
	if !ok {
		return false, nil, fmt.Errorf("object is not an ACLToken")
	}
	if s.LocalFilter != token.Local {
		return false, nil, nil
	}
	if token.ExpirationTime.IsZero() {
		return false, nil, nil
	}
	if token.ExpirationTime.Unix() < 0 {
		return false, nil, fmt.Errorf("token expiration time cannot be before the unix epoch: %s", token.ExpirationTime)
	}

	buf := s.encodeTime(token.ExpirationTime)

	return true, buf, nil
}

func (s *TokenExpirationIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	arg, ok := args[0].(time.Time)
	if !ok {
		return nil, fmt.Errorf("argument must be a time.Time: %#v", args[0])
	}
	if arg.Unix() < 0 {
		return nil, fmt.Errorf("argument must be a time.Time after the unix epoch: %s", args[0])
	}

	buf := s.encodeTime(arg)

	return buf, nil
}

func tokensTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "acl-tokens",
		Indexes: map[string]*memdb.IndexSchema{
			"accessor": &memdb.IndexSchema{
				Name: "accessor",
				// DEPRECATED (ACL-Legacy-Compat) - we should not AllowMissing here once legacy compat is removed
				AllowMissing: true,
				Unique:       true,
				Indexer: &memdb.UUIDFieldIndex{
					Field: "AccessorID",
				},
			},
			"id": &memdb.IndexSchema{
				Name:         "id",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.StringFieldIndex{
					Field:     "SecretID",
					Lowercase: false,
				},
			},
			"policies": &memdb.IndexSchema{
				Name: "policies",
				// Need to allow missing for the anonymous token
				AllowMissing: true,
				Unique:       false,
				Indexer:      &TokenPoliciesIndex{},
			},
			"roles": &memdb.IndexSchema{
				Name:         "roles",
				AllowMissing: true,
				Unique:       false,
				Indexer:      &TokenRolesIndex{boundNames: false},
			},
			"idp": &memdb.IndexSchema{
				Name:         "idp",
				AllowMissing: true,
				Unique:       false,
				Indexer: &memdb.StringFieldIndex{
					Field:     "IDPName",
					Lowercase: false,
				},
			},
			// TODO(rb): remove if not necessary for UI work
			"bound-roles": &memdb.IndexSchema{
				Name:         "bound-roles",
				AllowMissing: true,
				Unique:       false,
				Indexer:      &TokenRolesIndex{boundNames: true},
			},
			"local": &memdb.IndexSchema{
				Name:         "local",
				AllowMissing: false,
				Unique:       false,
				Indexer: &memdb.ConditionalIndex{
					Conditional: func(obj interface{}) (bool, error) {
						if token, ok := obj.(*structs.ACLToken); ok {
							return token.Local, nil
						}
						return false, nil
					},
				},
			},
			"expires-global": {
				Name:         "expires-global",
				AllowMissing: true,
				Unique:       false,
				Indexer:      &TokenExpirationIndex{LocalFilter: false},
			},
			"expires-local": {
				Name:         "expires-local",
				AllowMissing: true,
				Unique:       false,
				Indexer:      &TokenExpirationIndex{LocalFilter: true},
			},

			//DEPRECATED (ACL-Legacy-Compat) - This index is only needed while we support upgrading v1 to v2 acls
			// This table indexes all the ACL tokens that do not have an AccessorID
			"needs-upgrade": &memdb.IndexSchema{
				Name:         "needs-upgrade",
				AllowMissing: false,
				Unique:       false,
				Indexer: &memdb.ConditionalIndex{
					Conditional: func(obj interface{}) (bool, error) {
						if token, ok := obj.(*structs.ACLToken); ok {
							return token.AccessorID == "", nil
						}
						return false, nil
					},
				},
			},
		},
	}
}

func policiesTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "acl-policies",
		Indexes: map[string]*memdb.IndexSchema{
			"id": &memdb.IndexSchema{
				Name:         "id",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.UUIDFieldIndex{
					Field: "ID",
				},
			},
			"name": &memdb.IndexSchema{
				Name:         "name",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.StringFieldIndex{
					Field: "Name",
					// TODO (ACL-V2) - should we coerce to lowercase?
					Lowercase: true,
				},
			},
		},
	}
}

func rolesTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "acl-roles",
		Indexes: map[string]*memdb.IndexSchema{
			"id": &memdb.IndexSchema{
				Name:         "id",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.UUIDFieldIndex{
					Field: "ID",
				},
			},
			"name": &memdb.IndexSchema{
				Name:         "name",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.StringFieldIndex{
					Field:     "Name",
					Lowercase: true,
				},
			},
			"policies": &memdb.IndexSchema{
				Name: "policies",
				// Need to allow missing for the anonymous token
				AllowMissing: true,
				Unique:       false,
				Indexer:      &RolePoliciesIndex{},
			},
		},
	}
}

func roleBindingRulesTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "acl-role-binding-rules",
		Indexes: map[string]*memdb.IndexSchema{
			"id": &memdb.IndexSchema{
				Name:         "id",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.UUIDFieldIndex{
					Field: "ID",
				},
			},
			"idp": &memdb.IndexSchema{
				Name:         "idp",
				AllowMissing: false,
				Unique:       false,
				Indexer: &memdb.StringFieldIndex{
					Field:     "IDPName",
					Lowercase: true,
				},
			},
		},
	}
}

func identityProvidersTableSchema() *memdb.TableSchema {
	return &memdb.TableSchema{
		Name: "acl-identity-providers",
		Indexes: map[string]*memdb.IndexSchema{
			"id": &memdb.IndexSchema{
				Name:         "id",
				AllowMissing: false,
				Unique:       true,
				Indexer: &memdb.StringFieldIndex{
					Field:     "Name",
					Lowercase: true,
				},
			},
		},
	}
}

func init() {
	registerSchema(tokensTableSchema)
	registerSchema(policiesTableSchema)
	registerSchema(rolesTableSchema)
	registerSchema(roleBindingRulesTableSchema)
	registerSchema(identityProvidersTableSchema)
}

// ACLTokens is used when saving a snapshot
func (s *Snapshot) ACLTokens() (memdb.ResultIterator, error) {
	// DEPRECATED (ACL-Legacy-Compat) - This could use the "id" index when we remove v1 compat
	iter, err := s.tx.Get("acl-tokens", "id")
	if err != nil {
		return nil, err
	}
	return iter, nil
}

// ACLToken is used when restoring from a snapshot. For general inserts, use ACL.
func (s *Restore) ACLToken(token *structs.ACLToken) error {
	if err := s.tx.Insert("acl-tokens", token); err != nil {
		return fmt.Errorf("failed restoring acl token: %s", err)
	}

	if err := indexUpdateMaxTxn(s.tx, token.ModifyIndex, "acl-tokens"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}
	return nil
}

// ACLPolicies is used when saving a snapshot
func (s *Snapshot) ACLPolicies() (memdb.ResultIterator, error) {
	iter, err := s.tx.Get("acl-policies", "id")
	if err != nil {
		return nil, err
	}
	return iter, nil
}

func (s *Restore) ACLPolicy(policy *structs.ACLPolicy) error {
	if err := s.tx.Insert("acl-policies", policy); err != nil {
		return fmt.Errorf("failed restoring acl policy: %s", err)
	}

	if err := indexUpdateMaxTxn(s.tx, policy.ModifyIndex, "acl-policies"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}
	return nil
}

// ACLRoles is used when saving a snapshot
func (s *Snapshot) ACLRoles() (memdb.ResultIterator, error) {
	iter, err := s.tx.Get("acl-roles", "id")
	if err != nil {
		return nil, err
	}
	return iter, nil
}

func (s *Restore) ACLRole(role *structs.ACLRole) error {
	if err := s.tx.Insert("acl-roles", role); err != nil {
		return fmt.Errorf("failed restoring acl role: %s", err)
	}

	if err := indexUpdateMaxTxn(s.tx, role.ModifyIndex, "acl-roles"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}
	return nil
}

// ACLRoleBindingRules is used when saving a snapshot
func (s *Snapshot) ACLRoleBindingRules() (memdb.ResultIterator, error) {
	iter, err := s.tx.Get("acl-role-binding-rules", "id")
	if err != nil {
		return nil, err
	}
	return iter, nil
}

func (s *Restore) ACLRoleBindingRule(rule *structs.ACLRoleBindingRule) error {
	if err := s.tx.Insert("acl-role-binding-rules", rule); err != nil {
		return fmt.Errorf("failed restoring acl role binding rule: %s", err)
	}

	if err := indexUpdateMaxTxn(s.tx, rule.ModifyIndex, "acl-role-binding-rules"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}
	return nil
}

// ACLIdentityProviders is used when saving a snapshot
func (s *Snapshot) ACLIdentityProviders() (memdb.ResultIterator, error) {
	iter, err := s.tx.Get("acl-identity-providers", "id")
	if err != nil {
		return nil, err
	}
	return iter, nil
}

func (s *Restore) ACLIdentityProvider(idp *structs.ACLIdentityProvider) error {
	if err := s.tx.Insert("acl-identity-providers", idp); err != nil {
		return fmt.Errorf("failed restoring acl identity provider: %s", err)
	}

	if err := indexUpdateMaxTxn(s.tx, idp.ModifyIndex, "acl-identity-providers"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}
	return nil
}

// ACLBootstrap is used to perform a one-time ACL bootstrap operation on a
// cluster to get the first management token.
func (s *Store) ACLBootstrap(idx, resetIndex uint64, token *structs.ACLToken, legacy bool) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	// We must have initialized before this will ever be possible.
	existing, err := tx.First("index", "id", "acl-token-bootstrap")
	if err != nil {
		return fmt.Errorf("bootstrap check failed: %v", err)
	}
	if existing != nil {
		if resetIndex == 0 {
			return structs.ACLBootstrapNotAllowedErr
		} else if resetIndex != existing.(*IndexEntry).Value {
			return structs.ACLBootstrapInvalidResetIndexErr
		}
	}

	if err := s.aclTokenSetTxn(tx, idx, token, false, false, legacy); err != nil {
		return fmt.Errorf("failed inserting bootstrap token: %v", err)
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-tokens"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}
	if err := tx.Insert("index", &IndexEntry{"acl-token-bootstrap", idx}); err != nil {
		return fmt.Errorf("failed to mark ACL bootstrapping as complete: %v", err)
	}
	tx.Commit()
	return nil
}

// CanBootstrapACLToken checks if bootstrapping is possible and returns the reset index
func (s *Store) CanBootstrapACLToken() (bool, uint64, error) {
	txn := s.db.Txn(false)

	// Lookup the bootstrap sentinel
	out, err := txn.First("index", "id", "acl-token-bootstrap")
	if err != nil {
		return false, 0, err
	}

	// No entry, we haven't bootstrapped yet
	if out == nil {
		return true, 0, nil
	}

	// Return the reset index if we've already bootstrapped
	return false, out.(*IndexEntry).Value, nil
}

func (s *Store) resolveTokenPolicyLinks(tx *memdb.Txn, token *structs.ACLToken, allowMissing bool) error {
	for linkIndex, link := range token.Policies {
		if link.ID != "" {
			policy, err := s.getPolicyWithTxn(tx, nil, link.ID, "id")

			if err != nil {
				return err
			}

			if policy != nil {
				// the name doesn't matter here
				token.Policies[linkIndex].Name = policy.Name
			} else if !allowMissing {
				return fmt.Errorf("No such policy with ID: %s", link.ID)
			}
		} else {
			return fmt.Errorf("Encountered a Token with policies linked by Name in the state store")
		}
	}
	return nil
}

// fixupTokenPolicyLinks is to be used when retrieving tokens from memdb. The policy links could have gotten
// stale when a linked policy was deleted or renamed. This will correct them and generate a newly allocated
// token only when fixes are needed. If the policy links are still accurate then we just return the original
// token.
func (s *Store) fixupTokenPolicyLinks(tx *memdb.Txn, original *structs.ACLToken) (*structs.ACLToken, error) {
	owned := false
	token := original

	cloneToken := func(t *structs.ACLToken, copyNumLinks int) *structs.ACLToken {
		clone := *t
		clone.Policies = make([]structs.ACLTokenPolicyLink, copyNumLinks)
		copy(clone.Policies, t.Policies[:copyNumLinks])
		return &clone
	}

	for linkIndex, link := range original.Policies {
		if link.ID == "" {
			return nil, fmt.Errorf("Detected corrupted token within the state store - missing policy link ID")
		}

		policy, err := s.getPolicyWithTxn(tx, nil, link.ID, "id")

		if err != nil {
			return nil, err
		}

		if policy == nil {
			if !owned {
				// clone the token as we cannot touch the original
				token = cloneToken(original, linkIndex)
				owned = true
			}
			// if already owned then we just don't append it.
		} else if policy.Name != link.Name {
			if !owned {
				token = cloneToken(original, linkIndex)
				owned = true
			}

			// append the corrected policy
			token.Policies = append(token.Policies, structs.ACLTokenPolicyLink{ID: link.ID, Name: policy.Name})

		} else if owned {
			token.Policies = append(token.Policies, link)
		}
	}

	return token, nil
}

func (s *Store) resolveTokenRoleLinks(tx *memdb.Txn, token *structs.ACLToken, allowMissing bool) error {
	for linkIndex, link := range token.Roles {
		if link.ID != "" {
			role, err := s.getRoleWithTxn(tx, nil, link.ID, "id")

			if err != nil {
				return err
			}

			if role != nil {
				// the name doesn't matter here
				token.Roles[linkIndex].Name = role.Name
			} else if !allowMissing {
				return fmt.Errorf("No such role with ID: %s", link.ID)
			}
		} else if link.BoundName != "" {
			// skip expected
		} else {
			return fmt.Errorf("Encountered a Token with roles linked by Name in the state store")
		}
	}
	return nil
}

// fixupTokenRoleLinks is to be used when retrieving tokens from memdb. The role links could have gotten
// stale when a linked role was deleted or renamed. This will correct them and generate a newly allocated
// token only when fixes are needed. If the role links are still accurate then we just return the original
// token.
func (s *Store) fixupTokenRoleLinks(tx *memdb.Txn, original *structs.ACLToken) (*structs.ACLToken, error) {
	owned := false
	token := original

	cloneToken := func(t *structs.ACLToken, copyNumLinks int) *structs.ACLToken {
		clone := *t
		clone.Roles = make([]structs.ACLTokenRoleLink, copyNumLinks)
		copy(clone.Roles, t.Roles[:copyNumLinks])
		return &clone
	}

	for linkIndex, link := range original.Roles {
		if link.BoundName != "" {
			if owned {
				token.Roles = append(token.Roles, link)
			}
			continue
		} else if link.ID == "" {
			return nil, fmt.Errorf("Detected corrupted token within the state store - missing role link ID")
		}

		role, err := s.getRoleWithTxn(tx, nil, link.ID, "id")

		if err != nil {
			return nil, err
		}

		if role == nil {
			if !owned {
				// clone the token as we cannot touch the original
				token = cloneToken(original, linkIndex)
				owned = true
			}
			// if already owned then we just don't append it.
		} else if role.Name != link.Name {
			if !owned {
				token = cloneToken(original, linkIndex)
				owned = true
			}

			// append the corrected policy
			token.Roles = append(token.Roles, structs.ACLTokenRoleLink{ID: link.ID, Name: role.Name})

		} else if owned {
			token.Roles = append(token.Roles, link)
		}
	}

	return token, nil
}

func (s *Store) resolveRolePolicyLinks(tx *memdb.Txn, role *structs.ACLRole, allowMissing bool) error {
	for linkIndex, link := range role.Policies {
		if link.ID != "" {
			policy, err := s.getPolicyWithTxn(tx, nil, link.ID, "id")

			if err != nil {
				return err
			}

			if policy != nil {
				// the name doesn't matter here
				role.Policies[linkIndex].Name = policy.Name
			} else if !allowMissing {
				return fmt.Errorf("No such policy with ID: %s", link.ID)
			}
		} else {
			return fmt.Errorf("Encountered a Role with policies linked by Name in the state store")
		}
	}
	return nil
}

// fixupRolePolicyLinks is to be used when retrieving roles from memdb. The policy links could have gotten
// stale when a linked policy was deleted or renamed. This will correct them and generate a newly allocated
// role only when fixes are needed. If the policy links are still accurate then we just return the original
// role.
func (s *Store) fixupRolePolicyLinks(tx *memdb.Txn, original *structs.ACLRole) (*structs.ACLRole, error) {
	owned := false
	role := original

	cloneRole := func(t *structs.ACLRole, copyNumLinks int) *structs.ACLRole {
		clone := *t
		clone.Policies = make([]structs.ACLRolePolicyLink, copyNumLinks)
		copy(clone.Policies, t.Policies[:copyNumLinks])
		return &clone
	}

	for linkIndex, link := range original.Policies {
		if link.ID == "" {
			return nil, fmt.Errorf("Detected corrupted role within the state store - missing policy link ID")
		}

		policy, err := s.getPolicyWithTxn(tx, nil, link.ID, "id")

		if err != nil {
			return nil, err
		}

		if policy == nil {
			if !owned {
				// clone the token as we cannot touch the original
				role = cloneRole(original, linkIndex)
				owned = true
			}
			// if already owned then we just don't append it.
		} else if policy.Name != link.Name {
			if !owned {
				role = cloneRole(original, linkIndex)
				owned = true
			}

			// append the corrected policy
			role.Policies = append(role.Policies, structs.ACLRolePolicyLink{ID: link.ID, Name: policy.Name})

		} else if owned {
			role.Policies = append(role.Policies, link)
		}
	}

	return role, nil
}

// ACLTokenSet is used to insert an ACL rule into the state store.
func (s *Store) ACLTokenSet(idx uint64, token *structs.ACLToken, legacy bool) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	// Call set on the ACL
	if err := s.aclTokenSetTxn(tx, idx, token, false, false, legacy); err != nil {
		return err
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-tokens"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) ACLTokenBatchSet(idx uint64, tokens structs.ACLTokens, cas bool) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, token := range tokens {
		// this is only used when doing batch insertions for upgrades and replication. Therefore
		// we take whatever those said.
		if err := s.aclTokenSetTxn(tx, idx, token, cas, true, false); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-tokens"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

// aclTokenSetTxn is the inner method used to insert an ACL token with the
// proper indexes into the state store.
func (s *Store) aclTokenSetTxn(tx *memdb.Txn, idx uint64, token *structs.ACLToken, cas, allowMissingPolicyAndRoleIDs, legacy bool) error {
	// Check that the ID is set
	if token.SecretID == "" {
		return ErrMissingACLTokenSecret
	}

	if !legacy && token.AccessorID == "" {
		return ErrMissingACLTokenAccessor
	}

	// DEPRECATED (ACL-Legacy-Compat)
	if token.Rules != "" {
		// When we update a legacy acl token we may have to correct old HCL to
		// prevent the propagation of older syntax into the state store and
		// into in-memory representations.
		correctedRules := structs.SanitizeLegacyACLTokenRules(token.Rules)
		if correctedRules != "" {
			token.Rules = correctedRules
		}
	}

	// Check for an existing ACL
	// DEPRECATED (ACL-Legacy-Compat) - transition to using accessor index instead of secret once v1 compat is removed
	existing, err := tx.First("acl-tokens", "id", token.SecretID)
	if err != nil {
		return fmt.Errorf("failed token lookup: %s", err)
	}

	var original *structs.ACLToken

	if existing != nil {
		original = existing.(*structs.ACLToken)
	}

	if cas {
		// set-if-unset case
		if token.ModifyIndex == 0 && original != nil {
			return nil
		}
		// token already deleted
		if token.ModifyIndex != 0 && original == nil {
			return nil
		}
		// check for other modifications
		if token.ModifyIndex != 0 && token.ModifyIndex != original.ModifyIndex {
			return nil
		}
	}

	if legacy && original != nil {
		if original.UsesNonLegacyFields() {
			return fmt.Errorf("failed inserting acl token: cannot use legacy endpoint to modify a non-legacy token")
		}

		token.AccessorID = original.AccessorID
	}

	if err := s.resolveTokenPolicyLinks(tx, token, allowMissingPolicyAndRoleIDs); err != nil {
		return err
	}

	if err := s.resolveTokenRoleLinks(tx, token, allowMissingPolicyAndRoleIDs); err != nil {
		return err
	}

	if token.IDPName != "" {
		idp, err := s.getIdentityProviderWithTxn(tx, nil, token.IDPName, "id")
		if err != nil {
			return err
		} else if idp == nil {
			return fmt.Errorf("No such identity provider with Name: %s", token.IDPName)
		}
	}

	for _, svcid := range token.ServiceIdentities {
		if svcid.ServiceName == "" {
			return fmt.Errorf("Encountered a Token with an empty service identity name in the state store")
		}
	}

	// Set the indexes
	if original != nil {
		if original.AccessorID != "" && token.AccessorID != original.AccessorID {
			return fmt.Errorf("The ACL Token AccessorID field is immutable")
		}

		if token.SecretID != original.SecretID {
			return fmt.Errorf("The ACL Token SecretID field is immutable")
		}

		token.CreateIndex = original.CreateIndex
		token.ModifyIndex = idx
	} else {
		token.CreateIndex = idx
		token.ModifyIndex = idx
	}

	// Insert the ACL
	if err := tx.Insert("acl-tokens", token); err != nil {
		return fmt.Errorf("failed inserting acl token: %v", err)
	}

	return nil
}

// ACLTokenGetBySecret is used to look up an existing ACL token by its SecretID.
func (s *Store) ACLTokenGetBySecret(ws memdb.WatchSet, secret string) (uint64, *structs.ACLToken, error) {
	return s.aclTokenGet(ws, secret, "id")
}

// ACLTokenGetByAccessor is used to look up an existing ACL token by its AccessorID.
func (s *Store) ACLTokenGetByAccessor(ws memdb.WatchSet, accessor string) (uint64, *structs.ACLToken, error) {
	return s.aclTokenGet(ws, accessor, "accessor")
}

// aclTokenGet looks up a token using one of the indexes provided
func (s *Store) aclTokenGet(ws memdb.WatchSet, value, index string) (uint64, *structs.ACLToken, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	token, err := s.aclTokenGetTxn(tx, ws, value, index)
	if err != nil {
		return 0, nil, fmt.Errorf("failed acl token lookup: %v", err)
	}

	idx := maxIndexTxn(tx, "acl-tokens")
	return idx, token, nil
}

func (s *Store) ACLTokenBatchGet(ws memdb.WatchSet, accessors []string) (uint64, structs.ACLTokens, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	tokens := make(structs.ACLTokens, 0)
	for _, accessor := range accessors {
		token, err := s.aclTokenGetTxn(tx, ws, accessor, "accessor")
		if err != nil {
			return 0, nil, fmt.Errorf("failed acl token lookup: %v", err)
		}

		// token == nil is valid and will indic
		if token != nil {
			tokens = append(tokens, token)
		}
	}

	idx := maxIndexTxn(tx, "acl-tokens")

	return idx, tokens, nil
}

func (s *Store) aclTokenGetTxn(tx *memdb.Txn, ws memdb.WatchSet, value, index string) (*structs.ACLToken, error) {
	watchCh, rawToken, err := tx.FirstWatch("acl-tokens", index, value)
	if err != nil {
		return nil, fmt.Errorf("failed acl token lookup: %v", err)
	}
	ws.Add(watchCh)

	if rawToken != nil {
		token := rawToken.(*structs.ACLToken)
		token, err := s.fixupTokenPolicyLinks(tx, token)
		if err != nil {
			return nil, err
		}
		token, err = s.fixupTokenRoleLinks(tx, token)
		if err != nil {
			return nil, err
		}
		return token, nil
	}

	return nil, nil
}

// ACLTokenList is used to list out all of the ACLs in the state store.
func (s *Store) ACLTokenList(ws memdb.WatchSet, local, global bool, policy, role, idpName string) (uint64, structs.ACLTokens, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	var iter memdb.ResultIterator
	var err error

	// Note global == local works when both are true or false. It is not valid to set both
	// to false but for defaulted structs (zero values for both) we want it to list out
	// all tokens so our checks just ensure that global == local

	needLocalityFilter := false
	if policy == "" && role == "" && idpName == "" {
		if global == local {
			iter, err = tx.Get("acl-tokens", "id")
		} else if global {
			iter, err = tx.Get("acl-tokens", "local", false)
		} else {
			iter, err = tx.Get("acl-tokens", "local", true)
		}

	} else if policy != "" && role == "" && idpName == "" {
		iter, err = tx.Get("acl-tokens", "policies", policy)
		needLocalityFilter = true

	} else if policy == "" && role != "" && idpName == "" {
		iter, err = tx.Get("acl-tokens", "roles", role)
		needLocalityFilter = true

	} else if policy == "" && role == "" && idpName != "" {
		iter, err = tx.Get("acl-tokens", "idp", idpName)
		needLocalityFilter = true

	} else {
		return 0, nil, fmt.Errorf("can only filter by one of policy, role, or idpName at a time")
	}

	if err != nil {
		return 0, nil, fmt.Errorf("failed acl token lookup: %v", err)
	}

	if needLocalityFilter && global != local {
		iter = memdb.NewFilterIterator(iter, func(raw interface{}) bool {
			token, ok := raw.(*structs.ACLToken)
			if !ok {
				return true
			}

			if global && !token.Local {
				return false
			} else if local && token.Local {
				return false
			}

			return true
		})
	}

	ws.Add(iter.WatchCh())

	var result structs.ACLTokens
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		token := raw.(*structs.ACLToken)
		token, err := s.fixupTokenPolicyLinks(tx, token)
		if err != nil {
			return 0, nil, err
		}
		token, err = s.fixupTokenRoleLinks(tx, token)
		if err != nil {
			return 0, nil, err
		}
		result = append(result, token)
	}

	// Get the table index.
	idx := maxIndexTxn(tx, "acl-tokens")

	return idx, result, nil
}

func (s *Store) ACLTokenListUpgradeable(max int) (structs.ACLTokens, <-chan struct{}, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	iter, err := tx.Get("acl-tokens", "needs-upgrade", true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed acl token listing: %v", err)
	}

	var tokens structs.ACLTokens
	i := 0
	for token := iter.Next(); token != nil; token = iter.Next() {
		tokens = append(tokens, token.(*structs.ACLToken))
		i += 1
		if i >= max {
			return tokens, nil, nil
		}
	}

	return tokens, iter.WatchCh(), nil
}

func (s *Store) ACLTokenMinExpirationTime(local bool) (time.Time, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	item, err := tx.First("acl-tokens", s.expiresIndexName(local))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed acl token listing: %v", err)
	}

	if item == nil {
		return time.Time{}, nil
	}

	token := item.(*structs.ACLToken)

	return token.ExpirationTime, nil
}

// ACLTokenListExpires lists tokens that are expires as of the provided time.
// The returned set will be no larger than the max value provided.
func (s *Store) ACLTokenListExpired(local bool, asOf time.Time, max int) (structs.ACLTokens, <-chan struct{}, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	iter, err := tx.Get("acl-tokens", s.expiresIndexName(local))
	if err != nil {
		return nil, nil, fmt.Errorf("failed acl token listing: %v", err)
	}

	var (
		tokens structs.ACLTokens
		i      int
	)
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		token := raw.(*structs.ACLToken)

		if !token.ExpirationTime.Before(asOf) {
			return tokens, nil, nil
		}

		tokens = append(tokens, token)
		i += 1
		if i >= max {
			return tokens, nil, nil
		}
	}

	return tokens, iter.WatchCh(), nil
}

func (s *Store) expiresIndexName(local bool) string {
	if local {
		return "expires-local"
	}
	return "expires-global"
}

// ACLTokenDeleteBySecret is used to remove an existing ACL from the state store. If
// the ACL does not exist this is a no-op and no error is returned.
func (s *Store) ACLTokenDeleteBySecret(idx uint64, secret string) error {
	return s.aclTokenDelete(idx, secret, "id")
}

// ACLTokenDeleteByAccessor is used to remove an existing ACL from the state store. If
// the ACL does not exist this is a no-op and no error is returned.
func (s *Store) ACLTokenDeleteByAccessor(idx uint64, accessor string) error {
	return s.aclTokenDelete(idx, accessor, "accessor")
}

func (s *Store) ACLTokenBatchDelete(idx uint64, tokenIDs []string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, tokenID := range tokenIDs {
		if err := s.aclTokenDeleteTxn(tx, idx, tokenID, "accessor"); err != nil {
			return err
		}
	}

	tx.Commit()
	return nil
}

func (s *Store) aclTokenDelete(idx uint64, value, index string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclTokenDeleteTxn(tx, idx, value, index); err != nil {
		return err
	}

	tx.Commit()
	return nil
}

func (s *Store) aclTokenDeleteTxn(tx *memdb.Txn, idx uint64, value, index string) error {
	// Look up the existing token
	token, err := tx.First("acl-tokens", index, value)
	if err != nil {
		return fmt.Errorf("failed acl token lookup: %v", err)
	}

	if token == nil {
		return nil
	}

	if token.(*structs.ACLToken).AccessorID == structs.ACLTokenAnonymousID {
		return fmt.Errorf("Deletion of the builtin anonymous token is not permitted")
	}

	if err := tx.Delete("acl-tokens", token); err != nil {
		return fmt.Errorf("failed deleting acl token: %v", err)
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-tokens"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}
	return nil
}

func (s *Store) ACLPolicyBatchSet(idx uint64, policies structs.ACLPolicies) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, policy := range policies {
		if err := s.aclPolicySetTxn(tx, idx, policy); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-policies"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) ACLPolicySet(idx uint64, policy *structs.ACLPolicy) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclPolicySetTxn(tx, idx, policy); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-policies"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclPolicySetTxn(tx *memdb.Txn, idx uint64, policy *structs.ACLPolicy) error {
	// Check that the ID is set
	if policy.ID == "" {
		return ErrMissingACLPolicyID
	}

	if policy.Name == "" {
		return ErrMissingACLPolicyName
	}

	existing, err := tx.First("acl-policies", "id", policy.ID)
	if err != nil {
		return fmt.Errorf("failed acl policy lookup: %v", err)
	}

	if existing != nil {
		policyMatch := existing.(*structs.ACLPolicy)

		if policy.ID == structs.ACLPolicyGlobalManagementID {
			// Only the name and description are modifiable
			if policy.Rules != policyMatch.Rules {
				return fmt.Errorf("Changing the Rules for the builtin global-management policy is not permitted")
			}

			if policy.Datacenters != nil && len(policy.Datacenters) != 0 {
				return fmt.Errorf("Changing the Datacenters of the builtin global-management policy is not permitted")
			}
		}
	}

	// ensure the name is unique (cannot conflict with another policy with a different ID)
	nameMatch, err := tx.First("acl-policies", "name", policy.Name)
	if err != nil {
		return fmt.Errorf("failed acl policy lookup: %v", err)
	}
	if nameMatch != nil && policy.ID != nameMatch.(*structs.ACLPolicy).ID {
		return fmt.Errorf("A policy with name %q already exists", policy.Name)
	}

	// Set the indexes
	if existing != nil {
		policy.CreateIndex = existing.(*structs.ACLPolicy).CreateIndex
		policy.ModifyIndex = idx
	} else {
		policy.CreateIndex = idx
		policy.ModifyIndex = idx
	}

	// Insert the ACL
	if err := tx.Insert("acl-policies", policy); err != nil {
		return fmt.Errorf("failed inserting acl policy: %v", err)
	}
	return nil
}

func (s *Store) ACLPolicyGetByID(ws memdb.WatchSet, id string) (uint64, *structs.ACLPolicy, error) {
	return s.aclPolicyGet(ws, id, "id")
}

func (s *Store) ACLPolicyGetByName(ws memdb.WatchSet, name string) (uint64, *structs.ACLPolicy, error) {
	return s.aclPolicyGet(ws, name, "name")
}

func (s *Store) ACLPolicyBatchGet(ws memdb.WatchSet, ids []string) (uint64, structs.ACLPolicies, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	policies := make(structs.ACLPolicies, 0)
	for _, pid := range ids {
		policy, err := s.getPolicyWithTxn(tx, ws, pid, "id")
		if err != nil {
			return 0, nil, err
		}

		if policy != nil {
			policies = append(policies, policy)
		}
	}

	idx := maxIndexTxn(tx, "acl-policies")

	return idx, policies, nil
}

func (s *Store) getPolicyWithTxn(tx *memdb.Txn, ws memdb.WatchSet, value, index string) (*structs.ACLPolicy, error) {
	watchCh, policy, err := tx.FirstWatch("acl-policies", index, value)
	if err != nil {
		return nil, fmt.Errorf("failed acl policy lookup: %v", err)
	}
	ws.Add(watchCh)

	if err != nil || policy == nil {
		return nil, err
	}

	return policy.(*structs.ACLPolicy), nil
}

func (s *Store) aclPolicyGet(ws memdb.WatchSet, value, index string) (uint64, *structs.ACLPolicy, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	policy, err := s.getPolicyWithTxn(tx, ws, value, index)
	if err != nil {
		return 0, nil, err
	}

	idx := maxIndexTxn(tx, "acl-policies")

	return idx, policy, nil
}

func (s *Store) ACLPolicyList(ws memdb.WatchSet) (uint64, structs.ACLPolicies, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	iter, err := tx.Get("acl-policies", "id")
	if err != nil {
		return 0, nil, fmt.Errorf("failed acl policy lookup: %v", err)
	}
	ws.Add(iter.WatchCh())

	var result structs.ACLPolicies
	for policy := iter.Next(); policy != nil; policy = iter.Next() {
		result = append(result, policy.(*structs.ACLPolicy))
	}

	// Get the table index.
	idx := maxIndexTxn(tx, "acl-policies")

	return idx, result, nil
}

func (s *Store) ACLPolicyDeleteByID(idx uint64, id string) error {
	return s.aclPolicyDelete(idx, id, "id")
}

func (s *Store) ACLPolicyDeleteByName(idx uint64, name string) error {
	return s.aclPolicyDelete(idx, name, "name")
}

func (s *Store) ACLPolicyBatchDelete(idx uint64, policyIDs []string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, policyID := range policyIDs {
		if err := s.aclPolicyDeleteTxn(tx, idx, policyID, "id"); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-policies"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}
	tx.Commit()
	return nil
}

func (s *Store) aclPolicyDelete(idx uint64, value, index string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclPolicyDeleteTxn(tx, idx, value, index); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-policies"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclPolicyDeleteTxn(tx *memdb.Txn, idx uint64, value, index string) error {
	// Look up the existing token
	rawPolicy, err := tx.First("acl-policies", index, value)
	if err != nil {
		return fmt.Errorf("failed acl policy lookup: %v", err)
	}

	if rawPolicy == nil {
		return nil
	}

	policy := rawPolicy.(*structs.ACLPolicy)

	if policy.ID == structs.ACLPolicyGlobalManagementID {
		return fmt.Errorf("Deletion of the builtin global-management policy is not permitted")
	}

	if err := tx.Delete("acl-policies", policy); err != nil {
		return fmt.Errorf("failed deleting acl policy: %v", err)
	}
	return nil
}

func (s *Store) ACLRoleBatchSet(idx uint64, roles structs.ACLRoles) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, role := range roles {
		if err := s.aclRoleSetTxn(tx, idx, role, true); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-roles"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) ACLRoleSet(idx uint64, role *structs.ACLRole) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclRoleSetTxn(tx, idx, role, false); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-roles"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclRoleSetTxn(tx *memdb.Txn, idx uint64, role *structs.ACLRole, allowMissing bool) error {
	// Check that the ID is set
	if role.ID == "" {
		return ErrMissingACLRoleID
	}

	if role.Name == "" {
		return ErrMissingACLRoleName
	}

	existing, err := tx.First("acl-roles", "id", role.ID)
	if err != nil {
		return fmt.Errorf("failed acl role lookup: %v", err)
	}

	// ensure the name is unique (cannot conflict with another role with a different ID)
	nameMatch, err := tx.First("acl-roles", "name", role.Name)
	if err != nil {
		return fmt.Errorf("failed acl role lookup: %v", err)
	}
	if nameMatch != nil && role.ID != nameMatch.(*structs.ACLRole).ID {
		return fmt.Errorf("A role with name %q already exists", role.Name)
	}

	if err := s.resolveRolePolicyLinks(tx, role, allowMissing); err != nil {
		return err
	}

	for _, svcid := range role.ServiceIdentities {
		if svcid.ServiceName == "" {
			return fmt.Errorf("Encountered a Role with an empty service identity name in the state store")
		}
	}

	// Set the indexes
	if existing != nil {
		role.CreateIndex = existing.(*structs.ACLRole).CreateIndex
		role.ModifyIndex = idx
	} else {
		role.CreateIndex = idx
		role.ModifyIndex = idx
	}

	if err := tx.Insert("acl-roles", role); err != nil {
		return fmt.Errorf("failed inserting acl role: %v", err)
	}
	return nil
}

func (s *Store) ACLRoleGetByID(ws memdb.WatchSet, id string) (uint64, *structs.ACLRole, error) {
	return s.aclRoleGet(ws, id, "id")
}

func (s *Store) ACLRoleGetByName(ws memdb.WatchSet, name string) (uint64, *structs.ACLRole, error) {
	return s.aclRoleGet(ws, name, "name")
}

func (s *Store) ACLRoleBatchGet(ws memdb.WatchSet, ids, names []string) (uint64, structs.ACLRoles, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	roles := make(structs.ACLRoles, 0, len(ids)+len(names))
	for _, rid := range ids {
		role, err := s.getRoleWithTxn(tx, ws, rid, "id")
		if err != nil {
			return 0, nil, err
		}

		if role != nil {
			roles = append(roles, role)
		}
	}
	for _, rname := range names {
		role, err := s.getRoleWithTxn(tx, ws, rname, "name")
		if err != nil {
			return 0, nil, err
		}

		if role != nil {
			roles = append(roles, role)
		}
	}

	idx := maxIndexTxn(tx, "acl-roles")

	return idx, roles, nil
}

func (s *Store) getRoleWithTxn(tx *memdb.Txn, ws memdb.WatchSet, value, index string) (*structs.ACLRole, error) {
	watchCh, rawRole, err := tx.FirstWatch("acl-roles", index, value)
	if err != nil {
		return nil, fmt.Errorf("failed acl role lookup: %v", err)
	}
	ws.Add(watchCh)

	if rawRole != nil {
		role := rawRole.(*structs.ACLRole)
		role, err := s.fixupRolePolicyLinks(tx, role)
		if err != nil {
			return nil, err
		}
		return role, nil
	}

	return nil, nil
}

func (s *Store) aclRoleGet(ws memdb.WatchSet, value, index string) (uint64, *structs.ACLRole, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	role, err := s.getRoleWithTxn(tx, ws, value, index)
	if err != nil {
		return 0, nil, err
	}

	idx := maxIndexTxn(tx, "acl-roles")

	return idx, role, nil
}

func (s *Store) ACLRoleList(ws memdb.WatchSet, policy string) (uint64, structs.ACLRoles, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	var iter memdb.ResultIterator
	var err error

	if policy != "" {
		iter, err = tx.Get("acl-roles", "policies", policy)
	} else {
		iter, err = tx.Get("acl-roles", "id")
	}

	if err != nil {
		return 0, nil, fmt.Errorf("failed acl role lookup: %v", err)
	}
	ws.Add(iter.WatchCh())

	var result structs.ACLRoles
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		role := raw.(*structs.ACLRole)
		role, err := s.fixupRolePolicyLinks(tx, role)
		if err != nil {
			return 0, nil, err
		}
		result = append(result, role)
	}

	// Get the table index.
	idx := maxIndexTxn(tx, "acl-roles")

	return idx, result, nil
}

func (s *Store) ACLRoleDeleteByID(idx uint64, id string) error {
	return s.aclRoleDelete(idx, id, "id")
}

func (s *Store) ACLRoleDeleteByName(idx uint64, name string) error {
	return s.aclRoleDelete(idx, name, "name")
}

func (s *Store) ACLRoleBatchDelete(idx uint64, roleIDs []string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, roleID := range roleIDs {
		if err := s.aclRoleDeleteTxn(tx, idx, roleID, "id"); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-roles"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}
	tx.Commit()
	return nil
}

func (s *Store) aclRoleDelete(idx uint64, value, index string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclRoleDeleteTxn(tx, idx, value, index); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-roles"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclRoleDeleteTxn(tx *memdb.Txn, idx uint64, value, index string) error {
	// Look up the existing role
	rawRole, err := tx.First("acl-roles", index, value)
	if err != nil {
		return fmt.Errorf("failed acl role lookup: %v", err)
	}

	if rawRole == nil {
		return nil
	}

	role := rawRole.(*structs.ACLRole)

	if err := tx.Delete("acl-roles", role); err != nil {
		return fmt.Errorf("failed deleting acl role: %v", err)
	}
	return nil
}

func (s *Store) ACLRoleBindingRuleBatchSet(idx uint64, rules structs.ACLRoleBindingRules) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, rule := range rules {
		// this is only used when doing batch insertions for upgrades and replication. Therefore
		// we take whatever those said.
		if err := s.aclRoleBindingRuleSetTxn(tx, idx, rule); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-role-binding-rules"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) ACLRoleBindingRuleSet(idx uint64, rule *structs.ACLRoleBindingRule) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclRoleBindingRuleSetTxn(tx, idx, rule); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-role-binding-rules"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclRoleBindingRuleSetTxn(tx *memdb.Txn, idx uint64, rule *structs.ACLRoleBindingRule) error {
	// Check that the ID and IDPName are set
	if rule.ID == "" {
		return ErrMissingACLRoleBindingRuleID
	} else if rule.IDPName == "" {
		return ErrMissingACLRoleBindingRuleIDPName
	}

	existing, err := tx.First("acl-role-binding-rules", "id", rule.ID)
	if err != nil {
		return fmt.Errorf("failed acl role binding rule lookup: %v", err)
	}

	// Set the indexes
	if existing != nil {
		rule.CreateIndex = existing.(*structs.ACLRoleBindingRule).CreateIndex
		rule.ModifyIndex = idx
	} else {
		rule.CreateIndex = idx
		rule.ModifyIndex = idx
	}

	if idp, err := tx.First("acl-identity-providers", "id", rule.IDPName); err != nil {
		return fmt.Errorf("failed acl identity provider lookup: %v", err)
	} else if idp == nil {
		return fmt.Errorf("failed inserting acl role binding rule: identity provider not found")
	}

	if err := tx.Insert("acl-role-binding-rules", rule); err != nil {
		return fmt.Errorf("failed inserting acl role binding rule: %v", err)
	}
	return nil
}

func (s *Store) ACLRoleBindingRuleGetByID(ws memdb.WatchSet, id string) (uint64, *structs.ACLRoleBindingRule, error) {
	return s.aclRoleBindingRuleGet(ws, id, "id")
}

func (s *Store) ACLRoleBindingRuleBatchGet(ws memdb.WatchSet, ids []string) (uint64, structs.ACLRoleBindingRules, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	rules := make(structs.ACLRoleBindingRules, 0)
	for _, rid := range ids {
		rule, err := s.getRoleBindingRuleWithTxn(tx, ws, rid, "id")
		if err != nil {
			return 0, nil, err
		}

		if rule != nil {
			rules = append(rules, rule)
		}
	}

	idx := maxIndexTxn(tx, "acl-role-binding-rules")

	return idx, rules, nil
}

func (s *Store) getRoleBindingRuleWithTxn(tx *memdb.Txn, ws memdb.WatchSet, value, index string) (*structs.ACLRoleBindingRule, error) {
	watchCh, rawRule, err := tx.FirstWatch("acl-role-binding-rules", index, value)
	if err != nil {
		return nil, fmt.Errorf("failed acl role binding rule lookup: %v", err)
	}
	ws.Add(watchCh)

	if rawRule != nil {
		// TODO(rb): deep clone?
		return rawRule.(*structs.ACLRoleBindingRule), nil
	}

	return nil, nil
}

func (s *Store) aclRoleBindingRuleGet(ws memdb.WatchSet, value, index string) (uint64, *structs.ACLRoleBindingRule, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	rule, err := s.getRoleBindingRuleWithTxn(tx, ws, value, index)
	if err != nil {
		return 0, nil, err
	}

	idx := maxIndexTxn(tx, "acl-role-binding-rules")

	return idx, rule, nil
}

func (s *Store) ACLRoleBindingRuleList(ws memdb.WatchSet, idpName string) (uint64, structs.ACLRoleBindingRules, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	var (
		iter memdb.ResultIterator
		err  error
	)
	if idpName != "" {
		iter, err = tx.Get("acl-role-binding-rules", "idp", idpName)
	} else {
		iter, err = tx.Get("acl-role-binding-rules", "id")
	}
	if err != nil {
		return 0, nil, fmt.Errorf("failed acl role binding rule lookup: %v", err)
	}
	ws.Add(iter.WatchCh())

	var result structs.ACLRoleBindingRules
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		// TODO(rb): deep copy
		rule := raw.(*structs.ACLRoleBindingRule)
		result = append(result, rule)
	}

	// Get the table index.
	idx := maxIndexTxn(tx, "acl-role-binding-rules")

	return idx, result, nil
}

func (s *Store) ACLRoleBindingRuleDeleteByID(idx uint64, id string) error {
	return s.aclRoleBindingRuleDelete(idx, id, "id")
}

func (s *Store) ACLRoleBindingRuleBatchDelete(idx uint64, roleBindingRuleIDs []string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, roleBindingRuleID := range roleBindingRuleIDs {
		s.aclRoleBindingRuleDeleteTxn(tx, idx, roleBindingRuleID, "id")
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-role-binding-rules"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}
	tx.Commit()
	return nil
}

func (s *Store) aclRoleBindingRuleDelete(idx uint64, value, index string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclRoleBindingRuleDeleteTxn(tx, idx, value, index); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-role-binding-rules"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclRoleBindingRuleDeleteTxn(tx *memdb.Txn, idx uint64, value, index string) error {
	// Look up the existing role binding rule
	rawRule, err := tx.First("acl-role-binding-rules", index, value)
	if err != nil {
		return fmt.Errorf("failed acl role binding rule lookup: %v", err)
	}

	if rawRule == nil {
		return nil
	}

	rule := rawRule.(*structs.ACLRoleBindingRule)

	if err := tx.Delete("acl-role-binding-rules", rule); err != nil {
		return fmt.Errorf("failed deleting acl role binding rule: %v", err)
	}
	return nil
}

func (s *Store) aclRoleBindingRuleDeleteAllForIdentityProviderTxn(tx *memdb.Txn, idx uint64, idpName string) error {
	// collect them all
	iter, err := tx.Get("acl-role-binding-rules", "idp", idpName)
	if err != nil {
		return fmt.Errorf("failed acl role binding rule lookup: %v", err)
	}

	var rules structs.ACLRoleBindingRules
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		rule := raw.(*structs.ACLRoleBindingRule)
		rules = append(rules, rule)
	}

	if len(rules) > 0 {
		// delete them all
		for _, rule := range rules {
			if err := tx.Delete("acl-role-binding-rules", rule); err != nil {
				return fmt.Errorf("failed deleting acl role binding rule: %v", err)
			}
		}

		if err := indexUpdateMaxTxn(tx, idx, "acl-role-binding-rules"); err != nil {
			return fmt.Errorf("failed updating index: %v", err)
		}
	}

	return nil
}

func (s *Store) ACLIdentityProviderBatchSet(idx uint64, idps structs.ACLIdentityProviders) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, idp := range idps {
		// this is only used when doing batch insertions for upgrades and replication. Therefore
		// we take whatever those said.
		if err := s.aclIdentityProviderSetTxn(tx, idx, idp); err != nil {
			return err
		}
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-identity-providers"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) ACLIdentityProviderSet(idx uint64, idp *structs.ACLIdentityProvider) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclIdentityProviderSetTxn(tx, idx, idp); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-identity-providers"); err != nil {
		return fmt.Errorf("failed updating index: %s", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclIdentityProviderSetTxn(tx *memdb.Txn, idx uint64, idp *structs.ACLIdentityProvider) error {
	// Check that the Name and Type are set
	if idp.Name == "" {
		return ErrMissingACLIdentityProviderName
	} else if idp.Type == "" {
		return ErrMissingACLIdentityProviderType
	}

	existing, err := tx.First("acl-identity-providers", "id", idp.Name)
	if err != nil {
		return fmt.Errorf("failed acl identity provider lookup: %v", err)
	}

	// Set the indexes
	if existing != nil {
		idp.CreateIndex = existing.(*structs.ACLIdentityProvider).CreateIndex
		idp.ModifyIndex = idx
	} else {
		idp.CreateIndex = idx
		idp.ModifyIndex = idx
	}

	if err := tx.Insert("acl-identity-providers", idp); err != nil {
		return fmt.Errorf("failed inserting acl identity provider: %v", err)
	}
	return nil
}

func (s *Store) ACLIdentityProviderGetByName(ws memdb.WatchSet, name string) (uint64, *structs.ACLIdentityProvider, error) {
	return s.aclIdentityProviderGet(ws, name, "id")
}

func (s *Store) ACLIdentityProviderBatchGet(ws memdb.WatchSet, names []string) (uint64, structs.ACLIdentityProviders, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	idps := make(structs.ACLIdentityProviders, 0)
	for _, name := range names {
		idp, err := s.getIdentityProviderWithTxn(tx, ws, name, "id")
		if err != nil {
			return 0, nil, err
		}

		if idp != nil {
			idps = append(idps, idp)
		}
	}

	idx := maxIndexTxn(tx, "acl-identity-providers")

	return idx, idps, nil
}

func (s *Store) getIdentityProviderWithTxn(tx *memdb.Txn, ws memdb.WatchSet, value, index string) (*structs.ACLIdentityProvider, error) {
	watchCh, rawIdp, err := tx.FirstWatch("acl-identity-providers", index, value)
	if err != nil {
		return nil, fmt.Errorf("failed acl identity provider lookup: %v", err)
	}
	ws.Add(watchCh)

	if rawIdp != nil {
		// TODO(rb): deep clone?
		return rawIdp.(*structs.ACLIdentityProvider), nil
	}

	return nil, nil
}

func (s *Store) aclIdentityProviderGet(ws memdb.WatchSet, value, index string) (uint64, *structs.ACLIdentityProvider, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	idp, err := s.getIdentityProviderWithTxn(tx, ws, value, index)
	if err != nil {
		return 0, nil, err
	}

	idx := maxIndexTxn(tx, "acl-identity-providers")

	return idx, idp, nil
}

func (s *Store) ACLIdentityProviderList(ws memdb.WatchSet) (uint64, structs.ACLIdentityProviders, error) {
	tx := s.db.Txn(false)
	defer tx.Abort()

	iter, err := tx.Get("acl-identity-providers", "id")
	if err != nil {
		return 0, nil, fmt.Errorf("failed acl identity provider lookup: %v", err)
	}
	ws.Add(iter.WatchCh())

	var result structs.ACLIdentityProviders
	for raw := iter.Next(); raw != nil; raw = iter.Next() {
		// TODO(rb): deep copy
		idp := raw.(*structs.ACLIdentityProvider)
		result = append(result, idp)
	}

	// Get the table index.
	idx := maxIndexTxn(tx, "acl-identity-providers")

	return idx, result, nil
}

func (s *Store) ACLIdentityProviderDeleteByName(idx uint64, name string) error {
	return s.aclIdentityProviderDelete(idx, name, "id")
}

func (s *Store) ACLIdentityProviderBatchDelete(idx uint64, names []string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	for _, name := range names {
		s.aclIdentityProviderDeleteTxn(tx, idx, name, "id")
	}

	if err := indexUpdateMaxTxn(tx, idx, "acl-identity-providers"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}
	tx.Commit()
	return nil
}

func (s *Store) aclIdentityProviderDelete(idx uint64, value, index string) error {
	tx := s.db.Txn(true)
	defer tx.Abort()

	if err := s.aclIdentityProviderDeleteTxn(tx, idx, value, index); err != nil {
		return err
	}
	if err := indexUpdateMaxTxn(tx, idx, "acl-identity-providers"); err != nil {
		return fmt.Errorf("failed updating index: %v", err)
	}

	tx.Commit()
	return nil
}

func (s *Store) aclIdentityProviderDeleteTxn(tx *memdb.Txn, idx uint64, value, index string) error {
	// Look up the existing idp
	rawidp, err := tx.First("acl-identity-providers", index, value)
	if err != nil {
		return fmt.Errorf("failed acl identity provider lookup: %v", err)
	}

	if rawidp == nil {
		return nil
	}

	idp := rawidp.(*structs.ACLIdentityProvider)

	if err := s.aclRoleBindingRuleDeleteAllForIdentityProviderTxn(tx, idx, idp.Name); err != nil {
		return err
	}

	if err := tx.Delete("acl-identity-providers", idp); err != nil {
		return fmt.Errorf("failed deleting acl identity provider: %v", err)
	}
	return nil
}
