package consul

import (
	"fmt"
	"io/ioutil"
	"net/rpc"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/acl"
	"github.com/hashicorp/consul/agent/connect"
	"github.com/hashicorp/consul/agent/structs"
	tokenStore "github.com/hashicorp/consul/agent/token"
	"github.com/hashicorp/consul/lib"
	"github.com/hashicorp/consul/testrpc"
	"github.com/hashicorp/consul/sdk/testutil/retry"
	uuid "github.com/hashicorp/go-uuid"
	msgpackrpc "github.com/hashicorp/net-rpc-msgpackrpc"
	"github.com/stretchr/testify/require"
)

func TestACLEndpoint_Bootstrap(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.Build = "0.8.0" // Too low for auto init of bootstrap.
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	// Expect an error initially since ACL bootstrap is not initialized.
	arg := structs.DCSpecificRequest{
		Datacenter: "dc1",
	}
	var out structs.ACL
	// We can only do some high
	// level checks on the ACL since we don't have control over the UUID or
	// Raft indexes at this level.
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Bootstrap", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.ID) != len("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx") ||
		!strings.HasPrefix(out.Name, "Bootstrap Token") ||
		out.Type != structs.ACLTokenTypeManagement ||
		out.CreateIndex == 0 || out.ModifyIndex == 0 {
		t.Fatalf("bad: %#v", out)
	}

	// Finally, make sure that another attempt is rejected.
	err := msgpackrpc.CallWithCodec(codec, "ACL.Bootstrap", &arg, &out)
	if err.Error() != structs.ACLBootstrapNotAllowedErr.Error() {
		t.Fatalf("err: %v", err)
	}
}

func TestACLEndpoint_BootstrapTokens(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLsEnabled = true
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	// Expect an error initially since ACL bootstrap is not initialized.
	arg := structs.DCSpecificRequest{
		Datacenter: "dc1",
	}
	var out structs.ACLToken
	// We can only do some high
	// level checks on the ACL since we don't have control over the UUID or
	// Raft indexes at this level.
	require.NoError(t, msgpackrpc.CallWithCodec(codec, "ACL.BootstrapTokens", &arg, &out))
	require.Equal(t, 36, len(out.AccessorID))
	require.True(t, strings.HasPrefix(out.Description, "Bootstrap Token"))
	require.Equal(t, out.Type, structs.ACLTokenTypeManagement)
	require.True(t, out.CreateIndex > 0)
	require.Equal(t, out.CreateIndex, out.ModifyIndex)

	// Finally, make sure that another attempt is rejected.
	err := msgpackrpc.CallWithCodec(codec, "ACL.BootstrapTokens", &arg, &out)
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), structs.ACLBootstrapNotAllowedErr.Error()))

	_, resetIdx, err := s1.fsm.State().CanBootstrapACLToken()

	resetPath := filepath.Join(dir1, "acl-bootstrap-reset")
	require.NoError(t, ioutil.WriteFile(resetPath, []byte(fmt.Sprintf("%d", resetIdx)), 0600))

	oldID := out.AccessorID
	// Finally, make sure that another attempt is rejected.
	require.NoError(t, msgpackrpc.CallWithCodec(codec, "ACL.BootstrapTokens", &arg, &out))
	require.Equal(t, 36, len(out.AccessorID))
	require.NotEqual(t, oldID, out.AccessorID)
	require.True(t, strings.HasPrefix(out.Description, "Bootstrap Token"))
	require.Equal(t, out.Type, structs.ACLTokenTypeManagement)
	require.True(t, out.CreateIndex > 0)
	require.Equal(t, out.CreateIndex, out.ModifyIndex)
}

func TestACLEndpoint_Apply(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	id := out

	// Verify
	state := s1.fsm.State()
	_, s, err := state.ACLTokenGetBySecret(nil, out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s == nil {
		t.Fatalf("should not be nil")
	}
	if s.SecretID != out {
		t.Fatalf("bad: %v", s)
	}
	if s.Description != "User token" {
		t.Fatalf("bad: %v", s)
	}

	// Do a delete
	arg.Op = structs.ACLDelete
	arg.ACL.ID = out
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify
	_, s, err = state.ACLTokenGetBySecret(nil, id)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s != nil {
		t.Fatalf("bad: %v", s)
	}
}

func TestACLEndpoint_Update_PurgeCache(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	id := out

	// Resolve
	acl1, err := s1.ResolveToken(id)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if acl1 == nil {
		t.Fatalf("should not be nil")
	}
	if !acl1.KeyRead("foo") {
		t.Fatalf("should be allowed")
	}

	// Do an update
	arg.ACL.ID = out
	arg.ACL.Rules = `{"key": {"": {"policy": "deny"}}}`
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Resolve again
	acl2, err := s1.ResolveToken(id)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if acl2 == nil {
		t.Fatalf("should not be nil")
	}
	if acl2 == acl1 {
		t.Fatalf("should not be cached")
	}
	if acl2.KeyRead("foo") {
		t.Fatalf("should not be allowed")
	}

	// Do a delete
	arg.Op = structs.ACLDelete
	arg.ACL.Rules = ""
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Resolve again
	acl3, err := s1.ResolveToken(id)
	if !acl.IsErrNotFound(err) {
		t.Fatalf("err: %v", err)
	}
	if acl3 != nil {
		t.Fatalf("should be nil")
	}
}

func TestACLEndpoint_Apply_CustomID(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			ID:   "foobarbaz", // Specify custom ID, does not exist
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != "foobarbaz" {
		t.Fatalf("bad token ID: %s", out)
	}

	// Verify
	state := s1.fsm.State()
	_, s, err := state.ACLTokenGetBySecret(nil, out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s == nil {
		t.Fatalf("should not be nil")
	}
	if s.SecretID != out {
		t.Fatalf("bad: %v", s)
	}
	if s.Description != "User token" {
		t.Fatalf("bad: %v", s)
	}
}

func TestACLEndpoint_Apply_Denied(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
	}
	var out string
	err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out)
	if !acl.IsErrPermissionDenied(err) {
		t.Fatalf("err: %v", err)
	}
}

func TestACLEndpoint_Apply_DeleteAnon(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLDelete,
		ACL: structs.ACL{
			ID:   anonymousToken,
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out)
	if err == nil || !strings.Contains(err.Error(), "delete anonymous") {
		t.Fatalf("err: %v", err)
	}
}

func TestACLEndpoint_Apply_RootChange(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			ID:   "manage",
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out)
	if err == nil || !strings.Contains(err.Error(), "root ACL") {
		t.Fatalf("err: %v", err)
	}
}

func TestACLEndpoint_Get(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}

	getR := structs.ACLSpecificRequest{
		Datacenter: "dc1",
		ACL:        out,
	}
	var acls structs.IndexedACLs
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Get", &getR, &acls); err != nil {
		t.Fatalf("err: %v", err)
	}

	if acls.Index == 0 {
		t.Fatalf("Bad: %v", acls)
	}
	if len(acls.ACLs) != 1 {
		t.Fatalf("Bad: %v", acls)
	}
	s := acls.ACLs[0]
	if s.ID != out {
		t.Fatalf("bad: %v", s)
	}
}

func TestACLEndpoint_GetPolicy(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	arg := structs.ACLRequest{
		Datacenter: "dc1",
		Op:         structs.ACLSet,
		ACL: structs.ACL{
			Name: "User token",
			Type: structs.ACLTokenTypeClient,
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var out string
	if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
		t.Fatalf("err: %v", err)
	}

	getR := structs.ACLPolicyResolveLegacyRequest{
		Datacenter: "dc1",
		ACL:        out,
	}

	var acls structs.ACLPolicyResolveLegacyResponse
	retry.Run(t, func(r *retry.R) {

		if err := msgpackrpc.CallWithCodec(codec, "ACL.GetPolicy", &getR, &acls); err != nil {
			t.Fatalf("err: %v", err)
		}

		if acls.Policy == nil {
			t.Fatalf("Bad: %v", acls)
		}
		if acls.TTL != 30*time.Second {
			t.Fatalf("bad: %v", acls)
		}
	})

	// Do a conditional lookup with etag
	getR.ETag = acls.ETag
	var out2 structs.ACLPolicyResolveLegacyResponse
	if err := msgpackrpc.CallWithCodec(codec, "ACL.GetPolicy", &getR, &out2); err != nil {
		t.Fatalf("err: %v", err)
	}

	if out2.Policy != nil {
		t.Fatalf("Bad: %v", out2)
	}
	if out2.TTL != 30*time.Second {
		t.Fatalf("bad: %v", out2)
	}
}

func TestACLEndpoint_List(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ids := []string{}
	for i := 0; i < 5; i++ {
		arg := structs.ACLRequest{
			Datacenter: "dc1",
			Op:         structs.ACLSet,
			ACL: structs.ACL{
				Name: "User token",
				Type: structs.ACLTokenTypeClient,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		var out string
		if err := msgpackrpc.CallWithCodec(codec, "ACL.Apply", &arg, &out); err != nil {
			t.Fatalf("err: %v", err)
		}
		ids = append(ids, out)
	}

	getR := structs.DCSpecificRequest{
		Datacenter:   "dc1",
		QueryOptions: structs.QueryOptions{Token: "root"},
	}
	var acls structs.IndexedACLs
	if err := msgpackrpc.CallWithCodec(codec, "ACL.List", &getR, &acls); err != nil {
		t.Fatalf("err: %v", err)
	}

	if acls.Index == 0 {
		t.Fatalf("Bad: %v", acls)
	}

	// 5  + master
	if len(acls.ACLs) != 6 {
		t.Fatalf("Bad: %v", acls.ACLs)
	}
	for i := 0; i < len(acls.ACLs); i++ {
		s := acls.ACLs[i]
		if s.ID == anonymousToken || s.ID == "root" {
			continue
		}
		if !lib.StrContains(ids, s.ID) {
			t.Fatalf("bad: %v", s)
		}
		if s.Name != "User token" {
			t.Fatalf("bad: %v", s)
		}
	}
}

func TestACLEndpoint_List_Denied(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	getR := structs.DCSpecificRequest{
		Datacenter: "dc1",
	}
	var acls structs.IndexedACLs
	err := msgpackrpc.CallWithCodec(codec, "ACL.List", &getR, &acls)
	if !acl.IsErrPermissionDenied(err) {
		t.Fatalf("err: %v", err)
	}
}

func TestACLEndpoint_ReplicationStatus(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc2"
		c.ACLsEnabled = true
		c.ACLTokenReplication = true
		c.ACLReplicationRate = 100
		c.ACLReplicationBurst = 100
	})
	s1.tokens.UpdateReplicationToken("secret", tokenStore.TokenSourceConfig)
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	getR := structs.DCSpecificRequest{
		Datacenter: "dc1",
	}

	retry.Run(t, func(r *retry.R) {
		var status structs.ACLReplicationStatus
		err := msgpackrpc.CallWithCodec(codec, "ACL.ReplicationStatus", &getR, &status)
		if err != nil {
			r.Fatalf("err: %v", err)
		}
		if !status.Enabled || !status.Running || status.SourceDatacenter != "dc2" {
			r.Fatalf("bad: %#v", status)
		}
	})
}

func TestACLEndpoint_TokenRead(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	t.Run("exists and matches what we created", func(t *testing.T) {
		token, err := upsertTestToken(codec, "root", "dc1", nil)
		require.NoError(t, err)

		req := structs.ACLTokenGetRequest{
			Datacenter:   "dc1",
			TokenID:      token.AccessorID,
			TokenIDType:  structs.ACLTokenAccessor,
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenResponse{}

		err = acl.TokenRead(&req, &resp)
		require.NoError(t, err)

		if !reflect.DeepEqual(resp.Token, token) {
			t.Fatalf("tokens are not equal: %v != %v", resp.Token, token)
		}
	})

	t.Run("expired tokens are filtered", func(t *testing.T) {
		// insert a token that will expire
		token, err := upsertTestToken(codec, "root", "dc1", func(t *structs.ACLToken) {
			t.ExpirationTTL = 20 * time.Millisecond
		})
		require.NoError(t, err)

		t.Run("readable until expiration", func(t *testing.T) {
			req := structs.ACLTokenGetRequest{
				Datacenter:   "dc1",
				TokenID:      token.AccessorID,
				TokenIDType:  structs.ACLTokenAccessor,
				QueryOptions: structs.QueryOptions{Token: "root"},
			}

			resp := structs.ACLTokenResponse{}

			require.NoError(t, acl.TokenRead(&req, &resp))
			require.Equal(t, token, resp.Token)
		})

		time.Sleep(50 * time.Millisecond)

		t.Run("not returned when expired", func(t *testing.T) {
			req := structs.ACLTokenGetRequest{
				Datacenter:   "dc1",
				TokenID:      token.AccessorID,
				TokenIDType:  structs.ACLTokenAccessor,
				QueryOptions: structs.QueryOptions{Token: "root"},
			}

			resp := structs.ACLTokenResponse{}

			require.NoError(t, acl.TokenRead(&req, &resp))
			require.Nil(t, resp.Token)
		})
	})

	t.Run("nil when token does not exist", func(t *testing.T) {
		fakeID, err := uuid.GenerateUUID()
		require.NoError(t, err)

		req := structs.ACLTokenGetRequest{
			Datacenter:   "dc1",
			TokenID:      fakeID,
			TokenIDType:  structs.ACLTokenAccessor,
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenResponse{}

		err = acl.TokenRead(&req, &resp)
		require.Nil(t, resp.Token)
		require.NoError(t, err)
	})

	t.Run("validates ID format", func(t *testing.T) {
		req := structs.ACLTokenGetRequest{
			Datacenter:   "dc1",
			TokenID:      "definitely-really-certainly-not-a-uuid",
			TokenIDType:  structs.ACLTokenAccessor,
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenResponse{}

		err := acl.TokenRead(&req, &resp)
		require.Nil(t, resp.Token)
		require.EqualError(t, err, "failed acl token lookup: failed acl token lookup: index error: UUID must be 36 characters")
	})
}

func TestACLEndpoint_TokenClone(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	t1, err := upsertTestToken(codec, "root", "dc1", nil)
	require.NoError(t, err)

	endpoint := ACL{srv: s1}

	t.Run("normal", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter:   "dc1",
			ACLToken:     structs.ACLToken{AccessorID: t1.AccessorID},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		t2 := structs.ACLToken{}

		err = endpoint.TokenClone(&req, &t2)
		require.NoError(t, err)

		require.Equal(t, t1.Description, t2.Description)
		require.Equal(t, t1.Policies, t2.Policies)
		require.Equal(t, t1.Rules, t2.Rules)
		require.Equal(t, t1.Local, t2.Local)
		require.NotEqual(t, t1.AccessorID, t2.AccessorID)
		require.NotEqual(t, t1.SecretID, t2.SecretID)
	})

	t.Run("can't clone expired token", func(t *testing.T) {
		// insert a token that will expire
		t1, err := upsertTestToken(codec, "root", "dc1", func(t *structs.ACLToken) {
			t.ExpirationTTL = 11 * time.Millisecond
		})
		require.NoError(t, err)

		time.Sleep(30 * time.Millisecond)

		req := structs.ACLTokenSetRequest{
			Datacenter:   "dc1",
			ACLToken:     structs.ACLToken{AccessorID: t1.AccessorID},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		t2 := structs.ACLToken{}

		err = endpoint.TokenClone(&req, &t2)
		require.Error(t, err)
		require.Equal(t, acl.ErrNotFound, err)
	})
}

func TestACLEndpoint_TokenSet(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	var tokenID string

	t.Run("Create it", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Policies:    nil,
				Local:       false,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "foobar")
		require.Equal(t, token.AccessorID, resp.AccessorID)

		tokenID = token.AccessorID
	})

	t.Run("Update it", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "new-description",
				AccessorID:  tokenID,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "new-description")
		require.Equal(t, token.AccessorID, resp.AccessorID)
	})

	t.Run("Create it using Policies linked by id and name", func(t *testing.T) {
		policy1, err := upsertTestPolicy(codec, "root", "dc1")
		require.NoError(t, err)
		policy2, err := upsertTestPolicy(codec, "root", "dc1")
		require.NoError(t, err)

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Policies: []structs.ACLTokenPolicyLink{
					structs.ACLTokenPolicyLink{
						ID: policy1.ID,
					},
					structs.ACLTokenPolicyLink{
						Name: policy2.Name,
					},
				},
				Local: false,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err = acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Delete both policies to ensure that we skip resolving ID->Name
		// in the returned data.
		require.NoError(t, deleteTestPolicy(codec, "root", "dc1", policy1.ID))
		require.NoError(t, deleteTestPolicy(codec, "root", "dc1", policy2.ID))

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "foobar")
		require.Equal(t, token.AccessorID, resp.AccessorID)

		require.Len(t, token.Policies, 0)
	})

	t.Run("Create it using Roles linked by id and name", func(t *testing.T) {
		role1, err := upsertTestRole(codec, "root", "dc1")
		require.NoError(t, err)
		role2, err := upsertTestRole(codec, "root", "dc1")
		require.NoError(t, err)

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						ID: role1.ID,
					},
					structs.ACLTokenRoleLink{
						Name: role2.Name,
					},
				},
				Local: false,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err = acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Delete both roles to ensure that we skip resolving ID->Name
		// in the returned data.
		require.NoError(t, deleteTestRole(codec, "root", "dc1", role1.ID))
		require.NoError(t, deleteTestRole(codec, "root", "dc1", role2.ID))

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "foobar")
		require.Equal(t, token.AccessorID, resp.AccessorID)

		require.Len(t, token.Roles, 0)
	})

	t.Run("Create it with IDPName set outside of login", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				IDPName:     "k8s",
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "IDPName field is disallowed outside of Login")
	})

	t.Run("Create fails using bound Roles outside of login", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						BoundName: "web",
					},
				},
				Local: true,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Cannot link a role to a token using a bound name outside of login")
	})

	t.Run("Create fails linking a role with BoundName AND id", func(t *testing.T) {
		acl := ACL{
			srv:                                   s1,
			disableLoginOnlyRestrictionOnTokenSet: true,
		}

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				IDPName:     "k8s",
				Description: "foobar",
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						ID:        "abc",
						BoundName: "web",
					},
				},
				Local: true,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Role links can either set BoundName OR ID/Name but not both")
	})

	t.Run("Create fails linking a role with BoundName AND Name", func(t *testing.T) {
		acl := ACL{
			srv:                                   s1,
			disableLoginOnlyRestrictionOnTokenSet: true,
		}

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				IDPName:     "k8s",
				Description: "foobar",
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						Name:      "def",
						BoundName: "web",
					},
				},
				Local: true,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Role links can either set BoundName OR ID/Name but not both")
	})

	t.Run("Create fails with an empty IDPName when faking login", func(t *testing.T) {
		acl := ACL{
			srv:                                   s1,
			disableLoginOnlyRestrictionOnTokenSet: true,
		}

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				IDPName:     "",
				Description: "foobar",
				Local:       true,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "IDPName field is required during Login")
	})

	t.Run("Create it using bound Roles by faking login", func(t *testing.T) {
		// This allows for testing things that are only possible via Login, but
		// just cumbersome to wire up (multiple role binding rules, etc)
		acl := ACL{
			srv:                                   s1,
			disableLoginOnlyRestrictionOnTokenSet: true,
		}

		ca := connect.TestCA(t, nil)
		idp, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				IDPName:     idp.Name,
				Description: "foobar",
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						BoundName: "web",
					},
					structs.ACLTokenRoleLink{
						BoundName: "db",
					},
					structs.ACLTokenRoleLink{
						BoundName: "web", // add web twice to test dedupe
					},
				},
				Local: true,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err = acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.Len(t, token.Roles, 2)
		require.Equal(t, "web", token.Roles[0].BoundName)
		require.Equal(t, "db", token.Roles[1].BoundName)
	})

	t.Run("Create it with invalid service identity (empty)", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Policies:    nil,
				Local:       false,
				ServiceIdentities: []*structs.ACLServiceIdentity{
					&structs.ACLServiceIdentity{ServiceName: ""},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Service identity is missing the service name field")
	})

	t.Run("Create it with invalid service identity (too large)", func(t *testing.T) {
		long := strings.Repeat("x", serviceIdentityNameMaxLength+1)
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Policies:    nil,
				Local:       false,
				ServiceIdentities: []*structs.ACLServiceIdentity{
					&structs.ACLServiceIdentity{ServiceName: long},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		require.NotNil(t, err)
	})

	for _, test := range []struct {
		name string
		ok   bool
	}{
		{"-abc", false},
		{"abc-", false},
		{"a-bc", true},
		{"_abc", false},
		{"abc_", false},
		{"a_bc", true},
		{":abc", false},
		{"abc:", false},
		{"a:bc", false},
		{"Abc", false},
		{"aBc", false},
		{"abC", false},
		{"0abc", true},
		{"abc0", true},
		{"a0bc", true},
	} {
		var testName string
		if test.ok {
			testName = "Create it with valid service identity (by regex): " + test.name
		} else {
			testName = "Create it with invalid service identity (by regex): " + test.name
		}
		t.Run(testName, func(t *testing.T) {
			req := structs.ACLTokenSetRequest{
				Datacenter: "dc1",
				ACLToken: structs.ACLToken{
					Description: "foobar",
					Policies:    nil,
					Local:       false,
					ServiceIdentities: []*structs.ACLServiceIdentity{
						&structs.ACLServiceIdentity{ServiceName: test.name},
					},
				},
				WriteRequest: structs.WriteRequest{Token: "root"},
			}

			resp := structs.ACLToken{}

			err := acl.TokenSet(&req, &resp)
			if test.ok {
				require.NoError(t, err)

				// Get the token directly to validate that it exists
				tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
				require.NoError(t, err)
				token := tokenResp.Token
				require.ElementsMatch(t, req.ACLToken.ServiceIdentities, token.ServiceIdentities)
			} else {
				require.NotNil(t, err)
			}
		})
	}

	t.Run("Create it with invalid service identity (datacenters set on local token)", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description: "foobar",
				Policies:    nil,
				Local:       true,
				ServiceIdentities: []*structs.ACLServiceIdentity{
					&structs.ACLServiceIdentity{ServiceName: "foo", Datacenters: []string{"dc2"}},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "cannot specify a list of datacenters on a local token")
	})

	for _, test := range []struct {
		name         string
		offset       time.Duration
		errString    string
		errStringTTL string
	}{
		{"before create time", -5 * time.Minute, "ExpirationTime cannot be before CreateTime", ""},
		{"too soon", 1 * time.Millisecond, "ExpirationTime cannot be less than", "ExpirationTime cannot be less than"},
		{"too distant", 25 * time.Hour, "ExpirationTime cannot be more than", "ExpirationTime cannot be more than"},
	} {
		t.Run("Create it with an expiration time that is "+test.name, func(t *testing.T) {
			req := structs.ACLTokenSetRequest{
				Datacenter: "dc1",
				ACLToken: structs.ACLToken{
					Description:    "foobar",
					Policies:       nil,
					Local:          false,
					ExpirationTime: time.Now().Add(test.offset),
				},
				WriteRequest: structs.WriteRequest{Token: "root"},
			}

			resp := structs.ACLToken{}

			err := acl.TokenSet(&req, &resp)
			if test.errString != "" {
				requireErrorContains(t, err, test.errString)
			} else {
				require.NotNil(t, err)
			}
		})

		t.Run("Create it with an expiration TTL that is "+test.name, func(t *testing.T) {
			req := structs.ACLTokenSetRequest{
				Datacenter: "dc1",
				ACLToken: structs.ACLToken{
					Description:   "foobar",
					Policies:      nil,
					Local:         false,
					ExpirationTTL: test.offset,
				},
				WriteRequest: structs.WriteRequest{Token: "root"},
			}

			resp := structs.ACLToken{}

			err := acl.TokenSet(&req, &resp)
			if test.errString != "" {
				requireErrorContains(t, err, test.errStringTTL)
			} else {
				require.NotNil(t, err)
			}
		})
	}

	t.Run("Create it with expiration time AND expiration TTL set (error)", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description:    "foobar",
				Policies:       nil,
				Local:          false,
				ExpirationTime: time.Now().Add(4 * time.Second),
				ExpirationTTL:  4 * time.Second,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Expiration TTL and Expiration Time cannot both be set")
	})

	t.Run("Create it with expiration time using TTLs", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description:   "foobar",
				Policies:      nil,
				Local:         false,
				ExpirationTTL: 4 * time.Second,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		expectExpTime := resp.CreateTime.Add(4 * time.Second)

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "foobar")
		require.Equal(t, token.AccessorID, resp.AccessorID)
		requireTimeEquals(t, expectExpTime, resp.ExpirationTime)

		tokenID = token.AccessorID
	})

	var expTime time.Time
	t.Run("Create it with expiration time", func(t *testing.T) {
		expTime = time.Now().Add(4 * time.Second)
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description:    "foobar",
				Policies:       nil,
				Local:          false,
				ExpirationTime: expTime,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "foobar")
		require.Equal(t, token.AccessorID, resp.AccessorID)
		requireTimeEquals(t, expTime, resp.ExpirationTime)

		tokenID = token.AccessorID
	})

	// do not insert another test at this point: these tests need to be serial

	t.Run("Update expiration time is not allowed", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description:    "new-description",
				AccessorID:     tokenID,
				ExpirationTime: expTime.Add(-1 * time.Second),
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Cannot change expiration time")
	})

	// do not insert another test at this point: these tests need to be serial

	t.Run("Update anything except expiration time is ok", func(t *testing.T) {
		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description:    "new-description",
				AccessorID:     tokenID,
				ExpirationTime: expTime,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err := acl.TokenSet(&req, &resp)
		require.NoError(t, err)

		// Get the token directly to validate that it exists
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", resp.AccessorID)
		require.NoError(t, err)
		token := tokenResp.Token

		require.NotNil(t, token.AccessorID)
		require.Equal(t, token.Description, "new-description")
		require.Equal(t, token.AccessorID, resp.AccessorID)
		requireTimeEquals(t, expTime, resp.ExpirationTime)
	})

	t.Run("cannot update a token that is past its expiration time", func(t *testing.T) {
		// create a token that will expire
		expiringToken, err := upsertTestToken(codec, "root", "dc1", func(token *structs.ACLToken) {
			token.ExpirationTTL = 11 * time.Millisecond
		})
		require.NoError(t, err)

		time.Sleep(20 * time.Millisecond) // now 'expiringToken' is expired

		req := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Description:   "new-description",
				AccessorID:    expiringToken.AccessorID,
				ExpirationTTL: 4 * time.Second,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		resp := structs.ACLToken{}

		err = acl.TokenSet(&req, &resp)
		requireErrorContains(t, err, "Cannot find token")
	})
}

func TestACLEndpoint_TokenSet_anon(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")
	policy, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}

	// Assign the policies to a token
	tokenUpsertReq := structs.ACLTokenSetRequest{
		Datacenter: "dc1",
		ACLToken: structs.ACLToken{
			AccessorID: structs.ACLTokenAnonymousID,
			Policies: []structs.ACLTokenPolicyLink{
				structs.ACLTokenPolicyLink{
					ID: policy.ID,
				},
			},
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	token := structs.ACLToken{}
	err = acl.TokenSet(&tokenUpsertReq, &token)
	require.NoError(t, err)
	require.NotEmpty(t, token.SecretID)

	tokenResp, err := retrieveTestToken(codec, "root", "dc1", structs.ACLTokenAnonymousID)
	require.Equal(t, len(tokenResp.Token.Policies), 1)
	require.Equal(t, tokenResp.Token.Policies[0].ID, policy.ID)
}

func TestACLEndpoint_TokenDelete(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	dir2, s2 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.Datacenter = "dc2"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
		// token replication is required to test deleting non-local tokens in secondary dc
		c.ACLTokenReplication = true
	})
	defer os.RemoveAll(dir2)
	defer s2.Shutdown()
	codec2 := rpcClient(t, s2)
	defer codec2.Close()

	s2.tokens.UpdateReplicationToken("root", tokenStore.TokenSourceConfig)

	testrpc.WaitForLeader(t, s1.RPC, "dc1")
	testrpc.WaitForLeader(t, s2.RPC, "dc2")

	// Try to join
	joinWAN(t, s2, s1)

	acl := ACL{srv: s1}
	acl2 := ACL{srv: s2}

	existingToken, err := upsertTestToken(codec, "root", "dc1", nil)
	require.NoError(t, err)

	t.Run("deletes a token that has an expiration time in the future", func(t *testing.T) {
		// create a token that will expire
		testToken, err := upsertTestToken(codec, "root", "dc1", func(token *structs.ACLToken) {
			token.ExpirationTTL = 4 * time.Second
		})
		require.NoError(t, err)

		// Make sure the token is listable
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", testToken.AccessorID)
		require.NoError(t, err)
		require.NotNil(t, tokenResp.Token)

		// Now try to delete it (this should work).
		req := structs.ACLTokenDeleteRequest{
			Datacenter:   "dc1",
			TokenID:      testToken.AccessorID,
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var resp string

		err = acl.TokenDelete(&req, &resp)
		require.NoError(t, err)

		// Make sure the token is gone
		tokenResp, err = retrieveTestToken(codec, "root", "dc1", testToken.AccessorID)
		require.NoError(t, err)
		require.Nil(t, tokenResp.Token)
	})

	t.Run("deletes a token that is past its expiration time", func(t *testing.T) {
		// create a token that will expire
		expiringToken, err := upsertTestToken(codec, "root", "dc1", func(token *structs.ACLToken) {
			token.ExpirationTTL = 11 * time.Millisecond
		})
		require.NoError(t, err)

		time.Sleep(20 * time.Millisecond) // now 'expiringToken' is expired

		// Make sure the token is not listable (filtered due to expiry)
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", expiringToken.AccessorID)
		require.NoError(t, err)
		require.Nil(t, tokenResp.Token)

		// Now try to delete it (this should work).
		req := structs.ACLTokenDeleteRequest{
			Datacenter:   "dc1",
			TokenID:      expiringToken.AccessorID,
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var resp string

		err = acl.TokenDelete(&req, &resp)
		require.NoError(t, err)

		// Make sure the token is still gone (this time it's actually gone)
		tokenResp, err = retrieveTestToken(codec, "root", "dc1", expiringToken.AccessorID)
		require.NoError(t, err)
		require.Nil(t, tokenResp.Token)
	})

	t.Run("deletes a token", func(t *testing.T) {
		req := structs.ACLTokenDeleteRequest{
			Datacenter:   "dc1",
			TokenID:      existingToken.AccessorID,
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var resp string

		err = acl.TokenDelete(&req, &resp)
		require.NoError(t, err)

		// Make sure the token is gone
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", existingToken.AccessorID)
		require.Nil(t, tokenResp.Token)
		require.NoError(t, err)
	})

	t.Run("can't delete itself", func(t *testing.T) {
		readReq := structs.ACLTokenGetRequest{
			Datacenter:   "dc1",
			TokenID:      "root",
			TokenIDType:  structs.ACLTokenSecret,
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		var out structs.ACLTokenResponse

		err := acl.TokenRead(&readReq, &out)

		require.NoError(t, err)

		req := structs.ACLTokenDeleteRequest{
			Datacenter:   "dc1",
			TokenID:      out.Token.AccessorID,
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var resp string
		err = acl.TokenDelete(&req, &resp)
		require.EqualError(t, err, "Deletion of the request's authorization token is not permitted")
	})

	t.Run("errors when token doesn't exist", func(t *testing.T) {
		fakeID, err := uuid.GenerateUUID()
		require.NoError(t, err)

		req := structs.ACLTokenDeleteRequest{
			Datacenter:   "dc1",
			TokenID:      fakeID,
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var resp string

		err = acl.TokenDelete(&req, &resp)
		require.NoError(t, err)

		// token should be nil
		tokenResp, err := retrieveTestToken(codec, "root", "dc1", existingToken.AccessorID)
		require.Nil(t, tokenResp.Token)
		require.NoError(t, err)
	})

	t.Run("don't segfault when attempting to delete non existent token in secondary dc", func(t *testing.T) {
		fakeID, err := uuid.GenerateUUID()
		require.NoError(t, err)

		req := structs.ACLTokenDeleteRequest{
			Datacenter:   "dc2",
			TokenID:      fakeID,
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var resp string

		waitForNewACLs(t, s2)

		err = acl2.TokenDelete(&req, &resp)
		require.NoError(t, err)

		// token should be nil
		tokenResp, err := retrieveTestToken(codec2, "root", "dc1", existingToken.AccessorID)
		require.Nil(t, tokenResp.Token)
		require.NoError(t, err)
	})
}

func TestACLEndpoint_TokenDelete_anon(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	req := structs.ACLTokenDeleteRequest{
		Datacenter:   "dc1",
		TokenID:      structs.ACLTokenAnonymousID,
		WriteRequest: structs.WriteRequest{Token: "root"},
	}

	var resp string

	err := acl.TokenDelete(&req, &resp)
	require.EqualError(t, err, "Delete operation not permitted on the anonymous token")

	// Make sure the token is still there
	tokenResp, err := retrieveTestToken(codec, "root", "dc1", structs.ACLTokenAnonymousID)
	require.NotNil(t, tokenResp.Token)
}

func TestACLEndpoint_TokenList(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	t1, err := upsertTestToken(codec, "root", "dc1", nil)
	require.NoError(t, err)

	t2, err := upsertTestToken(codec, "root", "dc1", nil)
	require.NoError(t, err)

	t3, err := upsertTestToken(codec, "root", "dc1", func(token *structs.ACLToken) {
		token.ExpirationTTL = 11 * time.Millisecond
	})
	require.NoError(t, err)

	masterTokenAccessorID, err := retrieveTestTokenAccessorForSecret(codec, "root", "dc1", "root")
	require.NoError(t, err)

	t.Run("normal", func(t *testing.T) {
		req := structs.ACLTokenListRequest{
			Datacenter:   "dc1",
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenListResponse{}

		err = acl.TokenList(&req, &resp)
		require.NoError(t, err)

		tokens := []string{
			masterTokenAccessorID,
			structs.ACLTokenAnonymousID,
			t1.AccessorID,
			t2.AccessorID,
			t3.AccessorID,
		}
		require.ElementsMatch(t, gatherIDs(t, resp.Tokens), tokens)
	})

	time.Sleep(20 * time.Millisecond) // now 't3' is expired

	t.Run("filter expired", func(t *testing.T) {
		req := structs.ACLTokenListRequest{
			Datacenter:   "dc1",
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenListResponse{}

		err = acl.TokenList(&req, &resp)
		require.NoError(t, err)

		tokens := []string{
			masterTokenAccessorID,
			structs.ACLTokenAnonymousID,
			t1.AccessorID,
			t2.AccessorID,
		}
		require.ElementsMatch(t, gatherIDs(t, resp.Tokens), tokens)
	})
}

func TestACLEndpoint_TokenBatchRead(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	t1, err := upsertTestToken(codec, "root", "dc1", nil)
	require.NoError(t, err)

	t2, err := upsertTestToken(codec, "root", "dc1", nil)
	require.NoError(t, err)

	t3, err := upsertTestToken(codec, "root", "dc1", func(token *structs.ACLToken) {
		token.ExpirationTTL = 4 * time.Second
	})
	require.NoError(t, err)

	t.Run("normal", func(t *testing.T) {
		tokens := []string{t1.AccessorID, t2.AccessorID, t3.AccessorID}

		req := structs.ACLTokenBatchGetRequest{
			Datacenter:   "dc1",
			AccessorIDs:  tokens,
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenBatchResponse{}

		err = acl.TokenBatchRead(&req, &resp)
		require.NoError(t, err)
		require.ElementsMatch(t, gatherIDs(t, resp.Tokens), tokens)
	})

	time.Sleep(20 * time.Millisecond) // now 't3' is expired

	t.Run("returns expired tokens", func(t *testing.T) {
		tokens := []string{t1.AccessorID, t2.AccessorID, t3.AccessorID}

		req := structs.ACLTokenBatchGetRequest{
			Datacenter:   "dc1",
			AccessorIDs:  tokens,
			QueryOptions: structs.QueryOptions{Token: "root"},
		}

		resp := structs.ACLTokenBatchResponse{}

		err = acl.TokenBatchRead(&req, &resp)
		require.NoError(t, err)
		require.ElementsMatch(t, gatherIDs(t, resp.Tokens), tokens)
	})
}

func TestACLEndpoint_PolicyRead(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	policy, err := upsertTestPolicy(codec, "root", "dc1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	acl := ACL{srv: s1}

	req := structs.ACLPolicyGetRequest{
		Datacenter:   "dc1",
		PolicyID:     policy.ID,
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLPolicyResponse{}

	err = acl.PolicyRead(&req, &resp)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !reflect.DeepEqual(resp.Policy, policy) {
		t.Fatalf("tokens are not equal: %v != %v", resp.Policy, policy)
	}
}

func TestACLEndpoint_PolicyBatchRead(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	p1, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	p2, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}
	policies := []string{p1.ID, p2.ID}

	req := structs.ACLPolicyBatchGetRequest{
		Datacenter:   "dc1",
		PolicyIDs:    policies,
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLPolicyBatchResponse{}

	err = acl.PolicyBatchRead(&req, &resp)
	require.NoError(t, err)
	require.ElementsMatch(t, gatherIDs(t, resp.Policies), []string{p1.ID, p2.ID})
}

func TestACLEndpoint_PolicySet(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}
	var policyID string

	t.Run("Create it", func(t *testing.T) {
		req := structs.ACLPolicySetRequest{
			Datacenter: "dc1",
			Policy: structs.ACLPolicy{
				Description: "foobar",
				Name:        "baz",
				Rules:       "service \"\" { policy = \"read\" }",
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLPolicy{}

		err := acl.PolicySet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Get the policy directly to validate that it exists
		policyResp, err := retrieveTestPolicy(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		policy := policyResp.Policy

		require.NotNil(t, policy.ID)
		require.Equal(t, policy.Description, "foobar")
		require.Equal(t, policy.Name, "baz")
		require.Equal(t, policy.Rules, "service \"\" { policy = \"read\" }")

		policyID = policy.ID
	})

	t.Run("Update it", func(t *testing.T) {
		req := structs.ACLPolicySetRequest{
			Datacenter: "dc1",
			Policy: structs.ACLPolicy{
				ID:          policyID,
				Description: "bat",
				Name:        "bar",
				Rules:       "service \"\" { policy = \"write\" }",
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLPolicy{}

		err := acl.PolicySet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Get the policy directly to validate that it exists
		policyResp, err := retrieveTestPolicy(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		policy := policyResp.Policy

		require.NotNil(t, policy.ID)
		require.Equal(t, policy.Description, "bat")
		require.Equal(t, policy.Name, "bar")
		require.Equal(t, policy.Rules, "service \"\" { policy = \"write\" }")
	})
}

func TestACLEndpoint_PolicySet_globalManagement(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	// Can't change the rules
	{

		req := structs.ACLPolicySetRequest{
			Datacenter: "dc1",
			Policy: structs.ACLPolicy{
				ID:    structs.ACLPolicyGlobalManagementID,
				Name:  "foobar", // This is required to get past validation
				Rules: "service \"\" { policy = \"write\" }",
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLPolicy{}

		err := acl.PolicySet(&req, &resp)
		require.EqualError(t, err, "Changing the Rules for the builtin global-management policy is not permitted")
	}

	// Can rename it
	{
		req := structs.ACLPolicySetRequest{
			Datacenter: "dc1",
			Policy: structs.ACLPolicy{
				ID:    structs.ACLPolicyGlobalManagementID,
				Name:  "foobar",
				Rules: structs.ACLPolicyGlobalManagement,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLPolicy{}

		err := acl.PolicySet(&req, &resp)
		require.NoError(t, err)

		// Get the policy again
		policyResp, err := retrieveTestPolicy(codec, "root", "dc1", structs.ACLPolicyGlobalManagementID)
		require.NoError(t, err)
		policy := policyResp.Policy

		require.Equal(t, policy.ID, structs.ACLPolicyGlobalManagementID)
		require.Equal(t, policy.Name, "foobar")

	}
}

func TestACLEndpoint_PolicyDelete(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	existingPolicy, err := upsertTestPolicy(codec, "root", "dc1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	acl := ACL{srv: s1}

	req := structs.ACLPolicyDeleteRequest{
		Datacenter:   "dc1",
		PolicyID:     existingPolicy.ID,
		WriteRequest: structs.WriteRequest{Token: "root"},
	}

	var resp string

	err = acl.PolicyDelete(&req, &resp)
	require.NoError(t, err)

	// Make sure the policy is gone
	tokenResp, err := retrieveTestPolicy(codec, "root", "dc1", existingPolicy.ID)
	require.Nil(t, tokenResp.Policy)
}

func TestACLEndpoint_PolicyDelete_globalManagement(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	req := structs.ACLPolicyDeleteRequest{
		Datacenter:   "dc1",
		PolicyID:     structs.ACLPolicyGlobalManagementID,
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	var resp string

	err := acl.PolicyDelete(&req, &resp)

	require.EqualError(t, err, "Delete operation not permitted on the builtin global-management policy")
}

func TestACLEndpoint_PolicyList(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	p1, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	p2, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLPolicyListRequest{
		Datacenter:   "dc1",
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLPolicyListResponse{}

	err = acl.PolicyList(&req, &resp)
	require.NoError(t, err)

	policies := []string{
		structs.ACLPolicyGlobalManagementID,
		p1.ID,
		p2.ID,
	}
	require.ElementsMatch(t, gatherIDs(t, resp.Policies), policies)
}

func TestACLEndpoint_PolicyResolve(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	p1, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	p2, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}

	policies := []string{p1.ID, p2.ID}

	// Assign the policies to a token
	tokenUpsertReq := structs.ACLTokenSetRequest{
		Datacenter: "dc1",
		ACLToken: structs.ACLToken{
			Policies: []structs.ACLTokenPolicyLink{
				structs.ACLTokenPolicyLink{
					ID: p1.ID,
				},
				structs.ACLTokenPolicyLink{
					ID: p2.ID,
				},
			},
		},
		WriteRequest: structs.WriteRequest{Token: "root"},
	}
	token := structs.ACLToken{}
	err = acl.TokenSet(&tokenUpsertReq, &token)
	require.NoError(t, err)
	require.NotEmpty(t, token.SecretID)

	resp := structs.ACLPolicyBatchResponse{}
	req := structs.ACLPolicyBatchGetRequest{
		Datacenter:   "dc1",
		PolicyIDs:    []string{p1.ID, p2.ID},
		QueryOptions: structs.QueryOptions{Token: token.SecretID},
	}
	err = acl.PolicyResolve(&req, &resp)
	require.NoError(t, err)
	require.ElementsMatch(t, gatherIDs(t, resp.Policies), policies)
}

func TestACLEndpoint_RoleRead(t *testing.T) {
	t.Parallel()
	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	role, err := upsertTestRole(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLRoleGetRequest{
		Datacenter:   "dc1",
		RoleID:       role.ID,
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLRoleResponse{}

	err = acl.RoleRead(&req, &resp)
	require.NoError(t, err)
	require.Equal(t, role, resp.Role)
}

func TestACLEndpoint_RoleBatchRead(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	r1, err := upsertTestRole(codec, "root", "dc1")
	require.NoError(t, err)

	r2, err := upsertTestRole(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}
	roles := []string{r1.ID, r2.ID}

	req := structs.ACLRoleBatchGetRequest{
		Datacenter:   "dc1",
		RoleIDs:      roles,
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLRoleBatchResponse{}

	err = acl.RoleBatchRead(&req, &resp)
	require.NoError(t, err)
	require.ElementsMatch(t, gatherIDs(t, resp.Roles), roles)
}

func TestACLEndpoint_RoleSet(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}
	var roleID string

	testPolicy1, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)
	testPolicy2, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	t.Run("Create it", func(t *testing.T) {
		req := structs.ACLRoleSetRequest{
			Datacenter: "dc1",
			Role: structs.ACLRole{
				Description: "foobar",
				Name:        "baz",
				Policies: []structs.ACLRolePolicyLink{
					structs.ACLRolePolicyLink{
						ID: testPolicy1.ID,
					},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRole{}

		err := acl.RoleSet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Get the role directly to validate that it exists
		roleResp, err := retrieveTestRole(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		role := roleResp.Role

		require.NotNil(t, role.ID)
		require.Equal(t, role.Description, "foobar")
		require.Equal(t, role.Name, "baz")
		require.Len(t, role.Policies, 1)
		require.Equal(t, testPolicy1.ID, role.Policies[0].ID)

		roleID = role.ID
	})

	t.Run("Update it", func(t *testing.T) {
		req := structs.ACLRoleSetRequest{
			Datacenter: "dc1",
			Role: structs.ACLRole{
				ID:          roleID,
				Description: "bat",
				Name:        "bar",
				Policies: []structs.ACLRolePolicyLink{
					structs.ACLRolePolicyLink{
						ID: testPolicy2.ID,
					},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRole{}

		err := acl.RoleSet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Get the role directly to validate that it exists
		roleResp, err := retrieveTestRole(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		role := roleResp.Role

		require.NotNil(t, role.ID)
		require.Equal(t, role.Description, "bat")
		require.Equal(t, role.Name, "bar")
		require.Len(t, role.Policies, 1)
		require.Equal(t, testPolicy2.ID, role.Policies[0].ID)
	})

	t.Run("Create it using Policies linked by id and name", func(t *testing.T) {
		policy1, err := upsertTestPolicy(codec, "root", "dc1")
		require.NoError(t, err)
		policy2, err := upsertTestPolicy(codec, "root", "dc1")
		require.NoError(t, err)

		req := structs.ACLRoleSetRequest{
			Datacenter: "dc1",
			Role: structs.ACLRole{
				Description: "foobar",
				Name:        "baz",
				Policies: []structs.ACLRolePolicyLink{
					structs.ACLRolePolicyLink{
						ID: policy1.ID,
					},
					structs.ACLRolePolicyLink{
						Name: policy2.Name,
					},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRole{}

		err = acl.RoleSet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Delete both policies to ensure that we skip resolving ID->Name
		// in the returned data.
		require.NoError(t, deleteTestPolicy(codec, "root", "dc1", policy1.ID))
		require.NoError(t, deleteTestPolicy(codec, "root", "dc1", policy2.ID))

		// Get the role directly to validate that it exists
		roleResp, err := retrieveTestRole(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		role := roleResp.Role

		require.NotNil(t, role.ID)
		require.Equal(t, role.Description, "foobar")
		require.Equal(t, role.Name, "baz")

		require.Len(t, role.Policies, 0)
	})

	roleNameGen := func(t *testing.T) string {
		t.Helper()
		name, err := uuid.GenerateUUID()
		require.NoError(t, err)
		return name
	}

	t.Run("Create it with invalid service identity (empty)", func(t *testing.T) {
		req := structs.ACLRoleSetRequest{
			Datacenter: "dc1",
			Role: structs.ACLRole{
				Description: "foobar",
				Name:        roleNameGen(t),
				ServiceIdentities: []*structs.ACLServiceIdentity{
					&structs.ACLServiceIdentity{ServiceName: ""},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRole{}

		err := acl.RoleSet(&req, &resp)
		requireErrorContains(t, err, "Service identity is missing the service name field")
	})

	t.Run("Create it with invalid service identity (too large)", func(t *testing.T) {
		long := strings.Repeat("x", serviceIdentityNameMaxLength+1)
		req := structs.ACLRoleSetRequest{
			Datacenter: "dc1",
			Role: structs.ACLRole{
				Description: "foobar",
				Name:        roleNameGen(t),
				ServiceIdentities: []*structs.ACLServiceIdentity{
					&structs.ACLServiceIdentity{ServiceName: long},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRole{}

		err := acl.RoleSet(&req, &resp)
		require.NotNil(t, err)
	})

	for _, test := range []struct {
		name string
		ok   bool
	}{
		{"-abc", false},
		{"abc-", false},
		{"a-bc", true},
		{"_abc", false},
		{"abc_", false},
		{"a_bc", true},
		{":abc", false},
		{"abc:", false},
		{"a:bc", false},
		{"Abc", false},
		{"aBc", false},
		{"abC", false},
		{"0abc", true},
		{"abc0", true},
		{"a0bc", true},
	} {
		var testName string
		if test.ok {
			testName = "Create it with valid service identity (by regex): " + test.name
		} else {
			testName = "Create it with invalid service identity (by regex): " + test.name
		}
		t.Run(testName, func(t *testing.T) {
			req := structs.ACLRoleSetRequest{
				Datacenter: "dc1",
				Role: structs.ACLRole{
					Description: "foobar",
					Name:        roleNameGen(t),
					ServiceIdentities: []*structs.ACLServiceIdentity{
						&structs.ACLServiceIdentity{ServiceName: test.name},
					},
				},
				WriteRequest: structs.WriteRequest{Token: "root"},
			}

			resp := structs.ACLRole{}

			err := acl.RoleSet(&req, &resp)
			if test.ok {
				require.NoError(t, err)

				// Get the token directly to validate that it exists
				roleResp, err := retrieveTestRole(codec, "root", "dc1", resp.ID)
				require.NoError(t, err)
				role := roleResp.Role
				require.ElementsMatch(t, req.Role.ServiceIdentities, role.ServiceIdentities)
			} else {
				require.NotNil(t, err)
			}
		})
	}
}

func TestACLEndpoint_RoleSet_invalid(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	testPolicy1, err := upsertTestPolicy(codec, "root", "dc1")
	require.NoError(t, err)

	names := []string{
		"",
		"-bad",
		"bad-",
		"bad?bad",
		strings.Repeat("x", 257),
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			req := structs.ACLRoleSetRequest{
				Datacenter: "dc1",
				Role: structs.ACLRole{
					Name:        name,
					Description: "foobar",
					Policies: []structs.ACLRolePolicyLink{
						structs.ACLRolePolicyLink{
							ID: testPolicy1.ID,
						},
					},
				},
				WriteRequest: structs.WriteRequest{Token: "root"},
			}
			resp := structs.ACLRole{}

			err := acl.RoleSet(&req, &resp)
			require.Error(t, err)
		})
	}
}

func TestACLEndpoint_RoleDelete(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	existingRole, err := upsertTestRole(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLRoleDeleteRequest{
		Datacenter:   "dc1",
		RoleID:       existingRole.ID,
		WriteRequest: structs.WriteRequest{Token: "root"},
	}

	var resp string

	err = acl.RoleDelete(&req, &resp)
	require.NoError(t, err)

	// Make sure the role is gone
	roleResp, err := retrieveTestRole(codec, "root", "dc1", existingRole.ID)
	require.Nil(t, roleResp.Role)
}

func TestACLEndpoint_RoleList(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	r1, err := upsertTestRole(codec, "root", "dc1")
	require.NoError(t, err)

	r2, err := upsertTestRole(codec, "root", "dc1")
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLRoleListRequest{
		Datacenter:   "dc1",
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLRoleListResponse{}

	err = acl.RoleList(&req, &resp)
	require.NoError(t, err)
	require.ElementsMatch(t, gatherIDs(t, resp.Roles), []string{r1.ID, r2.ID})
}

func TestACLEndpoint_RoleResolve(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ca := connect.TestCA(t, nil)

	existingIDP, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	t.Run("Normal", func(t *testing.T) {
		r1, err := upsertTestRole(codec, "root", "dc1")
		require.NoError(t, err)

		r2, err := upsertTestRole(codec, "root", "dc1")
		require.NoError(t, err)

		acl := ACL{srv: s1}

		// Assign the roles to a token
		tokenUpsertReq := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						ID: r1.ID,
					},
					structs.ACLTokenRoleLink{
						ID: r2.ID,
					},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		token := structs.ACLToken{}
		err = acl.TokenSet(&tokenUpsertReq, &token)
		require.NoError(t, err)
		require.NotEmpty(t, token.SecretID)

		resp := structs.ACLRoleBatchResponse{}
		req := structs.ACLRoleBatchGetRequest{
			Datacenter:   "dc1",
			RoleIDs:      []string{r1.ID, r2.ID},
			QueryOptions: structs.QueryOptions{Token: token.SecretID},
		}
		err = acl.RoleResolve(&req, &resp)
		require.NoError(t, err)
		require.ElementsMatch(t, gatherIDs(t, resp.Roles), []string{r1.ID, r2.ID})
	})

	t.Run("With Bound Roles", func(t *testing.T) {
		r1, err := upsertTestRole(codec, "root", "dc1")
		require.NoError(t, err)

		r2, err := upsertTestRole(codec, "root", "dc1")
		require.NoError(t, err)

		acl := ACL{
			srv:                                   s1,
			disableLoginOnlyRestrictionOnTokenSet: true,
		}

		// Assign the roles to a token, with one bound role that doesn't exist
		tokenUpsertReq := structs.ACLTokenSetRequest{
			Datacenter: "dc1",
			ACLToken: structs.ACLToken{
				IDPName: existingIDP.Name,
				Local:   true,
				Roles: []structs.ACLTokenRoleLink{
					structs.ACLTokenRoleLink{
						ID: r1.ID,
					},
					structs.ACLTokenRoleLink{
						BoundName: "my-magic-role",
					},
				},
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		token := structs.ACLToken{}
		err = acl.TokenSet(&tokenUpsertReq, &token)
		require.NoError(t, err)
		require.NotEmpty(t, token.SecretID)

		resp := structs.ACLRoleBatchResponse{}
		req := structs.ACLRoleBatchGetRequest{
			Datacenter:   "dc1",
			RoleIDs:      []string{r1.ID},
			RoleNames:    []string{"my-magic-role"},
			QueryOptions: structs.QueryOptions{Token: token.SecretID},
		}
		err = acl.RoleResolve(&req, &resp)
		require.NoError(t, err)
		// note the synthetic role is not returned
		require.ElementsMatch(t, gatherIDs(t, resp.Roles), []string{r1.ID})

		// now rename r2 to have a name that matches our bound name
		{
			r2.Name = "my-magic-role"
			arg := structs.ACLRoleSetRequest{
				Datacenter:   "dc1",
				Role:         *r2,
				WriteRequest: structs.WriteRequest{Token: "root"},
			}

			var out structs.ACLRole
			err = msgpackrpc.CallWithCodec(codec, "ACL.RoleSet", &arg, &out)
			require.NoError(t, err)
			require.Equal(t, r2.ID, out.ID)

			r2 = &out
		}

		resp = structs.ACLRoleBatchResponse{}
		req = structs.ACLRoleBatchGetRequest{
			Datacenter:   "dc1",
			RoleIDs:      []string{r1.ID},
			RoleNames:    []string{"my-magic-role"},
			QueryOptions: structs.QueryOptions{Token: token.SecretID},
		}
		err = acl.RoleResolve(&req, &resp)
		require.NoError(t, err)
		// note the synthetic role is returned now that it exists
		require.ElementsMatch(t, gatherIDs(t, resp.Roles), []string{r1.ID, r2.ID})
	})
}

func TestACLEndpoint_IdentityProviderSet(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "consul")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	ca := connect.TestCA(t, nil)
	ca2 := connect.TestCA(t, nil)
	caPath := filepath.Join(tempDir, "ca.pem")
	caPath2 := filepath.Join(tempDir, "ca.pem")
	caPathBad := filepath.Join(tempDir, "ca-bad.pem")
	require.NoError(t, ioutil.WriteFile(caPath, []byte(ca.RootCert), 0644))
	require.NoError(t, ioutil.WriteFile(caPath2, []byte(ca2.RootCert), 0644))
	require.NoError(t, ioutil.WriteFile(caPathBad, []byte("invalid"), 0644))

	newK8S := func(name string) structs.ACLIdentityProvider {
		return structs.ACLIdentityProvider{
			Name:                        name,
			Description:                 "k8s test",
			Type:                        "kubernetes",
			KubernetesHost:              "https://abc:8443",
			KubernetesCACertFile:        caPath,
			KubernetesCACert:            "",
			KubernetesServiceAccountJWT: goodJWT_A,
		}
	}

	t.Run("Create k8s", func(t *testing.T) {
		reqIDP := newK8S("k8s")

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.NoError(t, err)

		// Get the idp directly to validate that it exists
		idpResp, err := retrieveTestIDP(codec, "root", "dc1", resp.Name)
		require.NoError(t, err)
		idp := idpResp.IdentityProvider

		require.Equal(t, idp.Name, "k8s")
		require.Equal(t, idp.Description, "k8s test")
		require.Equal(t, idp.Type, "kubernetes")
		require.Equal(t, idp.KubernetesHost, "https://abc:8443")
		require.Equal(t, idp.KubernetesCACertFile, caPath)
		require.Equal(t, idp.KubernetesCACert, "")
		require.Equal(t, idp.KubernetesServiceAccountJWT, goodJWT_A)
	})

	// Note that this test technically fails right now because the type is
	// invalid.  When we add another idp type this test will start failing for
	// a new reason.
	t.Run("Update k8s fails; not allowed to change types", func(t *testing.T) {
		reqIDP := newK8S("k8s")
		reqIDP.Type = "oidc"

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Update k8s", func(t *testing.T) {
		reqIDP := newK8S("k8s")
		reqIDP.Description = "k8s test modified"
		reqIDP.KubernetesHost = "https://def:1111"
		reqIDP.KubernetesCACertFile = ""
		reqIDP.KubernetesCACert = ca2.RootCert
		reqIDP.KubernetesServiceAccountJWT = goodJWT_B

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.NoError(t, err)

		// Get the idp directly to validate that it exists
		idpResp, err := retrieveTestIDP(codec, "root", "dc1", resp.Name)
		require.NoError(t, err)
		idp := idpResp.IdentityProvider

		require.Equal(t, idp.Name, "k8s")
		require.Equal(t, idp.Description, "k8s test modified")
		require.Equal(t, idp.Type, "kubernetes")
		require.Equal(t, idp.KubernetesHost, "https://def:1111")
		require.Equal(t, idp.KubernetesCACertFile, "")
		require.Equal(t, idp.KubernetesCACert, ca2.RootCert)
		require.Equal(t, idp.KubernetesServiceAccountJWT, goodJWT_B)
	})

	t.Run("Create with no name", func(t *testing.T) {
		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: newK8S(""),
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create with invalid type", func(t *testing.T) {
		req := structs.ACLIdentityProviderSetRequest{
			Datacenter: "dc1",
			IdentityProvider: structs.ACLIdentityProvider{
				Name:        "invalid",
				Description: "invalid test",
				Type:        "invalid",
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	for _, test := range []struct {
		name string
		ok   bool
	}{
		{"-abc", false},
		{"abc-", false},
		{"a-bc", true},
		{"_abc", false},
		{"abc_", false},
		{"a_bc", true},
		{":abc", false},
		{"abc:", false},
		{"a:bc", false},
		{"Abc", false},
		{"aBc", false},
		{"abC", false},
		{"0abc", true},
		{"abc0", true},
		{"a0bc", true},
	} {
		var testName string
		if test.ok {
			testName = "Create k8s with valid name (by regex): " + test.name
		} else {
			testName = "Create k8s with invalid name (by regex): " + test.name
		}
		t.Run(testName, func(t *testing.T) {
			req := structs.ACLIdentityProviderSetRequest{
				Datacenter:       "dc1",
				IdentityProvider: newK8S(test.name),
				WriteRequest:     structs.WriteRequest{Token: "root"},
			}
			resp := structs.ACLIdentityProvider{}

			err := acl.IdentityProviderSet(&req, &resp)

			if test.ok {
				require.NoError(t, err)

				// Get the idp directly to validate that it exists
				idpResp, err := retrieveTestIDP(codec, "root", "dc1", resp.Name)
				require.NoError(t, err)
				idp := idpResp.IdentityProvider

				require.Equal(t, idp.Name, test.name)
				require.Equal(t, idp.Type, "kubernetes")
				require.Equal(t, idp.KubernetesHost, "https://abc:8443")
				require.Equal(t, idp.KubernetesCACertFile, caPath)
				require.Equal(t, idp.KubernetesServiceAccountJWT, goodJWT_A)
			} else {
				require.Error(t, err)
			}
		})
	}

	t.Run("Create k8s with missing k8s host", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesHost = ""

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create k8s with missing ca cert", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesCACertFile = ""
		reqIDP.KubernetesCACert = ""

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create k8s with bad ca cert file", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesCACertFile = caPathBad
		reqIDP.KubernetesCACert = ""

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create k8s with bad ca cert", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesCACertFile = ""
		reqIDP.KubernetesCACert = "garbage"

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create k8s with missing ca cert file", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesCACertFile = filepath.Join(tempDir, "missing.crt")
		reqIDP.KubernetesCACert = ""

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create k8s with missing jwt", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesServiceAccountJWT = ""

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})

	t.Run("Create k8s with bad jwt", func(t *testing.T) {
		reqIDP := newK8S("k8s-2")
		reqIDP.KubernetesServiceAccountJWT = "bad"

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: reqIDP,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLIdentityProvider{}

		err := acl.IdentityProviderSet(&req, &resp)
		require.Error(t, err)
	})
}

func TestACLEndpoint_IdentityProviderDelete(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ca := connect.TestCA(t, nil)

	existingIDP, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	acl := ACL{srv: s1}

	t.Run("normal", func(t *testing.T) {
		req := structs.ACLIdentityProviderDeleteRequest{
			Datacenter:           "dc1",
			IdentityProviderName: existingIDP.Name,
			WriteRequest:         structs.WriteRequest{Token: "root"},
		}

		var ignored bool
		err = acl.IdentityProviderDelete(&req, &ignored)
		require.NoError(t, err)

		// Make sure the idp is gone
		idpResp, err := retrieveTestIDP(codec, "root", "dc1", existingIDP.Name)
		require.NoError(t, err)
		require.Nil(t, idpResp.IdentityProvider)
	})

	t.Run("delete something that doesn't exist", func(t *testing.T) {
		req := structs.ACLIdentityProviderDeleteRequest{
			Datacenter:           "dc1",
			IdentityProviderName: "missing",
			WriteRequest:         structs.WriteRequest{Token: "root"},
		}

		var ignored bool
		err = acl.IdentityProviderDelete(&req, &ignored)
		require.NoError(t, err)
	})
}

// Deleting an identity provider atomically deletes all rules as well.
func TestACLEndpoint_IdentityProviderDelete_RuleCascade(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ca := connect.TestCA(t, nil)

	idp1, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)
	i1_r1, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		idp1.Name,
		[]string{"serviceaccount.name=abc"},
		"abc",
		false,
	)
	require.NoError(t, err)
	i1_r2, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		idp1.Name,
		[]string{"serviceaccount.name=def"},
		"def",
		false,
	)
	require.NoError(t, err)

	idp2, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)
	i2_r1, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		idp2.Name,
		[]string{"serviceaccount.name=abc"},
		"abc",
		false,
	)
	require.NoError(t, err)
	i2_r2, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		idp2.Name,
		[]string{"serviceaccount.name=def"},
		"def",
		false,
	)
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLIdentityProviderDeleteRequest{
		Datacenter:           "dc1",
		IdentityProviderName: idp1.Name,
		WriteRequest:         structs.WriteRequest{Token: "root"},
	}

	var ignored bool
	err = acl.IdentityProviderDelete(&req, &ignored)
	require.NoError(t, err)

	// Make sure the idp is gone.
	idpResp, err := retrieveTestIDP(codec, "root", "dc1", idp1.Name)
	require.NoError(t, err)
	require.Nil(t, idpResp.IdentityProvider)

	// Make sure the rules are gone.
	for _, id := range []string{i1_r1.ID, i1_r2.ID} {
		ruleResp, err := retrieveTestRoleBindingRule(codec, "root", "dc1", id)
		require.NoError(t, err)
		require.Nil(t, ruleResp.RoleBindingRule)
	}

	// Make sure the rules for the untouched IDP are still there.
	for _, id := range []string{i2_r1.ID, i2_r2.ID} {
		ruleResp, err := retrieveTestRoleBindingRule(codec, "root", "dc1", id)
		require.NoError(t, err)
		require.NotNil(t, ruleResp.RoleBindingRule)
	}
}

func TestACLEndpoint_IdentityProviderList(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ca := connect.TestCA(t, nil)

	i1, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	i2, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLIdentityProviderListRequest{
		Datacenter:   "dc1",
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLIdentityProviderListResponse{}

	err = acl.IdentityProviderList(&req, &resp)
	require.NoError(t, err)
	require.ElementsMatch(t, gatherIDs(t, resp.IdentityProviders), []string{i1.Name, i2.Name})
}

func TestACLEndpoint_RoleBindingRuleSet(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}
	var ruleID string

	ca := connect.TestCA(t, nil)
	testIDP, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)
	otherTestIDP, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	newRule := func() structs.ACLRoleBindingRule {
		return structs.ACLRoleBindingRule{
			Description: "foobar",
			IDPName:     testIDP.Name,
			Match: []*structs.ACLRoleBindingRuleMatch{
				&structs.ACLRoleBindingRuleMatch{
					Selector: []string{
						"serviceaccount.name=abc",
					},
				},
			},
			RoleName: "abc",
		}
	}

	requireSetErrors := func(t *testing.T, reqRule structs.ACLRoleBindingRule) {
		req := structs.ACLRoleBindingRuleSetRequest{
			Datacenter:      "dc1",
			RoleBindingRule: reqRule,
			WriteRequest:    structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRoleBindingRule{}

		err := acl.RoleBindingRuleSet(&req, &resp)
		require.Error(t, err)
	}

	requireOK := func(t *testing.T, reqRule structs.ACLRoleBindingRule) *structs.ACLRoleBindingRule {
		req := structs.ACLRoleBindingRuleSetRequest{
			Datacenter:      "dc1",
			RoleBindingRule: reqRule,
			WriteRequest:    structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRoleBindingRule{}

		err := acl.RoleBindingRuleSet(&req, &resp)
		require.NoError(t, err)
		require.NotEmpty(t, resp.ID)
		return &resp
	}

	t.Run("Create it", func(t *testing.T) {
		reqRule := newRule()

		req := structs.ACLRoleBindingRuleSetRequest{
			Datacenter:      "dc1",
			RoleBindingRule: reqRule,
			WriteRequest:    structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRoleBindingRule{}

		err := acl.RoleBindingRuleSet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Get the rule directly to validate that it exists
		ruleResp, err := retrieveTestRoleBindingRule(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		rule := ruleResp.RoleBindingRule

		require.NotEmpty(t, rule.ID)
		require.Equal(t, rule.Description, "foobar")
		require.Equal(t, rule.IDPName, testIDP.Name)
		require.Len(t, rule.Match, 1)
		require.Len(t, rule.Match[0].Selector, 1)
		require.Equal(t, "serviceaccount.name=abc", rule.Match[0].Selector[0])
		require.Equal(t, "abc", rule.RoleName)
		require.False(t, rule.MustExist)

		ruleID = rule.ID
	})

	t.Run("Update fails; cannot change idp name", func(t *testing.T) {
		reqRule := newRule()
		reqRule.ID = ruleID
		reqRule.IDPName = otherTestIDP.Name
		requireSetErrors(t, reqRule)
	})

	t.Run("Update it", func(t *testing.T) {
		reqRule := newRule()
		reqRule.ID = ruleID
		reqRule.Description = "foobar modified"
		reqRule.Match = []*structs.ACLRoleBindingRuleMatch{
			&structs.ACLRoleBindingRuleMatch{
				Selector: []string{
					"serviceaccount.namespace=def",
				},
			},
		}
		reqRule.RoleName = "def"
		reqRule.MustExist = true

		req := structs.ACLRoleBindingRuleSetRequest{
			Datacenter:      "dc1",
			RoleBindingRule: reqRule,
			WriteRequest:    structs.WriteRequest{Token: "root"},
		}
		resp := structs.ACLRoleBindingRule{}

		err := acl.RoleBindingRuleSet(&req, &resp)
		require.NoError(t, err)
		require.NotNil(t, resp.ID)

		// Get the rule directly to validate that it exists
		ruleResp, err := retrieveTestRoleBindingRule(codec, "root", "dc1", resp.ID)
		require.NoError(t, err)
		rule := ruleResp.RoleBindingRule

		require.NotEmpty(t, rule.ID)
		require.Equal(t, rule.Description, "foobar modified")
		require.Equal(t, rule.IDPName, testIDP.Name)
		require.Len(t, rule.Match, 1)
		require.Len(t, rule.Match[0].Selector, 1)
		require.Equal(t, "serviceaccount.namespace=def", rule.Match[0].Selector[0])
		require.Equal(t, "def", rule.RoleName)
		require.True(t, rule.MustExist)
	})

	t.Run("Create fails; empty idp name", func(t *testing.T) {
		reqRule := newRule()
		reqRule.IDPName = ""
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; unknown idp name", func(t *testing.T) {
		reqRule := newRule()
		reqRule.IDPName = "unknown"
		requireSetErrors(t, reqRule)
	})

	t.Run("Create with no explicit matches", func(t *testing.T) {
		reqRule := newRule()
		reqRule.Match = nil

		rule := requireOK(t, reqRule)
		require.Len(t, rule.Match, 0)
	})

	t.Run("Create fails; match contains no selector", func(t *testing.T) {
		// If you don't want any selectors you should not provide any match.
		reqRule := newRule()
		reqRule.Match = []*structs.ACLRoleBindingRuleMatch{
			&structs.ACLRoleBindingRuleMatch{
				Selector: nil,
			},
		}
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; match selector reuses vars", func(t *testing.T) {
		reqRule := newRule()
		reqRule.Match = []*structs.ACLRoleBindingRuleMatch{
			&structs.ACLRoleBindingRuleMatch{
				Selector: []string{
					"serviceaccount.name=a",
					"serviceaccount.name=b",
				},
			},
		}
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; match selector with unknown vars", func(t *testing.T) {
		reqRule := newRule()
		reqRule.Match = []*structs.ACLRoleBindingRuleMatch{
			&structs.ACLRoleBindingRuleMatch{
				Selector: []string{
					"serviceaccount.name=a",
					"serviceaccount.bizarroname=b",
				},
			},
		}
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; match selector invalid", func(t *testing.T) {
		reqRule := newRule()
		reqRule.Match = []*structs.ACLRoleBindingRuleMatch{
			&structs.ACLRoleBindingRuleMatch{
				Selector: []string{
					"serviceaccount.name",
				},
			},
		}
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; empty role name", func(t *testing.T) {
		reqRule := newRule()
		reqRule.RoleName = ""
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; role name with unknown vars", func(t *testing.T) {
		reqRule := newRule()
		reqRule.RoleName = "k8s-{{ serviceaccount.bizarroname }}"
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; invalid role name no template", func(t *testing.T) {
		reqRule := newRule()
		reqRule.RoleName = "-abc-"
		requireSetErrors(t, reqRule)
	})

	t.Run("Create fails; invalid role name with template", func(t *testing.T) {
		reqRule := newRule()
		reqRule.RoleName = "k8s-{{ serviceaccount.name"
		requireSetErrors(t, reqRule)
	})
	t.Run("Create fails; invalid role name after template computed", func(t *testing.T) {
		reqRule := newRule()
		reqRule.RoleName = "k8s-{{ serviceaccount.name }}-blah-"
		requireSetErrors(t, reqRule)
	})
}

func TestACLEndpoint_RoleBindingRuleDelete(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ca := connect.TestCA(t, nil)
	testIDP, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	existingRule, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		testIDP.Name,
		[]string{"serviceaccount.name=abc"},
		"abc",
		false,
	)
	require.NoError(t, err)

	acl := ACL{srv: s1}

	t.Run("normal", func(t *testing.T) {
		req := structs.ACLRoleBindingRuleDeleteRequest{
			Datacenter:        "dc1",
			RoleBindingRuleID: existingRule.ID,
			WriteRequest:      structs.WriteRequest{Token: "root"},
		}

		var ignored bool
		err = acl.RoleBindingRuleDelete(&req, &ignored)
		require.NoError(t, err)

		// Make sure the rule is gone
		ruleResp, err := retrieveTestRoleBindingRule(codec, "root", "dc1", existingRule.ID)
		require.NoError(t, err)
		require.Nil(t, ruleResp.RoleBindingRule)
	})

	t.Run("delete something that doesn't exist", func(t *testing.T) {
		fakeID, err := uuid.GenerateUUID()
		require.NoError(t, err)

		req := structs.ACLRoleBindingRuleDeleteRequest{
			Datacenter:        "dc1",
			RoleBindingRuleID: fakeID,
			WriteRequest:      structs.WriteRequest{Token: "root"},
		}

		var ignored bool
		err = acl.RoleBindingRuleDelete(&req, &ignored)
		require.NoError(t, err)
	})
}

func TestACLEndpoint_RoleBindingRuleList(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	ca := connect.TestCA(t, nil)
	testIDP, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	r1, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		testIDP.Name,
		[]string{"serviceaccount.name=abc"},
		"abc",
		false,
	)
	require.NoError(t, err)

	r2, err := upsertTestRoleBindingRule(
		codec, "root", "dc1",
		testIDP.Name,
		[]string{"serviceaccount.name=def"},
		"def",
		false,
	)
	require.NoError(t, err)

	acl := ACL{srv: s1}

	req := structs.ACLRoleBindingRuleListRequest{
		Datacenter:   "dc1",
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	resp := structs.ACLRoleBindingRuleListResponse{}

	err = acl.RoleBindingRuleList(&req, &resp)
	require.NoError(t, err)
	require.ElementsMatch(t, gatherIDs(t, resp.RoleBindingRules), []string{r1.ID, r2.ID})
}

type fakeK8SIdentityProviderValidator struct {
	data map[string]map[string]string // token -> fieldmap

	*k8sIdentityProviderValidator
}

func (p *fakeK8SIdentityProviderValidator) Reset() {
	p.data = nil
}

func (p *fakeK8SIdentityProviderValidator) InstallToken(token string, fieldMap map[string]string) {
	if p.data == nil {
		p.data = make(map[string]map[string]string)
	}
	p.data[token] = fieldMap
}

func (p *fakeK8SIdentityProviderValidator) ValidateLogin(req *LoginValidationRequest) (*LoginValidationResponse, error) {
	if p.data == nil {
		return nil, acl.ErrNotFound
	}
	fm, ok := p.data[req.Token]
	if !ok {
		return nil, acl.ErrNotFound
	}

	fmCopy := make(map[string]string)
	for k, v := range fm {
		fmCopy[k] = v
	}

	return &LoginValidationResponse{Fields: fmCopy}, nil
}

func TestACLEndpoint_Login_LocalTokensDisabled(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	dir2, s2 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.Datacenter = "dc2"
		c.ACLTokenMinExpirationTTL = 10 * time.Millisecond
		c.ACLTokenMaxExpirationTTL = 5 * time.Second
		// disable local tokens
		c.ACLTokenReplication = false
	})
	defer os.RemoveAll(dir2)
	defer s2.Shutdown()
	codec2 := rpcClient(t, s2)
	defer codec2.Close()

	s2.tokens.UpdateReplicationToken("root", tokenStore.TokenSourceConfig)

	testrpc.WaitForLeader(t, s1.RPC, "dc1")
	testrpc.WaitForLeader(t, s2.RPC, "dc2")

	// Try to join
	joinWAN(t, s2, s1)

	waitForNewACLs(t, s1)
	waitForNewACLs(t, s2)

	acl := ACL{srv: s1}
	acl2 := ACL{srv: s2}
	_ = acl

	t.Run("unknown idp", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  "k8s",
				IDPToken: "fake-web",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc2",
		}
		resp := structs.ACLToken{}

		requireErrorContains(t, acl2.Login(&req, &resp), "Local tokens are disabled")
	})
}

func TestACLEndpoint_Login(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	ca := connect.TestCA(t, nil)

	idp, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	ruleDB, err := upsertTestRoleBindingRule(
		codec, "root", "dc1", idp.Name,
		[]string{
			"serviceaccount.namespace=default",
			"serviceaccount.name=db",
		},
		"k8s-{{serviceaccount.name}}",
		false,
	)
	_, err = upsertTestRoleBindingRule(
		codec, "root", "dc1", idp.Name,
		[]string{
			"serviceaccount.namespace=default",
			"serviceaccount.name=monolith",
		},
		"k8s-{{serviceaccount.name}}",
		true,
	)
	require.NoError(t, err)

	// Swap out the k8s validator with our own test one.
	validator := &fakeK8SIdentityProviderValidator{}
	validator.InstallToken(
		"fake-web", // no rules
		map[string]string{
			"serviceaccount.namespace": "default",
			"serviceaccount.name":      "web",
			"serviceaccount.uid":       "abc123",
		},
	)
	validator.InstallToken(
		"fake-db", // 1 rule
		map[string]string{
			"serviceaccount.namespace": "default",
			"serviceaccount.name":      "db",
			"serviceaccount.uid":       "def456",
		},
	)
	validator.InstallToken(
		"fake-monolith", // 1 rule, must exist
		map[string]string{
			"serviceaccount.namespace": "default",
			"serviceaccount.name":      "monolith",
			"serviceaccount.uid":       "ghi789",
		},
	)
	s1.aclIDPValidatorCreateTestHook = func(orig IdentityProviderValidator) (IdentityProviderValidator, error) {
		if k8s, ok := orig.(*k8sIdentityProviderValidator); ok {
			validator.k8sIdentityProviderValidator = k8s
			return validator, nil
		}
		return orig, nil
	}

	t.Run("do not provide a token", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-web",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		req.Token = "nope"
		resp := structs.ACLToken{}

		requireErrorContains(t, acl.Login(&req, &resp), "do not provide a token")
	})

	t.Run("unknown idp", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name + "-notexist",
				IDPToken: "fake-web",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		requireErrorContains(t, acl.Login(&req, &resp), "ACL not found")
	})

	t.Run("idp is known but type doesn't match", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "not-kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-web",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		require.Error(t, acl.Login(&req, &resp))
	})

	t.Run("invalid idp token", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "invalid",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		require.Error(t, acl.Login(&req, &resp))
	})

	t.Run("valid idp token no bindings", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-web",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		requireErrorContains(t, acl.Login(&req, &resp), "Permission denied")
	})

	t.Run("valid idp token 1 binding must exist and does not exist", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-monolith",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		require.Error(t, acl.Login(&req, &resp))
	})

	// create the role so that the mustexist login works
	var monolithRoleID string
	{
		arg := structs.ACLRoleSetRequest{
			Datacenter: "dc1",
			Role: structs.ACLRole{
				Name: "k8s-monolith",
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var out structs.ACLRole
		require.NoError(t, acl.RoleSet(&arg, &out))

		monolithRoleID = out.ID
	}

	t.Run("valid idp token 1 binding must exist and now exists", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-monolith",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		require.NoError(t, acl.Login(&req, &resp))

		require.Equal(t, idp.Name, resp.IDPName)
		require.Equal(t, `token created via login: {"pod":"pod1"}`, resp.Description)
		require.True(t, resp.Local)
		require.Len(t, resp.Roles, 1)
		role := resp.Roles[0]
		require.Equal(t, monolithRoleID, role.ID)
		require.Equal(t, "k8s-monolith", role.Name)
		require.Empty(t, role.BoundName)
	})

	t.Run("valid idp token 1 binding", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-db",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		require.NoError(t, acl.Login(&req, &resp))

		require.Equal(t, idp.Name, resp.IDPName)
		require.Equal(t, `token created via login: {"pod":"pod1"}`, resp.Description)
		require.True(t, resp.Local)
		require.Len(t, resp.Roles, 1)
		role := resp.Roles[0]
		require.Empty(t, role.ID)
		require.Empty(t, role.Name)
		require.Equal(t, "k8s-db", role.BoundName)
	})

	{
		req := structs.ACLRoleBindingRuleSetRequest{
			Datacenter: "dc1",
			RoleBindingRule: structs.ACLRoleBindingRule{
				IDPName:   ruleDB.IDPName,
				RoleName:  ruleDB.RoleName,
				MustExist: false,
				Match:     nil,
			},
			WriteRequest: structs.WriteRequest{Token: "root"},
		}

		var out structs.ACLRoleBindingRule
		require.NoError(t, acl.RoleBindingRuleSet(&req, &out))
	}

	t.Run("valid idp token 1 binding (no selectors this time)", func(t *testing.T) {
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-db",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		require.NoError(t, acl.Login(&req, &resp))

		require.Equal(t, idp.Name, resp.IDPName)
		require.Equal(t, `token created via login: {"pod":"pod1"}`, resp.Description)
		require.True(t, resp.Local)
		require.Len(t, resp.Roles, 1)
		role := resp.Roles[0]
		require.Empty(t, role.ID)
		require.Empty(t, role.Name)
		require.Equal(t, "k8s-db", role.BoundName)
	})

	{
		// Update the k8s idp to force the cache to invalidate for the next
		// subtest.
		updated := *idp
		updated.Description = "updated for the test"

		req := structs.ACLIdentityProviderSetRequest{
			Datacenter:       "dc1",
			IdentityProvider: updated,
			WriteRequest:     structs.WriteRequest{Token: "root"},
		}

		var ignored structs.ACLIdentityProvider
		require.NoError(t, acl.IdentityProviderSet(&req, &ignored))
	}

	// ensure our create hook does something different this time
	validator2 := &fakeK8SIdentityProviderValidator{}
	s1.aclIDPValidatorCreateTestHook = func(orig IdentityProviderValidator) (IdentityProviderValidator, error) {
		if k8s, ok := orig.(*k8sIdentityProviderValidator); ok {
			validator2.k8sIdentityProviderValidator = k8s
			return validator2, nil
		}
		return orig, nil
	}

	t.Run("updating the idp invalidates the cache", func(t *testing.T) {
		// We'll try to login with the 'fake-db' cred which DOES exist in the
		// old fake validator, but no longer exists in the new fake validator.
		req := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-db",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		resp := structs.ACLToken{}

		requireErrorContains(t, acl.Login(&req, &resp), "ACL not found")
	})
}

func TestACLEndpoint_Logout(t *testing.T) {
	t.Parallel()

	dir1, s1 := testServerWithConfig(t, func(c *Config) {
		c.ACLDatacenter = "dc1"
		c.ACLsEnabled = true
		c.ACLMasterToken = "root"
	})
	defer os.RemoveAll(dir1)
	defer s1.Shutdown()
	codec := rpcClient(t, s1)
	defer codec.Close()

	testrpc.WaitForLeader(t, s1.RPC, "dc1")

	acl := ACL{srv: s1}

	ca := connect.TestCA(t, nil)

	idp, err := upsertTestIDP(codec, "root", "dc1", ca.RootCert)
	require.NoError(t, err)

	_, err = upsertTestRoleBindingRule(
		codec, "root", "dc1", idp.Name,
		nil,
		"k8s-{{serviceaccount.name}}",
		false,
	)
	require.NoError(t, err)

	// Swap out the k8s validator with our own test one.
	validator := &fakeK8SIdentityProviderValidator{}
	validator.InstallToken(
		"fake-web", // no rules
		map[string]string{
			"serviceaccount.namespace": "default",
			"serviceaccount.name":      "web",
			"serviceaccount.uid":       "abc123",
		},
	)
	s1.aclIDPValidatorCreateTestHook = func(orig IdentityProviderValidator) (IdentityProviderValidator, error) {
		if k8s, ok := orig.(*k8sIdentityProviderValidator); ok {
			validator.k8sIdentityProviderValidator = k8s
			return validator, nil
		}
		return orig, nil
	}

	t.Run("you must provide a token", func(t *testing.T) {
		req := structs.ACLLogoutRequest{
			Datacenter: "dc1",
			// WriteRequest: structs.WriteRequest{Token: "root"},
		}
		req.Token = ""
		var ignored bool

		requireErrorContains(t, acl.Logout(&req, &ignored), "ACL not found")
	})

	t.Run("logout from deleted token", func(t *testing.T) {
		req := structs.ACLLogoutRequest{
			Datacenter:   "dc1",
			WriteRequest: structs.WriteRequest{Token: "not-found"},
		}
		var ignored bool
		requireErrorContains(t, acl.Logout(&req, &ignored), "ACL not found")
	})

	t.Run("logout from non-IDP-linked token should fail", func(t *testing.T) {
		req := structs.ACLLogoutRequest{
			Datacenter:   "dc1",
			WriteRequest: structs.WriteRequest{Token: "root"},
		}
		var ignored bool
		requireErrorContains(t, acl.Logout(&req, &ignored), "Permission denied")
	})

	t.Run("login then logout", func(t *testing.T) {
		// Create a totally legit Login token.
		loginReq := structs.ACLLoginRequest{
			Auth: &structs.ACLLoginParams{
				IDPType:  "kubernetes",
				IDPName:  idp.Name,
				IDPToken: "fake-web",
				Meta:     map[string]string{"pod": "pod1"},
			},
			Datacenter: "dc1",
		}
		loginToken := structs.ACLToken{}

		require.NoError(t, acl.Login(&loginReq, &loginToken))
		require.NotEmpty(t, loginToken.SecretID)

		// Now turn around and nuke it.
		req := structs.ACLLogoutRequest{
			Datacenter:   "dc1",
			WriteRequest: structs.WriteRequest{Token: loginToken.SecretID},
		}

		var ignored bool
		require.NoError(t, acl.Logout(&req, &ignored))
	})

	// TODO: token not found
	// TODO: not an idp token
	// TODO: not in acl datacenter or token is not local (FORWARD)
}

func gatherIDs(t *testing.T, v interface{}) []string {
	t.Helper()

	var out []string
	switch x := v.(type) {
	case []*structs.ACLRole:
		for _, r := range x {
			out = append(out, r.ID)
		}
	case structs.ACLRoleListStubs:
		for _, r := range x {
			out = append(out, r.ID)
		}
	case []*structs.ACLPolicy:
		for _, p := range x {
			out = append(out, p.ID)
		}
	case structs.ACLPolicyListStubs:
		for _, p := range x {
			out = append(out, p.ID)
		}
	case []*structs.ACLToken:
		for _, p := range x {
			out = append(out, p.AccessorID)
		}
	case structs.ACLTokenListStubs:
		for _, p := range x {
			out = append(out, p.AccessorID)
		}
	case []*structs.ACLIdentityProvider:
		for _, p := range x {
			out = append(out, p.Name)
		}
	case structs.ACLIdentityProviderListStubs:
		for _, p := range x {
			out = append(out, p.Name)
		}
	case []*structs.ACLRoleBindingRule:
		for _, p := range x {
			out = append(out, p.ID)
		}
	case structs.ACLRoleBindingRules:
		for _, p := range x {
			out = append(out, p.ID)
		}
	default:
		t.Fatalf("unknown type: %T", x)
	}
	return out
}

// upsertTestToken creates a token for testing purposes
func upsertTestToken(codec rpc.ClientCodec, masterToken string, datacenter string,
	tokenModificationFn func(token *structs.ACLToken)) (*structs.ACLToken, error) {
	arg := structs.ACLTokenSetRequest{
		Datacenter: datacenter,
		ACLToken: structs.ACLToken{
			Description: "User token",
			Local:       false,
			Policies:    nil,
		},
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}

	if tokenModificationFn != nil {
		tokenModificationFn(&arg.ACLToken)
	}

	var out structs.ACLToken

	err := msgpackrpc.CallWithCodec(codec, "ACL.TokenSet", &arg, &out)

	if err != nil {
		return nil, err
	}

	if out.AccessorID == "" {
		return nil, fmt.Errorf("AccessorID is nil: %v", out)
	}

	return &out, nil
}

func retrieveTestTokenAccessorForSecret(codec rpc.ClientCodec, masterToken string, datacenter string, id string) (string, error) {
	arg := structs.ACLTokenGetRequest{
		TokenID:      "root",
		TokenIDType:  structs.ACLTokenSecret,
		Datacenter:   "dc1",
		QueryOptions: structs.QueryOptions{Token: "root"},
	}

	var out structs.ACLTokenResponse

	err := msgpackrpc.CallWithCodec(codec, "ACL.TokenRead", &arg, &out)

	if err != nil {
		return "", err
	}

	if out.Token == nil {
		return "", nil
	}

	return out.Token.AccessorID, nil
}

// retrieveTestToken returns a policy for testing purposes
func retrieveTestToken(codec rpc.ClientCodec, masterToken string, datacenter string, id string) (*structs.ACLTokenResponse, error) {
	arg := structs.ACLTokenGetRequest{
		Datacenter:   datacenter,
		TokenID:      id,
		TokenIDType:  structs.ACLTokenAccessor,
		QueryOptions: structs.QueryOptions{Token: masterToken},
	}

	var out structs.ACLTokenResponse

	err := msgpackrpc.CallWithCodec(codec, "ACL.TokenRead", &arg, &out)

	if err != nil {
		return nil, err
	}

	return &out, nil
}

func deleteTestPolicy(codec rpc.ClientCodec, masterToken string, datacenter string, policyID string) error {
	arg := structs.ACLPolicyDeleteRequest{
		Datacenter:   datacenter,
		PolicyID:     policyID,
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}

	var ignored string
	err := msgpackrpc.CallWithCodec(codec, "ACL.PolicyDelete", &arg, &ignored)
	return err
}

// upsertTestPolicy creates a policy for testing purposes
func upsertTestPolicy(codec rpc.ClientCodec, masterToken string, datacenter string) (*structs.ACLPolicy, error) {
	// Make sure test policies can't collide
	policyUnq, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	arg := structs.ACLPolicySetRequest{
		Datacenter: datacenter,
		Policy: structs.ACLPolicy{
			Name: fmt.Sprintf("test-policy-%s", policyUnq),
		},
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}

	var out structs.ACLPolicy

	err = msgpackrpc.CallWithCodec(codec, "ACL.PolicySet", &arg, &out)

	if err != nil {
		return nil, err
	}

	if out.ID == "" {
		return nil, fmt.Errorf("ID is nil: %v", out)
	}

	return &out, nil
}

// retrieveTestPolicy returns a policy for testing purposes
func retrieveTestPolicy(codec rpc.ClientCodec, masterToken string, datacenter string, id string) (*structs.ACLPolicyResponse, error) {
	arg := structs.ACLPolicyGetRequest{
		Datacenter:   datacenter,
		PolicyID:     id,
		QueryOptions: structs.QueryOptions{Token: masterToken},
	}

	var out structs.ACLPolicyResponse

	err := msgpackrpc.CallWithCodec(codec, "ACL.PolicyRead", &arg, &out)

	if err != nil {
		return nil, err
	}

	return &out, nil
}

func deleteTestRole(codec rpc.ClientCodec, masterToken string, datacenter string, roleID string) error {
	arg := structs.ACLRoleDeleteRequest{
		Datacenter:   datacenter,
		RoleID:       roleID,
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}

	var ignored string
	err := msgpackrpc.CallWithCodec(codec, "ACL.RoleDelete", &arg, &ignored)
	return err
}

// upsertTestRole creates a role for testing purposes
func upsertTestRole(codec rpc.ClientCodec, masterToken string, datacenter string) (*structs.ACLRole, error) {
	// Make sure test roles can't collide
	roleUnq, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	policyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	arg := structs.ACLRoleSetRequest{
		Datacenter: datacenter,
		Role: structs.ACLRole{
			Name: fmt.Sprintf("test-role-%s", roleUnq),
			Policies: []structs.ACLRolePolicyLink{
				structs.ACLRolePolicyLink{
					ID: policyID,
				},
			},
		},
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}

	var out structs.ACLRole

	err = msgpackrpc.CallWithCodec(codec, "ACL.RoleSet", &arg, &out)

	if err != nil {
		return nil, err
	}

	if out.ID == "" {
		return nil, fmt.Errorf("ID is nil: %v", out)
	}

	return &out, nil
}

// retrieveTestRole returns a role for testing purposes
func retrieveTestRole(codec rpc.ClientCodec, masterToken string, datacenter string, id string) (*structs.ACLRoleResponse, error) {
	arg := structs.ACLRoleGetRequest{
		Datacenter:   datacenter,
		RoleID:       id,
		QueryOptions: structs.QueryOptions{Token: masterToken},
	}

	var out structs.ACLRoleResponse

	err := msgpackrpc.CallWithCodec(codec, "ACL.RoleRead", &arg, &out)

	if err != nil {
		return nil, err
	}

	return &out, nil
}

func deleteTestIDP(codec rpc.ClientCodec, masterToken string, datacenter string, idpName string) error {
	arg := structs.ACLIdentityProviderDeleteRequest{
		Datacenter:           datacenter,
		IdentityProviderName: idpName,
		WriteRequest:         structs.WriteRequest{Token: masterToken},
	}

	var ignored string
	err := msgpackrpc.CallWithCodec(codec, "ACL.IdentityProviderDelete", &arg, &ignored)
	return err
}

func upsertTestIDP(codec rpc.ClientCodec, masterToken string, datacenter string, caCert string) (*structs.ACLIdentityProvider, error) {
	name, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	req := structs.ACLIdentityProviderSetRequest{
		Datacenter: datacenter,
		IdentityProvider: structs.ACLIdentityProvider{
			Name:                        "test-idp-" + name,
			Type:                        "kubernetes",
			KubernetesHost:              "https://abc:8443",
			KubernetesCACert:            caCert,
			KubernetesServiceAccountJWT: goodJWT_A,
		},
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}

	var out structs.ACLIdentityProvider

	err = msgpackrpc.CallWithCodec(codec, "ACL.IdentityProviderSet", &req, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func retrieveTestIDP(codec rpc.ClientCodec, masterToken string, datacenter string, name string) (*structs.ACLIdentityProviderResponse, error) {
	arg := structs.ACLIdentityProviderGetRequest{
		Datacenter:           datacenter,
		IdentityProviderName: name,
		QueryOptions:         structs.QueryOptions{Token: masterToken},
	}

	var out structs.ACLIdentityProviderResponse

	err := msgpackrpc.CallWithCodec(codec, "ACL.IdentityProviderRead", &arg, &out)

	if err != nil {
		return nil, err
	}

	return &out, nil
}

func deleteTestRoleBindingRule(codec rpc.ClientCodec, masterToken string, datacenter string, ruleID string) error {
	arg := structs.ACLRoleBindingRuleDeleteRequest{
		Datacenter:        datacenter,
		RoleBindingRuleID: ruleID,
		WriteRequest:      structs.WriteRequest{Token: masterToken},
	}

	var ignored string
	err := msgpackrpc.CallWithCodec(codec, "ACL.RoleBindingRuleDelete", &arg, &ignored)
	return err
}

func upsertTestRoleBindingRule(
	codec rpc.ClientCodec,
	masterToken string,
	datacenter string,
	idpName string,
	singleSelector []string,
	roleName string,
	mustExist bool,
) (*structs.ACLRoleBindingRule, error) {
	req := structs.ACLRoleBindingRuleSetRequest{
		Datacenter: datacenter,
		RoleBindingRule: structs.ACLRoleBindingRule{
			IDPName:   idpName,
			RoleName:  roleName,
			MustExist: mustExist,
		},
		WriteRequest: structs.WriteRequest{Token: masterToken},
	}
	if len(singleSelector) > 0 {
		req.RoleBindingRule.Match = []*structs.ACLRoleBindingRuleMatch{
			&structs.ACLRoleBindingRuleMatch{
				Selector: singleSelector,
			},
		}
	}

	var out structs.ACLRoleBindingRule

	err := msgpackrpc.CallWithCodec(codec, "ACL.RoleBindingRuleSet", &req, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func retrieveTestRoleBindingRule(codec rpc.ClientCodec, masterToken string, datacenter string, ruleID string) (*structs.ACLRoleBindingRuleResponse, error) {
	arg := structs.ACLRoleBindingRuleGetRequest{
		Datacenter:        datacenter,
		RoleBindingRuleID: ruleID,
		QueryOptions:      structs.QueryOptions{Token: masterToken},
	}

	var out structs.ACLRoleBindingRuleResponse

	err := msgpackrpc.CallWithCodec(codec, "ACL.RoleBindingRuleRead", &arg, &out)

	if err != nil {
		return nil, err
	}

	return &out, nil
}

func requireTimeEquals(t *testing.T, expect, got time.Time) {
	t.Helper()
	if !expect.Equal(got) {
		t.Fatalf("expected=%q != got=%q", expect, got)
	}
}

func requireErrorContains(t *testing.T, err error, expectedErrorMessage string) {
	t.Helper()
	if err == nil {
		t.Fatal("An error is expected but got nil.")
	}
	if !strings.Contains(err.Error(), expectedErrorMessage) {
		t.Fatalf("unexpected error: %v", err)
	}
}

const goodJWT_A = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlbW8tdG9rZW4ta21iOW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVtbyIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijc2MDkxYWY0LTRiNTYtMTFlOS1hYzRiLTcwOGIxMTgwMWNiZSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlbW8ifQ.ZiAHjijBAOsKdum0Aix6lgtkLkGo9_Tu87dWQ5Zfwnn3r2FejEWDAnftTft1MqqnMzivZ9Wyyki5ZjQRmTAtnMPJuHC-iivqY4Wh4S6QWCJ1SivBv5tMZR79t5t8mE7R1-OHwst46spru1pps9wt9jsA04d3LpV0eeKYgdPTVaQKklxTm397kIMUugA6yINIBQ3Rh8eQqBgNwEmL4iqyYubzHLVkGkoP9MJikFI05vfRiHtYr-piXz6JFDzXMQj9rW6xtMmrBSn79ChbyvC5nz-Nj2rJPnHsb_0rDUbmXY5PpnMhBpdSH-CbZ4j8jsiib6DtaGJhVZeEQ1GjsFAZwQ"
const goodJWT_B = "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImNvbnN1bC1pZHAtdG9rZW4tcmV2aWV3LWFjY291bnQtdG9rZW4tbTYyZHMiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiY29uc3VsLWlkcC10b2tlbi1yZXZpZXctYWNjb3VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijc1ZTNjYmVhLTRiNTYtMTFlOS1hYzRiLTcwOGIxMTgwMWNiZSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmNvbnN1bC1pZHAtdG9rZW4tcmV2aWV3LWFjY291bnQifQ.uMb66tZ8d8gNzS8EnjlkzbrGKc5M-BESwS5B46IUbKfdMtajsCwgBXICytWKQ2X7wfm4QQykHVaElijBlO8QVvYeYzQE0uy75eH9EXNXmRh862YL_Qcy_doPC0R6FQXZW99S5Joc-3riKsq7N-sjEDBshOqyfDaGfan3hxaiV4Bv4hXXWRFUQ9aTAfPVvk1FQi21U9Fbml9ufk8kkk6gAmIEA_o7p-ve6WIhm48t7MJv314YhyVqXdrvmRykPdMwj4TfwSn3pTJ82P4NgSbXMJhwNkwIadJPZrM8EfN5ISpR4EW3jzP3IHtgQxrIovWQ9TQib1Z5zdRaLWaFVm6XaQ"
