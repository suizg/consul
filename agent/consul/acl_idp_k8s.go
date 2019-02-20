package consul

import (
	"fmt"
	"io/ioutil"

	k8sidp "github.com/hashicorp/consul/agent/consul/kubernetesidp"
	"github.com/hashicorp/consul/agent/structs"
)

type k8sIdentityProviderValidator struct {
	// idp is the underlying state store object with configuration settings
	idp *structs.ACLIdentityProvider

	// tr is used to configure the strategy for doing a token review.
	// Currently the only options are using the kubernetes API or mocking the
	// review. Mocks should only be used in tests.
	tr k8sidp.TokenReviewer

	// publicKeys is an optional list of public key objects used to verify JWTs
	publicKeys []interface{}
}

var _ IdentityProviderValidator = (*k8sIdentityProviderValidator)(nil)

func newK8SIdentityProviderValidator(idp *structs.ACLIdentityProvider) (*k8sIdentityProviderValidator, error) {
	idp = idp.Clone() // avoid monkeying with memdb copy

	if idp.Type != "kubernetes" {
		return nil, fmt.Errorf("%q is not a kubernetes identity provider", idp.Name)
	}

	if idp.KubernetesHost == "" {
		return nil, fmt.Errorf("KubernetesHost is required")
	}

	if idp.KubernetesCACertFile == "" && idp.KubernetesCACert == "" {
		return nil, fmt.Errorf("one of KubernetesCACertFile or KubernetesCACert must be set")
	}

	if idp.KubernetesCACertFile != "" {
		caData, err := ioutil.ReadFile(idp.KubernetesCACertFile)
		if err != nil {
			return nil, err
		}
		idp.KubernetesCACert = string(caData)
		idp.KubernetesCACertFile = ""
	}

	if _, err := k8sidp.ParsePublicKeyPEM([]byte(idp.KubernetesCACert)); err != nil {
		return nil, fmt.Errorf("error parsing kubernetes ca cert: %v", err)
	}

	// This is the bearer token we give the apiserver to use the API.
	if idp.KubernetesServiceAccountJWT == "" {
		return nil, fmt.Errorf("KubernetesServiceAccountJWT is required")
	}
	if err := k8sidp.ValidateJWT(idp.KubernetesServiceAccountJWT); err != nil {
		return nil, fmt.Errorf("KubernetesServiceAccountJWT is not a valid JWT: %v", err)
	}

	if len(idp.KubernetesPEMKeyFiles) > 0 {
		idp.KubernetesPEMKeys = make([]string, len(idp.KubernetesPEMKeyFiles))
		for i, certFile := range idp.KubernetesPEMKeyFiles {
			certData, err := ioutil.ReadFile(certFile)
			if err != nil {
				return nil, err
			}
			idp.KubernetesPEMKeys[i] = string(certData)
		}
		idp.KubernetesPEMKeyFiles = nil
	}

	var publicKeys []interface{}
	if len(idp.KubernetesPEMKeys) > 0 {
		publicKeys = make([]interface{}, len(idp.KubernetesPEMKeys))
		for i, cert := range idp.KubernetesPEMKeys {
			data, err := k8sidp.ParsePublicKeyPEM([]byte(cert))
			if err != nil {
				return nil, fmt.Errorf("provided kubernetes public key is invalid: %v", err)
			}
			publicKeys[i] = data
		}
	}

	tr, err := k8sidp.NewTokenReviewer(idp)
	if err != nil {
		return nil, err
	}

	return &k8sIdentityProviderValidator{
		idp:        idp,
		tr:         tr,
		publicKeys: publicKeys,
	}, nil
}

func k8sValidateIdentityProvider(idp *structs.ACLIdentityProvider) error {
	_, err := newK8SIdentityProviderValidator(idp)
	return err
}

func (v *k8sIdentityProviderValidator) ValidateLogin(req *LoginValidationRequest) (*LoginValidationResponse, error) {
	sa, err := k8sidp.ParseAndValidateJWT(req.Token, v.publicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate JWT: %v", err)
	}

	// look up the JWT token in the kubernetes API
	r, err := v.tr.Review(req.Token)
	if err != nil {
		return nil, err
	}

	// TODO(rb): is this strictly necessary since the whole point of tokenreview
	// TODO(rb): is that you don't even have to care about the claims?
	// Verify the returned metadata matches the expected data from the service
	// account.
	if sa.EffectiveNamespace() != r.Namespace {
		return nil, fmt.Errorf("JWT namepaces did not match")
	}
	if sa.EffectiveName() != r.Name {
		return nil, fmt.Errorf("JWT names did not match")
	}
	if sa.EffectiveUID() != r.UID {
		return nil, fmt.Errorf("JWT UIDs did not match")
	}

	return &LoginValidationResponse{
		Fields: map[string]string{
			"serviceaccount.namespace": r.Namespace,
			"serviceaccount.name":      r.Name,
			"serviceaccount.uid":       r.UID,
		},
	}, nil
}

var k8sAvailableFields = []string{
	"serviceaccount.namespace",
	"serviceaccount.name",
	"serviceaccount.uid",
}

func (p *k8sIdentityProviderValidator) AvailableFields() []string {
	return k8sAvailableFields
}
