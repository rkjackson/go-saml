package saml

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSignedRequest(t *testing.T) {
	assert := assert.New(t)
	sp := ServiceProviderSettings{
		PublicCertPath:              "./default.crt",
		PrivateKeyPath:              "./default.key",
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               true,
	}
	err := sp.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	signedXML, err := authnRequest.SignedString(sp.PrivateKeyPath)
	assert.NoError(err)
	assert.NotEmpty(signedXML)

	_, err = Verify(signedXML, sp.IDPPublicCert)
	assert.NoError(err)
}

func TestGetUnsignedRequest(t *testing.T) {
	assert := assert.New(t)
	sp := ServiceProviderSettings{
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCertPath:           "./default.crt",
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               false,
	}
	err := sp.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	assert.NoError(err)
	assert.NotEmpty(authnRequest)
}

func TestGetUnsignedRequestFromString(t *testing.T) {
	assert := assert.New(t)

	b, err := ioutil.ReadFile("./default.crt")
	require.NoError(t, err)

	sp := ServiceProviderSettings{
		IDPSSOURL:                   "http://www.onelogin.net",
		IDPSSODescriptorURL:         "http://www.onelogin.net",
		IDPPublicCert:               string(b),
		AssertionConsumerServiceURL: "http://localhost:8000/auth/saml/name",
		SPSignRequest:               false,
	}
	err = sp.Init()
	assert.NoError(err)

	// Construct an AuthnRequest
	authnRequest := sp.GetAuthnRequest()
	assert.NoError(err)
	assert.NotEmpty(authnRequest)
}
