package saml

import "github.com/rkjackson/go-saml/util"

// ServiceProviderSettings provides settings to configure server acting as a SAML Service Provider.
// Expect only one IDP per SP in this configuration. If you need to configure multipe IDPs for an SP
// then configure multiple instances of this module
type ServiceProviderSettings struct {
	PublicCertPath      string
	PrivateKeyPath      string
	IDPSSOURL           string
	IDPSSODescriptorURL string

	IDPPublicCertPath string // optional - to load cert by URL
	IDPPublicCert     string // full certificate

	AssertionConsumerServiceURL string
	SPSignRequest               bool

	hasInit    bool
	publicCert string
	privateKey string
}

type IdentityProviderSettings struct {
}

func (s *ServiceProviderSettings) Init() (err error) {
	if s.hasInit {
		return nil
	}
	s.hasInit = true

	if s.SPSignRequest {
		s.publicCert, err = util.LoadCertificate(s.PublicCertPath)
		if err != nil {
			panic(err)
		}

		s.privateKey, err = util.LoadCertificate(s.PrivateKeyPath)
		if err != nil {
			panic(err)
		}
	}

	if len(s.IDPPublicCertPath) > 0 {
		s.IDPPublicCert, err = util.LoadCertificate(s.IDPPublicCertPath)
	}

	if err != nil {
		panic(err)
	}

	return nil
}

func (s *ServiceProviderSettings) PublicCert() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.publicCert
}

func (s *ServiceProviderSettings) PrivateKey() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return s.privateKey
}

func (s *ServiceProviderSettings) IDPPublicCertBody() string {
	if !s.hasInit {
		panic("Must call ServiceProviderSettings.Init() first")
	}
	return util.ParseCertificate(s.IDPPublicCert)
}
