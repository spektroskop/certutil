package certutil

import (
	"crypto/x509"
	"encoding/pem"
	"time"
)

type Result struct {
	Chains [][]string
	Error  error
	Expiry time.Time
	Issuer string
	Name   string
}

func CommonNamesFromChain(chain []*x509.Certificate) (r []string) {
	for _, cert := range chain {
		r = append(r, cert.Subject.CommonName)
	}
	return
}

func Verify(options x509.VerifyOptions, c *x509.Certificate) Result {
	result := Result{Expiry: c.NotAfter, Issuer: c.Issuer.CommonName, Name: c.Subject.CommonName}
	chains, err := c.Verify(options)
	result.Error = err
	for _, chain := range chains {
		result.Chains = append(result.Chains, CommonNamesFromChain(chain))
	}

	return result
}

type List []*x509.Certificate

func ListFromBundle(data []byte) (cl List) {
	cl.AddBundle(data)
	return cl
}

func SplitBundle(data []byte) (List, List) {
	all := ListFromBundle(data)
	return all.Split()
}

func (cl *List) AddBundle(data []byte) {
	for {
		var block *pem.Block
		if block, data = pem.Decode(data); block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			*cl = append(*cl, cert)
		}
	}
}

func (cl List) Split() (server List, issuers List) {
	for _, cert := range cl {
		if cert.IsCA {
			issuers = append(issuers, cert)
		} else {
			server = append(server, cert)
		}
	}

	return
}

func (cl List) Verify(options x509.VerifyOptions) (result []Result) {
	for _, cert := range cl {
		result = append(result, Verify(options, cert))
	}

	return
}

func (cl List) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range cl {
		pool.AddCert(cert)
	}

	return pool
}
