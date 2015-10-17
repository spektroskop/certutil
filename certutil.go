package certutil

import (
	"crypto/x509"
	"encoding/pem"
)

func CommonNamesFromChain(chain []*x509.Certificate) (r []string) {
	for _, cert := range chain {
		r = append(r, cert.Subject.CommonName)
	}

	return
}

type List []*x509.Certificate

func ListFromBundle(data []byte) (cl List) {
	cl.AddBundle(data)
	return cl
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

func SplitBundle(data []byte) (List, List) {
	all := ListFromBundle(data)
	return all.Split()
}

func (cl List) Split() (cert List, isca List) {
	for _, c := range cl {
		if c.IsCA {
			isca = append(isca, c)
		} else {
			cert = append(cert, c)
		}
	}

	return
}

type Result struct {
	*x509.Certificate
	Chains [][]string
	Error  error
}

func Verify(options x509.VerifyOptions, cert *x509.Certificate) Result {
	result := Result{Certificate: cert}
	chains, err := cert.Verify(options)
	result.Error = err
	for _, chain := range chains {
		result.Chains = append(result.Chains, CommonNamesFromChain(chain))
	}

	return result
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
